import os
import json
import hmac
import ipaddress
import logging
from typing import Optional
import requests
from fastapi import FastAPI, HTTPException, Header, UploadFile, File, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

from .database import init_db, SessionLocal, IncidentRecord, VisitorLog
from .sanitizer import LogSanitizer
from .retriever import HybridKnowledgeEngine, RUNBOOKS_DIR
from .llm import synthesize_diagnosis

SENTINELOPS_API_KEY = os.getenv("SENTINELOPS_API_KEY", "SentinelOps-webhook-secret-2026")
VISITOR_API_KEY = os.getenv("VISITOR_API_KEY", "").strip()
logger = logging.getLogger(__name__)
FRONTEND_HTML = os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "index.html")

app = FastAPI(title="SentinelOps: Automated Linux Log Telemetry & Hybrid-RAG System")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

def parse_device_summary(user_agent: str) -> str:
    lowered_ua = user_agent.lower()
    if "windows" in lowered_ua:
        os_name = "Windows"
    elif "android" in lowered_ua:
        os_name = "Android"
    elif "iphone" in lowered_ua or "ipad" in lowered_ua:
        os_name = "iOS"
    elif "mac os" in lowered_ua:
        os_name = "macOS"
    elif "linux" in lowered_ua:
        os_name = "Linux"
    else:
        os_name = "Unknown OS"

    if "edg/" in lowered_ua:
        browser = "Edge"
    elif "chrome/" in lowered_ua:
        browser = "Chrome"
    elif "firefox/" in lowered_ua:
        browser = "Firefox"
    elif "safari/" in lowered_ua and "chrome/" not in lowered_ua:
        browser = "Safari"
    elif "curl" in lowered_ua or "python-requests" in lowered_ua:
        browser = "CLI / Bot"
    else:
        browser = "Unknown Browser"

    return f"{browser} on {os_name} | Raw: {user_agent[:120]}"

def _lookup_visitor_location(ip_address: str) -> tuple[str, str, str, str]:
    try:
        address = ipaddress.ip_address(ip_address)
    except ValueError:
        logger.warning("Skipping visitor geolocation for an invalid IP address")
        return "Unknown", "Unknown", "Unknown", "Unknown"

    if not address.is_global:
        return "Unknown", "Unknown", "Unknown", "Unknown"

    try:
        response = requests.get(
            f"https://ipapi.co/{address.compressed}/json/",
            timeout=3,
        )
        response.raise_for_status()
        geo = response.json()
        if not isinstance(geo, dict) or geo.get("error"):
            raise ValueError("Geolocation provider returned an invalid response")
    except (requests.RequestException, ValueError) as exc:
        logger.warning("Visitor geolocation lookup failed (%s)", type(exc).__name__)
        return "Unknown", "Unknown", "Unknown", "Unknown"

    return (
        str(geo.get("city") or "Unknown")[:100],
        str(geo.get("region") or "Unknown")[:100],
        str(geo.get("country_name") or "Unknown")[:100],
        str(geo.get("org") or "Unknown")[:150],
    )

def save_visitor_in_background(
    ip_address: str,
    user_agent: str,
    referrer: str,
    accept_language: str,
    path: str,
) -> None:
    city, region, country, isp = _lookup_visitor_location(ip_address)
    with SessionLocal() as db:
        db.add(
            VisitorLog(
                ip_address=ip_address[:64],
                city=city,
                region=region,
                country=country,
                isp=isp,
                browser_os=parse_device_summary(user_agent)[:200],
                referrer=referrer[:250],
                accept_language=accept_language[:100],
                path=path[:150],
            )
        )
        db.commit()

@app.middleware("http")
async def capture_passive_visitors(request: Request, call_next):
    response = await call_next(request)

    if request.method == "GET" and request.url.path == "/":
        forwarded = request.headers.get("x-forwarded-for", "").split(",", 1)[0].strip()
        client_host = request.client.host if request.client else "Unknown"
        real_ip = forwarded or client_host
        user_agent = request.headers.get("user-agent", "Unknown")
        referrer = request.headers.get("referer", "Direct")
        accept_language = request.headers.get("accept-language", "Unknown")

        if response.background is None:
            response.background = BackgroundTasks()
        elif not isinstance(response.background, BackgroundTasks):
            existing_background = response.background
            response.background = BackgroundTasks()
            response.background.add_task(existing_background)

        response.background.add_task(
            save_visitor_in_background,
            real_ip,
            user_agent,
            referrer,
            accept_language,
            request.url.path,
        )

    return response

rag_engine: Optional[HybridKnowledgeEngine] = None

@app.on_event("startup")
def on_startup():
    global rag_engine
    init_db()
    rag_engine = HybridKnowledgeEngine()

class TriageRequest(BaseModel):
    raw_log: str
    stack_filter: str = "All"
    hostname: str = "web-console"
    source_type: str = "manual"

class AgentWebhookPayload(BaseModel):
    hostname: str
    stack_tag: str = "Linux"
    cpu_load: float = 0.0
    mem_used_pct: float = 0.0
    disk_used_pct: float = 0.0
    raw_log: str

def process_incident(raw_log: str, stack_filter: str, hostname: str, source_type: str, cpu: float = 0.0, mem: float = 0.0, disk: float = 0.0):
    sanitized, redactions, dropped = LogSanitizer.filter_and_sanitize(raw_log)
    chunks = rag_engine.search_hybrid(sanitized, stack_filter=stack_filter, top_k=3)
    diagnosis = synthesize_diagnosis(sanitized, chunks)

    db = SessionLocal()
    try:
        rec = IncidentRecord(
            hostname=hostname,
            source_type=source_type,
            stack_tag=stack_filter,
            cpu_load=cpu,
            mem_used_pct=mem,
            disk_used_pct=disk,
            sanitized_log=sanitized,
            root_cause=diagnosis.get("root_cause", ""),
            diagnostic_commands=json.dumps(diagnosis.get("diagnostic_commands", [])),
            fix_commands=json.dumps(diagnosis.get("fix_commands", [])),
            risk_level=diagnosis.get("risk_level", "SAFE"),
            citations=json.dumps(diagnosis.get("citations", [])),
        )
        db.add(rec)
        db.commit()
        db.refresh(rec)
        inc_id = rec.id

        # Trigger autonomous notification dispatch
        from .notifier import send_slack_alert
        send_slack_alert(
            incident_id=inc_id,
            hostname=hostname,
            stack=stack_filter,
            root_cause=diagnosis.get("root_cause", ""),
            risk_level=diagnosis.get("risk_level", "SAFE"),
            fix_commands=diagnosis.get("fix_commands", [])
        )
    finally:
        db.close()

    return {
        "incident_id": inc_id,
        "hostname": hostname,
        "source_type": source_type,
        "sanitized_log": sanitized,
        "redactions": redactions,
        "noise_lines_dropped": dropped,
        "diagnosis": diagnosis
    }

@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    with open(FRONTEND_HTML, "r", encoding="utf-8") as f:
        return f.read()

@app.get("/api/health")
def health_check():
    return {"status": "online", "app": "SentinelOps", "indexed_chunks": len(rag_engine.documents) if rag_engine else 0}

@app.post("/api/diagnose")
def diagnose_manual(req: TriageRequest):
    if not req.raw_log.strip():
        raise HTTPException(status_code=400, detail="Error log cannot be empty")
    return process_incident(req.raw_log, req.stack_filter, req.hostname, req.source_type)

@app.post("/api/webhook/ingest")
def ingest_from_linux_agent(payload: AgentWebhookPayload, x_api_key: Optional[str] = Header(None)):
    if x_api_key != SENTINELOPS_API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized SentinelOps Agent API Key")
    return process_incident(
        payload.raw_log,
        payload.stack_tag,
        payload.hostname,
        "systemd-agent",
        payload.cpu_load,
        payload.mem_used_pct,
        payload.disk_used_pct,
    )

@app.get("/api/incidents")
def list_recent_incidents(limit: int = 10):
    db = SessionLocal()
    try:
        rows = db.query(IncidentRecord).order_by(IncidentRecord.id.desc()).limit(limit).all()
        return [
            {
                "id": r.id,
                "hostname": r.hostname,
                "source_type": r.source_type,
                "stack_tag": r.stack_tag,
                "cpu_load": r.cpu_load,
                "mem_used_pct": r.mem_used_pct,
                "disk_used_pct": r.disk_used_pct,
                "sanitized_log": r.sanitized_log,
                "root_cause": r.root_cause,
                "diagnostic_commands": json.loads(r.diagnostic_commands or "[]"),
                "fix_commands": json.loads(r.fix_commands or "[]"),
                "risk_level": r.risk_level,
                "citations": json.loads(r.citations or "[]"),
                "created_at": r.created_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
            }
            for r in rows
        ]
    finally:
        db.close()

@app.post("/api/runbooks/upload")
async def upload_runbook(file: UploadFile = File(...)):
    if not file.filename.endswith(".md"):
        raise HTTPException(status_code=400, detail="Only Markdown (.md) runbooks allowed")
    dest = os.path.join(RUNBOOKS_DIR, os.path.basename(file.filename))
    with open(dest, "wb") as f:
        f.write(await file.read())
    rag_engine.rebuild_index()
    return {"status": "indexed", "filename": file.filename, "total_chunks": len(rag_engine.documents)}

@app.get("/api/export/{incident_id}", response_class=PlainTextResponse)
def export_postmortem(incident_id: int):
    db = SessionLocal()
    try:
        r = db.query(IncidentRecord).filter(IncidentRecord.id == incident_id).first()
        if not r:
            raise HTTPException(status_code=404, detail="Incident not found")
        diags = "\n".join(json.loads(r.diagnostic_commands or "[]"))
        fixes = "\n".join(json.loads(r.fix_commands or "[]"))
        cites = ", ".join(json.loads(r.citations or "[]"))
        return f"""# SentinelOps Incident Post-Mortem Report (#INC-{r.id})
- **Host / Node:** {r.hostname} ({r.source_type})
- **Timestamp:** {r.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}
- **Stack Domain:** {r.stack_tag}
- **Telemetry Snapshot:** CPU Load: {r.cpu_load} | RAM Used: {r.mem_used_pct}% | Disk Used: {r.disk_used_pct}%
- **Command Safety Rating:** {r.risk_level}

## 1. Sanitized Terminal Error Log
```text
{r.sanitized_log}
```

## 2. Root Cause Analysis
{r.root_cause}

## 3. Diagnostic Verification Commands
```bash
{diags}
```

## 4. Remediation Commands
```bash
{fixes}
```

## 5. Grounded Runbook Citations
{cites}
"""
    finally:
        db.close()

from .remediator import SSHRemediationEngine

@app.post("/api/remediate/{incident_id}")
def approve_and_remediate(incident_id: int):
    db = SessionLocal()
    try:
        rec = db.query(IncidentRecord).filter(IncidentRecord.id == incident_id).first()
        if not rec:
            raise HTTPException(status_code=404, detail="Incident record not found")

        commands = json.loads(rec.fix_commands or "[]")
        if not commands:
            raise HTTPException(status_code=400, detail="No remediation commands associated with this incident")

        execution_report = SSHRemediationEngine.execute_fix(
            hostname=rec.hostname,
            commands=commands,
            risk_level=rec.risk_level
        )
        return {
            "incident_id": rec.id,
            "hostname": rec.hostname,
            "remediation": execution_report
        }
    finally:
        db.close()

@app.get("/api/visitors")
def list_visitors(x_api_key: Optional[str] = Header(None)):
    if not VISITOR_API_KEY:
        raise HTTPException(status_code=503, detail="Visitor API is not configured")
    if not x_api_key or not hmac.compare_digest(x_api_key, VISITOR_API_KEY):
        raise HTTPException(status_code=401, detail="Unauthorized visitor API key")

    db = SessionLocal()
    try:
        rows = db.query(VisitorLog).order_by(VisitorLog.visited_at.desc()).limit(50).all()
        return [
            {
                "id": row.id,
                "ip_address": row.ip_address,
                "location": f"{row.city}, {row.region}, {row.country}",
                "isp": row.isp,
                "device": row.browser_os,
                "referrer": row.referrer,
                "language": row.accept_language,
                "visited_at": row.visited_at.isoformat() if row.visited_at else None,
            }
            for row in rows
        ]
    finally:
        db.close()