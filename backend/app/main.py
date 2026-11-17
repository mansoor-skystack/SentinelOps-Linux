import os
import json
import hmac
import ipaddress
import logging
import re
import uuid
from datetime import datetime, timedelta
from typing import Dict, Literal, Optional
import requests
from urllib.parse import urlsplit
from fastapi import FastAPI, HTTPException, Header, UploadFile, File, Request, BackgroundTasks, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, or_
from dotenv import load_dotenv

load_dotenv()

from . import auth
from .database import init_db, SessionLocal, IncidentRecord, VisitorLog
from .sanitizer import LogSanitizer
from .retriever import HybridKnowledgeEngine, RUNBOOKS_DIR
from .llm import synthesize_diagnosis
from .notifier import send_slack_alert

SENTINELOPS_API_KEY = os.getenv("SENTINELOPS_API_KEY", "").strip()
logger = logging.getLogger(__name__)
FRONTEND_HTML = os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "index.html")
MAX_RUNBOOK_BYTES = 1_000_000

app = FastAPI(title="SentinelOps: Automated Linux Log Telemetry & Hybrid-RAG System")

def _parse_cors_origins(configured_origins: str) -> list[str]:
    origins = []
    for configured in configured_origins.split(","):
        origin = configured.strip().rstrip("/")
        if not origin:
            continue
        parsed = urlsplit(origin)
        hostname = (parsed.hostname or "").lower()
        if (
            not hostname
            or parsed.username
            or parsed.password
            or parsed.path
            or parsed.query
            or parsed.fragment
            or (parsed.scheme != "https" and hostname not in {"localhost", "127.0.0.1", "::1"})
        ):
            raise ValueError("CORS_ALLOWED_ORIGINS must contain exact HTTPS origins (HTTP is allowed for localhost)")
        origins.append(f"{parsed.scheme}://{parsed.netloc}")
    return origins


cors_origins = _parse_cors_origins(os.getenv("CORS_ALLOWED_ORIGINS", ""))
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-API-Key"],
)

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
    with SessionLocal() as db:
        cached_location = (
            db.query(VisitorLog)
            .filter(
                VisitorLog.ip_address == ip_address,
                VisitorLog.country != "Unknown",
            )
            .order_by(VisitorLog.visited_at.desc())
            .first()
        )
        if cached_location:
            city, region, country, isp = (
                cached_location.city,
                cached_location.region,
                cached_location.country,
                cached_location.isp,
            )
        else:
            city, region, country, isp = _lookup_visitor_location(ip_address)
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
    raw_log: str = Field(..., max_length=100_000)
    stack_filter: str = Field(default="All", max_length=50)
    hostname: str = Field(default="web-console", max_length=120)
    source_type: str = Field(default="manual", max_length=50)

class AgentWebhookPayload(BaseModel):
    hostname: str = Field(..., max_length=120)
    stack_tag: str = Field(default="Linux", max_length=50)
    cpu_load: float = 0.0
    mem_used_pct: float = 0.0
    disk_used_pct: float = 0.0
    raw_log: str = Field(..., max_length=100_000)

class AdminLoginRequest(BaseModel):
    password: str = Field(..., min_length=1, max_length=256)

class IncidentStatusUpdate(BaseModel):
    status: Literal["PENDING", "COMPLETED"]

class RemediationApproval(BaseModel):
    approved: Literal[True]
    diagnostic_run_id: str = Field(..., min_length=16, max_length=64)

_CORRELATION_STOP_WORDS = {
    "about", "after", "because", "before", "being", "cause", "could", "error",
    "failed", "failure", "from", "host", "issue", "linux", "process", "service",
    "system", "systemd", "that", "there", "this", "unable", "with",
}

def _correlation_terms(root_cause: str, sanitized_log: str) -> set[str]:
    text = f"{root_cause} {sanitized_log}".lower()
    text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b\d+\b", " ", text)
    return {
        term for term in re.findall(r"[a-z][a-z0-9_-]{2,}", text)
        if term not in _CORRELATION_STOP_WORDS
    }

def _incidents_are_correlated(first: IncidentRecord, second: IncidentRecord) -> bool:
    if (
        (first.hostname or "").strip().lower() == (second.hostname or "").strip().lower()
        or (first.stack_tag or "").strip().lower() != (second.stack_tag or "").strip().lower()
    ):
        return False
    first_terms = _correlation_terms(first.root_cause or "", first.sanitized_log or "")
    second_terms = _correlation_terms(second.root_cause or "", second.sanitized_log or "")
    shared = first_terms & second_terms
    union = first_terms | second_terms
    return len(shared) >= 2 and len(shared) / max(1, len(union)) >= 0.5

def _correlate_incident(db, incident: IncidentRecord) -> tuple[Optional[int], int]:
    cutoff = incident.created_at - timedelta(minutes=5)
    candidates = (
        db.query(IncidentRecord)
        .filter(
            IncidentRecord.id != incident.id,
            IncidentRecord.created_at >= cutoff,
            IncidentRecord.created_at <= incident.created_at,
        )
        .all()
    )
    matching = [candidate for candidate in candidates if _incidents_are_correlated(incident, candidate)]
    if not matching:
        return None, 1

    group_ids = {row.correlation_id or row.id for row in matching}
    group_id = min(group_ids)
    affected = (
        db.query(IncidentRecord)
        .filter(
            or_(
                IncidentRecord.id.in_(group_ids),
                IncidentRecord.correlation_id.in_(group_ids),
            )
        )
        .all()
    )
    hosts = {incident.hostname}
    for row in affected:
        row.correlation_id = group_id
        hosts.add(row.hostname)
    incident.correlation_id = group_id
    db.commit()
    return group_id, len(hosts)

def process_incident(
    raw_log: str,
    stack_filter: str,
    hostname: str,
    source_type: str,
    cpu: float = 0.0,
    mem: float = 0.0,
    disk: float = 0.0,
    background_tasks: Optional[BackgroundTasks] = None,
    telemetry: Optional[Dict[str, float]] = None,
):
    sanitized, redactions, dropped = LogSanitizer.filter_and_sanitize(raw_log)
    chunks = rag_engine.search_hybrid(sanitized, stack_filter=stack_filter, top_k=3)
    try:
        diagnosis = synthesize_diagnosis(sanitized, chunks, telemetry=telemetry)
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

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
        correlation_id, correlated_hosts = _correlate_incident(db, rec)
        inc_id = rec.id

        alert_args = {
            "incident_id": inc_id,
            "hostname": hostname,
            "stack": stack_filter,
            "root_cause": diagnosis.get("root_cause", ""),
            "risk_level": diagnosis.get("risk_level", "SAFE"),
            "fix_commands": diagnosis.get("fix_commands", []),
        }
        if background_tasks is None:
            send_slack_alert(**alert_args)
        else:
            background_tasks.add_task(send_slack_alert, **alert_args)
    finally:
        db.close()

    return {
        "incident_id": inc_id,
        "hostname": hostname,
        "source_type": source_type,
        "sanitized_log": sanitized,
        "redactions": redactions,
        "noise_lines_dropped": dropped,
        "diagnosis": diagnosis,
        "correlation_id": correlation_id,
        "correlated_hosts": correlated_hosts,
    }

@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    with open(FRONTEND_HTML, "r", encoding="utf-8") as f:
        return f.read()

@app.get("/api/health")
def health_check():
    return {"status": "online", "app": "SentinelOps", "indexed_chunks": len(rag_engine.documents) if rag_engine else 0}

@app.get("/api/auth/status")
def auth_status(request: Request):
    return {
        "configured": auth.auth_is_configured(),
        "authenticated": auth.has_admin_session(request),
    }

@app.post("/api/auth/login")
def admin_login(req: AdminLoginRequest, request: Request):
    if not auth.auth_is_configured():
        raise HTTPException(status_code=503, detail="Admin authentication is not configured")
    client_ip = request.client.host if request.client else "unknown"
    if auth.is_login_rate_limited(client_ip):
        raise HTTPException(status_code=429, detail="Too many failed sign-in attempts. Try again later.")
    if not auth.verify_admin_password(req.password):
        auth.record_failed_login(client_ip)
        raise HTTPException(status_code=401, detail="Invalid admin password")
    auth.clear_failed_logins(client_ip)

    response = JSONResponse({"authenticated": True})
    response.set_cookie(
        key=auth.SESSION_COOKIE_NAME,
        value=auth.create_session_token(),
        max_age=auth.SESSION_TTL_SECONDS,
        httponly=True,
        secure=auth.SESSION_COOKIE_SECURE,
        samesite="strict",
        path="/",
    )
    return response

@app.post("/api/auth/logout")
def admin_logout():
    response = JSONResponse({"authenticated": False})
    response.delete_cookie(
        key=auth.SESSION_COOKIE_NAME,
        httponly=True,
        secure=auth.SESSION_COOKIE_SECURE,
        samesite="strict",
        path="/",
    )
    return response

@app.post("/api/diagnose")
def diagnose_manual(
    req: TriageRequest,
    background_tasks: BackgroundTasks,
    _: None = Depends(auth.require_admin),
):
    if not req.raw_log.strip():
        raise HTTPException(status_code=400, detail="Error log cannot be empty")
    return process_incident(
        req.raw_log, req.stack_filter, req.hostname, req.source_type,
        background_tasks=background_tasks,
    )

@app.post("/api/webhook/ingest")
def ingest_from_linux_agent(
    payload: AgentWebhookPayload,
    background_tasks: BackgroundTasks,
    x_api_key: Optional[str] = Header(None),
):
    if not SENTINELOPS_API_KEY:
        raise HTTPException(status_code=503, detail="Agent webhook authentication is not configured")
    if not x_api_key or not hmac.compare_digest(x_api_key, SENTINELOPS_API_KEY):
        raise HTTPException(status_code=401, detail="Unauthorized agent API key")
    return process_incident(
        payload.raw_log,
        payload.stack_tag,
        payload.hostname,
        "systemd-agent",
        payload.cpu_load,
        payload.mem_used_pct,
        payload.disk_used_pct,
        background_tasks=background_tasks,
        telemetry={
            "cpu_load": payload.cpu_load,
            "mem_used_pct": payload.mem_used_pct,
            "disk_used_pct": payload.disk_used_pct,
        },
    )

@app.get("/api/incidents")
def list_recent_incidents(
    limit: Optional[int] = Query(default=None, ge=1),
    source_type: Optional[str] = Query(default=None, max_length=50),
    _: None = Depends(auth.require_admin),
):
    db = SessionLocal()
    try:
        query = db.query(IncidentRecord)
        if source_type:
            query = query.filter(IncidentRecord.source_type == source_type)
        query = query.order_by(IncidentRecord.id.desc())
        if limit is not None:
            query = query.limit(limit)
        rows = query.all()
        group_ids = {row.correlation_id for row in rows if row.correlation_id is not None}
        group_sizes = {}
        if group_ids:
            group_sizes = {
                group_id: host_count
                for group_id, host_count in (
                    db.query(
                        IncidentRecord.correlation_id,
                        func.count(func.distinct(IncidentRecord.hostname)),
                    )
                    .filter(IncidentRecord.correlation_id.in_(group_ids))
                    .group_by(IncidentRecord.correlation_id)
                    .all()
                )
            }
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
                "status": r.status,
                "correlation_id": r.correlation_id,
                "correlated_hosts": group_sizes.get(r.correlation_id, 1),
                "diagnostic_report": json.loads(r.diagnostic_report or "null"),
                "remediation_report": json.loads(r.remediation_report or "null"),
                "post_check_report": json.loads(r.post_check_report or "null"),
                "remediation_approved_at": (
                    r.remediation_approved_at.strftime("%Y-%m-%d %H:%M:%S UTC")
                    if r.remediation_approved_at else None
                ),
                "remediation_approved_by": r.remediation_approved_by,
                "citations": json.loads(r.citations or "[]"),
                "created_at": r.created_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
            }
            for r in rows
        ]
    finally:
        db.close()

@app.post("/api/incidents/{incident_id}/status")
def update_incident_status(
    incident_id: int,
    update: IncidentStatusUpdate,
    _: None = Depends(auth.require_admin),
):
    db = SessionLocal()
    try:
        incident = db.query(IncidentRecord).filter(IncidentRecord.id == incident_id).first()
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        incident.status = update.status
        db.commit()
        return {"incident_id": incident.id, "status": incident.status}
    finally:
        db.close()

@app.post("/api/runbooks/upload")
async def upload_runbook(file: UploadFile = File(...), _: None = Depends(auth.require_admin)):
    filename = file.filename or ""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*\.md", filename, re.IGNORECASE):
        raise HTTPException(status_code=400, detail="Only Markdown (.md) runbooks allowed")

    contents = await file.read(MAX_RUNBOOK_BYTES + 1)
    await file.close()
    if len(contents) > MAX_RUNBOOK_BYTES:
        raise HTTPException(status_code=413, detail="Runbook exceeds the 1 MB upload limit")

    dest = os.path.join(RUNBOOKS_DIR, filename)
    with open(dest, "wb") as f:
        f.write(contents)
    rag_engine.rebuild_index()
    return {"status": "indexed", "filename": filename, "total_chunks": len(rag_engine.documents)}

@app.get("/api/export/{incident_id}", response_class=PlainTextResponse)
def export_postmortem(incident_id: int, _: None = Depends(auth.require_admin)):
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
- **Correlation Group:** {r.correlation_id or "None"}

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

## 6. Read-only Diagnostic Execution
{json.dumps(json.loads(r.diagnostic_report or "null"), indent=2)}

## 7. Remediation Approval and Execution
- **Approved by:** {r.remediation_approved_by or "Not approved"}
- **Approved at:** {r.remediation_approved_at.strftime('%Y-%m-%d %H:%M:%S UTC') if r.remediation_approved_at else "Not approved"}
{json.dumps(json.loads(r.remediation_report or "null"), indent=2)}

## 8. Post-remediation Health Check
{json.dumps(json.loads(r.post_check_report or "null"), indent=2)}
"""
    finally:
        db.close()

from .remediator import SSHRemediationEngine

@app.post("/api/incidents/{incident_id}/diagnose")
def run_incident_diagnostics(
    incident_id: int,
    _: None = Depends(auth.require_admin),
):
    db = SessionLocal()
    try:
        rec = db.query(IncidentRecord).filter(IncidentRecord.id == incident_id).first()
        if not rec:
            raise HTTPException(status_code=404, detail="Incident record not found")
        commands = json.loads(rec.diagnostic_commands or "[]")
        if not commands:
            raise HTTPException(status_code=400, detail="No diagnostic commands associated with this incident")

        report = SSHRemediationEngine.execute_diagnostics(rec.hostname, commands)
        report["run_id"] = uuid.uuid4().hex
        report["created_at"] = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        rec.diagnostic_report = json.dumps(report)
        rec.remediation_report = None
        rec.post_check_report = None
        rec.remediation_approved_at = None
        rec.remediation_approved_by = None
        db.commit()
        return {"incident_id": rec.id, "diagnostics": report}
    finally:
        db.close()

@app.post("/api/remediate/{incident_id}")
def approve_and_remediate(
    incident_id: int,
    approval: RemediationApproval,
    _: None = Depends(auth.require_admin),
):
    db = SessionLocal()
    try:
        rec = db.query(IncidentRecord).filter(IncidentRecord.id == incident_id).first()
        if not rec:
            raise HTTPException(status_code=404, detail="Incident record not found")

        commands = json.loads(rec.fix_commands or "[]")
        if not commands:
            raise HTTPException(status_code=400, detail="No remediation commands associated with this incident")

        diagnostic_report = json.loads(rec.diagnostic_report or "null")
        if (
            not isinstance(diagnostic_report, dict)
            or diagnostic_report.get("run_id") != approval.diagnostic_run_id
            or diagnostic_report.get("status") not in {"COMPLETED", "SIMULATION_ONLY"}
        ):
            raise HTTPException(status_code=409, detail="Run read-only diagnostics before approving this fix")
        if (
            os.getenv("SSH_REMEDIATION_ENABLED", "").strip().lower() == "true"
            and not diagnostic_report.get("executed")
        ):
            raise HTTPException(status_code=409, detail="Live fixes require successfully executed diagnostics")

        execution_report = SSHRemediationEngine.execute_fix(
            hostname=rec.hostname,
            commands=commands,
            risk_level=rec.risk_level
        )
        post_check_report = {
            "executed": False,
            "status": "NOT_RUN",
            "outputs": [],
        }
        if execution_report.get("executed"):
            post_check_report = SSHRemediationEngine.execute_post_check(rec.hostname)
            if post_check_report.get("status") == "HEALTHY":
                rec.status = "COMPLETED"
        elif execution_report.get("status") == "SIMULATION_ONLY":
            post_check_report["status"] = "SIMULATION_ONLY"

        approved_at = datetime.utcnow()
        rec.remediation_approved_at = approved_at
        rec.remediation_approved_by = "authenticated-admin-session"
        rec.remediation_report = json.dumps(execution_report)
        rec.post_check_report = json.dumps(post_check_report)
        db.commit()
        return {
            "incident_id": rec.id,
            "hostname": rec.hostname,
            "remediation": execution_report,
            "post_check": post_check_report,
            "approved_at": approved_at.isoformat(timespec="seconds") + "Z",
            "approved_by": rec.remediation_approved_by,
        }
    finally:
        db.close()

@app.get("/api/visitors")
def list_visitors(_: None = Depends(auth.require_admin)):
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