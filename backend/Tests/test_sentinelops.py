import pytest
from fastapi.testclient import TestClient
from app import main
from app.main import app
from app.sanitizer import LogSanitizer
from app.guardrails import CommandSafetyGuardrail

@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_health_endpoint(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "online"
    assert body["indexed_chunks"] > 0


def test_page_views_only_track_dashboard_requests(client, monkeypatch):
    recorded = []
    monkeypatch.setattr(
        main,
        "save_visitor_in_background",
        lambda *args: recorded.append(args),
    )
    headers = {
        "x-forwarded-for": "203.0.113.10, 10.0.0.1",
        "user-agent": "SentinelOps test client",
    }

    home_response = client.get("/", headers=headers)
    health_response = client.get("/api/health", headers=headers)

    assert home_response.status_code == 200
    assert health_response.status_code == 200
    assert recorded == [
        ("203.0.113.10", "SentinelOps test client", "Direct", "Unknown", "/")
    ]


def test_visitor_endpoint_requires_dedicated_key(client, monkeypatch):
    monkeypatch.setattr(main, "VISITOR_API_KEY", "")
    assert client.get("/api/visitors").status_code == 503

    monkeypatch.setattr(main, "VISITOR_API_KEY", "test-visitor-key")
    assert client.get("/api/visitors").status_code == 401
    response = client.get(
        "/api/visitors",
        headers={"X-API-Key": "test-visitor-key"},
    )
    assert response.status_code == 200


def test_pii_and_secret_sanitization():
    raw = (
        "DEBUG: verbose heartbeat\n"
        "ERROR: DB connection failed at DATABASE_URL=postgresql://admin:SecretPass123@10.0.2.15:5432/prod"
    )
    sanitized, redactions, dropped = LogSanitizer.filter_and_sanitize(raw)
    assert "SecretPass123" not in sanitized
    assert "10.0.2.15" not in sanitized
    assert dropped >= 1
    assert len(redactions) > 0


def test_command_safety_guardrail_blocks_destructive():
    risk, flagged = CommandSafetyGuardrail.inspect(["rm -rf /var/log/*", "sudo systemctl restart nginx"])
    assert risk == "HIGH_RISK"
    assert len(flagged) >= 1


def test_command_safety_guardrail_allows_safe():
    risk, flagged = CommandSafetyGuardrail.inspect(["sudo systemctl restart nginx", "df -h"])
    assert risk == "SAFE"
    assert flagged == []


def test_diagnose_and_remediate_workflow(client, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "")
    monkeypatch.delenv("TARGET_SSH_KEY_PATH", raising=False)
    monkeypatch.delenv("TARGET_SSH_PASSWORD", raising=False)

    res = client.post("/api/diagnose", json={
        "raw_log": "nginx: [emerg] bind() to 0.0.0.0:80 failed (98: Address already in use)",
        "stack_filter": "Nginx",
        "hostname": "test-vm-01",
        "source_type": "pytest"
    })
    assert res.status_code == 200
    data = res.json()
    inc_id = data["incident_id"]
    assert data["diagnosis"]["risk_level"] == "SAFE"

    # Test approval remediation endpoint
    rem_res = client.post(f"/api/remediate/{inc_id}")
    assert rem_res.status_code == 200
    assert rem_res.json()["remediation"]["executed"] is True