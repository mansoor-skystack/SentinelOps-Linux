import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.sanitizer import LogSanitizer
from app.guardrails import CommandSafetyGuardrail

client = TestClient(app)


def test_health_endpoint():
    res = client.get("/api/health")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "online"
    assert body["indexed_chunks"] > 0


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


def test_diagnose_and_remediate_workflow():
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