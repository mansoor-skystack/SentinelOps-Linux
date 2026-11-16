import os
import pytest
import runpy
import tempfile
from pathlib import Path

_TEST_STORAGE = tempfile.TemporaryDirectory(prefix="sentinelops-tests-")
os.environ["DATABASE_URL"] = f"sqlite:///{(Path(_TEST_STORAGE.name) / 'sentinelops-tests.db').as_posix()}"
os.environ["SLACK_WEBHOOK_URL"] = ""
os.environ["GROQ_API_KEY"] = ""
os.environ["SENTINELOPS_API_KEY"] = ""
os.environ["ADMIN_PASSWORD"] = ""
os.environ["SESSION_SECRET"] = ""

from fastapi.testclient import TestClient
from app import main
from app import auth
from app.main import app
from app.sanitizer import LogSanitizer
from app.guardrails import CommandSafetyGuardrail
from app.remediator import SSHRemediationEngine
from app.database import _enforce_remote_postgres_tls, engine
from sqlalchemy.engine import make_url

COLLECTOR = runpy.run_path(
    str(Path(__file__).resolve().parents[2] / "agent" / "linux_collector.py")
)

@pytest.fixture(scope="module")
def client():
    assert engine.url.drivername.startswith("sqlite"), "Tests must use the isolated SQLite database"
    with TestClient(app, base_url="https://testserver") as test_client:
        yield test_client
    engine.dispose()


@pytest.fixture
def configure_admin(monkeypatch):
    monkeypatch.setattr(auth, "ADMIN_PASSWORD", "test-admin-password-123")
    monkeypatch.setattr(auth, "SESSION_SECRET", "test-session-secret-" * 3)
    monkeypatch.setattr(auth, "SESSION_COOKIE_SECURE", True)


@pytest.fixture
def admin_client(client, configure_admin):
    response = client.post("/api/auth/login", json={"password": "test-admin-password-123"})
    assert response.status_code == 200
    yield client
    client.post("/api/auth/logout")


def test_health_endpoint(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "online"
    assert body["indexed_chunks"] > 0


def test_admin_routes_fail_closed_when_auth_is_unconfigured(client, monkeypatch):
    monkeypatch.setattr(auth, "ADMIN_PASSWORD", "")
    monkeypatch.setattr(auth, "SESSION_SECRET", "")
    status = client.get("/api/auth/status").json()
    assert status == {"configured": False, "authenticated": False}
    assert client.get("/api/incidents").status_code == 503


def test_cors_requires_exact_secure_origins():
    assert main._parse_cors_origins("https://ops.example.com/,http://localhost:3000") == [
        "https://ops.example.com",
        "http://localhost:3000",
    ]
    with pytest.raises(ValueError, match="exact HTTPS origins"):
        main._parse_cors_origins("http://ops.example.com")
    with pytest.raises(ValueError, match="exact HTTPS origins"):
        main._parse_cors_origins("*")


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


def test_admin_login_sets_secure_session_cookie_and_logout(client, configure_admin):
    bad_login = client.post("/api/auth/login", json={"password": "wrong"})
    assert bad_login.status_code == 401

    login = client.post("/api/auth/login", json={"password": "test-admin-password-123"})
    assert login.status_code == 200
    cookie = login.headers["set-cookie"].lower()
    assert "httponly" in cookie
    assert "secure" in cookie
    assert "samesite=strict" in cookie

    assert client.get("/api/incidents").status_code == 200
    assert client.post("/api/auth/logout").status_code == 200
    assert client.get("/api/incidents").status_code == 401


def test_visitor_endpoint_requires_admin_session(client, configure_admin):
    assert client.get("/api/visitors").status_code == 401
    client.post("/api/auth/login", json={"password": "test-admin-password-123"})
    response = client.get("/api/visitors")
    assert response.status_code == 200
    client.post("/api/auth/logout")


def test_webhook_fails_closed_without_key(client, monkeypatch):
    monkeypatch.setattr(main, "SENTINELOPS_API_KEY", "")
    response = client.post("/api/webhook/ingest", json={
        "hostname": "test-vm",
        "raw_log": "test",
    })
    assert response.status_code == 503

    monkeypatch.setattr(main, "SENTINELOPS_API_KEY", "test-agent-secret")
    monkeypatch.setattr(main, "process_incident", lambda *args: {"accepted": True})
    payload = {"hostname": "test-vm", "raw_log": "test"}
    assert client.post("/api/webhook/ingest", json=payload, headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.post("/api/webhook/ingest", json=payload, headers={"X-API-Key": "test-agent-secret"}).status_code == 200


def test_ssh_remediation_is_disabled_by_default(monkeypatch):
    monkeypatch.setenv("SSH_REMEDIATION_ENABLED", "false")
    report = SSHRemediationEngine.execute_fix("test-host", ["df -h"], "SAFE")
    assert report["executed"] is False
    assert report["status"] == "SIMULATION_ONLY"


def test_ssh_remediation_requires_allowlisted_host_and_command(monkeypatch):
    monkeypatch.setenv("SSH_REMEDIATION_ENABLED", "true")
    monkeypatch.setenv("SSH_ALLOWED_HOSTS", "trusted-host")
    monkeypatch.setenv("SSH_ALLOWED_COMMANDS", '["df -h"]')

    blocked_host = SSHRemediationEngine.execute_fix("untrusted-host", ["df -h"], "SAFE")
    assert blocked_host["status"] == "BLOCKED_HOST"

    blocked_command = SSHRemediationEngine.execute_fix("trusted-host", ["df -h; id"], "SAFE")
    assert blocked_command["status"] == "BLOCKED_COMMAND"


def test_remote_postgres_requires_tls():
    remote = _enforce_remote_postgres_tls(make_url("postgresql://user:pass@db.example.invalid/app?sslmode=disable"))
    assert remote.query["sslmode"] == "require"

    verified = _enforce_remote_postgres_tls(make_url("postgresql://user:pass@db.example.invalid/app?sslmode=verify-full"))
    assert verified.query["sslmode"] == "verify-full"

    local = _enforce_remote_postgres_tls(make_url("postgresql://user:pass@localhost/app"))
    assert "sslmode" not in local.query


def test_collector_requires_explicit_https_configuration(monkeypatch):
    monkeypatch.delenv("SENTINELOPS_URL", raising=False)
    monkeypatch.delenv("SENTINELOPS_API_URL", raising=False)
    monkeypatch.delenv("SENTINELOPS_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="must be configured"):
        COLLECTOR["_webhook_config"]()

    monkeypatch.setenv("SENTINELOPS_URL", "http://public.example.invalid")
    monkeypatch.setenv("SENTINELOPS_API_KEY", "test-key")
    with pytest.raises(RuntimeError, match="must use HTTPS"):
        COLLECTOR["_webhook_config"]()

    monkeypatch.setenv("SENTINELOPS_URL", "https://collector.example.invalid")
    endpoint, key = COLLECTOR["_webhook_config"]()
    assert endpoint == "https://collector.example.invalid/api/webhook/ingest"
    assert key == "test-key"


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


def test_diagnose_and_remediate_workflow(admin_client, monkeypatch):
    client = admin_client
    monkeypatch.setenv("GROQ_API_KEY", "")
    monkeypatch.delenv("TARGET_SSH_KEY_PATH", raising=False)
    monkeypatch.delenv("TARGET_SSH_PASSWORD", raising=False)
    monkeypatch.setenv("SSH_REMEDIATION_ENABLED", "false")

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
    assert rem_res.json()["remediation"]["executed"] is False
    assert rem_res.json()["remediation"]["status"] == "SIMULATION_ONLY"