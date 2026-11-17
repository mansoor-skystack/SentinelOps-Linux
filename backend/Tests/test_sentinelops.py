import os
import json
import pytest
import runpy
import tempfile
from datetime import datetime, timedelta
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
from app import llm
from app import remediator
from app.main import app
from app.sanitizer import LogSanitizer
from app.guardrails import CommandSafetyGuardrail
from app.remediator import SSHRemediationEngine
from app.database import _enforce_remote_postgres_tls, engine, IncidentRecord, SessionLocal, VisitorLog
from sqlalchemy.engine import make_url
from types import SimpleNamespace

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
    assert client.post(
        "/api/remediate/1",
        json={"approved": True},
    ).status_code == 401


def test_incident_resolution_status_can_be_updated(admin_client):
    with SessionLocal() as db:
        incident = IncidentRecord(
            hostname="status-test-vm",
            source_type="systemd-agent",
            stack_tag="Linux",
            sanitized_log="test log",
            root_cause="test cause",
            diagnostic_commands="[]",
            fix_commands="[]",
            risk_level="SAFE",
            citations="[]",
        )
        manual_incident = IncidentRecord(
            hostname="status-test-console",
            source_type="manual",
            stack_tag="Linux",
            sanitized_log="manual test log",
            root_cause="manual test cause",
            diagnostic_commands="[]",
            fix_commands="[]",
            risk_level="SAFE",
            citations="[]",
        )
        db.add_all([incident, manual_incident])
        db.commit()
        incident_id = incident.id

    listed = admin_client.get("/api/incidents").json()
    incident_data = next(item for item in listed if item["id"] == incident_id)
    assert incident_data["status"] == "PENDING"
    vm_incidents = admin_client.get(
        "/api/incidents?limit=15&source_type=systemd-agent"
    ).json()
    assert vm_incidents
    assert all(item["source_type"] == "systemd-agent" for item in vm_incidents)
    assert incident_id in {item["id"] for item in vm_incidents}

    completed = admin_client.post(
        f"/api/incidents/{incident_id}/status",
        json={"status": "COMPLETED"},
    )
    assert completed.status_code == 200
    assert completed.json()["status"] == "COMPLETED"

    pending = admin_client.post(
        f"/api/incidents/{incident_id}/status",
        json={"status": "PENDING"},
    )
    assert pending.status_code == 200
    assert pending.json()["status"] == "PENDING"
    assert admin_client.post(
        f"/api/incidents/{incident_id}/status",
        json={"status": "UNKNOWN"},
    ).status_code == 422


def test_incident_list_is_unlimited_by_default_and_accepts_explicit_limit(admin_client):
    prefix = "unlimited-list-test-"
    with SessionLocal() as db:
        db.add_all(
            [
                IncidentRecord(
                    hostname=f"{prefix}{index}",
                    source_type="manual",
                    stack_tag="Linux",
                    sanitized_log="test log",
                    root_cause="test cause",
                    diagnostic_commands="[]",
                    fix_commands="[]",
                    risk_level="SAFE",
                    citations="[]",
                )
                for index in range(55)
            ]
        )
        db.commit()

    all_incidents = admin_client.get("/api/incidents").json()
    matching = [item for item in all_incidents if item["hostname"].startswith(prefix)]
    assert len(matching) == 55

    limited = admin_client.get("/api/incidents?limit=15").json()
    assert len(limited) == 15


def test_admin_login_rate_limits_failed_attempts_per_ip(client, configure_admin):
    auth.clear_failed_logins("testclient")
    for _ in range(auth.LOGIN_RATE_LIMIT_ATTEMPTS):
        assert client.post("/api/auth/login", json={"password": "wrong"}).status_code == 401
    assert client.post("/api/auth/login", json={"password": "wrong"}).status_code == 429
    auth.clear_failed_logins("testclient")


def test_visitor_endpoint_requires_admin_session(client, configure_admin):
    assert client.get("/api/visitors").status_code == 401
    client.post("/api/auth/login", json={"password": "test-admin-password-123"})
    response = client.get("/api/visitors")
    assert response.status_code == 200
    client.post("/api/auth/logout")


def test_visitor_geolocation_is_reused_from_database(client, monkeypatch):
    lookups = []

    def lookup(ip_address):
        lookups.append(ip_address)
        return "Test City", "Test Region", "Test Country", "Test ISP"

    monkeypatch.setattr(main, "_lookup_visitor_location", lookup)
    for _ in range(2):
        main.save_visitor_in_background(
            "198.51.100.40", "test-agent", "Direct", "en", "/"
        )

    with SessionLocal() as db:
        rows = db.query(VisitorLog).filter_by(ip_address="198.51.100.40").all()
    assert len(rows) == 2
    assert lookups == ["198.51.100.40"]


def test_webhook_fails_closed_without_key(client, monkeypatch):
    monkeypatch.setattr(main, "SENTINELOPS_API_KEY", "")
    response = client.post("/api/webhook/ingest", json={
        "hostname": "test-vm",
        "raw_log": "test",
    })
    assert response.status_code == 503

    monkeypatch.setattr(main, "SENTINELOPS_API_KEY", "test-agent-secret")
    monkeypatch.setattr(main, "process_incident", lambda *args, **kwargs: {"accepted": True})
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

def test_read_only_diagnostics_reject_shell_and_write_commands(monkeypatch):
    monkeypatch.setenv("SSH_REMEDIATION_ENABLED", "false")
    assert SSHRemediationEngine.execute_diagnostics("test-host", ["df -h"])["status"] == "SIMULATION_ONLY"
    assert SSHRemediationEngine.execute_diagnostics("test-host", ["df -h && free -m"])["status"] == "BLOCKED_COMMAND"
    assert SSHRemediationEngine.execute_diagnostics("test-host", ["sudo systemctl restart nginx"])["status"] == "BLOCKED_COMMAND"
    assert SSHRemediationEngine.execute_diagnostics("test-host", ["ip addr add 192.0.2.10/24 dev eth0"])["status"] == "BLOCKED_COMMAND"
    assert SSHRemediationEngine.execute_diagnostics("test-host", ["dmesg --clear"])["status"] == "BLOCKED_COMMAND"
    assert SSHRemediationEngine.execute_diagnostics("test-host", ["ss -K dst 192.0.2.10"])["status"] == "BLOCKED_COMMAND"

def test_remediation_records_failed_exit_and_sanitizes_command_output(monkeypatch, tmp_path):
    class FakeChannel:
        def __init__(self):
            self.stdout_data = bytearray(b"password=synthetic-secret\n")
            self.stderr_data = bytearray()

        def exit_status_ready(self):
            return True

        def recv_ready(self):
            return bool(self.stdout_data)

        def recv_stderr_ready(self):
            return bool(self.stderr_data)

        def recv(self, size):
            chunk = bytes(self.stdout_data[:size])
            del self.stdout_data[:size]
            return chunk

        def recv_stderr(self, size):
            chunk = bytes(self.stderr_data[:size])
            del self.stderr_data[:size]
            return chunk

        def recv_exit_status(self):
            return 1

    channel = FakeChannel()

    class FakeClient:
        def load_host_keys(self, _):
            pass

        def set_missing_host_key_policy(self, _):
            pass

        def connect(self, **_):
            pass

        def exec_command(self, command, **_):
            assert command == "sudo systemctl restart app.service"
            stream = SimpleNamespace(channel=channel)
            return None, stream, stream

        def close(self):
            pass

    key_path = tmp_path / "test.key"
    known_hosts_path = tmp_path / "known_hosts"
    key_path.write_text("test-only", encoding="utf-8")
    known_hosts_path.write_text("test-only", encoding="utf-8")
    monkeypatch.setattr(remediator.paramiko, "SSHClient", FakeClient)
    monkeypatch.setenv("SSH_REMEDIATION_ENABLED", "true")
    monkeypatch.setenv("SSH_ALLOWED_HOSTS", "trusted-host")
    monkeypatch.setenv("SSH_ALLOWED_COMMANDS", '["sudo systemctl restart app.service"]')
    monkeypatch.setenv("TARGET_SSH_USER", "sentinelops")
    monkeypatch.setenv("TARGET_SSH_KEY_PATH", str(key_path))
    monkeypatch.setenv("SSH_KNOWN_HOSTS", str(known_hosts_path))

    report = SSHRemediationEngine.execute_fix(
        "trusted-host",
        ["sudo systemctl restart app.service"],
        "SAFE",
    )
    assert report["status"] == "COMMANDS_FAILED"
    assert report["outputs"][0]["exit_code"] == 1
    assert "synthetic-secret" not in report["outputs"][0]["stdout"]


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


def test_collector_journal_cursor_tracks_only_new_entries(monkeypatch, tmp_path):
    captured_commands = []
    output = "\n".join([
        json.dumps({"MESSAGE": "first error", "__CURSOR": "cursor-1"}),
        json.dumps({"MESSAGE": "second error", "__CURSOR": "cursor-2"}),
    ])

    def fake_check_output(command, **kwargs):
        captured_commands.append(command)
        return output

    monkeypatch.setattr(COLLECTOR["subprocess"], "check_output", fake_check_output)
    logs, cursor = COLLECTOR["collect_journal_batch"]("cursor-0")
    assert logs == "first error\nsecond error"
    assert cursor == "cursor-2"
    assert captured_commands[0][-2:] == ["--after-cursor", "cursor-0"]

    cursor_path = str(tmp_path / "state" / "journal.cursor")
    COLLECTOR["_save_journal_cursor"](cursor_path, cursor)
    assert COLLECTOR["_load_journal_cursor"](cursor_path) == "cursor-2"

def test_collector_thresholds_deduplicate_and_rearm_with_hysteresis():
    configuration = {
        "limits": {
            "cpu_used_pct": 90.0,
            "mem_used_pct": 90.0,
            "disk_used_pct": 90.0,
        },
        "clear_margin_pct": 5.0,
        "cooldown_seconds": 300,
    }
    state = {"active": [], "last_alert_at": {}}
    alerts, state = COLLECTOR["detect_threshold_alerts"](
        90.0, 91.0, 50.0, state, configuration=configuration, now=1000
    )
    assert len(alerts) == 2
    assert any("CPU usage" in alert for alert in alerts)

    alerts, state = COLLECTOR["detect_threshold_alerts"](
        95.0, 95.0, 50.0, state, configuration=configuration, now=1100
    )
    assert alerts == []

    alerts, state = COLLECTOR["detect_threshold_alerts"](
        84.0, 84.0, 50.0, state, configuration=configuration, now=1200
    )
    assert alerts == []
    assert state["active"] == []

    alerts, _ = COLLECTOR["detect_threshold_alerts"](
        90.0, 91.0, 50.0, state, configuration=configuration, now=1401
    )
    assert len(alerts) == 2

def test_collector_cpu_utilization_uses_proc_stat_deltas(monkeypatch):
    readings = iter([(1000, 800), (1100, 870)])
    collector_globals = COLLECTOR["collect_cpu_utilization_pct"].__globals__
    monkeypatch.setitem(collector_globals, "_read_cpu_counters", lambda: next(readings))
    monkeypatch.setattr(COLLECTOR["time"], "sleep", lambda _: None)
    assert COLLECTOR["collect_cpu_utilization_pct"]() == 30.0


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


def test_sanitizer_preserves_loopback_and_bind_addresses():
    raw_log = "bind 0.0.0.0:80 failed; upstream 127.0.0.1:8000; peer 192.0.2.10"
    sanitized, redactions, _ = LogSanitizer.filter_and_sanitize(raw_log)
    assert "0.0.0.0" in sanitized
    assert "127.0.0.1" in sanitized
    assert "192.0.2.10" not in sanitized
    assert redactions["IPV4"] == 1


def test_offline_diagnosis_parses_resolution_commands_without_nginx_default(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "")
    chunks = [
        {
            "text": "### Diagnostic Commands\n- journalctl -u docker",
            "meta": {"source": "docker-containers.md", "section": "diagnostics"},
        },
        {
            "text": (
                "### Resolution\n"
                "```bash\nsudo systemctl restart docker.service\n```\n"
                "- sudo systemctl status docker.service"
            ),
            "meta": {"source": "docker-containers.md", "section": "daemon"},
        },
    ]
    diagnosis = llm.synthesize_diagnosis("docker daemon unavailable", chunks)
    assert diagnosis["fix_commands"] == [
        "sudo systemctl restart docker.service",
        "sudo systemctl status docker.service",
    ]
    assert all("nginx" not in command for command in diagnosis["fix_commands"])

def test_public_reference_cannot_authorize_offline_fix_commands(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "")
    chunks = [{
        "text": "## Resolution\n- sudo systemctl restart nginx.service",
        "meta": {"source": "tldr/systemctl.md", "section": "Resolution", "type": "public_reference"},
    }]
    diagnosis = llm.synthesize_diagnosis("nginx failed", chunks)
    assert diagnosis["fix_commands"] == []
    assert "Public command reference" in diagnosis["citations"][0]

def test_index_separates_curated_runbooks_from_public_references(client):
    engine = main.rag_engine
    sources = {
        metadata["source"]: metadata["type"]
        for metadata in engine.metadatas
    }
    assert sources["linux-memory-oom.md"] == "verified_runbook"
    assert sources["tldr/systemctl.md"] == "public_reference"
    assert "TLDR_LICENSE.md" not in sources
    assert "kernel-oom-memory.md" not in sources


def test_groq_model_is_configurable(monkeypatch):
    captured = {}

    class FakeCompletions:
        def create(self, **kwargs):
            captured.update(kwargs)
            message = SimpleNamespace(content='{"fix_commands": [], "citations": []}')
            return SimpleNamespace(choices=[SimpleNamespace(message=message)])

    fake_client = SimpleNamespace(
        chat=SimpleNamespace(completions=FakeCompletions())
    )
    monkeypatch.setattr(llm, "Groq", lambda api_key: fake_client)
    monkeypatch.setenv("GROQ_API_KEY", "test-api-key")
    monkeypatch.setenv("GROQ_MODEL", "test-model-name")
    telemetry = {"cpu_load": 2.5, "mem_used_pct": 91.0, "disk_used_pct": 48.0}
    llm.synthesize_diagnosis("test", [], telemetry=telemetry)
    assert captured["model"] == "test-model-name"
    user_prompt = captured["messages"][1]["content"]
    assert json.dumps(telemetry, sort_keys=True) in user_prompt
    assert "one-minute load average" in user_prompt
    llm.synthesize_diagnosis("manual test", [])
    assert "Unavailable for this diagnosis" in captured["messages"][1]["content"]


def test_agent_telemetry_reaches_diagnosis(admin_client, monkeypatch):
    observed = {}

    def fake_synthesize(sanitized_log, chunks, telemetry=None):
        observed["telemetry"] = telemetry
        return {
            "root_cause": "test diagnosis",
            "diagnostic_commands": [],
            "fix_commands": [],
            "citations": [],
            "risk_level": "SAFE",
        }

    monkeypatch.setattr(main, "SENTINELOPS_API_KEY", "test-agent-secret")
    monkeypatch.setattr(main, "synthesize_diagnosis", fake_synthesize)
    response = admin_client.post(
        "/api/webhook/ingest",
        headers={"X-API-Key": "test-agent-secret"},
        json={
            "hostname": "test-vm",
            "cpu_load": 2.5,
            "mem_used_pct": 91.0,
            "disk_used_pct": 48.0,
            "raw_log": "kernel: memory pressure warning",
        },
    )
    assert response.status_code == 200
    assert observed["telemetry"] == {
        "cpu_load": 2.5,
        "mem_used_pct": 91.0,
        "disk_used_pct": 48.0,
    }

def test_correlates_matching_incidents_across_hosts_in_five_minute_window(admin_client, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "")
    monkeypatch.setattr(main, "synthesize_diagnosis", lambda *args, **kwargs: {
        "root_cause": "Nginx upstream database connection refused",
        "diagnostic_commands": ["df -h"],
        "fix_commands": [],
        "citations": [],
        "risk_level": "SAFE",
    })
    payload = {
        "raw_log": "nginx 502 upstream database connection refused",
        "stack_filter": "Nginx",
        "source_type": "pytest",
    }
    first = admin_client.post(
        "/api/diagnose",
        json={**payload, "hostname": "correlation-node-a"},
    )
    second = admin_client.post(
        "/api/diagnose",
        json={**payload, "hostname": "correlation-node-b"},
    )
    assert first.status_code == second.status_code == 200
    assert first.json()["correlation_id"] is None
    assert second.json()["correlation_id"] == first.json()["incident_id"]
    assert second.json()["correlated_hosts"] == 2

    incidents = admin_client.get("/api/incidents").json()
    correlated = [row for row in incidents if row["hostname"].startswith("correlation-node-")]
    assert len(correlated) == 2
    assert {row["correlated_hosts"] for row in correlated} == {2}

def test_incident_correlation_ignores_records_older_than_five_minutes(admin_client, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "")
    isolated_log = "tamarind rift packet queue mismatch"
    isolated_cause = "tamarind rift packet queue mismatch"
    with SessionLocal() as db:
        db.add(IncidentRecord(
            hostname="expired-correlation-node",
            source_type="pytest",
            stack_tag="Nginx",
            sanitized_log=isolated_log,
            root_cause=isolated_cause,
            diagnostic_commands="[]",
            fix_commands="[]",
            risk_level="SAFE",
            citations="[]",
            created_at=datetime.utcnow() - timedelta(minutes=6),
        ))
        db.commit()
    monkeypatch.setattr(main, "synthesize_diagnosis", lambda *args, **kwargs: {
        "root_cause": isolated_cause,
        "diagnostic_commands": ["df -h"],
        "fix_commands": [],
        "citations": [],
        "risk_level": "SAFE",
    })
    response = admin_client.post("/api/diagnose", json={
        "raw_log": isolated_log,
        "stack_filter": "Nginx",
        "hostname": "new-correlation-node",
        "source_type": "pytest",
    })
    assert response.status_code == 200
    assert response.json()["correlation_id"] is None


def test_groq_client_setup_failure_is_reported_to_dashboard(admin_client, monkeypatch):
    def fail_to_initialize(**kwargs):
        raise TypeError("incompatible HTTP client")

    monkeypatch.setattr(llm, "Groq", fail_to_initialize)
    monkeypatch.setenv("GROQ_API_KEY", "test-api-key")
    response = admin_client.post("/api/diagnose", json={
        "raw_log": "docker daemon unavailable",
        "stack_filter": "Docker",
        "hostname": "test-vm",
        "source_type": "pytest",
    })
    assert response.status_code == 502
    assert response.json()["detail"] == "Unable to initialize the configured Groq diagnosis client"


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

    # Remediation requires an authenticated admin and explicit approval.
    assert client.post(f"/api/remediate/{inc_id}").status_code == 422
    assert client.post(
        f"/api/remediate/{inc_id}",
        json={"approved": False},
    ).status_code == 422
    assert client.post(
        f"/api/remediate/{inc_id}",
        json={"approved": True, "diagnostic_run_id": "unverified-run-id-0001"},
    ).status_code == 409
    diagnostic_res = client.post(f"/api/incidents/{inc_id}/diagnose")
    assert diagnostic_res.status_code == 200
    diagnostics = diagnostic_res.json()["diagnostics"]
    assert diagnostics["status"] == "SIMULATION_ONLY"
    assert diagnostics["run_id"]
    rem_res = client.post(
        f"/api/remediate/{inc_id}",
        json={"approved": True, "diagnostic_run_id": diagnostics["run_id"]},
    )
    assert rem_res.status_code == 200
    assert rem_res.json()["remediation"]["executed"] is False
    assert rem_res.json()["remediation"]["status"] == "SIMULATION_ONLY"
    assert rem_res.json()["post_check"]["status"] == "SIMULATION_ONLY"

    listed = next(item for item in client.get("/api/incidents").json() if item["id"] == inc_id)
    assert listed["diagnostic_report"]["run_id"] == diagnostics["run_id"]
    assert listed["remediation_report"]["status"] == "SIMULATION_ONLY"


def test_slack_notification_runs_as_background_task(admin_client, monkeypatch):
    notifications = []
    monkeypatch.setattr(main, "send_slack_alert", lambda **kwargs: notifications.append(kwargs))
    monkeypatch.setenv("GROQ_API_KEY", "")
    response = admin_client.post("/api/diagnose", json={
        "raw_log": "Out of memory: Killed process 1234 (worker)",
        "stack_filter": "Linux",
        "hostname": "test-vm",
        "source_type": "pytest",
    })
    assert response.status_code == 200
    assert len(notifications) == 1
    assert notifications[0]["incident_id"] == response.json()["incident_id"]