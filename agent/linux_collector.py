#!/usr/bin/env python3
"""
Layer 2: SentinelOps Lightweight Linux Diagnostic Log Collector Agent
Monitors systemd journalctl errors, /var/log/syslog, disk usage (df -h), and RAM (free -m),
then ships filtered crash telemetry to the SentinelOps FastAPI Webhook.
"""
import os
import socket
import shutil
import subprocess
import argparse
import time
import json
import requests
from typing import Any, Dict, Optional
from urllib.parse import urlsplit, urlunsplit

try:
    from log_sanitizer import LogSanitizer
except ModuleNotFoundError as exc:
    if exc.name != "log_sanitizer":
        raise
    from agent.log_sanitizer import LogSanitizer

SIMULATED_CRASHES = {
    "nginx": {
        "stack": "Nginx",
        "log": (
            "INFO: Starting Nginx worker health check on 10.24.18.9\n"
            "nginx: [emerg] bind() to 0.0.0.0:80 failed (98: Address already in use)\n"
            "systemd[1]: nginx.service: Main process exited, code=exited, status=1/FAILURE"
        )
    },
    "oom": {
        "stack": "Linux",
        "log": (
            "DEBUG: Memory allocator sweep started\n"
            "kernel: [91824.441] Out of memory: Killed process 3910 (java) total-vm:2048120kB, anon-rss:894120kB\n"
            "systemd[1]: backend-api.service: A process of this unit has been killed by the OOM killer (Exit Code 137)"
        )
    },
    "disk": {
        "stack": "Linux",
        "log": (
            "INFO: Running logrotate cron job\n"
            "systemd-journald[401]: Failed to write entry (28: No space left on device) - /var/log partition at 100%"
        )
    },
    "docker": {
        "stack": "Docker",
        "log": (
            "Got permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock"
        )
    }
}

def collect_system_metrics():
    hostname = socket.gethostname()
    try:
        cpu_load = round(os.getloadavg()[0], 2)
    except Exception:
        cpu_load = 0.42

    total, used, _ = shutil.disk_usage("/")
    disk_pct = round((used / total) * 100, 1)

    mem_pct = 54.0
    if os.path.exists("/proc/meminfo"):
        with open("/proc/meminfo") as f:
            info = {line.split(":")[0]: int(line.split(":")[1].strip().split()[0]) for line in f if ":" in line}
        mem_total = info.get("MemTotal", 1)
        mem_avail = info.get("MemAvailable", mem_total)
        mem_pct = round(((mem_total - mem_avail) / mem_total) * 100, 1)

    return hostname, cpu_load, mem_pct, disk_pct

def _read_cpu_counters():
    with open("/proc/stat", "r", encoding="utf-8") as stat_file:
        cpu_line = stat_file.readline().split()
    if not cpu_line or cpu_line[0] != "cpu":
        raise ValueError("CPU counters are missing from /proc/stat")
    values = [int(value) for value in cpu_line[1:]]
    if len(values) < 4:
        raise ValueError("CPU counters in /proc/stat are incomplete")
    return sum(values[:8]), values[3] + (values[4] if len(values) > 4 else 0)

def collect_cpu_utilization_pct(interval: float = 0.1) -> Optional[float]:
    try:
        total_before, idle_before = _read_cpu_counters()
        time.sleep(interval)
        total_after, idle_after = _read_cpu_counters()
    except (OSError, ValueError):
        return None
    total_delta = total_after - total_before
    idle_delta = idle_after - idle_before
    if total_delta <= 0 or idle_delta < 0:
        return None
    return round(max(0.0, min(100.0, 100.0 * (total_delta - idle_delta) / total_delta)), 1)

def collect_live_journal_errors() -> str:
    try:
        out = subprocess.check_output(
            ["journalctl", "-p", "err", "-n", "25", "--no-pager"],
            stderr=subprocess.STDOUT,
            text=True,
            timeout=5
        )
        return out.strip()
    except (subprocess.SubprocessError, OSError, UnicodeError):
        return "ERROR: Unable to read journalctl directly. Fallback telemetry check."

def collect_journal_batch(cursor: str = "") -> tuple[str, str]:
    command = ["journalctl", "-p", "err", "-n", "25", "--no-pager", "-o", "json"]
    if cursor:
        command.extend(["--after-cursor", cursor])
    try:
        output = subprocess.check_output(
            command,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=5,
        )
    except (subprocess.SubprocessError, OSError, UnicodeError):
        return "", cursor

    messages = []
    latest_cursor = cursor
    for line in output.splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        message = entry.get("MESSAGE")
        if message:
            messages.append(str(message))
        if entry.get("__CURSOR"):
            latest_cursor = str(entry["__CURSOR"])
    return "\n".join(messages).strip(), latest_cursor

def _journal_cursor_path() -> str:
    configured_path = os.getenv("SENTINELOPS_CURSOR_FILE", "").strip()
    if configured_path:
        return os.path.expanduser(configured_path)
    return os.path.join(
        os.path.expanduser("~"),
        ".local",
        "state",
        "sentinelops",
        "journal.cursor",
    )

def _load_journal_cursor(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as cursor_file:
            return cursor_file.read().strip()
    except FileNotFoundError:
        return ""

def _save_journal_cursor(path: str, cursor: str) -> None:
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    temporary_path = f"{path}.tmp"
    with open(temporary_path, "w", encoding="utf-8") as cursor_file:
        cursor_file.write(cursor)
    os.replace(temporary_path, path)

def _threshold_state_path(cursor_path: str) -> str:
    configured_path = os.getenv("SENTINELOPS_THRESHOLD_STATE_FILE", "").strip()
    return os.path.expanduser(configured_path) if configured_path else f"{cursor_path}.thresholds.json"

def _load_threshold_state(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as state_file:
            state = json.load(state_file)
    except FileNotFoundError:
        return {"active": [], "last_alert_at": {}}
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Unable to read threshold state ({type(exc).__name__})") from exc
    if (
        not isinstance(state, dict)
        or not isinstance(state.get("active", []), list)
        or not isinstance(state.get("last_alert_at", {}), dict)
    ):
        raise RuntimeError("Threshold state file has an invalid structure")
    return {
        "active": [name for name in state.get("active", []) if isinstance(name, str)],
        "last_alert_at": {
            name: timestamp
            for name, timestamp in state.get("last_alert_at", {}).items()
            if isinstance(name, str) and isinstance(timestamp, (int, float))
        },
    }

def _save_threshold_state(path: str, state: Dict[str, Any]) -> None:
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    temporary_path = f"{path}.tmp"
    with open(temporary_path, "w", encoding="utf-8") as state_file:
        json.dump(state, state_file, sort_keys=True)
    os.replace(temporary_path, path)

def _threshold_configuration() -> Dict[str, Any]:
    limits = {}
    for metric, environment_variable, default, maximum in (
        ("cpu_used_pct", "SENTINELOPS_CPU_THRESHOLD_PCT", 90.0, 100.0),
        ("mem_used_pct", "SENTINELOPS_MEMORY_THRESHOLD_PCT", 90.0, 100.0),
        ("disk_used_pct", "SENTINELOPS_DISK_THRESHOLD_PCT", 90.0, 100.0),
    ):
        try:
            value = float(os.getenv(environment_variable, str(default)))
        except ValueError as exc:
            raise RuntimeError(f"{environment_variable} must be a number") from exc
        if not 0 < value <= maximum:
            raise RuntimeError(f"{environment_variable} must be greater than 0 and at most {maximum:g}")
        limits[metric] = value
    try:
        clear_margin = float(os.getenv("SENTINELOPS_THRESHOLD_CLEAR_MARGIN_PCT", "5"))
        cooldown = int(os.getenv("SENTINELOPS_THRESHOLD_COOLDOWN_SECONDS", "300"))
    except ValueError as exc:
        raise RuntimeError("Threshold clear margin and cooldown must be numeric") from exc
    if not 0 <= clear_margin < 100 or not 0 <= cooldown <= 86400:
        raise RuntimeError("Threshold clear margin must be 0-99 and cooldown 0-86400 seconds")
    return {"limits": limits, "clear_margin_pct": clear_margin, "cooldown_seconds": cooldown}

def detect_threshold_alerts(
    cpu_used_pct: Optional[float],
    mem_pct: float,
    disk_pct: float,
    state: Dict[str, Any],
    *,
    configuration: Optional[Dict[str, Any]] = None,
    now: Optional[float] = None,
):
    config = configuration or _threshold_configuration()
    timestamp = time.time() if now is None else now
    readings = {
        "mem_used_pct": mem_pct,
        "disk_used_pct": disk_pct,
    }
    if cpu_used_pct is not None:
        readings["cpu_used_pct"] = cpu_used_pct
    active = set(state.get("active", []))
    last_alert_at = dict(state.get("last_alert_at", {}))
    labels = {
        "cpu_used_pct": "CPU usage",
        "mem_used_pct": "memory usage",
        "disk_used_pct": "disk usage",
    }
    alerts = []
    for metric, value in readings.items():
        limit = config["limits"][metric]
        if metric in active:
            if value < limit - config["clear_margin_pct"]:
                active.remove(metric)
            continue
        if value < limit:
            continue
        last_sent = float(last_alert_at.get(metric, 0.0))
        if timestamp - last_sent < config["cooldown_seconds"]:
            active.add(metric)
            continue
        alerts.append(f"{labels[metric]} is {value:.1f}% (threshold {limit:.1f}%).")
        active.add(metric)
        last_alert_at[metric] = timestamp
    return alerts, {"active": sorted(active), "last_alert_at": last_alert_at}

def _webhook_config():
    backend_url = (os.getenv("SENTINELOPS_URL") or os.getenv("SENTINELOPS_API_URL") or "").strip()
    api_key = os.getenv("SENTINELOPS_API_KEY", "").strip()
    if not backend_url or not api_key:
        raise RuntimeError("SENTINELOPS_URL and SENTINELOPS_API_KEY must be configured")

    parsed = urlsplit(backend_url)
    if (
        not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or (parsed.scheme != "https" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"})
    ):
        raise RuntimeError("SentinelOps webhook URL must use HTTPS and contain no credentials or query string")

    path = parsed.path.rstrip("/")
    if not path.endswith("/api/webhook/ingest"):
        path = f"{path}/api/webhook/ingest" if path else "/api/webhook/ingest"
    endpoint = urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))
    return endpoint, api_key

def ship_alert(
    raw_log: str,
    stack_tag: str = "Linux",
    telemetry: Optional[Dict[str, Any]] = None,
    *,
    redact_local: bool = False,
):
    api_endpoint, api_key = _webhook_config()
    if redact_local:
        raw_log, _, _ = LogSanitizer.filter_and_sanitize(raw_log)
    if telemetry is None:
        hostname, cpu_load, mem_pct, disk_pct = collect_system_metrics()
    else:
        hostname = telemetry["hostname"]
        cpu_load = telemetry["cpu_load"]
        mem_pct = telemetry["mem_used_pct"]
        disk_pct = telemetry["disk_used_pct"]
    payload = {
        "hostname": hostname,
        "stack_tag": stack_tag,
        "cpu_load": cpu_load,
        "mem_used_pct": mem_pct,
        "disk_used_pct": disk_pct,
        "raw_log": raw_log
    }
    headers = {"X-API-Key": api_key, "Content-Type": "application/json"}
    print(f"[SentinelOps Agent] Sending telemetry from '{hostname}'...")

    try:
        resp = requests.post(api_endpoint, json=payload, headers=headers, timeout=(3, 10))
    except requests.RequestException as exc:
        raise RuntimeError(f"Webhook request failed ({type(exc).__name__})") from None

    print(f"Response Status: {resp.status_code}")

    if not resp.ok:
        raise RuntimeError(f"Backend rejected telemetry (HTTP {resp.status_code})")
    try:
        data = resp.json()
    except ValueError:
        raise RuntimeError("Backend returned an invalid JSON response") from None
    print(f"[Success] Incident #{data.get('incident_id')} logged!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SentinelOps Linux Diagnostic Log Collector Agent")
    parser.add_argument("--simulate", choices=list(SIMULATED_CRASHES.keys()), help="Simulate a real Linux service crash")
    parser.add_argument("--daemon", action="store_true", help="Run continuously as a systemd background watcher")
    parser.add_argument("--interval", type=int, default=30, help="Polling interval in seconds for daemon mode")
    parser.add_argument(
        "--redact-local",
        action="store_true",
        default=os.getenv("SENTINELOPS_REDACT_LOCAL", "").strip().lower() == "true",
        help="Sanitize log text on this VM before sending it to the backend",
    )
    args = parser.parse_args()

    if args.simulate:
        case = SIMULATED_CRASHES[args.simulate]
        ship_alert(case["log"], stack_tag=case["stack"], redact_local=args.redact_local)
    elif args.daemon:
        print(f"Starting SentinelOps Linux Collector Daemon (polling every {args.interval}s)...")
        cursor_path = _journal_cursor_path()
        cursor = _load_journal_cursor(cursor_path)
        threshold_path = _threshold_state_path(cursor_path)
        threshold_state = _load_threshold_state(threshold_path)
        threshold_configuration = _threshold_configuration()
        while True:
            logs, next_cursor = collect_journal_batch(cursor)
            hostname, cpu_load, mem_pct, disk_pct = collect_system_metrics()
            cpu_used_pct = collect_cpu_utilization_pct()
            threshold_alerts, next_threshold_state = detect_threshold_alerts(
                cpu_used_pct,
                mem_pct,
                disk_pct,
                threshold_state,
                configuration=threshold_configuration,
            )
            telemetry = {
                "hostname": hostname,
                "cpu_load": cpu_load,
                "mem_used_pct": mem_pct,
                "disk_used_pct": disk_pct,
            }
            alert_parts = [logs] if logs else []
            if threshold_alerts:
                alert_parts.append("SentinelOps proactive telemetry threshold warning:\n- " + "\n- ".join(threshold_alerts))
            if alert_parts:
                try:
                    ship_alert(
                        "\n\n".join(alert_parts),
                        stack_tag="Linux",
                        telemetry=telemetry,
                        redact_local=args.redact_local,
                    )
                except RuntimeError as exc:
                    print(f"[Warn] Webhook delivery failed: {exc}")
                else:
                    if next_cursor and next_cursor != cursor:
                        try:
                            _save_journal_cursor(cursor_path, next_cursor)
                            cursor = next_cursor
                        except OSError as exc:
                            print(f"[Warn] Could not save journal cursor: {exc}")
                    try:
                        _save_threshold_state(threshold_path, next_threshold_state)
                        threshold_state = next_threshold_state
                    except OSError as exc:
                        print(f"[Warn] Could not save threshold state: {exc}")
            elif next_threshold_state != threshold_state:
                try:
                    _save_threshold_state(threshold_path, next_threshold_state)
                    threshold_state = next_threshold_state
                except OSError as exc:
                    print(f"[Warn] Could not save threshold state: {exc}")
            time.sleep(args.interval)
    else:
        logs = collect_live_journal_errors()
        ship_alert(logs, stack_tag="Linux", redact_local=args.redact_local)
