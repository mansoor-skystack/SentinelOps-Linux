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
from urllib.parse import urlsplit, urlunsplit

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

def ship_alert(raw_log: str, stack_tag: str = "Linux"):
    api_endpoint, api_key = _webhook_config()
    hostname, cpu_load, mem_pct, disk_pct = collect_system_metrics()
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
    args = parser.parse_args()

    if args.simulate:
        case = SIMULATED_CRASHES[args.simulate]
        ship_alert(case["log"], stack_tag=case["stack"])
    elif args.daemon:
        print(f"Starting SentinelOps Linux Collector Daemon (polling every {args.interval}s)...")
        cursor_path = _journal_cursor_path()
        cursor = _load_journal_cursor(cursor_path)
        while True:
            logs, next_cursor = collect_journal_batch(cursor)
            if logs:
                try:
                    ship_alert(logs, stack_tag="Linux")
                except RuntimeError as exc:
                    print(f"[Warn] Webhook delivery failed: {exc}")
                else:
                    if next_cursor and next_cursor != cursor:
                        try:
                            _save_journal_cursor(cursor_path, next_cursor)
                            cursor = next_cursor
                        except OSError as exc:
                            print(f"[Warn] Could not save journal cursor: {exc}")
            time.sleep(args.interval)
    else:
        logs = collect_live_journal_errors()
        ship_alert(logs, stack_tag="Linux")
