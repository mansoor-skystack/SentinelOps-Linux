#!/usr/bin/env python3
import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from backend.app.database import IncidentRecord, SessionLocal, init_db


DEMO_INCIDENTS = [
    {
        "hostname": "ssh-target",
        "stack_tag": "Linux",
        "cpu_load": 0.2,
        "mem_used_pct": 18.0,
        "disk_used_pct": 21.0,
        "sanitized_log": "[DEMO: SentinelOps] OpenSSH demo target is ready for approved remediation testing.",
        "root_cause": "Demo incident for the isolated SSH target; no live service failure is present.",
        "diagnostic_commands": ["df -h"],
        "fix_commands": ["touch /tmp/sentinelops-demo-fixed"],
        "citations": ["Disposable Docker Compose SSH target"],
    },
    {
        "hostname": "sentinelops-demo-web-01",
        "stack_tag": "Nginx",
        "cpu_load": 0.7,
        "mem_used_pct": 62.0,
        "disk_used_pct": 54.0,
        "sanitized_log": "[DEMO: SentinelOps] nginx upstream timed out while reading response header.",
        "root_cause": "The demo web proxy reports an upstream timeout; validate the upstream before restarting services.",
        "diagnostic_commands": ["systemctl status nginx.service"],
        "fix_commands": ["sudo systemctl restart nginx.service"],
        "citations": ["Demo incident fixture"],
    },
    {
        "hostname": "sentinelops-demo-db-01",
        "stack_tag": "Database",
        "cpu_load": 1.3,
        "mem_used_pct": 79.0,
        "disk_used_pct": 71.0,
        "sanitized_log": "[DEMO: SentinelOps] PostgreSQL connection pool exhausted; new client connections were rejected.",
        "root_cause": "The demo database reached its connection limit; inspect pool usage and active sessions.",
        "diagnostic_commands": ["pg_isready"],
        "fix_commands": ["sudo systemctl restart postgresql.service"],
        "citations": ["Demo incident fixture"],
    },
    {
        "hostname": "sentinelops-demo-worker-01",
        "stack_tag": "Linux",
        "cpu_load": 2.4,
        "mem_used_pct": 93.0,
        "disk_used_pct": 42.0,
        "sanitized_log": "[DEMO: SentinelOps] kernel: Out of memory: Killed process 1234 (worker).",
        "root_cause": "The demo worker exceeded available memory and was selected by the OOM killer.",
        "diagnostic_commands": ["free -m"],
        "fix_commands": ["sudo systemctl restart worker.service"],
        "citations": ["Demo incident fixture"],
    },
]


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed disposable SentinelOps demo incidents.")
    parser.add_argument("--confirm", action="store_true", help="Confirm that this is a demo database.")
    args = parser.parse_args()
    if os.getenv("SENTINELOPS_DEMO_MODE", "").strip().lower() != "true" or not args.confirm:
        parser.error("Refusing to seed: set SENTINELOPS_DEMO_MODE=true and pass --confirm.")

    init_db()
    added = 0
    existing = 0
    with SessionLocal() as db:
        for sample in DEMO_INCIDENTS:
            marker = sample["sanitized_log"]
            if db.query(IncidentRecord.id).filter(IncidentRecord.sanitized_log == marker).first():
                existing += 1
                continue
            db.add(
                IncidentRecord(
                    hostname=sample["hostname"],
                    source_type="systemd-agent",
                    stack_tag=sample["stack_tag"],
                    cpu_load=sample["cpu_load"],
                    mem_used_pct=sample["mem_used_pct"],
                    disk_used_pct=sample["disk_used_pct"],
                    sanitized_log=marker,
                    root_cause=sample["root_cause"],
                    diagnostic_commands=json.dumps(sample["diagnostic_commands"]),
                    fix_commands=json.dumps(sample["fix_commands"]),
                    risk_level="SAFE",
                    status="PENDING",
                    citations=json.dumps(sample["citations"]),
                    created_at=datetime.utcnow(),
                )
            )
            added += 1
        db.commit()
    print(f"Demo incidents added: {added}; already present: {existing}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
