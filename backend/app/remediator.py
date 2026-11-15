import os
import json
import paramiko
from typing import Dict, Any, List
from .guardrails import CommandSafetyGuardrail


class SSHRemediationEngine:
    """Executes verified SAFE remediation commands on remote Linux hosts via SSH."""

    @staticmethod
    def execute_fix(hostname: str, commands: List[str], risk_level: str) -> Dict[str, Any]:
        # Hard guardrail check: refuse execution if flagged or not SAFE
        recheck_risk, flagged = CommandSafetyGuardrail.inspect(commands)
        if risk_level != "SAFE" or recheck_risk != "SAFE":
            return {
                "executed": False,
                "status": "BLOCKED_BY_GUARDRAIL",
                "reason": f"Command safety guardrail blocked execution. Flagged: {flagged}",
                "outputs": []
            }

        ssh_user = os.getenv("TARGET_SSH_USER", "ubuntu").strip()
        ssh_key_path = os.getenv("TARGET_SSH_KEY_PATH", "").strip()
        ssh_password = os.getenv("TARGET_SSH_PASSWORD", "").strip()

        # Simulation mode when no SSH credentials are configured in cloud env
        if not ssh_key_path and not ssh_password:
            return {
                "executed": True,
                "status": "SIMULATED_EXECUTION",
                "host": hostname,
                "outputs": [
                    {"command": cmd, "exit_code": 0, "stdout": f"[Simulated SSH on {hostname}] Executed: {cmd}"}
                    for cmd in commands
                ]
            }

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        results = []

        try:
            connect_kwargs = {"hostname": hostname, "username": ssh_user, "timeout": 10}
            if ssh_key_path and os.path.exists(ssh_key_path):
                connect_kwargs["key_filename"] = ssh_key_path
            else:
                connect_kwargs["password"] = ssh_password

            client.connect(**connect_kwargs)

            for cmd in commands:
                _, stdout, stderr = client.exec_command(cmd, timeout=15)
                exit_code = stdout.channel.recv_exit_status()
                results.append({
                    "command": cmd,
                    "exit_code": exit_code,
                    "stdout": stdout.read().decode("utf-8", errors="ignore").strip(),
                    "stderr": stderr.read().decode("utf-8", errors="ignore").strip()
                })

            return {
                "executed": True,
                "status": "COMPLETED",
                "host": hostname,
                "outputs": results
            }
        except Exception as exc:
            return {
                "executed": False,
                "status": "SSH_CONNECTION_ERROR",
                "reason": str(exc),
                "outputs": results
            }
        finally:
            client.close()