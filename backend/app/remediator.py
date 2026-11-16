import json
import os
import paramiko
from typing import Dict, Any, List
from .guardrails import CommandSafetyGuardrail


class SSHRemediationEngine:
    """Runs only explicitly approved remediation commands on trusted SSH hosts."""

    @staticmethod
    def execute_fix(hostname: str, commands: List[str], risk_level: str) -> Dict[str, Any]:
        recheck_risk, flagged = CommandSafetyGuardrail.inspect(commands)
        if risk_level != "SAFE" or recheck_risk != "SAFE":
            return {
                "executed": False,
                "status": "BLOCKED_BY_GUARDRAIL",
                "reason": f"Command safety guardrail blocked execution. Flagged: {flagged}",
                "outputs": []
            }

        if os.getenv("SSH_REMEDIATION_ENABLED", "").strip().lower() != "true":
            return {
                "executed": False,
                "status": "SIMULATION_ONLY",
                "host": hostname,
                "outputs": [
                    {"command": cmd, "exit_code": None, "stdout": "Not executed; live SSH remediation is disabled."}
                    for cmd in commands
                ],
            }

        allowed_hosts = {
            host.strip().lower()
            for host in os.getenv("SSH_ALLOWED_HOSTS", "").split(",")
            if host.strip()
        }
        target_host = hostname.strip()
        if not target_host or target_host != hostname or target_host.lower() not in allowed_hosts:
            return {
                "executed": False,
                "status": "BLOCKED_HOST",
                "reason": "Host is not in SSH_ALLOWED_HOSTS.",
                "outputs": [],
            }

        try:
            configured_commands = json.loads(os.getenv("SSH_ALLOWED_COMMANDS", "[]"))
        except ValueError:
            configured_commands = None
        if not isinstance(configured_commands, list) or any(
            not isinstance(command, str) for command in configured_commands
        ):
            return {
                "executed": False,
                "status": "BLOCKED_CONFIGURATION",
                "reason": "SSH_ALLOWED_COMMANDS must be a JSON array of exact command strings.",
                "outputs": [],
            }
        allowed_commands = {command.strip() for command in configured_commands if command.strip()}
        if not commands or any(command not in allowed_commands for command in commands):
            return {
                "executed": False,
                "status": "BLOCKED_COMMAND",
                "reason": "Every command must exactly match an entry in SSH_ALLOWED_COMMANDS.",
                "outputs": [],
            }

        ssh_user = os.getenv("TARGET_SSH_USER", "").strip()
        ssh_key_path = os.getenv("TARGET_SSH_KEY_PATH", "").strip()
        known_hosts_path = os.getenv("SSH_KNOWN_HOSTS", "").strip()

        if (
            not ssh_user
            or not ssh_key_path
            or not known_hosts_path
            or not os.path.isfile(ssh_key_path)
            or not os.path.isfile(known_hosts_path)
        ):
            return {
                "executed": False,
                "status": "BLOCKED_CONFIGURATION",
                "reason": "A user, private key file, and known-hosts file are required.",
                "outputs": [],
            }

        client = paramiko.SSHClient()
        try:
            client.load_host_keys(known_hosts_path)
        except (OSError, paramiko.SSHException):
            return {
                "executed": False,
                "status": "BLOCKED_CONFIGURATION",
                "reason": "The configured known-hosts file could not be loaded.",
                "outputs": [],
            }
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        results = []

        try:
            client.connect(
                hostname=target_host,
                username=ssh_user,
                key_filename=ssh_key_path,
                timeout=10,
                banner_timeout=10,
                auth_timeout=10,
                allow_agent=False,
                look_for_keys=False,
            )

            for cmd in commands:
                _, stdout, stderr = client.exec_command(cmd, timeout=15)
                exit_code = stdout.channel.recv_exit_status()
                results.append({
                    "command": cmd,
                    "exit_code": exit_code,
                    "stdout": stdout.read(4097).decode("utf-8", errors="replace").strip()[:4096],
                    "stderr": stderr.read(4097).decode("utf-8", errors="replace").strip()[:4096],
                })

            return {
                "executed": True,
                "status": "COMPLETED",
                "host": hostname,
                "outputs": results
            }
        except (paramiko.SSHException, OSError, EOFError) as exc:
            return {
                "executed": False,
                "status": "SSH_CONNECTION_ERROR",
                "reason": f"SSH operation failed ({type(exc).__name__}).",
                "outputs": results
            }
        finally:
            client.close()