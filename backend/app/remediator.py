import json
import os
import re
import shlex
import time
from typing import Any, Dict, List, Optional, Tuple

import paramiko

from .guardrails import CommandSafetyGuardrail
from .sanitizer import LogSanitizer


class SSHRemediationEngine:
    """Runs exact-allowlisted checks and explicitly approved fixes over pinned SSH."""

    READ_ONLY_COMMANDS = {
        "df", "dmesg", "free", "findmnt", "ip", "journalctl", "lsblk", "test",
        "pg_isready", "ps", "ss", "systemctl", "uname", "uptime", "vmstat",
    }
    SHELL_OPERATORS = re.compile(r"[;&|<>`$\r\n\x00]")

    @staticmethod
    def _read_command_output(stdout, stderr) -> Tuple[int, bytes, bytes]:
        channel = stdout.channel
        output_limit = 4096
        stdout_data = bytearray()
        stderr_data = bytearray()
        deadline = time.monotonic() + 15
        while not channel.exit_status_ready():
            if time.monotonic() >= deadline:
                raise TimeoutError("Remote command exceeded the execution timeout")
            received_data = False
            if channel.recv_ready():
                chunk = channel.recv(4096)
                stdout_data.extend(chunk[:max(0, output_limit - len(stdout_data))])
                received_data = True
            if channel.recv_stderr_ready():
                chunk = channel.recv_stderr(4096)
                stderr_data.extend(chunk[:max(0, output_limit - len(stderr_data))])
                received_data = True
            if not received_data:
                time.sleep(0.01)
        while channel.recv_ready():
            chunk = channel.recv(4096)
            stdout_data.extend(chunk[:max(0, output_limit - len(stdout_data))])
        while channel.recv_stderr_ready():
            chunk = channel.recv_stderr(4096)
            stderr_data.extend(chunk[:max(0, output_limit - len(stderr_data))])
        return channel.recv_exit_status(), bytes(stdout_data), bytes(stderr_data)

    @classmethod
    def _is_read_only(cls, command: str) -> bool:
        if not command or len(command) > 512 or cls.SHELL_OPERATORS.search(command):
            return False
        try:
            parts = shlex.split(command)
        except ValueError:
            return False
        if not parts or os.path.basename(parts[0]) not in cls.READ_ONLY_COMMANDS:
            return False
        executable = os.path.basename(parts[0])
        arguments = parts[1:]
        if executable == "systemctl":
            return len(parts) > 1 and parts[1] in {"status", "is-active", "show", "list-units"}
        if executable == "ip":
            return bool(arguments) and arguments[0] in {"address", "addr", "route", "link", "neighbor"} and not any(
                argument in {"add", "delete", "del", "flush", "replace", "set"}
                for argument in arguments[1:]
            )
        if executable == "dmesg" and any(argument in {"-c", "--clear", "-C", "--console-off"} for argument in arguments):
            return False
        if executable == "journalctl" and any(
            argument in {"--rotate", "--flush", "--sync", "--vacuum-size", "--vacuum-time"}
            or argument.startswith(("--vacuum-size=", "--vacuum-time="))
            for argument in arguments
        ):
            return False
        if executable == "ss" and any(argument in {"-K", "--kill"} for argument in arguments):
            return False
        return True

    @staticmethod
    def _configured_commands(environment_variable: str) -> Optional[set[str]]:
        try:
            configured = json.loads(os.getenv(environment_variable, "[]"))
        except ValueError:
            return None
        if not isinstance(configured, list) or any(
            not isinstance(command, str) or not command.strip()
            for command in configured
        ):
            return None
        return {command.strip() for command in configured}

    @staticmethod
    def _simulation(hostname: str, commands: List[str], label: str) -> Dict[str, Any]:
        return {
            "executed": False,
            "status": "SIMULATION_ONLY",
            "host": hostname,
            "outputs": [
                {"command": command, "exit_code": None, "stdout": f"Not executed; live SSH {label} is disabled."}
                for command in commands
            ],
        }

    @classmethod
    def _execute_allowlisted(
        cls,
        hostname: str,
        commands: List[str],
        environment_variable: str,
        *,
        require_read_only: bool,
        label: str,
    ) -> Dict[str, Any]:
        if not isinstance(commands, list) or not commands or len(commands) > 20 or any(
            not isinstance(command, str) or not command.strip() or len(command) > 512
            for command in commands
        ):
            return {
                "executed": False,
                "status": "BLOCKED_COMMAND",
                "reason": "A non-empty list of at most 20 commands (512 characters each) is required.",
                "outputs": [],
            }
        if require_read_only and any(not cls._is_read_only(command) for command in commands):
            return {
                "executed": False,
                "status": "BLOCKED_COMMAND",
                "reason": "Diagnostics must be single, read-only commands without shell operators.",
                "outputs": [],
            }

        if os.getenv("SSH_REMEDIATION_ENABLED", "").strip().lower() != "true":
            return cls._simulation(hostname, commands, label)

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

        allowed_commands = cls._configured_commands(environment_variable)
        if allowed_commands is None:
            return {
                "executed": False,
                "status": "BLOCKED_CONFIGURATION",
                "reason": f"{environment_variable} must be a JSON array of exact command strings.",
                "outputs": [],
            }
        if any(command not in allowed_commands for command in commands):
            return {
                "executed": False,
                "status": "BLOCKED_COMMAND",
                "reason": f"Every command must exactly match an entry in {environment_variable}.",
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
        results = []
        try:
            client.load_host_keys(known_hosts_path)
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
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
            for command in commands:
                _, stdout, stderr = client.exec_command(command, timeout=15)
                exit_code, stdout_bytes, stderr_bytes = cls._read_command_output(stdout, stderr)
                stdout_text, _, _ = LogSanitizer.filter_and_sanitize(
                    stdout_bytes.decode("utf-8", errors="replace")
                )
                stderr_text, _, _ = LogSanitizer.filter_and_sanitize(
                    stderr_bytes.decode("utf-8", errors="replace")
                )
                results.append({
                    "command": command,
                    "exit_code": exit_code,
                    "stdout": stdout_text.strip()[:4096],
                    "stderr": stderr_text.strip()[:4096],
                })
                if label == "remediation" and exit_code != 0:
                    break
            report = {
                "executed": True,
                "status": "COMPLETED",
                "host": hostname,
                "outputs": results,
            }
            if label == "remediation" and any(result["exit_code"] != 0 for result in results):
                report["status"] = "COMMANDS_FAILED"
            return report
        except (paramiko.SSHException, OSError, EOFError, TimeoutError) as exc:
            return {
                "executed": False,
                "status": "SSH_TIMEOUT" if isinstance(exc, TimeoutError) else "SSH_CONNECTION_ERROR",
                "reason": f"SSH operation failed ({type(exc).__name__}).",
                "outputs": results,
            }
        finally:
            client.close()

    @classmethod
    def execute_diagnostics(cls, hostname: str, commands: List[str]) -> Dict[str, Any]:
        return cls._execute_allowlisted(
            hostname,
            commands,
            "SSH_ALLOWED_DIAGNOSTIC_COMMANDS",
            require_read_only=True,
            label="diagnostics",
        )

    @classmethod
    def execute_fix(cls, hostname: str, commands: List[str], risk_level: str) -> Dict[str, Any]:
        if not isinstance(commands, list) or any(not isinstance(command, str) for command in commands):
            return {
                "executed": False,
                "status": "BLOCKED_COMMAND",
                "reason": "Fix commands must be a list of strings.",
                "outputs": [],
            }
        risk, flagged = CommandSafetyGuardrail.inspect(commands)
        if risk_level != "SAFE" or risk != "SAFE":
            return {
                "executed": False,
                "status": "BLOCKED_BY_GUARDRAIL",
                "reason": f"Command safety guardrail blocked execution. Flagged: {flagged}",
                "outputs": [],
            }
        return cls._execute_allowlisted(
            hostname,
            commands,
            "SSH_ALLOWED_COMMANDS",
            require_read_only=False,
            label="remediation",
        )

    @classmethod
    def execute_post_check(cls, hostname: str) -> Dict[str, Any]:
        commands = cls._configured_commands("SSH_ALLOWED_POSTCHECK_COMMANDS")
        if commands is None:
            return {
                "executed": False,
                "status": "BLOCKED_CONFIGURATION",
                "reason": "SSH_ALLOWED_POSTCHECK_COMMANDS must be a JSON array of exact command strings.",
                "outputs": [],
            }
        if not commands:
            return {
                "executed": False,
                "status": "NOT_CONFIGURED",
                "reason": "No post-remediation health checks are configured.",
                "outputs": [],
            }
        report = cls._execute_allowlisted(
            hostname,
            sorted(commands),
            "SSH_ALLOWED_POSTCHECK_COMMANDS",
            require_read_only=True,
            label="post-check",
        )
        if report["status"] != "COMPLETED":
            return report

        healthy = True
        for result in report["outputs"]:
            if result["exit_code"] != 0:
                healthy = False
            if result["command"].startswith("systemctl is-active "):
                if "--quiet" not in shlex.split(result["command"]) and result["stdout"] != "active":
                    healthy = False
        report["status"] = "HEALTHY" if healthy else "UNHEALTHY"
        return report
