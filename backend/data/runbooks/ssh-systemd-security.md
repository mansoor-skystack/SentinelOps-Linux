# SSH Authentication Failures & Systemd Unit Recovery Runbook

## Section: SSH Brute-Force Lockout or Permission Refused (Publickey)
If SSH logins fail with `Permission denied (publickey)` or `Connection refused`, either `sshd.service` is stopped or `~/.ssh/authorized_keys` permissions are too permissive (`0777` instead of `0600`).

### Diagnostic Commands:
- `sudo systemctl status sshd`
- `journalctl -u ssh -n 30 --no-pager`
- `ls -la ~/.ssh`

### Fix:
- `chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys && sudo systemctl restart sshd`

---

## Section: Systemd Service Crash Loop (start-limit-hit)
When a daemon crashes repeatedly within seconds, systemd halts restarts with `Start request repeated too quickly` (`start-limit-hit`).

### Diagnostic Commands:
- `systemctl --failed`
- `journalctl -xeu <service_name> -n 40 --no-pager`

### Fix:
- `sudo systemctl reset-failed && sudo systemctl daemon-reload`