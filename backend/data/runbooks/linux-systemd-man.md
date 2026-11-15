# Linux Systemd & Journalctl Troubleshooting Guide (man systemctl / journalctl)

## Service Unit Failed to Start: Address Already in Use (EADDRINUSE / Exit Code 1)
When `systemctl status nginx.service` or `apache2.service` fails with `bind() to 0.0.0.0:80 failed (98: Address already in use)`, another process is actively listening on the target TCP socket.

### Diagnostic Steps
1. Identify the exact process ID (PID) and binary holding port 80 or 443:
```bash
ss -tulpn | grep -E ':(80|443|8080)\b'
```
2. Inspect the last 50 systemd journal entries for the unit:
```bash
journalctl -u nginx.service -n 50 --no-pager
```

### Resolution
Stop the conflicting service (e.g., `apache2`) and restart the primary daemon:
```bash
sudo systemctl disable --now apache2 && sudo systemctl restart nginx.service
```

## Disk Space Exhaustion: No Space Left on Device (ENOSPC)
Triggered when `/` or `/var/log` reaches 100% block or inode utilization, preventing services from writing PID files, sockets, or journal logs.

### Diagnostic Steps
```bash
df -h && df -i && du -sh /var/log/* | sort -hr | head -n 10
```

### Resolution
Reclaim disk space by vacuuming systemd journal logs older than 3 days and clearing package caches:
```bash
sudo journalctl --vacuum-time=3d && sudo apt-get clean
```

## Permission Denied on Script or Binary (EACCES / Exit Code 126)
Occurs when an executable script in `/usr/local/bin` or systemd `ExecStart` lacks execute (`+x`) permissions or has incorrect ownership.

### Diagnostic Steps
```bash
ls -la /usr/local/bin/<script-name> && namei -l /usr/local/bin/<script-name>
```

### Resolution
Grant standard executable permissions (`755`) to the script:
```bash
sudo chmod 755 /usr/local/bin/<script-name>
```
