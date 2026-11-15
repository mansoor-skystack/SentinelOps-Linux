# Linux Networking, DNS Resolution & Socket Exhaustion Runbook

## Section: DNS Resolution Failure (Temporary failure in name resolution)
When services or `curl`/`apt` fail with `Temporary failure in name resolution` or `Could not resolve host`, `/etc/resolv.conf` or `systemd-resolved` is misconfigured or unreachable.

### Diagnostic Commands:
- `resolvectl status`
- `cat /etc/resolv.conf`
- `dig @8.8.8.8 google.com +short`

### Fix:
- `sudo systemctl restart systemd-resolved`

---

## Section: TCP Socket Exhaustion & TIME_WAIT Backlog
High-traffic reverse proxies or API servers may fail with `Cannot assign requested address` or `Too many open files` (`EMFILE`) when ephemeral ports or file descriptors are depleted.

### Diagnostic Commands:
- `ss -s`
- `ulimit -n`
- `sysctl net.ipv4.ip_local_port_range`

### Fix:
- `sudo sysctl -w net.ipv4.tcp_tw_reuse=1`