# Linux Kernel OOM-Killer & Memory Exhaustion Guide (man dmesg / free)

## Out of Memory: Killed Process (OOM-Killer / Signal 9 / Exit Code 137)
When system RAM and swap are exhausted, the Linux kernel `oom_reaper` terminates the highest `oom_score` process (`Out of memory: Killed process <PID>`), resulting in `SIGKILL` (exit code `137`).

### Diagnostic Steps
1. Query kernel ring buffer (`dmesg`) and journal for OOM events:
```bash
dmesg -T | grep -iE "oom|killed process" && free -m
```
2. Identify the top memory-consuming processes:
```bash
ps aux --sort=-%mem | head -n 10
```

### Resolution
Configure a systemd `MemoryMax` cgroup limit on the leaky service and add swap space if running on a micro VM:
```bash
sudo systemctl set-property <service-name>.service MemoryMax=512M && sudo systemctl restart <service-name>.service
```
