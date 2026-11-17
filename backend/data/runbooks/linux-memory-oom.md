# Linux Kernel OOM-Killer & Memory Exhaustion Guide (man dmesg / free)

## Out of Memory: Killed Process (OOM-Killer / Signal 9 / Exit Code 137)
When system RAM and swap are exhausted, the Linux kernel `oom_reaper` terminates the highest `oom_score` process (`Out of memory: Killed process <PID>`), resulting in `SIGKILL` (exit code `137`).

### Diagnostic Commands
- Query kernel ring buffer and journal for OOM events:
```bash
dmesg -T | grep -i -E "oom|killed process"
free -h
```
- Identify the top memory-consuming processes:
```bash
ps aux --sort=-%mem | head -n 10
```

### Resolution
When system RAM and swap are exhausted, the Linux kernel invokes the OOM killer to terminate high-memory processes. Identify the affected service and constrain its memory use; add swap space when appropriate for a small VM:
```bash
sudo systemctl set-property <service-name>.service MemoryMax=512M && sudo systemctl restart <service-name>.service
```
