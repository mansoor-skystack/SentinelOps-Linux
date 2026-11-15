# Linux Kernel Memory Management & OOM-Killer Runbook

## Section: Out-Of-Memory Killer Termination (Exit Code 137)
When system RAM and swap are exhausted, the Linux kernel invokes `oom-killer` to terminate high-memory processes (such as JVM/Java or Python workers), logging `Out of memory: Killed process` and exiting containers with code `137`.

### Diagnostic Commands:
- `dmesg -T | grep -i -E "oom|killed process"`
- `free -h`
- `ps aux --sort=-%mem | head -n 10`

### Fix:
- `sudo sync && sudo sysctl -w vm.drop_caches=1`