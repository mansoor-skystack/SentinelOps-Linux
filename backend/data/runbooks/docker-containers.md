# Docker Engine & Container Runtime Troubleshooting Guide

## Docker Daemon Permission Denied (unix:///var/run/docker.sock)
Occurs when a non-root user runs `docker ps` without belonging to the `docker` Unix group, or `docker.service` is inactive.

### Diagnostic Steps
```bash
systemctl is-active docker && id -nG $USER
```

### Resolution
Enable the Docker daemon and append the user to the `docker` group:
```bash
sudo systemctl enable --now docker && sudo usermod -aG docker $USER
```

## Container CrashLoop / Exit Code 137 or Port Conflict
Occurs when a container exceeds memory limits or binds to an already-occupied host port.

### Diagnostic Steps
```bash
docker ps -a && docker logs --tail 50 <container-name>
```

### Resolution
Restart the container cleanly via Docker Compose:
```bash
docker compose down && docker compose up -d
```
