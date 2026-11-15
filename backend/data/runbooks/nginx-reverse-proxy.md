# Nginx Reverse Proxy & Upstream Connectivity Troubleshooting Guide

## 502 Bad Gateway: connect() failed (111: Connection refused)
Nginx accepted the external HTTP request but failed to establish a TCP socket connection with the upstream backend application on `127.0.0.1:8000` or Unix socket.

### Diagnostic Steps
1. Verify upstream application status and listening ports:
```bash
ss -tlnp | grep 8000 && nginx -t
```
2. Inspect Nginx upstream error logs:
```bash
tail -n 40 /var/log/nginx/error.log
```

### Resolution
Restart the upstream application service and reload Nginx worker processes gracefully:
```bash
sudo systemctl restart app-backend.service && sudo systemctl reload nginx.service
```
