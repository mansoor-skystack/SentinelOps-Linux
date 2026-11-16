# SentinelOps (`SentinelOps-Linux`)

Automated Linux Log Telemetry, PII/Secret Sanitization, and Hybrid-RAG Incident Resolution System.

## VS Code Quickstart
1. Extract this archive and double-click **`SentinelOps-Linux.code-workspace`** in **VS Code** (or run `code SentinelOps-Linux/SentinelOps-Linux.code-workspace`).
2. Copy **`.env.example`** to **`.env`**. Set a strong `ADMIN_PASSWORD` (at least 16 characters), generate a random `SESSION_SECRET` (at least 32 characters), and configure `GROQ_API_KEY` and `DATABASE_URL` if needed. For local HTTP development, keep `SESSION_COOKIE_SECURE=false`; set it to `true` in production.
   Generate a secret with `python -c "import secrets; print(secrets.token_urlsafe(32))"`. Never commit `.env`; deployment secrets belong in your hosting provider's secret settings.
3. Open the VS Code terminal (`Ctrl + ~`) and run:
   ```bash
   python -m venv venv
   # Windows PowerShell: .\venv\Scripts\Activate.ps1
   # Linux/Mac/Git Bash: source venv/bin/activate
   pip install -r requirements.txt
   python scripts/evaluate_system.py
   uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
   ```
4. Open `http://localhost:8000` in your browser, or press **`F5`** in VS Code to launch with the preconfigured debugger profiles in `.vscode/launch.json`.

## Security configuration

- The dashboard, diagnosis, incident, export, runbook upload, visitor, and remediation endpoints require the shared admin login. It uses a one-hour, `HttpOnly`, `SameSite=Strict` session cookie. Configure `ADMIN_PASSWORD` and `SESSION_SECRET` on every deployment; authentication fails closed if either is missing or too short.
- Keep `SESSION_COOKIE_SECURE=true` in production and serve the app only over HTTPS. `CORS_ALLOWED_ORIGINS` is an exact comma-separated list and defaults to no cross-origin access; the bundled dashboard is same-origin.
- Set a unique random `SENTINELOPS_API_KEY` on the backend, collector host, and GitHub Actions secret. Rotate it immediately if it was previously deployed or committed. Do not put it in source code or a systemd unit.
- The database automatically uses TLS (`sslmode=require`) for non-local PostgreSQL hosts. Use a dedicated database user with only the permissions the app needs, and avoid logging connection strings.
- Frontend CDN scripts are pinned to fixed versions with Subresource Integrity. For production builds, bundle/precompile the dashboard to remove runtime CDN and Babel dependencies.
- Visitor IP addresses are sent to ipapi.co over HTTPS for geolocation. Disclose this processing and apply an appropriate retention policy.
- Live SSH remediation is disabled by default. To enable it, configure exact `SSH_ALLOWED_HOSTS` and `SSH_ALLOWED_COMMANDS` as a JSON array of exact command strings, a dedicated SSH user/private key, and a pinned `SSH_KNOWN_HOSTS` file. Do not enable it for broad host sets or AI-generated commands that are not in the exact allowlist.
- For a Linux collector, create a dedicated `sentinelops` system user and add it to the `systemd-journal` group. Store `SENTINELOPS_URL` and `SENTINELOPS_API_KEY` in `/etc/sentinelops/collector.env`, owned by `root:sentinelops` with mode `640`; do not place secrets in the unit file. Example setup:
  ```bash
  sudo useradd --system --user-group --no-create-home --shell /usr/sbin/nologin sentinelops
  sudo usermod -aG systemd-journal sentinelops
  sudo install -d -o root -g sentinelops -m 750 /etc/sentinelops
  sudo install -o root -g sentinelops -m 640 collector.env /etc/sentinelops/collector.env
  ```
- For production, put login rate limiting at the reverse proxy/edge and enable platform request limits, especially if running multiple app instances.

## Push to GitHub (`SentinelOps-Linux`)
```bash
git init
git add .
git commit -m "feat: initial SentinelOps 4-layer system"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/SentinelOps-Linux.git
git push -u origin main
```
