# SentinelOps (`SentinelOps-Linux`)

Automated Linux Log Telemetry, PII/Secret Sanitization, and Hybrid-RAG Incident Resolution System.

## Problem SentinelOps Solves

SentinelOps is designed for production incidents where sending raw logs to a public LLM or letting generated shell commands run unchecked is not acceptable. It adds three controls to incident triage:

- **Privacy before inference:** local sanitization removes credentials, tokens, passwords, and public IPs from logs before they are sent to a configured model.
- **Runbook-grounded diagnosis:** hybrid TF-IDF and BM25 retrieval supplies operational runbooks and historical incidents as evidence for diagnosis.
- **Zero-trust remediation:** command guardrails and exact SSH host/command allowlists constrain any approved remediation; live execution remains disabled by default.

Agent webhooks also pass CPU load, memory usage, and disk usage into model-backed triage as contextual evidence. Manual diagnoses mark telemetry unavailable rather than treating missing measurements as zero.

The dashboard separates **Manual Logs** from **VM Agent Logs**. Incidents start as **Pending**; admins can mark an issue **Completed** after addressing it or return it to **Pending**. Resolution status is stored with the incident.

The VM collector only submits logs and telemetry; it never runs the suggested fixes. Admins can open an incident's details to review the diagnosis, verification commands, proposed fixes, and runbook citations. Running fixes requires an authenticated admin to explicitly approve the displayed commands, and SSH allowlists and safety checks still apply.

## VS Code Quickstart
1. Extract this archive and double-click **`SentinelOps-Linux.code-workspace`** in **VS Code** (or run `code SentinelOps-Linux/SentinelOps-Linux.code-workspace`).
2. Copy **`.env.example`** to **`.env`**. Set a strong `ADMIN_PASSWORD` (at least 16 characters), generate a random `SESSION_SECRET` (at least 32 characters), and configure `GROQ_API_KEY`, `GROQ_MODEL`, and `DATABASE_URL` if needed. For local HTTP development, keep `SESSION_COOKIE_SECURE=false`; set it to `true` in production.
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
   The VS Code workspace is configured to use and activate this project-local virtual environment. If `python` is not recognized before creating it on Windows, run the installed interpreter by its full path (for example, `& "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe" -m venv venv`; adjust the version/path to match your installation). Once the environment exists, open a new VS Code terminal or activate it with `.\venv\Scripts\Activate.ps1`.
4. Open `http://localhost:8000` in your browser, or press **`F5`** in VS Code to launch with the preconfigured debugger profiles in `.vscode/launch.json`.

## Security configuration

- The dashboard, diagnosis, incident, export, runbook upload, visitor, and remediation endpoints require the shared admin login. It uses a one-hour, `HttpOnly`, `SameSite=Strict` session cookie. Configure `ADMIN_PASSWORD` and `SESSION_SECRET` on every deployment; authentication fails closed if either is missing or too short.
- Keep `SESSION_COOKIE_SECURE=true` in production and serve the app only over HTTPS. `CORS_ALLOWED_ORIGINS` is an exact comma-separated list and defaults to no cross-origin access; the bundled dashboard is same-origin.
- Set a strong random `SENTINELOPS_API_KEY` on the backend and use the exact same value on each authorized collector host and in the GitHub Actions secret. Rotate it immediately if it was previously deployed or committed. Do not put it in source code or a systemd unit.
- The database automatically uses TLS (`sslmode=require`) for non-local PostgreSQL hosts. Use a dedicated database user with only the permissions the app needs, and avoid logging connection strings.
- Frontend CDN scripts are pinned to fixed versions with Subresource Integrity. For production builds, bundle/precompile the dashboard to remove runtime CDN and Babel dependencies.
- Visitor IP addresses are sent to ipapi.co over HTTPS for geolocation. Disclose this processing and apply an appropriate retention policy.
- Successful visitor location lookups are reused from the database for later visits from the same IP address.
- Live SSH remediation is disabled by default. To enable it, configure exact `SSH_ALLOWED_HOSTS` and `SSH_ALLOWED_COMMANDS` as a JSON array of exact command strings, a dedicated SSH user/private key, and a pinned `SSH_KNOWN_HOSTS` file. Do not enable it for broad host sets or AI-generated commands that are not in the exact allowlist.
- To install and run the Linux collector, follow [Deploy the Linux collector agent](#deploy-the-linux-collector-agent). Keep its API key in the protected environment file, not in the service unit or repository.
- Admin sign-in allows five failed attempts per client IP in a five-minute window. This in-memory limit is per app process; use an edge/reverse-proxy limit as well, especially with multiple app instances.

## Run with Docker

Build and run the included image from the repository root:
```bash
docker build -t sentinelops .
docker run --rm -p 8000:8000 --env-file .env \
  -e DATABASE_URL=sqlite:////var/lib/sentinelops/sentinelops.db \
  -v sentinelops-db:/var/lib/sentinelops \
  -v sentinelops-runbooks:/app/backend/data/runbooks sentinelops
```
Set `DATABASE_URL` to a persistent database for production deployments. Configure the admin credentials and any API keys through the environment or a secret manager.

## Deploy the Linux collector agent

Run these steps on each Linux host you want to monitor. The collector sends telemetry outbound over HTTPS to the SentinelOps backend; it does not require an inbound port. The instructions below assume Ubuntu or Debian with `systemd`.

1. Make the repository available on the Linux host (clone it or copy it there), then from the repository root install the collector dependency and files:
   ```bash
   sudo apt-get update
   sudo apt-get install -y python3 python3-requests

   id sentinelops >/dev/null 2>&1 || \
     sudo useradd --system --user-group --no-create-home \
       --shell /usr/sbin/nologin sentinelops
   sudo usermod -aG systemd-journal sentinelops

   sudo install -d -o root -g root -m 755 /opt/sentinelops
   sudo install -o root -g root -m 755 \
     agent/linux_collector.py /opt/sentinelops/linux_collector.py
   sudo install -o root -g root -m 644 \
     agent/sentinelops-agent.service \
     /etc/systemd/system/sentinelops-agent.service
   ```
   On other Linux distributions, install the equivalent Python 3 and `requests` packages with that distribution's package manager.

2. Create the protected environment file:
   ```bash
   sudo install -d -o root -g sentinelops -m 750 /etc/sentinelops
   sudo install -o root -g sentinelops -m 640 /dev/null \
     /etc/sentinelops/collector.env
   sudoedit /etc/sentinelops/collector.env
   ```
   Add the backend URL and the exact same API key configured as `SENTINELOPS_API_KEY` in the Render Web Service:
   ```ini
   SENTINELOPS_URL=https://sentinelops-linux.onrender.com
   SENTINELOPS_API_KEY=replace_with_the_same_key_configured_in_Render
   ```
   Replace the placeholder with the real key; do not include quotes or commit this file. The collector appends `/api/webhook/ingest` to the base URL. Keep the file owned by `root:sentinelops` with mode `640`.

3. Test delivery with a simulated alert. This sends a test incident to the backend:
   ```bash
   sudo systemd-run --wait --collect --unit=sentinelops-test \
     --property=User=sentinelops \
     --property=Group=sentinelops \
     --property=EnvironmentFile=/etc/sentinelops/collector.env \
     /usr/bin/python3 /opt/sentinelops/linux_collector.py --simulate nginx
   ```
   A successful response prints an incident ID. HTTP `401` usually means the collector key does not match the backend key; HTTP `503` means the backend has no webhook key configured. Never share the key when troubleshooting.

4. Start the continuous collector and inspect its status and logs:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now sentinelops-agent
   sudo systemctl status sentinelops-agent --no-pager
   sudo journalctl -u sentinelops-agent -n 50 --no-pager
   ```
   The service polls `journalctl` for new error-level entries every 30 seconds and stores its journal cursor under `/var/lib/sentinelops`, so already-delivered entries are not resent on every poll. It may be running correctly without creating an incident if the host has no new errors. Real alerts appear in the dashboard with source `systemd-agent`.

## Push to GitHub (`SentinelOps-Linux`)
```bash
git init
git add .
git commit -m "feat: initial SentinelOps 4-layer system"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/SentinelOps-Linux.git
git push -u origin main
```
