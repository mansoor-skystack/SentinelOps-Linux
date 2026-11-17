# SentinelOps (`SentinelOps-Linux`)

Automated Linux Log Telemetry, PII/Secret Sanitization, and Hybrid-RAG Incident Resolution System.

## Problem SentinelOps Solves

SentinelOps is designed for production incidents where sending raw logs to a public LLM or letting generated shell commands run unchecked is not acceptable. It adds three controls to incident triage:

- **Privacy before inference:** local sanitization removes credentials, tokens, passwords, and public IPs from logs before they are sent to a configured model.
- **Runbook-grounded diagnosis:** hybrid TF-IDF and BM25 retrieval supplies operational runbooks and historical incidents as evidence for diagnosis.
- **Zero-trust remediation:** command guardrails and exact SSH host/command allowlists constrain any approved remediation; live execution remains disabled by default.

Agent webhooks also pass CPU load, memory usage, and disk usage into model-backed triage as contextual evidence. Manual diagnoses mark telemetry unavailable rather than treating missing measurements as zero.

The dashboard separates **Manual Logs** from **VM Agent Logs**. Incidents start as **Pending**; admins can mark an issue **Completed** after addressing it or return it to **Pending**. Resolution status is stored with the incident.

The VM collector only submits logs and telemetry; it never runs the suggested fixes. Admins can run exact-allowlisted read-only diagnostics and inspect their output before explicitly approving the proposed fixes. A fix is followed by configured health checks; SentinelOps marks it completed automatically only when those checks pass. The incident keeps the latest reports, and a separate append-only remediation audit table retains authenticated attempts for existing incidents, including blocked requests, commands, exit results, and verification outcomes.

The curated incident runbooks in `backend/data/runbooks/` are indexed separately from the public TLDR command references in `backend/data/public-reference/tldr/`. Public references can help with command context, but they are weighted as lower-trust retrieval material and cannot authorize offline fix commands. Cross-host correlation is a five-minute lexical signal for shared symptoms, not proof of a common root cause.

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
   The evaluation reports development and held-out Hit@3/MRR, index-build duration, p95 retrieval latency, and synthetic sanitizer cases separately.
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
- Live SSH remediation is disabled by default. To enable it, configure exact `SSH_ALLOWED_HOSTS`, `SSH_ALLOWED_DIAGNOSTIC_COMMANDS`, `SSH_ALLOWED_COMMANDS`, and `SSH_ALLOWED_POSTCHECK_COMMANDS` as comma-separated hosts and JSON arrays of exact command strings, a dedicated SSH user/private key, and a pinned `SSH_KNOWN_HOSTS` file. Diagnostics and post-checks must be single read-only commands without shell operators. Do not enable it for broad host sets or AI-generated commands that are not in the exact allowlist. Successful fixes are not marked complete unless all configured post-checks pass.
- The collector raises proactive alerts at 90% by default for sampled CPU utilization, memory, and disk. CPU utilization is measured from `/proc/stat`; the separate `cpu_load` telemetry remains a one-minute load average. Configure `SENTINELOPS_CPU_THRESHOLD_PCT`, `SENTINELOPS_MEMORY_THRESHOLD_PCT`, and `SENTINELOPS_DISK_THRESHOLD_PCT`; a five-point clear margin and five-minute cooldown suppress alert flapping. Threshold state is stored beside the journal cursor under the service state directory.
- To install and run the Linux collector, follow [Deploy the Linux collector agent](#deploy-the-linux-collector-agent). Keep its API key in the protected environment file, not in the service unit or repository.
- Collector-side redaction is opt-in. Set `SENTINELOPS_REDACT_LOCAL=true` in the protected agent environment file, or pass `--redact-local` for a one-shot invocation, to sanitize logs on the VM before webhook transmission. Install both `linux_collector.py` and `log_sanitizer.py` on the VM; without this option the backend sanitizes after receiving the HTTPS request.
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

## Isolated Docker Compose demo

The Compose stack runs the app with PostgreSQL and a disposable OpenSSH target. The target has no published host port and is reachable only from the app on a private Docker network. PostgreSQL uses a disposable self-signed TLS certificate because the backend requires TLS for non-local database hosts. SSH client, SSH host, and database TLS keys are generated into separate Docker-managed volumes; they are not stored in the repository. `SSH_REMEDIATION_ENABLED` defaults to `false`.

1. Copy `.env.demo.example` to `.env.demo` and set strong, local-only values for `ADMIN_PASSWORD`, `SESSION_SECRET`, `SENTINELOPS_API_KEY`, and `POSTGRES_PASSWORD`. Generate values with `python -c "import secrets; print('ADMIN_PASSWORD='+secrets.token_urlsafe(24)); print('SESSION_SECRET='+secrets.token_urlsafe(32)); print('SENTINELOPS_API_KEY='+secrets.token_hex(32)); print('POSTGRES_PASSWORD='+secrets.token_hex(24))"`. Do not reuse production credentials.
2. Start the stack and seed sample incidents:
   ```bash
   docker compose --env-file .env.demo up --build -d
   docker compose --env-file .env.demo exec app python scripts/seed_demo.py --confirm
   ```
3. Open `http://127.0.0.1:8001` and sign in with the demo admin password. Change `SENTINELOPS_DEMO_PORT` if that loopback port is already in use.
4. To exercise SSH only against the disposable container, change `SSH_REMEDIATION_ENABLED=false` to `true` in `.env.demo`, then recreate the app:
   ```bash
   docker compose --env-file .env.demo up -d --force-recreate app
   ```
   Select the seeded incident for `ssh-target`, run diagnostics, and approve the allowlisted marker-file command. The post-check verifies the marker. No command is run against a host outside the Compose network.
5. Remove the containers, database, and generated SSH keys with:
   ```bash
   docker compose --env-file .env.demo down -v
   ```

The seeder refuses to run unless the Compose demo-mode environment is present and `--confirm` is supplied. It adds records idempotently and does not delete existing incidents.

The GitHub Actions workflow runs the backend tests, scans tracked source with Gitleaks, builds the application and demo SSH images, and scans those images with Trivy. It uses no deployment credentials.

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
     agent/log_sanitizer.py /opt/sentinelops/log_sanitizer.py
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
   Add the backend URL, the exact same API key configured as `SENTINELOPS_API_KEY` in the Render Web Service, and optionally override the default proactive thresholds:
   ```ini
   SENTINELOPS_URL=https://sentinelops-linux.onrender.com
   SENTINELOPS_API_KEY=replace_with_the_same_key_configured_in_Render
   SENTINELOPS_REDACT_LOCAL=true
   SENTINELOPS_CPU_THRESHOLD_PCT=90
   SENTINELOPS_MEMORY_THRESHOLD_PCT=90
   SENTINELOPS_DISK_THRESHOLD_PCT=90
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
