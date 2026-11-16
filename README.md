# SentinelOps (`SentinelOps-Linux`)

Automated Linux Log Telemetry, PII/Secret Sanitization, and Hybrid-RAG Incident Resolution System.

## VS Code Quickstart
1. Extract this archive and double-click **`SentinelOps-Linux.code-workspace`** in **VS Code** (or run `code SentinelOps-Linux/SentinelOps-Linux.code-workspace`).
2. Copy **`.env.example`** to **`.env`** and paste your free **`GROQ_API_KEY`** (created under API Key name **`SentinelOps`** at `console.groq.com`) and your **`DATABASE_URL`** from `neon.tech`.
   Set a separate, strong **`VISITOR_API_KEY`** in your local `.env` and Render environment to access `GET /api/visitors`; send it in the `X-API-Key` header. Public visitor IPs are looked up over HTTPS with ipapi.co, so disclose this processing and set an appropriate data-retention policy.
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

## Push to GitHub (`SentinelOps-Linux`)
```bash
git init
git add .
git commit -m "feat: initial SentinelOps 4-layer system"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/SentinelOps-Linux.git
git push -u origin main
```
