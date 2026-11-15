import os
import requests

def send_slack_alert(incident_id: int, hostname: str, stack: str, root_cause: str, risk_level: str, fix_commands: list):
    webhook_url = os.getenv("SLACK_WEBHOOK_URL", "").strip()
    if not webhook_url:
        print("SLACK_WEBHOOK_URL not set. Skipping notification.")
        return

    fixes_str = "\n".join(fix_commands)
    payload = {
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*🚨 Autonomous Incident Detected (#INC-{incident_id})*\n• *Host:* `{hostname}`\n• *Stack:* `{stack}`\n• *Safety Rating:* `{risk_level}`\n• *Root Cause:* {root_cause}"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Suggested Remediation Commands:*\n```{fixes_str}```"
                }
            }
        ]
    }
    try:
        res = requests.post(webhook_url, json=payload, timeout=5)
        print(f"Slack webhook dispatch status: {res.status_code}")
    except Exception as e:
        print(f"Failed to dispatch Slack notification: {e}")