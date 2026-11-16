import os
import logging
from urllib.parse import urlsplit
import requests

logger = logging.getLogger(__name__)

def send_slack_alert(incident_id: int, hostname: str, stack: str, root_cause: str, risk_level: str, fix_commands: list):
    webhook_url = os.getenv("SLACK_WEBHOOK_URL", "").strip()
    if not webhook_url:
        logger.debug("Slack notification skipped because no webhook is configured")
        return
    parsed_url = urlsplit(webhook_url)
    if parsed_url.scheme != "https" or not parsed_url.hostname or parsed_url.username or parsed_url.password:
        logger.warning("Slack notification skipped because the configured webhook URL is invalid")
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
        logger.info("Slack webhook dispatch returned HTTP %s", res.status_code)
    except requests.RequestException as exc:
        logger.warning("Slack webhook dispatch failed (%s)", type(exc).__name__)