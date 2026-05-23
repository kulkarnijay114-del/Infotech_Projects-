"""
Alert System
Sends notifications when high-risk threats are detected or IPs are blocked.
Supports Slack webhook and simple SMTP email.
"""

import smtplib
import requests
from email.mime.text import MIMEText
from rich.console import Console

from src.config import SLACK_WEBHOOK_URL, ALERT_EMAIL

console = Console()


def send_slack(title: str, message: str):
    """Send a message to a Slack channel via incoming webhook."""
    if not SLACK_WEBHOOK_URL:
        return

    payload = {
        "text": f"*🚨 TIP Alert: {title}*\n{message}"
    }
    try:
        resp = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=5)
        resp.raise_for_status()
        console.print(f"[green]Slack alert sent:[/green] {title}")
    except Exception as e:
        console.print(f"[yellow]Slack alert failed: {e}[/yellow]")


def send_email(title: str, message: str):
    """
    Send a plain-text email alert via localhost SMTP (port 25).
    For production, replace with SendGrid/SES/SMTP credentials.
    """
    if not ALERT_EMAIL:
        return

    msg = MIMEText(f"TIP Alert\n\n{title}\n\n{message}")
    msg["Subject"] = f"[TIP] {title}"
    msg["From"]    = "tip-noreply@localhost"
    msg["To"]      = ALERT_EMAIL

    try:
        with smtplib.SMTP("localhost", 25, timeout=5) as smtp:
            smtp.sendmail(msg["From"], [ALERT_EMAIL], msg.as_string())
        console.print(f"[green]Email alert sent to {ALERT_EMAIL}[/green]")
    except Exception as e:
        console.print(f"[yellow]Email alert failed: {e}[/yellow]")


def send_alert(title: str, message: str):
    """Fire all configured alert channels."""
    send_slack(title, message)
    send_email(title, message)
