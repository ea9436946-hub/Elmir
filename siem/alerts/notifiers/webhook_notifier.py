import json
import logging
import requests

logger = logging.getLogger(__name__)

_SEVERITY_COLORS = {
    "LOW": "#36a64f",
    "MEDIUM": "#ff9800",
    "HIGH": "#f44336",
    "CRITICAL": "#b71c1c",
}


class WebhookNotifier:
    def __init__(self, config: dict):
        self.url = config["url"]
        self.timeout = config.get("timeout", 10)

    def send(self, alert: dict):
        severity = alert.get("severity", "INFO")
        payload = {
            "text": f":warning: *SIEM Alert — {severity}*",
            "attachments": [
                {
                    "color": _SEVERITY_COLORS.get(severity, "#888888"),
                    "fields": [
                        {"title": "Rule", "value": alert.get("rule_name"), "short": True},
                        {"title": "Severity", "value": severity, "short": True},
                        {"title": "Source IP", "value": alert.get("source_ip", "N/A"), "short": True},
                        {"title": "Username", "value": alert.get("username", "N/A"), "short": True},
                        {"title": "Description", "value": alert.get("description"), "short": False},
                    ],
                    "footer": f"Elmir SIEM | {alert.get('timestamp')}",
                }
            ],
        }
        resp = requests.post(self.url, json=payload, timeout=self.timeout)
        resp.raise_for_status()
        logger.info("Webhook alert sent (status %d)", resp.status_code)
