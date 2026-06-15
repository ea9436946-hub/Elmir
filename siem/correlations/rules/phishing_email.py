import re

PHISHING_SUBJECTS = re.compile(
    r'(phishing|password\s*reset|verify\s*your|account\s*suspend|urgent|click\s*here|'
    r'wire\s*transfer|invoice\s*attach|bitcoin|congratulation|you\s*have\s*won|'
    r'confirm\s*your\s*identity|security\s*alert|unusual\s*sign)',
    re.IGNORECASE,
)
PHISHING_DOMAINS = re.compile(
    r'(\.ru|\.cn|\.tk|\.xyz|\.top|\.click|\.download|bit\.ly|tinyurl|'
    r'paypa1\.|micosoft\.|g00gle\.|amaz0n\.)',
    re.IGNORECASE,
)
MALICIOUS_ATTACHMENTS = re.compile(
    r'\.(exe|vbs|js|bat|cmd|ps1|scr|jar|docm|xlsm)\b',
    re.IGNORECASE,
)


class PhishingEmailRule:
    name = "phishing_email"

    def __init__(self, config: dict):
        self.enabled = config.get("enabled", True)
        self.severity = config.get("severity", "HIGH")

    def evaluate(self, event: dict, store) -> dict | None:
        msg = (event.get("message") or "") + " " + (event.get("raw") or "")

        if not any(kw in msg.lower() for kw in ("mail", "smtp", "postfix", "dovecot", "subject", "from:")):
            return None

        reasons = []
        if PHISHING_SUBJECTS.search(msg):
            reasons.append("verdächtiger Betreff")
        if PHISHING_DOMAINS.search(msg):
            reasons.append("verdächtige Domain")
        if MALICIOUS_ATTACHMENTS.search(msg):
            reasons.append("gefährlicher Anhang")

        if not reasons:
            return None

        return {
            "rule_name": self.name,
            "severity": self.severity,
            "source_ip": event.get("source_ip"),
            "username": event.get("username"),
            "description": f"Phishing-E-Mail erkannt ({', '.join(reasons)}): {msg[:120]}",
            "event_ids": [event.get("id")] if event.get("id") else [],
        }
