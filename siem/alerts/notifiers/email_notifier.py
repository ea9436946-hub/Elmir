import logging
import smtplib
from email.mime.text import MIMEText

logger = logging.getLogger(__name__)


class EmailNotifier:
    def __init__(self, config: dict):
        self.host = config["smtp_host"]
        self.port = config.get("smtp_port", 587)
        self.username = config.get("username")
        self.password = config.get("password")
        self.from_addr = config.get("from_addr", self.username)
        self.to_addrs = config.get("to_addrs", [])

    def send(self, alert: dict):
        if not self.to_addrs:
            return

        subject = f"[SIEM {alert.get('severity')}] {alert.get('rule_name')}"
        body = (
            f"Severity: {alert.get('severity')}\n"
            f"Rule: {alert.get('rule_name')}\n"
            f"Time: {alert.get('timestamp')}\n"
            f"Source IP: {alert.get('source_ip')}\n"
            f"Username: {alert.get('username')}\n\n"
            f"Description:\n{alert.get('description')}\n"
        )

        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = self.from_addr
        msg["To"] = ", ".join(self.to_addrs)

        with smtplib.SMTP(self.host, self.port) as smtp:
            smtp.starttls()
            if self.username and self.password:
                smtp.login(self.username, self.password)
            smtp.sendmail(self.from_addr, self.to_addrs, msg.as_string())

        logger.info("Email alert sent: %s", subject)
