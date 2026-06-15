import logging
from .notifiers.email_notifier import EmailNotifier
from .notifiers.webhook_notifier import WebhookNotifier

logger = logging.getLogger(__name__)


class AlertManager:
    def __init__(self, config: dict):
        self.notifiers = []
        alert_cfg = config.get("alerts", {})

        email_cfg = alert_cfg.get("email", {})
        if email_cfg.get("enabled"):
            self.notifiers.append(EmailNotifier(email_cfg))

        webhook_cfg = alert_cfg.get("webhook", {})
        if webhook_cfg.get("enabled"):
            self.notifiers.append(WebhookNotifier(webhook_cfg))

    def send(self, alert: dict):
        for notifier in self.notifiers:
            try:
                notifier.send(alert)
            except Exception as e:
                logger.error("Notifier %s failed: %s", type(notifier).__name__, e)
