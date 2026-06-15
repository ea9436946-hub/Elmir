import logging
from datetime import datetime
from .rules.brute_force import BruteForceRule
from .rules.port_scan import PortScanRule
from .rules.privilege_escalation import PrivilegeEscalationRule

logger = logging.getLogger(__name__)


class RuleEngine:
    def __init__(self, config: dict, event_store, alert_manager):
        self.event_store = event_store
        self.alert_manager = alert_manager
        cfg = config.get("correlations", {})
        self.rules = [
            BruteForceRule(cfg.get("brute_force", {})),
            PortScanRule(cfg.get("port_scan", {})),
            PrivilegeEscalationRule(cfg.get("privilege_escalation", {})),
        ]

    def process(self, event: dict):
        for rule in self.rules:
            if not rule.enabled:
                continue
            alert = rule.evaluate(event, self.event_store)
            if alert:
                alert["timestamp"] = datetime.utcnow().isoformat()
                alert_id = self.event_store.store_alert(alert)
                logger.warning("ALERT [%s] %s", alert.get("severity"), alert.get("description"))
                self.alert_manager.send(alert)
