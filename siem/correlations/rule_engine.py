import logging
from datetime import datetime
from .rules.brute_force import BruteForceRule
from .rules.port_scan import PortScanRule
from .rules.privilege_escalation import PrivilegeEscalationRule
from .rules.lateral_movement import LateralMovementRule
from .rules.data_exfiltration import DataExfiltrationRule
from .rules.malware_download import MalwareDownloadRule

logger = logging.getLogger(__name__)


class RuleEngine:
    def __init__(self, config: dict, event_store, alert_manager):
        self.event_store = event_store
        self.alert_manager = alert_manager
        self._new_alert_callbacks: list = []
        cfg = config.get("correlations", {})
        self.rules = [
            BruteForceRule(cfg.get("brute_force", {})),
            PortScanRule(cfg.get("port_scan", {})),
            PrivilegeEscalationRule(cfg.get("privilege_escalation", {})),
            LateralMovementRule(cfg.get("lateral_movement", {})),
            DataExfiltrationRule(cfg.get("data_exfiltration", {})),
            MalwareDownloadRule(cfg.get("malware_download", {})),
        ]

    def on_alert(self, callback):
        self._new_alert_callbacks.append(callback)

    def process(self, event: dict):
        for rule in self.rules:
            if not rule.enabled:
                continue
            alert = rule.evaluate(event, self.event_store)
            if alert:
                alert["timestamp"] = datetime.utcnow().isoformat()
                alert_id = self.event_store.store_alert(alert)
                alert["id"] = alert_id
                logger.warning("ALERT [%s] %s", alert.get("severity"), alert.get("description"))
                self.alert_manager.send(alert)
                for cb in self._new_alert_callbacks:
                    try:
                        cb(alert)
                    except Exception:
                        pass
