from datetime import datetime, timedelta
from collections import defaultdict


class LateralMovementRule:
    name = "lateral_movement"

    def __init__(self, config: dict):
        self.enabled = config.get("enabled", True)
        self.threshold = config.get("threshold", 3)
        self.window = config.get("window_seconds", 120)
        self.severity = config.get("severity", "CRITICAL")
        self._ip_users: dict[str, list[tuple[datetime, str]]] = defaultdict(list)
        self._alerted: dict[str, datetime] = {}

    def evaluate(self, event: dict, store) -> dict | None:
        if event.get("event_type") not in ("failed_login", "invalid_user", "successful_login"):
            return None
        source_ip = event.get("source_ip")
        username = event.get("username")
        if not source_ip or not username:
            return None

        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=self.window)

        # Suppress duplicate alerts
        last = self._alerted.get(source_ip)
        if last and (now - last).total_seconds() < self.window:
            return None

        entries = self._ip_users[source_ip]
        entries.append((now, username))
        # Keep only entries within window
        self._ip_users[source_ip] = [(t, u) for t, u in entries if t >= cutoff]

        unique_users = {u for _, u in self._ip_users[source_ip]}
        if len(unique_users) >= self.threshold:
            self._alerted[source_ip] = now
            self._ip_users[source_ip] = []
            return {
                "rule_name": self.name,
                "severity": self.severity,
                "source_ip": source_ip,
                "username": username,
                "description": (
                    f"Lateral movement detected: IP {source_ip} tried "
                    f"{len(unique_users)} different usernames in {self.window}s: "
                    f"{', '.join(sorted(unique_users))}"
                ),
                "event_ids": [],
            }
        return None
