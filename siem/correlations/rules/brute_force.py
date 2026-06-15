from datetime import datetime, timedelta


class BruteForceRule:
    name = "brute_force_detection"

    def __init__(self, config: dict):
        self.enabled = config.get("enabled", True)
        self.threshold = config.get("threshold", 5)
        self.window = config.get("window_seconds", 60)
        self.severity = config.get("severity", "HIGH")
        self._alerted: dict[str, datetime] = {}

    def evaluate(self, event: dict, store) -> dict | None:
        if event.get("event_type") not in ("failed_login", "invalid_user"):
            return None

        source_ip = event.get("source_ip")
        if not source_ip:
            return None

        # Suppress duplicate alerts within the window
        last_alert = self._alerted.get(source_ip)
        if last_alert and (datetime.utcnow() - last_alert).total_seconds() < self.window:
            return None

        since = datetime.utcnow() - timedelta(seconds=self.window)
        recent = store.get_events_since(since, source_ip=source_ip)
        failed = [e for e in recent if e.get("event_type") in ("failed_login", "invalid_user")]

        if len(failed) >= self.threshold:
            self._alerted[source_ip] = datetime.utcnow()
            return {
                "rule_name": self.name,
                "severity": self.severity,
                "source_ip": source_ip,
                "username": event.get("username"),
                "description": (
                    f"Brute force detected: {len(failed)} failed logins from "
                    f"{source_ip} in {self.window}s"
                ),
                "event_ids": [e["id"] for e in failed],
            }
        return None
