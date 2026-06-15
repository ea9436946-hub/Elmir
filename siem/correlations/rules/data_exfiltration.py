from datetime import datetime, timedelta
from collections import defaultdict


class DataExfiltrationRule:
    name = "data_exfiltration"

    def __init__(self, config: dict):
        self.enabled = config.get("enabled", True)
        self.threshold = config.get("threshold", 50)
        self.window = config.get("window_seconds", 60)
        self.severity = config.get("severity", "HIGH")
        self._ip_requests: dict[str, list[datetime]] = defaultdict(list)
        self._alerted: dict[str, datetime] = {}

    def evaluate(self, event: dict, store) -> dict | None:
        if event.get("event_type") not in ("http_request",):
            return None
        source_ip = event.get("source_ip")
        if not source_ip:
            return None

        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=self.window)

        last = self._alerted.get(source_ip)
        if last and (now - last).total_seconds() < self.window:
            return None

        reqs = self._ip_requests[source_ip]
        reqs.append(now)
        self._ip_requests[source_ip] = [t for t in reqs if t >= cutoff]

        count = len(self._ip_requests[source_ip])
        if count >= self.threshold:
            self._alerted[source_ip] = now
            self._ip_requests[source_ip] = []
            return {
                "rule_name": self.name,
                "severity": self.severity,
                "source_ip": source_ip,
                "username": event.get("username"),
                "description": (
                    f"Possible data exfiltration: {count} requests from "
                    f"{source_ip} in {self.window}s"
                ),
                "event_ids": [],
            }
        return None
