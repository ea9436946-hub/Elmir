from datetime import datetime, timedelta
from collections import defaultdict


class PortScanRule:
    name = "port_scan_detection"

    def __init__(self, config: dict):
        self.enabled = config.get("enabled", True)
        self.threshold = config.get("threshold", 20)
        self.window = config.get("window_seconds", 30)
        self.severity = config.get("severity", "HIGH")
        self._port_hits: dict[str, list] = defaultdict(list)
        self._alerted: dict[str, datetime] = {}

    def evaluate(self, event: dict, store) -> dict | None:
        if event.get("event_type") != "http_request":
            return None

        source_ip = event.get("source_ip")
        if not source_ip:
            return None

        extra = event.get("extra") or {}
        status = extra.get("status_code", 200)
        # Port scans often produce many 404s or connection resets
        if status not in (404, 400, 403, 0):
            return None

        now = datetime.utcnow()
        window_start = now - timedelta(seconds=self.window)

        hits = self._port_hits[source_ip]
        hits.append(now)
        self._port_hits[source_ip] = [h for h in hits if h > window_start]

        last_alert = self._alerted.get(source_ip)
        if last_alert and (now - last_alert).total_seconds() < self.window:
            return None

        if len(self._port_hits[source_ip]) >= self.threshold:
            self._alerted[source_ip] = now
            return {
                "rule_name": self.name,
                "severity": self.severity,
                "source_ip": source_ip,
                "description": (
                    f"Possible port/path scan: {len(self._port_hits[source_ip])} "
                    f"error responses from {source_ip} in {self.window}s"
                ),
                "event_ids": [],
            }
        return None
