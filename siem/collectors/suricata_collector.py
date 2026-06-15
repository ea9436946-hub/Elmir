import json
import logging
import os
import time
from datetime import datetime
from threading import Thread

logger = logging.getLogger(__name__)

SEVERITY_MAP = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}


def _parse_eve(line: str) -> dict | None:
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None

    event_type = obj.get("event_type")
    if event_type != "alert":
        return None

    alert = obj.get("alert", {})
    severity_num = alert.get("severity", 3)

    return {
        "timestamp": obj.get("timestamp", datetime.utcnow().isoformat()),
        "source": "suricata",
        "event_type": "ids_alert",
        "severity": SEVERITY_MAP.get(severity_num, "MEDIUM"),
        "source_ip": obj.get("src_ip"),
        "message": alert.get("signature", "Suricata IDS Alert"),
        "raw": line.strip(),
        "extra": {
            "dest_ip": obj.get("dest_ip"),
            "proto": obj.get("proto"),
            "category": alert.get("category"),
            "signature_id": alert.get("signature_id"),
        },
    }


class SuricataCollector:
    def __init__(self, eve_path: str, callback):
        self.eve_path = eve_path
        self.callback = callback
        self._running = False
        self._thread: Thread | None = None

    def start(self):
        self._running = True
        self._thread = Thread(target=self._tail, daemon=True, name="suricata-collector")
        self._thread.start()
        logger.info("Suricata collector started: %s", self.eve_path)

    def stop(self):
        self._running = False

    def _tail(self):
        while self._running and not os.path.exists(self.eve_path):
            logger.debug("Suricata EVE log not found yet: %s", self.eve_path)
            time.sleep(10)

        try:
            with open(self.eve_path, "r") as f:
                f.seek(0, 2)  # Jump to end
                while self._running:
                    line = f.readline()
                    if not line:
                        time.sleep(0.5)
                        continue
                    event = _parse_eve(line)
                    if event:
                        self.callback(event)
        except Exception as e:
            logger.error("Suricata collector error: %s", e)
