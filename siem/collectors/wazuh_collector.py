import logging
import os
import time
from datetime import datetime
from threading import Thread, Event
from typing import Callable

import requests
import urllib3

logger = logging.getLogger(__name__)

# Self-signed certs are common in Wazuh deployments; silence the warnings.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _map_severity(level) -> str:
    try:
        level = int(level)
    except (TypeError, ValueError):
        return "INFO"
    if level >= 13:
        return "CRITICAL"
    if level >= 10:
        return "HIGH"
    if level >= 6:
        return "MEDIUM"
    if level >= 1:
        return "LOW"
    return "INFO"


class WazuhCollector:
    """Polls the Wazuh REST API and emits alerts as Elmir events."""

    def __init__(
        self,
        callback: Callable[[dict], None],
        url: str = "https://192.168.0.187:55000",
        fetch_interval: int = 30,
        verify_ssl: bool = False,
        user: str = None,
        password: str = None,
    ):
        self.callback = callback
        self.url = url.rstrip("/")
        self.fetch_interval = fetch_interval
        self.verify_ssl = verify_ssl
        self.user = user or os.getenv("WAZUH_USER", "")
        self.password = password or os.getenv("WAZUH_PASS", "")
        self._stop_event = Event()
        self._thread: Thread = None
        self._token = None
        self._offset = 0

    def start(self):
        self._thread = Thread(target=self._run, daemon=True, name="wazuh-collector")
        self._thread.start()
        logger.info("WazuhCollector started, polling %s every %ds", self.url, self.fetch_interval)

    def stop(self):
        self._stop_event.set()

    def _authenticate(self) -> bool:
        try:
            resp = requests.post(
                f"{self.url}/security/user/authenticate",
                auth=(self.user, self.password),
                verify=self.verify_ssl,
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
            self._token = data.get("data", {}).get("token")
            if self._token:
                logger.debug("Wazuh authentication successful")
                return True
            logger.error("Wazuh authentication returned no token")
            return False
        except Exception as e:
            logger.error("Wazuh authentication failed: %s", e)
            return False

    def _fetch_alerts(self) -> list:
        if not self._token:
            if not self._authenticate():
                return []
        headers = {"Authorization": f"Bearer {self._token}"}
        try:
            resp = requests.get(
                f"{self.url}/alerts",
                headers=headers,
                params={"limit": 100, "offset": self._offset},
                verify=self.verify_ssl,
                timeout=15,
            )
            if resp.status_code == 401:
                # Token expired; re-authenticate and retry once.
                if self._authenticate():
                    headers = {"Authorization": f"Bearer {self._token}"}
                    resp = requests.get(
                        f"{self.url}/alerts",
                        headers=headers,
                        params={"limit": 100, "offset": self._offset},
                        verify=self.verify_ssl,
                        timeout=15,
                    )
            resp.raise_for_status()
            data = resp.json()
            items = data.get("data", {}).get("affected_items", [])
            self._offset += len(items)
            return items
        except Exception as e:
            logger.error("Wazuh alert fetch failed: %s", e)
            return []

    def _to_event(self, alert: dict) -> dict:
        rule = alert.get("rule", {}) or {}
        agent = alert.get("agent", {}) or {}
        data = alert.get("data", {}) or {}
        level = rule.get("level")
        src_ip = data.get("srcip") or alert.get("srcip")
        return {
            "timestamp": alert.get("timestamp", datetime.utcnow().isoformat()),
            "source": "wazuh",
            "event_type": "wazuh_alert",
            "severity": _map_severity(level),
            "source_ip": src_ip,
            "username": data.get("srcuser") or data.get("dstuser"),
            "message": rule.get("description", "Wazuh alert"),
            "raw": str(alert),
            "extra": {
                "rule_id": rule.get("id"),
                "level": level,
                "groups": rule.get("groups", []),
                "agent_name": agent.get("name"),
                "agent_id": agent.get("id"),
            },
        }

    def _run(self):
        while not self._stop_event.is_set():
            try:
                alerts = self._fetch_alerts()
                for alert in alerts:
                    event = self._to_event(alert)
                    self.callback(event)
                if alerts:
                    logger.info("WazuhCollector processed %d alert(s)", len(alerts))
            except Exception as e:
                logger.error("WazuhCollector loop error: %s", e)
            self._stop_event.wait(self.fetch_interval)
