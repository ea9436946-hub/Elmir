import sys
sys.path.insert(0, __import__("os").path.join(__import__("os").path.dirname(__file__), ".."))

from datetime import datetime
from unittest.mock import MagicMock
from siem.correlations.rules.brute_force import BruteForceRule
from siem.correlations.rules.privilege_escalation import PrivilegeEscalationRule


def _make_store(events):
    store = MagicMock()
    store.get_events_since.return_value = events
    return store


def test_brute_force_triggered():
    rule = BruteForceRule({"threshold": 3, "window_seconds": 60})
    ip = "10.0.0.99"
    failed_events = [
        {"id": i, "event_type": "failed_login", "source_ip": ip}
        for i in range(4)
    ]
    store = _make_store(failed_events)
    event = {"event_type": "failed_login", "source_ip": ip, "username": "root"}
    alert = rule.evaluate(event, store)
    assert alert is not None
    assert alert["rule_name"] == "brute_force_detection"
    assert alert["source_ip"] == ip


def test_brute_force_not_triggered():
    rule = BruteForceRule({"threshold": 5, "window_seconds": 60})
    store = _make_store([{"id": 1, "event_type": "failed_login", "source_ip": "1.1.1.1"}])
    event = {"event_type": "failed_login", "source_ip": "1.1.1.1", "username": "admin"}
    alert = rule.evaluate(event, store)
    assert alert is None


def test_privilege_escalation_su_root():
    rule = PrivilegeEscalationRule({})
    event = {
        "event_type": "su_session",
        "username": "bob",
        "message": "su session opened for user root by bob",
    }
    alert = rule.evaluate(event, MagicMock())
    assert alert is not None
    assert alert["severity"] == "CRITICAL"


def test_privilege_escalation_no_root():
    rule = PrivilegeEscalationRule({})
    event = {
        "event_type": "su_session",
        "username": "alice",
        "message": "su session opened for user alice by admin",
    }
    alert = rule.evaluate(event, MagicMock())
    assert alert is None


if __name__ == "__main__":
    test_brute_force_triggered()
    test_brute_force_not_triggered()
    test_privilege_escalation_su_root()
    test_privilege_escalation_no_root()
    print("All correlation tests passed.")
