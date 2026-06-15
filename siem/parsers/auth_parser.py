import re
from datetime import datetime
from .base_parser import BaseParser

# Jun 15 10:23:45 hostname sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2
_SYSLOG_TS = r"(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})"
_FAILED_LOGIN = re.compile(
    rf"{_SYSLOG_TS} \S+ \S+\[\d+\]: Failed password for (\S+) from ([\d\.]+)"
)
_ACCEPTED_LOGIN = re.compile(
    rf"{_SYSLOG_TS} \S+ \S+\[\d+\]: Accepted (\S+) for (\S+) from ([\d\.]+)"
)
_INVALID_USER = re.compile(
    rf"{_SYSLOG_TS} \S+ \S+\[\d+\]: Invalid user (\S+) from ([\d\.]+)"
)
_SUDO = re.compile(
    rf"{_SYSLOG_TS} \S+ sudo\[\d+\]:\s+(\S+) : (.*)"
)
_SU = re.compile(
    rf"{_SYSLOG_TS} \S+ su\[\d+\]:.*pam_unix.*session opened for user (\S+) by (\S+)"
)


def _parse_ts(ts_str: str) -> str:
    try:
        dt = datetime.strptime(f"{datetime.utcnow().year} {ts_str.strip()}", "%Y %b %d %H:%M:%S")
        return dt.isoformat()
    except ValueError:
        return datetime.utcnow().isoformat()


class AuthParser(BaseParser):
    source_name = "auth.log"

    def can_parse(self, line: str) -> bool:
        return any(kw in line for kw in ("sshd", "sudo", "su[", "pam_unix"))

    def parse(self, line: str) -> dict | None:
        event = self._base_event()
        event["raw"] = line.rstrip()

        m = _FAILED_LOGIN.search(line)
        if m:
            event.update({
                "timestamp": _parse_ts(m.group(1)),
                "event_type": "failed_login",
                "severity": "WARNING",
                "username": m.group(2),
                "source_ip": m.group(3),
                "message": f"Failed SSH login for {m.group(2)} from {m.group(3)}",
            })
            return event

        m = _ACCEPTED_LOGIN.search(line)
        if m:
            event.update({
                "timestamp": _parse_ts(m.group(1)),
                "event_type": "successful_login",
                "severity": "INFO",
                "username": m.group(3),
                "source_ip": m.group(4),
                "message": f"Successful SSH login ({m.group(2)}) for {m.group(3)} from {m.group(4)}",
            })
            return event

        m = _INVALID_USER.search(line)
        if m:
            event.update({
                "timestamp": _parse_ts(m.group(1)),
                "event_type": "invalid_user",
                "severity": "WARNING",
                "username": m.group(2),
                "source_ip": m.group(3),
                "message": f"Invalid user {m.group(2)} from {m.group(3)}",
            })
            return event

        m = _SUDO.search(line)
        if m:
            event.update({
                "timestamp": _parse_ts(m.group(1)),
                "event_type": "sudo_command",
                "severity": "INFO",
                "username": m.group(2),
                "message": f"sudo by {m.group(2)}: {m.group(3)}",
            })
            if "FAILED" in line:
                event["severity"] = "WARNING"
                event["event_type"] = "sudo_failed"
            return event

        m = _SU.search(line)
        if m:
            event.update({
                "timestamp": _parse_ts(m.group(1)),
                "event_type": "su_session",
                "severity": "INFO",
                "username": m.group(3),
                "message": f"su session opened for {m.group(2)} by {m.group(3)}",
            })
            return event

        return None
