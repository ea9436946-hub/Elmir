import re
from datetime import datetime
from .base_parser import BaseParser

_SYSLOG = re.compile(
    r"(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}) (\S+) (\S+?)(?:\[(\d+)\])?: (.*)"
)


def _parse_ts(ts: str) -> str:
    try:
        dt = datetime.strptime(f"{datetime.utcnow().year} {ts.strip()}", "%Y %b %d %H:%M:%S")
        return dt.isoformat()
    except ValueError:
        return datetime.utcnow().isoformat()


class SyslogParser(BaseParser):
    source_name = "syslog"

    def can_parse(self, line: str) -> bool:
        return bool(_SYSLOG.match(line))

    def parse(self, line: str) -> dict | None:
        m = _SYSLOG.match(line)
        if not m:
            return None

        ts, host, process, pid, message = m.groups()
        severity = "INFO"
        msg_lower = message.lower()
        if any(w in msg_lower for w in ("error", "fail", "critical", "alert", "emerg")):
            severity = "ERROR"
        elif any(w in msg_lower for w in ("warn", "notice")):
            severity = "WARNING"

        event = self._base_event()
        event.update({
            "timestamp": _parse_ts(ts),
            "event_type": "syslog",
            "severity": severity,
            "message": message,
            "raw": line.rstrip(),
            "extra": {"hostname": host, "process": process, "pid": pid},
        })
        return event
