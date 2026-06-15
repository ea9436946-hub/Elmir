import re
from datetime import datetime
from .base_parser import BaseParser

# Combined Log Format: 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326
_COMBINED = re.compile(
    r'([\d\.]+) \S+ (\S+) \[([^\]]+)\] "(\S+) ([^"]*) HTTP/[\d\.]+" (\d{3}) (\d+|-)'
    r'(?: "([^"]*)" "([^"]*)")?'
)


def _parse_ts(ts: str) -> str:
    try:
        dt = datetime.strptime(ts.split()[0], "%d/%b/%Y:%H:%M:%S")
        return dt.isoformat()
    except ValueError:
        return datetime.utcnow().isoformat()


class ApacheParser(BaseParser):
    source_name = "apache"

    def can_parse(self, line: str) -> bool:
        return bool(_COMBINED.match(line))

    def parse(self, line: str) -> dict | None:
        m = _COMBINED.match(line)
        if not m:
            return None

        ip, user, ts, method, path, status, size, referer, ua = m.groups()
        status_int = int(status)

        severity = "INFO"
        if status_int >= 500:
            severity = "ERROR"
        elif status_int == 404:
            severity = "WARNING"
        elif status_int in (401, 403):
            severity = "WARNING"

        event = self._base_event()
        event.update({
            "timestamp": _parse_ts(ts),
            "event_type": "http_request",
            "severity": severity,
            "source_ip": ip,
            "username": user if user != "-" else None,
            "message": f'{method} {path} -> {status}',
            "raw": line.rstrip(),
            "extra": {
                "method": method,
                "path": path,
                "status_code": status_int,
                "bytes": size,
                "user_agent": ua,
                "referer": referer,
            },
        })
        return event
