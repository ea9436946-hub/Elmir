import re
from datetime import datetime
from .base_parser import BaseParser

# Nginx default: 127.0.0.1 - - [15/Jun/2024:10:23:45 +0000] "GET / HTTP/1.1" 200 615 "-" "curl/7.68"
_NGINX = re.compile(
    r'([\d\.]+) - (\S+) \[([^\]]+)\] "(\S+) ([^"]*) HTTP/[\d\.]+" (\d{3}) (\d+)'
    r'(?: "([^"]*)" "([^"]*)")?'
)


def _parse_ts(ts: str) -> str:
    try:
        dt = datetime.strptime(ts.split()[0], "%d/%b/%Y:%H:%M:%S")
        return dt.isoformat()
    except ValueError:
        return datetime.utcnow().isoformat()


class NginxParser(BaseParser):
    source_name = "nginx"

    def can_parse(self, line: str) -> bool:
        return bool(_NGINX.match(line))

    def parse(self, line: str) -> dict | None:
        m = _NGINX.match(line)
        if not m:
            return None

        ip, user, ts, method, path, status, size, referer, ua = m.groups()
        status_int = int(status)

        severity = "INFO"
        if status_int >= 500:
            severity = "ERROR"
        elif status_int in (401, 403, 404):
            severity = "WARNING"

        event = self._base_event()
        event.update({
            "timestamp": _parse_ts(ts),
            "event_type": "http_request",
            "severity": severity,
            "source_ip": ip,
            "username": user if user != "-" else None,
            "message": f"{method} {path} -> {status}",
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
