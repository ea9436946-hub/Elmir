from datetime import datetime
from .auth_parser import AuthParser
from .apache_parser import ApacheParser
from .nginx_parser import NginxParser
from .syslog_parser import SyslogParser

ALL_PARSERS = [AuthParser(), ApacheParser(), NginxParser(), SyslogParser()]


def parse_line(line: str) -> dict | None:
    line = line.strip()
    if not line:
        return None
    for parser in ALL_PARSERS:
        if parser.can_parse(line):
            result = parser.parse(line)
            if result:
                return result
    # Fallback: store every non-empty line as generic syslog event
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "source": "syslog",
        "event_type": "syslog",
        "severity": "INFO",
        "source_ip": None,
        "username": None,
        "message": line[:500],
        "raw": line[:500],
        "extra": {},
    }
