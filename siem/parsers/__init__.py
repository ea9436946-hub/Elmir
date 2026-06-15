from .auth_parser import AuthParser
from .apache_parser import ApacheParser
from .nginx_parser import NginxParser
from .syslog_parser import SyslogParser

ALL_PARSERS = [AuthParser(), ApacheParser(), NginxParser(), SyslogParser()]


def parse_line(line: str) -> dict | None:
    for parser in ALL_PARSERS:
        if parser.can_parse(line):
            return parser.parse(line)
    return None
