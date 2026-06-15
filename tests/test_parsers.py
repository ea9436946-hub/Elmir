import sys
sys.path.insert(0, __import__("os").path.join(__import__("os").path.dirname(__file__), ".."))

from siem.parsers.auth_parser import AuthParser
from siem.parsers.apache_parser import ApacheParser
from siem.parsers.nginx_parser import NginxParser


def test_auth_failed_login():
    p = AuthParser()
    line = "Jun 15 10:23:45 myhost sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2"
    assert p.can_parse(line)
    event = p.parse(line)
    assert event is not None
    assert event["event_type"] == "failed_login"
    assert event["source_ip"] == "192.168.1.100"
    assert event["username"] == "root"
    assert event["severity"] == "WARNING"


def test_auth_successful_login():
    p = AuthParser()
    line = "Jun 15 10:24:00 myhost sshd[1235]: Accepted publickey for admin from 10.0.0.5 port 44321 ssh2"
    event = p.parse(line)
    assert event is not None
    assert event["event_type"] == "successful_login"
    assert event["source_ip"] == "10.0.0.5"


def test_auth_invalid_user():
    p = AuthParser()
    line = "Jun 15 10:25:00 myhost sshd[1236]: Invalid user hacker from 1.2.3.4 port 22"
    event = p.parse(line)
    assert event is not None
    assert event["event_type"] == "invalid_user"
    assert event["source_ip"] == "1.2.3.4"


def test_apache_access_log():
    p = ApacheParser()
    line = '192.168.1.5 - frank [15/Jun/2024:10:23:45 +0000] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"'
    assert p.can_parse(line)
    event = p.parse(line)
    assert event is not None
    assert event["event_type"] == "http_request"
    assert event["source_ip"] == "192.168.1.5"
    assert event["extra"]["status_code"] == 200


def test_apache_404():
    p = ApacheParser()
    line = '10.0.0.1 - - [15/Jun/2024:10:24:00 +0000] "GET /notfound HTTP/1.1" 404 512'
    event = p.parse(line)
    assert event is not None
    assert event["severity"] == "WARNING"
    assert event["extra"]["status_code"] == 404


def test_nginx_access_log():
    p = NginxParser()
    line = '172.16.0.1 - - [15/Jun/2024:12:00:00 +0000] "POST /api/login HTTP/1.1" 401 123 "-" "python-requests/2.28"'
    assert p.can_parse(line)
    event = p.parse(line)
    assert event is not None
    assert event["severity"] == "WARNING"
    assert event["extra"]["method"] == "POST"


if __name__ == "__main__":
    test_auth_failed_login()
    test_auth_successful_login()
    test_auth_invalid_user()
    test_apache_access_log()
    test_apache_404()
    test_nginx_access_log()
    print("All parser tests passed.")
