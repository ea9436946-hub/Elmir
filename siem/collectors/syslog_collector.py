import logging
import socketserver
from threading import Thread, Event
from typing import Callable

logger = logging.getLogger(__name__)


class _UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0].decode("utf-8", errors="replace").strip()
        if data:
            self.server.callback(data, f"syslog_udp:{self.client_address[0]}")


class _TCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        for line in self.rfile:
            data = line.decode("utf-8", errors="replace").strip()
            if data:
                self.server.callback(data, f"syslog_tcp:{self.client_address[0]}")


class SyslogCollector:
    def __init__(self, host: str, udp_port: int, tcp_port: int, callback: Callable[[str, str], None]):
        self.host = host
        self.udp_port = udp_port
        self.tcp_port = tcp_port
        self.callback = callback
        self._servers: list = []
        self._threads: list[Thread] = []

    def start(self):
        try:
            udp_server = socketserver.UDPServer((self.host, self.udp_port), _UDPHandler)
            udp_server.callback = self.callback
            self._servers.append(udp_server)
            t = Thread(target=udp_server.serve_forever, daemon=True, name="syslog-udp")
            t.start()
            self._threads.append(t)
            logger.info("Syslog UDP listener on %s:%d", self.host, self.udp_port)
        except Exception as e:
            logger.warning("Could not start syslog UDP listener: %s", e)

        try:
            tcp_server = socketserver.TCPServer((self.host, self.tcp_port), _TCPHandler)
            tcp_server.callback = self.callback
            self._servers.append(tcp_server)
            t = Thread(target=tcp_server.serve_forever, daemon=True, name="syslog-tcp")
            t.start()
            self._threads.append(t)
            logger.info("Syslog TCP listener on %s:%d", self.host, self.tcp_port)
        except Exception as e:
            logger.warning("Could not start syslog TCP listener: %s", e)

    def stop(self):
        for s in self._servers:
            s.shutdown()
