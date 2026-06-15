"""Elmir SIEM v2 — main entry point."""
import logging
import os
import queue
import signal
import sys
import time
from threading import Thread
from pathlib import Path

import colorlog

from .config import load_config
from .storage import EventStore
from .parsers import parse_line
from .collectors import FileLogCollector, SyslogCollector
from .collectors.suricata_collector import SuricataCollector
from .correlations import RuleEngine
from .alerts import AlertManager
from .dashboard.web_dashboard import WebDashboard

BANNER = r"""
  ███████╗██╗     ███╗   ███╗██╗██████╗     ███████╗██╗███████╗███╗   ███╗
  ██╔════╝██║     ████╗ ████║██║██╔══██╗    ██╔════╝██║██╔════╝████╗ ████║
  █████╗  ██║     ██╔████╔██║██║██████╔╝    ███████╗██║█████╗  ██╔████╔██║
  ██╔══╝  ██║     ██║╚██╔╝██║██║██╔══██╗    ╚════██║██║██╔══╝  ██║╚██╔╝██║
  ███████╗███████╗██║ ╚═╝ ██║██║██║  ██║    ███████║██║███████╗██║ ╚═╝ ██║
  ╚══════╝╚══════╝╚═╝     ╚═╝╚═╝╚═╝  ╚═╝    ╚══════╝╚═╝╚══════╝╚═╝     ╚═╝
  v2.0  Security Information & Event Management
"""


def _setup_logging(level: str):
    handler = colorlog.StreamHandler()
    handler.setFormatter(colorlog.ColoredFormatter(
        "%(log_color)s%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        log_colors={
            "DEBUG": "cyan", "INFO": "green", "WARNING": "yellow",
            "ERROR": "red", "CRITICAL": "bold_red",
        },
    ))
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.addHandler(handler)
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    logging.getLogger("geventwebsocket").setLevel(logging.WARNING)
    logging.getLogger("engineio").setLevel(logging.WARNING)
    logging.getLogger("socketio").setLevel(logging.WARNING)


def _start_prometheus(port: int):
    try:
        from prometheus_client import start_http_server
        start_http_server(port)
        logging.getLogger("siem.main").info("Prometheus metrics: http://0.0.0.0:%d", port)
    except Exception as e:
        logging.getLogger("siem.main").warning("Prometheus not available: %s", e)


def main():
    print(BANNER)
    config = load_config()
    _setup_logging(config["siem"]["log_level"])
    logger = logging.getLogger("siem.main")
    logger.info("Starting Elmir SIEM %s", config["siem"]["version"])

    # Storage
    store = EventStore(
        db_path=config["storage"]["db_path"],
        max_events=config["storage"]["max_events"],
        retention_days=config["storage"]["retention_days"],
    )

    # Alert manager
    alert_mgr = AlertManager(config)

    # Correlation engine
    rule_engine = RuleEngine(config, store, alert_mgr)

    # Dashboard
    dash_cfg = config.get("dashboard", {})
    dashboard = None
    if dash_cfg.get("enabled", True):
        dashboard = WebDashboard(dash_cfg, store)
        dashboard.start()

    # Wire alert push to dashboard WebSocket
    if dashboard:
        rule_engine.on_alert(dashboard.push_alert)

    # Prometheus metrics server
    metrics_cfg = config.get("metrics", {})
    if metrics_cfg.get("enabled", True):
        _start_prometheus(metrics_cfg.get("port", 9091))

    # Event processing queue
    event_queue: queue.Queue = queue.Queue(maxsize=10000)

    def on_event(event: dict, source: str = ""):
        if source:
            event["source"] = event.get("source") or source
        try:
            event_queue.put_nowait(event)
        except queue.Full:
            logger.warning("Event queue full, dropping event from %s", source)

    def on_line(line: str, source: str):
        event = parse_line(line)
        if event:
            on_event(event, source)

    # Collectors
    collectors = []

    file_cfg = config["collectors"]["file"]
    if file_cfg.get("enabled"):
        fc = FileLogCollector(
            paths=file_cfg.get("paths", []),
            callback=on_line,
            poll_interval=file_cfg.get("poll_interval", 5),
        )
        fc.start()
        collectors.append(fc)
        logger.info("File collector watching %d paths", len(file_cfg.get("paths", [])))

    syslog_cfg = config["collectors"]["syslog"]
    if syslog_cfg.get("enabled"):
        sc = SyslogCollector(
            host=syslog_cfg.get("bind_host", "0.0.0.0"),
            udp_port=syslog_cfg.get("udp_port", 5514),
            tcp_port=syslog_cfg.get("tcp_port", 5514),
            callback=on_line,
        )
        sc.start()
        collectors.append(sc)

    suricata_cfg = config.get("collectors", {}).get("suricata", {})
    if suricata_cfg.get("enabled"):
        eve_path = suricata_cfg.get("eve_path", "/var/log/suricata/eve.json")
        sur = SuricataCollector(eve_path=eve_path, callback=on_event)
        sur.start()
        collectors.append(sur)

    wazuh_cfg = config.get("collectors", {}).get("wazuh", {})
    if wazuh_cfg.get("enabled"):
        try:
            from .collectors.wazuh_collector import WazuhCollector
            wc = WazuhCollector(
                url=wazuh_cfg.get("url", "https://127.0.0.1:55000"),
                username=os.environ.get("WAZUH_USER", "admin"),
                password=os.environ.get("WAZUH_PASS", "SecretPassword"),
                poll_interval=wazuh_cfg.get("poll_interval", 30),
                callback=on_event,
            )
            wc.start()
            collectors.append(wc)
        except Exception as e:
            logger.warning("Wazuh collector failed to start: %s", e)

    # Graceful shutdown
    def _shutdown(sig, frame):
        logger.info("Shutting down Elmir SIEM…")
        for c in collectors:
            if hasattr(c, "stop"):
                c.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    logger.info("Elmir SIEM running — Dashboard: http://0.0.0.0:%d", dash_cfg.get("port", 8080))

    # Main processing loop
    while True:
        try:
            event = event_queue.get(timeout=1.0)
        except queue.Empty:
            continue

        event_id = store.store_event(event)
        event["id"] = event_id
        if dashboard:
            dashboard.record_event(event)
        rule_engine.process(event)


if __name__ == "__main__":
    main()
