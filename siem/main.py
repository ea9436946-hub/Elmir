"""Elmir SIEM — main entry point."""
import logging
import queue
import signal
import sys
import time
from pathlib import Path

import colorlog

from .config import load_config
from .storage import EventStore
from .parsers import parse_line
from .collectors import FileLogCollector, SyslogCollector
from .correlations import RuleEngine
from .alerts import AlertManager
from .dashboard.web_dashboard import WebDashboard


def _setup_logging(level: str):
    handler = colorlog.StreamHandler()
    handler.setFormatter(colorlog.ColoredFormatter(
        "%(log_color)s%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        log_colors={
            "DEBUG": "cyan", "INFO": "green", "WARNING": "yellow",
            "ERROR": "red", "CRITICAL": "bold_red",
        },
    ))
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.addHandler(handler)
    # Silence noisy Flask/werkzeug output
    logging.getLogger("werkzeug").setLevel(logging.WARNING)


def main():
    config = load_config()
    _setup_logging(config["siem"]["log_level"])
    logger = logging.getLogger("siem.main")

    logger.info("Starting Elmir SIEM v%s", config["siem"]["version"])

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

    # Event processing queue
    event_queue: queue.Queue = queue.Queue(maxsize=10000)

    def on_line(line: str, source: str):
        event = parse_line(line)
        if event:
            event["source"] = event.get("source") or source
            try:
                event_queue.put_nowait(event)
            except queue.Full:
                logger.warning("Event queue full, dropping event")

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

    # Dashboard
    dash_cfg = config.get("dashboard", {})
    if dash_cfg.get("enabled", True):
        dashboard = WebDashboard(dash_cfg, store)
        dashboard.start()

    # Graceful shutdown
    def _shutdown(sig, frame):
        logger.info("Shutting down…")
        for c in collectors:
            if hasattr(c, "stop"):
                c.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    logger.info("SIEM running. Press Ctrl+C to stop.")

    # Main processing loop
    while True:
        try:
            event = event_queue.get(timeout=1.0)
        except queue.Empty:
            continue

        event_id = store.store_event(event)
        event["id"] = event_id
        rule_engine.process(event)


if __name__ == "__main__":
    main()
