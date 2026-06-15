import sqlite3
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from threading import Lock

logger = logging.getLogger(__name__)


class EventStore:
    def __init__(self, db_path: str, max_events: int = 100000, retention_days: int = 90):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.max_events = max_events
        self.retention_days = retention_days
        self._lock = Lock()
        self._init_db()

    def _init_db(self):
        with self._get_conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    source TEXT,
                    event_type TEXT,
                    severity TEXT DEFAULT 'INFO',
                    source_ip TEXT,
                    username TEXT,
                    message TEXT,
                    raw TEXT,
                    extra TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_source_ip ON events(source_ip);
                CREATE INDEX IF NOT EXISTS idx_event_type ON events(event_type);

                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    rule_name TEXT,
                    severity TEXT,
                    description TEXT,
                    source_ip TEXT,
                    username TEXT,
                    event_ids TEXT,
                    acknowledged INTEGER DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_alert_timestamp ON alerts(timestamp);
            """)

    def _get_conn(self):
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def store_event(self, event: dict) -> int:
        with self._lock:
            with self._get_conn() as conn:
                cur = conn.execute(
                    """INSERT INTO events
                       (timestamp, source, event_type, severity, source_ip, username, message, raw, extra)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        event.get("timestamp", datetime.utcnow().isoformat()),
                        event.get("source"),
                        event.get("event_type"),
                        event.get("severity", "INFO"),
                        event.get("source_ip"),
                        event.get("username"),
                        event.get("message"),
                        event.get("raw"),
                        json.dumps(event.get("extra", {})),
                    ),
                )
                return cur.lastrowid

    def store_alert(self, alert: dict) -> int:
        with self._lock:
            with self._get_conn() as conn:
                cur = conn.execute(
                    """INSERT INTO alerts
                       (timestamp, rule_name, severity, description, source_ip, username, event_ids)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        alert.get("timestamp", datetime.utcnow().isoformat()),
                        alert.get("rule_name"),
                        alert.get("severity"),
                        alert.get("description"),
                        alert.get("source_ip"),
                        alert.get("username"),
                        json.dumps(alert.get("event_ids", [])),
                    ),
                )
                return cur.lastrowid

    def get_recent_events(self, limit: int = 100, severity: str = None) -> list:
        with self._get_conn() as conn:
            if severity:
                rows = conn.execute(
                    "SELECT * FROM events WHERE severity = ? ORDER BY timestamp DESC LIMIT ?",
                    (severity, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)
                ).fetchall()
        return [dict(r) for r in rows]

    def get_recent_alerts(self, limit: int = 50) -> list:
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_events_since(self, since: datetime, source_ip: str = None) -> list:
        with self._get_conn() as conn:
            if source_ip:
                rows = conn.execute(
                    "SELECT * FROM events WHERE timestamp >= ? AND source_ip = ? ORDER BY timestamp",
                    (since.isoformat(), source_ip),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM events WHERE timestamp >= ? ORDER BY timestamp",
                    (since.isoformat(),),
                ).fetchall()
        return [dict(r) for r in rows]

    def get_stats(self) -> dict:
        with self._get_conn() as conn:
            total_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            open_alerts = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE acknowledged = 0"
            ).fetchone()[0]
            severity_counts = conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM events GROUP BY severity"
            ).fetchall()
        return {
            "total_events": total_events,
            "total_alerts": total_alerts,
            "open_alerts": open_alerts,
            "severity_counts": {r["severity"]: r["cnt"] for r in severity_counts},
        }

    def purge_old_events(self):
        cutoff = (datetime.utcnow() - timedelta(days=self.retention_days)).isoformat()
        with self._lock:
            with self._get_conn() as conn:
                deleted = conn.execute(
                    "DELETE FROM events WHERE timestamp < ?", (cutoff,)
                ).rowcount
                logger.info("Purged %d old events", deleted)

    def acknowledge_alert(self, alert_id: int):
        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    "UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,)
                )
