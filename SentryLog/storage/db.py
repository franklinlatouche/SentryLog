"""SQLite database layer with WAL mode for concurrent access."""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

from sentrylog.storage.models import Alert, NormalizedEvent

log = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source TEXT NOT NULL,
    source_ip TEXT,
    dest_ip TEXT,
    user TEXT,
    action TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'info',
    raw_line TEXT NOT NULL DEFAULT '',
    parsed_fields TEXT DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_action ON events(action);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    event_ids TEXT DEFAULT '[]',
    mitre_tags TEXT DEFAULT '[]',
    source_ip TEXT,
    user TEXT,
    acknowledged INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_acknowledged ON alerts(acknowledged);
"""


class Database:
    def __init__(self, db_path: Path | str = "sentrylog.db"):
        self.db_path = str(db_path)
        self._conn: sqlite3.Connection | None = None

    def connect(self) -> None:
        try:
            self._conn = sqlite3.connect(self.db_path)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.executescript(SCHEMA)
            log.info("Connected to database: %s", self.db_path)
        except sqlite3.Error as e:
            log.error("Failed to connect to database %s: %s", self.db_path, e)
            raise

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None
            log.debug("Database connection closed")

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self.connect()
        return self._conn

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *exc):
        self.close()

    def insert_event(self, event: NormalizedEvent) -> int:
        cur = self.conn.execute(
            """INSERT INTO events (timestamp, source, source_ip, dest_ip, user, action,
               severity, raw_line, parsed_fields)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event.timestamp.isoformat(),
                event.source,
                event.source_ip,
                event.dest_ip,
                event.user,
                event.action,
                event.severity.value,
                event.raw_line,
                json.dumps(event.parsed_fields),
            ),
        )
        self.conn.commit()
        event.id = cur.lastrowid
        return cur.lastrowid

    def insert_events(self, events: list[NormalizedEvent]) -> int:
        rows = [
            (
                e.timestamp.isoformat(),
                e.source,
                e.source_ip,
                e.dest_ip,
                e.user,
                e.action,
                e.severity.value,
                e.raw_line,
                json.dumps(e.parsed_fields),
            )
            for e in events
        ]
        try:
            cur = self.conn.executemany(
                """INSERT INTO events (timestamp, source, source_ip, dest_ip, user, action,
                   severity, raw_line, parsed_fields)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                rows,
            )
            self.conn.commit()
            log.info("Inserted %d events into database", cur.rowcount)
            return cur.rowcount
        except sqlite3.Error as e:
            log.error("Failed to insert %d events: %s", len(events), e)
            raise

    def insert_alert(self, alert: Alert) -> int:
        try:
            cur = self.conn.execute(
                """INSERT INTO alerts (rule_name, severity, description, timestamp,
                   event_ids, mitre_tags, source_ip, user, acknowledged)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    alert.rule_name,
                    alert.severity.value,
                    alert.description,
                    alert.timestamp.isoformat(),
                    json.dumps(alert.event_ids),
                    json.dumps(alert.mitre_tags),
                    alert.source_ip,
                    alert.user,
                    int(alert.acknowledged),
                ),
            )
            self.conn.commit()
            alert.id = cur.lastrowid
            log.debug("Stored alert: rule=%s severity=%s ip=%s", alert.rule_name, alert.severity.value, alert.source_ip)
            return cur.lastrowid
        except sqlite3.Error as e:
            log.error("Failed to insert alert '%s': %s", alert.rule_name, e)
            raise

    def query_events(
        self,
        source_ip: str | None = None,
        severity: str | None = None,
        action: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 100,
    ) -> list[NormalizedEvent]:
        clauses: list[str] = []
        params: list[Any] = []
        if source_ip:
            clauses.append("source_ip = ?")
            params.append(source_ip)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if action:
            clauses.append("action LIKE ?")
            params.append(f"%{action}%")
        if since:
            clauses.append("timestamp >= ?")
            params.append(since.isoformat())
        if until:
            clauses.append("timestamp <= ?")
            params.append(until.isoformat())
        where = " AND ".join(clauses) if clauses else "1=1"
        rows = self.conn.execute(
            f"SELECT * FROM events WHERE {where} ORDER BY timestamp DESC LIMIT ?",
            params + [limit],
        ).fetchall()
        return [NormalizedEvent.from_row(dict(r)) for r in rows]

    def query_alerts(
        self,
        severity: str | None = None,
        acknowledged: bool | None = None,
        since: datetime | None = None,
        limit: int = 100,
    ) -> list[Alert]:
        clauses: list[str] = []
        params: list[Any] = []
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if acknowledged is not None:
            clauses.append("acknowledged = ?")
            params.append(int(acknowledged))
        if since:
            clauses.append("timestamp >= ?")
            params.append(since.isoformat())
        where = " AND ".join(clauses) if clauses else "1=1"
        rows = self.conn.execute(
            f"SELECT * FROM alerts WHERE {where} ORDER BY timestamp DESC LIMIT ?",
            params + [limit],
        ).fetchall()
        return [Alert.from_row(dict(r)) for r in rows]

    def acknowledge_alert(self, alert_id: int) -> bool:
        cur = self.conn.execute(
            "UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,)
        )
        self.conn.commit()
        return cur.rowcount > 0

    def get_event_count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def get_alert_count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

    def get_all_events(self) -> list[NormalizedEvent]:
        rows = self.conn.execute(
            "SELECT * FROM events ORDER BY timestamp ASC"
        ).fetchall()
        return [NormalizedEvent.from_row(dict(r)) for r in rows]
