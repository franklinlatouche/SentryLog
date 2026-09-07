"""Tests for database layer."""

from datetime import datetime

from sentrylog.storage.db import Database
from sentrylog.storage.models import NormalizedEvent, Alert, Severity


class TestDatabase:
    def test_insert_and_query_event(self, tmp_path):
        db = Database(tmp_path / "test.db")
        db.connect()
        event = NormalizedEvent(
            timestamp=datetime(2025, 3, 10, 6, 42, 12),
            source="authlog",
            source_ip="192.168.1.100",
            user="root",
            action="auth_failure",
            severity=Severity.MEDIUM,
            raw_line="test line",
        )
        eid = db.insert_event(event)
        assert eid == 1

        events = db.query_events(source_ip="192.168.1.100")
        assert len(events) == 1
        assert events[0].user == "root"
        assert events[0].action == "auth_failure"
        db.close()

    def test_insert_events_batch(self, tmp_path):
        db = Database(tmp_path / "test.db")
        db.connect()
        events = [
            NormalizedEvent(
                timestamp=datetime(2025, 3, 10, 6, 42, i),
                source="authlog",
                source_ip="10.0.0.1",
                action="auth_failure",
                severity=Severity.MEDIUM,
                raw_line=f"line {i}",
            )
            for i in range(10)
        ]
        count = db.insert_events(events)
        assert count == 10
        assert db.get_event_count() == 10
        db.close()

    def test_query_events_filters(self, tmp_path):
        db = Database(tmp_path / "test.db")
        db.connect()
        db.insert_event(NormalizedEvent(
            timestamp=datetime(2025, 3, 10, 6, 0, 0),
            source="authlog", source_ip="10.0.0.1",
            action="auth_failure", severity=Severity.MEDIUM, raw_line="",
        ))
        db.insert_event(NormalizedEvent(
            timestamp=datetime(2025, 3, 10, 7, 0, 0),
            source="apache", source_ip="10.0.0.2",
            action="http_request", severity=Severity.INFO, raw_line="",
        ))
        assert len(db.query_events(severity="medium")) == 1
        assert len(db.query_events(action="auth")) == 1
        assert len(db.query_events(since=datetime(2025, 3, 10, 6, 30, 0))) == 1
        db.close()

    def test_insert_and_query_alert(self, tmp_path):
        db = Database(tmp_path / "test.db")
        db.connect()
        alert = Alert(
            rule_name="ssh_brute_force",
            severity=Severity.HIGH,
            description="5 failed SSH logins from 10.0.0.1",
            timestamp=datetime(2025, 3, 10, 6, 42, 12),
            event_ids=[1, 2, 3, 4, 5],
            mitre_tags=["T1110"],
            source_ip="10.0.0.1",
        )
        aid = db.insert_alert(alert)
        assert aid == 1

        alerts = db.query_alerts(severity="high")
        assert len(alerts) == 1
        assert alerts[0].rule_name == "ssh_brute_force"
        assert alerts[0].mitre_tags == ["T1110"]
        db.close()

    def test_acknowledge_alert(self, tmp_path):
        db = Database(tmp_path / "test.db")
        db.connect()
        db.insert_alert(Alert(
            rule_name="test", severity=Severity.LOW,
            description="test alert", timestamp=datetime(2025, 1, 1),
        ))
        assert db.acknowledge_alert(1) is True
        alerts = db.query_alerts(acknowledged=False)
        assert len(alerts) == 0
        alerts = db.query_alerts(acknowledged=True)
        assert len(alerts) == 1
        db.close()

    def test_context_manager(self, tmp_path):
        with Database(tmp_path / "test.db") as db:
            db.insert_event(NormalizedEvent(
                timestamp=datetime(2025, 1, 1),
                source="test", action="test", raw_line="test",
            ))
            assert db.get_event_count() == 1
