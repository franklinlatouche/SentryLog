"""Tests for detection engine."""

from datetime import datetime, timedelta

from sentrylog.engine.detector import (
    DetectionEngine,
    SingleDetector,
    ThresholdDetector,
    _get_field_value,
    _match_condition,
)
from sentrylog.engine.rules import Rule, RuleCondition
from sentrylog.storage.models import NormalizedEvent, Severity


def make_event(
    action="auth_failure",
    source_ip="10.0.0.1",
    user="root",
    severity=Severity.MEDIUM,
    timestamp=None,
    event_id=None,
    parsed_fields=None,
):
    e = NormalizedEvent(
        timestamp=timestamp or datetime(2025, 3, 10, 6, 42, 0),
        source="authlog",
        source_ip=source_ip,
        user=user,
        action=action,
        severity=severity,
        raw_line="test",
        parsed_fields=parsed_fields or {},
        id=event_id,
    )
    return e


class TestFieldAccess:
    def test_direct_field(self):
        e = make_event(action="auth_failure")
        assert _get_field_value(e, "action") == "auth_failure"

    def test_parsed_field(self):
        e = make_event(parsed_fields={"method": "GET"})
        assert _get_field_value(e, "parsed_fields.method") == "GET"

    def test_missing_parsed_field(self):
        e = make_event()
        assert _get_field_value(e, "parsed_fields.nonexistent") is None


class TestMatchCondition:
    def test_equals(self):
        e = make_event(action="auth_failure")
        c = RuleCondition("action", "equals", "auth_failure")
        assert _match_condition(e, c) is True

    def test_not_equals(self):
        e = make_event(action="auth_failure")
        c = RuleCondition("action", "not_equals", "auth_success")
        assert _match_condition(e, c) is True

    def test_contains(self):
        e = make_event(action="auth_failure")
        c = RuleCondition("action", "contains", "auth")
        assert _match_condition(e, c) is True

    def test_regex(self):
        e = make_event(parsed_fields={"command": "/bin/bash"})
        c = RuleCondition("parsed_fields.command", "regex", r"/bin/(ba)?sh$")
        assert _match_condition(e, c) is True

    def test_in_list(self):
        e = make_event(action="auth_failure")
        c = RuleCondition("action", "in", ["auth_failure", "invalid_user"])
        assert _match_condition(e, c) is True

    def test_gt(self):
        e = make_event(parsed_fields={"status": 500})
        c = RuleCondition("parsed_fields.status", "gt", 400)
        assert _match_condition(e, c) is True

    def test_lt(self):
        e = make_event(parsed_fields={"status": 200})
        c = RuleCondition("parsed_fields.status", "lt", 300)
        assert _match_condition(e, c) is True

    def test_none_value_no_match(self):
        e = make_event()
        c = RuleCondition("parsed_fields.missing", "equals", "x")
        assert _match_condition(e, c) is False


class TestSingleDetector:
    def test_match(self):
        rule = Rule(
            name="test_single", type="single", severity=Severity.HIGH,
            description="Test", conditions=[
                RuleCondition("action", "equals", "sudo"),
                RuleCondition("parsed_fields.command", "regex", r"/bin/(ba)?sh$"),
            ],
        )
        detector = SingleDetector([rule])
        e = make_event(action="sudo", parsed_fields={"command": "/bin/bash", "target_user": "root"}, event_id=1)
        alerts = detector.check(e)
        assert len(alerts) == 1
        assert alerts[0].rule_name == "test_single"

    def test_no_match(self):
        rule = Rule(
            name="test_single", type="single", severity=Severity.HIGH,
            description="Test", conditions=[
                RuleCondition("action", "equals", "sudo"),
            ],
        )
        detector = SingleDetector([rule])
        e = make_event(action="auth_failure")
        assert detector.check(e) == []


class TestThresholdDetector:
    def test_fires_at_threshold(self):
        rule = Rule(
            name="brute_force", type="threshold", severity=Severity.HIGH,
            description="Brute force", conditions=[
                RuleCondition("action", "equals", "auth_failure"),
            ],
            threshold_count=3, threshold_window=60,
            group_by="source_ip",
        )
        detector = ThresholdDetector([rule])
        base = datetime(2025, 3, 10, 6, 0, 0)
        alerts = []
        for i in range(5):
            e = make_event(
                timestamp=base + timedelta(seconds=i * 5),
                event_id=i + 1,
            )
            alerts.extend(detector.check(e))

        assert len(alerts) == 1
        assert alerts[0].rule_name == "brute_force"
        assert len(alerts[0].event_ids) >= 3

    def test_no_fire_below_threshold(self):
        rule = Rule(
            name="brute_force", type="threshold", severity=Severity.HIGH,
            description="Brute force", conditions=[
                RuleCondition("action", "equals", "auth_failure"),
            ],
            threshold_count=5, threshold_window=60,
            group_by="source_ip",
        )
        detector = ThresholdDetector([rule])
        base = datetime(2025, 3, 10, 6, 0, 0)
        alerts = []
        for i in range(3):
            e = make_event(timestamp=base + timedelta(seconds=i * 5), event_id=i + 1)
            alerts.extend(detector.check(e))
        assert len(alerts) == 0

    def test_window_expiry(self):
        rule = Rule(
            name="brute_force", type="threshold", severity=Severity.HIGH,
            description="Brute force", conditions=[
                RuleCondition("action", "equals", "auth_failure"),
            ],
            threshold_count=3, threshold_window=10,
            group_by="source_ip",
        )
        detector = ThresholdDetector([rule])
        base = datetime(2025, 3, 10, 6, 0, 0)
        alerts = []
        # 3 events spread over 30s — window is 10s, so never 3 within window
        for i in range(3):
            e = make_event(timestamp=base + timedelta(seconds=i * 15), event_id=i + 1)
            alerts.extend(detector.check(e))
        assert len(alerts) == 0

    def test_separate_groups(self):
        rule = Rule(
            name="brute_force", type="threshold", severity=Severity.HIGH,
            description="Brute force", conditions=[
                RuleCondition("action", "equals", "auth_failure"),
            ],
            threshold_count=3, threshold_window=60,
            group_by="source_ip",
        )
        detector = ThresholdDetector([rule])
        base = datetime(2025, 3, 10, 6, 0, 0)
        alerts = []
        # 2 from IP A, 2 from IP B — neither hits threshold
        for i in range(2):
            e = make_event(source_ip="10.0.0.1", timestamp=base + timedelta(seconds=i), event_id=i)
            alerts.extend(detector.check(e))
        for i in range(2):
            e = make_event(source_ip="10.0.0.2", timestamp=base + timedelta(seconds=i), event_id=10 + i)
            alerts.extend(detector.check(e))
        assert len(alerts) == 0


class TestDetectionEngine:
    def test_combined(self):
        single_rule = Rule(
            name="sqli", type="single", severity=Severity.HIGH,
            description="SQLi", conditions=[
                RuleCondition("action", "equals", "sqli_attempt"),
            ],
            mitre_tags=["T1190"],
        )
        threshold_rule = Rule(
            name="brute_force", type="threshold", severity=Severity.HIGH,
            description="Brute force", conditions=[
                RuleCondition("action", "equals", "auth_failure"),
            ],
            threshold_count=3, threshold_window=60,
            group_by="source_ip",
        )
        engine = DetectionEngine([single_rule, threshold_rule])

        base = datetime(2025, 3, 10, 6, 0, 0)
        events = [
            make_event(action="auth_failure", timestamp=base + timedelta(seconds=i), event_id=i + 1)
            for i in range(5)
        ] + [
            make_event(action="sqli_attempt", source_ip="10.0.0.99", timestamp=base + timedelta(seconds=10), event_id=100),
        ]

        alerts = engine.check_batch(events)
        rule_names = [a.rule_name for a in alerts]
        assert "brute_force" in rule_names
        assert "sqli" in rule_names
