"""Tests for the correlation detector."""

from datetime import datetime, timedelta

from sentrylog.engine.detector import CorrelationDetector, DetectionEngine
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
    return NormalizedEvent(
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


def _brute_then_success_rule(**overrides):
    defaults = dict(
        name="brute_then_success",
        type="correlation",
        severity=Severity.CRITICAL,
        description="Brute force then success",
        conditions=[],
        group_by="source_ip",
        correlation_window=300,
        sequence=[
            {"conditions": [{"field": "action", "operator": "equals", "value": "auth_failure"}]},
            {"conditions": [{"field": "action", "operator": "equals", "value": "auth_success"}]},
        ],
    )
    defaults.update(overrides)
    return Rule(**defaults)


class TestCorrelationDetector:
    def test_basic_sequence_fires(self):
        """Step 1 (failure) then step 2 (success) from same IP triggers alert."""
        rule = _brute_then_success_rule()
        detector = CorrelationDetector([rule])
        base = datetime(2025, 3, 10, 6, 0, 0)

        alerts = []
        # Step 1: auth failure
        e1 = make_event(action="auth_failure", timestamp=base, event_id=1)
        alerts.extend(detector.check(e1))
        assert len(alerts) == 0

        # Step 2: auth success from same IP
        e2 = make_event(action="auth_success", timestamp=base + timedelta(seconds=60), event_id=2)
        alerts.extend(detector.check(e2))
        assert len(alerts) == 1
        assert alerts[0].rule_name == "brute_then_success"
        assert alerts[0].severity == Severity.CRITICAL
        assert 1 in alerts[0].event_ids
        assert 2 in alerts[0].event_ids

    def test_no_fire_without_step1(self):
        """Success without prior failure doesn't trigger."""
        rule = _brute_then_success_rule()
        detector = CorrelationDetector([rule])
        base = datetime(2025, 3, 10, 6, 0, 0)

        e = make_event(action="auth_success", timestamp=base, event_id=1)
        alerts = detector.check(e)
        assert len(alerts) == 0

    def test_no_fire_wrong_order(self):
        """Success before failure doesn't trigger."""
        rule = _brute_then_success_rule()
        detector = CorrelationDetector([rule])
        base = datetime(2025, 3, 10, 6, 0, 0)

        alerts = []
        e1 = make_event(action="auth_success", timestamp=base, event_id=1)
        alerts.extend(detector.check(e1))
        e2 = make_event(action="auth_failure", timestamp=base + timedelta(seconds=60), event_id=2)
        alerts.extend(detector.check(e2))
        assert len(alerts) == 0

    def test_window_expiry(self):
        """Sequence outside the window doesn't fire."""
        rule = _brute_then_success_rule(correlation_window=60)
        detector = CorrelationDetector([rule])
        base = datetime(2025, 3, 10, 6, 0, 0)

        alerts = []
        e1 = make_event(action="auth_failure", timestamp=base, event_id=1)
        alerts.extend(detector.check(e1))
        # 120s later — outside 60s window
        e2 = make_event(action="auth_success", timestamp=base + timedelta(seconds=120), event_id=2)
        alerts.extend(detector.check(e2))
        assert len(alerts) == 0

    def test_separate_groups(self):
        """Events from different IPs don't correlate when group_by=source_ip."""
        rule = _brute_then_success_rule()
        detector = CorrelationDetector([rule])
        base = datetime(2025, 3, 10, 6, 0, 0)

        alerts = []
        e1 = make_event(action="auth_failure", source_ip="10.0.0.1", timestamp=base, event_id=1)
        alerts.extend(detector.check(e1))
        # Success from different IP
        e2 = make_event(action="auth_success", source_ip="10.0.0.2", timestamp=base + timedelta(seconds=30), event_id=2)
        alerts.extend(detector.check(e2))
        assert len(alerts) == 0

    def test_multiple_failures_then_success(self):
        """Multiple failures followed by success fires once."""
        rule = _brute_then_success_rule()
        detector = CorrelationDetector([rule])
        base = datetime(2025, 3, 10, 6, 0, 0)

        alerts = []
        for i in range(5):
            e = make_event(action="auth_failure", timestamp=base + timedelta(seconds=i * 5), event_id=i + 1)
            alerts.extend(detector.check(e))
        assert len(alerts) == 0

        e_success = make_event(action="auth_success", timestamp=base + timedelta(seconds=30), event_id=10)
        alerts.extend(detector.check(e_success))
        # At least one alert (first pending sequence completes)
        assert len(alerts) >= 1

    def test_three_step_sequence(self):
        """Three-step correlation rule works."""
        rule = Rule(
            name="recon_exploit_exfil",
            type="correlation",
            severity=Severity.CRITICAL,
            description="Full attack chain",
            conditions=[],
            group_by="source_ip",
            correlation_window=600,
            sequence=[
                {"conditions": [{"field": "action", "operator": "equals", "value": "scanner_probe"}]},
                {"conditions": [{"field": "action", "operator": "equals", "value": "sqli_attempt"}]},
                {"conditions": [{"field": "action", "operator": "equals", "value": "path_traversal"}]},
            ],
        )
        detector = CorrelationDetector([rule])
        base = datetime(2025, 3, 10, 6, 0, 0)

        alerts = []
        e1 = make_event(action="scanner_probe", timestamp=base, event_id=1)
        alerts.extend(detector.check(e1))
        e2 = make_event(action="sqli_attempt", timestamp=base + timedelta(seconds=60), event_id=2)
        alerts.extend(detector.check(e2))
        assert len(alerts) == 0
        e3 = make_event(action="path_traversal", timestamp=base + timedelta(seconds=120), event_id=3)
        alerts.extend(detector.check(e3))
        assert len(alerts) == 1
        assert alerts[0].rule_name == "recon_exploit_exfil"
        assert len(alerts[0].event_ids) == 3

    def test_no_group_by(self):
        """Correlation without group_by matches across all IPs."""
        rule = Rule(
            name="ungrouped",
            type="correlation",
            severity=Severity.HIGH,
            description="Ungrouped correlation",
            conditions=[],
            correlation_window=300,
            sequence=[
                {"conditions": [{"field": "action", "operator": "equals", "value": "auth_failure"}]},
                {"conditions": [{"field": "action", "operator": "equals", "value": "auth_success"}]},
            ],
        )
        detector = CorrelationDetector([rule])
        base = datetime(2025, 3, 10, 6, 0, 0)

        alerts = []
        e1 = make_event(action="auth_failure", source_ip="10.0.0.1", timestamp=base, event_id=1)
        alerts.extend(detector.check(e1))
        e2 = make_event(action="auth_success", source_ip="10.0.0.2", timestamp=base + timedelta(seconds=30), event_id=2)
        alerts.extend(detector.check(e2))
        assert len(alerts) == 1

    def test_reset_clears_state(self):
        """Reset clears all pending sequences."""
        rule = _brute_then_success_rule()
        detector = CorrelationDetector([rule])
        base = datetime(2025, 3, 10, 6, 0, 0)

        e1 = make_event(action="auth_failure", timestamp=base, event_id=1)
        detector.check(e1)
        detector.reset()

        # Success after reset should not fire
        e2 = make_event(action="auth_success", timestamp=base + timedelta(seconds=30), event_id=2)
        alerts = detector.check(e2)
        assert len(alerts) == 0

    def test_dedup_within_window(self):
        """Same correlation doesn't fire multiple times in the same time bucket."""
        rule = _brute_then_success_rule()
        detector = CorrelationDetector([rule])
        base = datetime(2025, 3, 10, 6, 0, 0)

        alerts = []
        # First sequence
        e1 = make_event(action="auth_failure", timestamp=base, event_id=1)
        alerts.extend(detector.check(e1))
        e2 = make_event(action="auth_success", timestamp=base + timedelta(seconds=10), event_id=2)
        alerts.extend(detector.check(e2))
        assert len(alerts) == 1

        # Second sequence, same time bucket
        e3 = make_event(action="auth_failure", timestamp=base + timedelta(seconds=20), event_id=3)
        alerts.extend(detector.check(e3))
        e4 = make_event(action="auth_success", timestamp=base + timedelta(seconds=30), event_id=4)
        alerts.extend(detector.check(e4))
        # Deduped — still just 1
        assert len(alerts) == 1

    def test_condition_operators_in_sequence(self):
        """Sequence steps can use different operators (in, regex, etc.)."""
        rule = Rule(
            name="scan_then_exploit",
            type="correlation",
            severity=Severity.CRITICAL,
            description="Scan then exploit",
            conditions=[],
            group_by="source_ip",
            correlation_window=600,
            sequence=[
                {"conditions": [{"field": "action", "operator": "in", "value": ["scanner_probe", "http_not_found"]}]},
                {"conditions": [{"field": "action", "operator": "in", "value": ["sqli_attempt", "xss_attempt"]}]},
            ],
        )
        detector = CorrelationDetector([rule])
        base = datetime(2025, 3, 10, 6, 0, 0)

        alerts = []
        e1 = make_event(action="http_not_found", timestamp=base, event_id=1)
        alerts.extend(detector.check(e1))
        e2 = make_event(action="xss_attempt", timestamp=base + timedelta(seconds=60), event_id=2)
        alerts.extend(detector.check(e2))
        assert len(alerts) == 1


class TestEngineWithCorrelation:
    def test_engine_includes_correlation(self):
        """DetectionEngine runs correlation rules alongside single/threshold."""
        corr_rule = _brute_then_success_rule()
        single_rule = Rule(
            name="sqli", type="single", severity=Severity.HIGH,
            description="SQLi", conditions=[
                RuleCondition("action", "equals", "sqli_attempt"),
            ],
        )
        engine = DetectionEngine([corr_rule, single_rule])
        base = datetime(2025, 3, 10, 6, 0, 0)

        events = [
            make_event(action="auth_failure", timestamp=base, event_id=1),
            make_event(action="auth_success", timestamp=base + timedelta(seconds=60), event_id=2),
            make_event(action="sqli_attempt", source_ip="10.0.0.99", timestamp=base + timedelta(seconds=120), event_id=3),
        ]
        alerts = engine.check_batch(events)
        rule_names = [a.rule_name for a in alerts]
        assert "brute_then_success" in rule_names
        assert "sqli" in rule_names
