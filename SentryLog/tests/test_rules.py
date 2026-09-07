"""Tests for rule loading and validation."""

import pytest

from sentrylog.engine.rules import (
    Rule,
    RuleCondition,
    load_rule,
    load_rules_from_file,
    load_rules_from_dir,
    validate_rule,
)
from sentrylog.storage.models import Severity


class TestRuleCondition:
    def test_valid_operator(self):
        c = RuleCondition(field="action", operator="equals", value="auth_failure")
        assert c.operator == "equals"

    def test_invalid_operator(self):
        with pytest.raises(ValueError, match="Invalid operator"):
            RuleCondition(field="action", operator="nope", value="x")


class TestRule:
    def test_valid_single_rule(self):
        rule = Rule(
            name="test",
            type="single",
            severity=Severity.HIGH,
            description="test rule",
            conditions=[RuleCondition("action", "equals", "auth_failure")],
        )
        assert rule.type == "single"

    def test_invalid_type(self):
        with pytest.raises(ValueError, match="Invalid rule type"):
            Rule(name="x", type="bad", severity=Severity.LOW, description="", conditions=[])

    def test_threshold_requires_count(self):
        with pytest.raises(ValueError, match="threshold_count"):
            Rule(
                name="x", type="threshold", severity=Severity.LOW, description="",
                conditions=[], threshold_window=60,
            )

    def test_threshold_requires_window(self):
        with pytest.raises(ValueError, match="threshold_window"):
            Rule(
                name="x", type="threshold", severity=Severity.LOW, description="",
                conditions=[], threshold_count=5,
            )

    def test_correlation_requires_sequence(self):
        with pytest.raises(ValueError, match="sequence"):
            Rule(
                name="x", type="correlation", severity=Severity.HIGH, description="",
                conditions=[], correlation_window=300,
            )

    def test_correlation_requires_window(self):
        with pytest.raises(ValueError, match="correlation_window"):
            Rule(
                name="x", type="correlation", severity=Severity.HIGH, description="",
                conditions=[],
                sequence=[{"conditions": [{"field": "a", "value": "b"}]}, {"conditions": [{"field": "a", "value": "c"}]}],
            )


class TestLoadRule:
    def test_load_single(self):
        data = {
            "name": "test_rule",
            "type": "single",
            "severity": "high",
            "description": "A test rule",
            "conditions": [{"field": "action", "operator": "equals", "value": "auth_failure"}],
            "mitre_tags": ["T1110"],
        }
        rule = load_rule(data)
        assert rule.name == "test_rule"
        assert rule.severity == Severity.HIGH
        assert len(rule.conditions) == 1
        assert rule.mitre_tags == ["T1110"]

    def test_load_threshold(self):
        data = {
            "name": "brute_force",
            "type": "threshold",
            "severity": "high",
            "description": "Brute force",
            "conditions": [{"field": "action", "value": "auth_failure"}],
            "threshold_count": 5,
            "threshold_window": 120,
            "group_by": "source_ip",
        }
        rule = load_rule(data)
        assert rule.threshold_count == 5
        assert rule.group_by == "source_ip"

    def test_load_correlation(self):
        data = {
            "name": "brute_then_success",
            "type": "correlation",
            "severity": "critical",
            "description": "Brute force then login",
            "conditions": [],
            "mitre_tags": ["T1110", "T1078"],
            "group_by": "source_ip",
            "correlation_window": 600,
            "sequence": [
                {"conditions": [{"field": "action", "operator": "equals", "value": "auth_failure"}]},
                {"conditions": [{"field": "action", "operator": "equals", "value": "auth_success"}]},
            ],
        }
        rule = load_rule(data)
        assert rule.type == "correlation"
        assert rule.correlation_window == 600
        assert len(rule.sequence) == 2
        assert rule.mitre_tags == ["T1110", "T1078"]


class TestLoadFromFile:
    def test_load_single_rule_file(self, tmp_path):
        f = tmp_path / "rule.yml"
        f.write_text(
            "name: test\ntype: single\nseverity: low\n"
            "description: test\nconditions:\n  - field: action\n    value: test\n"
        )
        rules = load_rules_from_file(f)
        assert len(rules) == 1

    def test_load_multi_rule_file(self, tmp_path):
        f = tmp_path / "rules.yml"
        f.write_text(
            "- name: r1\n  type: single\n  severity: low\n  description: r1\n"
            "  conditions:\n    - field: action\n      value: a\n"
            "- name: r2\n  type: single\n  severity: high\n  description: r2\n"
            "  conditions:\n    - field: action\n      value: b\n"
        )
        rules = load_rules_from_file(f)
        assert len(rules) == 2

    def test_load_empty_file(self, tmp_path):
        f = tmp_path / "empty.yml"
        f.write_text("")
        assert load_rules_from_file(f) == []

    def test_disabled_rule_excluded(self, tmp_path):
        f = tmp_path / "rule.yml"
        f.write_text(
            "name: disabled\ntype: single\nseverity: low\n"
            "description: nope\nenabled: false\nconditions:\n  - field: action\n    value: x\n"
        )
        rules_dir = tmp_path
        rules = load_rules_from_dir(rules_dir)
        assert len(rules) == 0


class TestValidateRule:
    def test_valid(self):
        data = {
            "name": "r", "type": "single",
            "conditions": [{"field": "action", "value": "x"}],
        }
        assert validate_rule(data) == []

    def test_missing_name(self):
        errors = validate_rule({"type": "single", "conditions": [{"field": "a", "value": "b"}]})
        assert any("name" in e for e in errors)

    def test_missing_conditions(self):
        errors = validate_rule({"name": "r", "type": "single"})
        assert any("conditions" in e for e in errors)

    def test_invalid_type(self):
        errors = validate_rule({"name": "r", "type": "bad", "conditions": [{"field": "a", "value": "b"}]})
        assert any("type" in e.lower() for e in errors)

    def test_threshold_missing_fields(self):
        errors = validate_rule({
            "name": "r", "type": "threshold",
            "conditions": [{"field": "a", "value": "b"}],
        })
        assert any("threshold_count" in e for e in errors)
        assert any("threshold_window" in e for e in errors)

    def test_correlation_valid(self):
        data = {
            "name": "corr",
            "type": "correlation",
            "conditions": [{"field": "action", "value": "x"}],
            "correlation_window": 300,
            "sequence": [
                {"conditions": [{"field": "action", "value": "a"}]},
                {"conditions": [{"field": "action", "value": "b"}]},
            ],
        }
        assert validate_rule(data) == []

    def test_correlation_missing_sequence(self):
        errors = validate_rule({
            "name": "r", "type": "correlation",
            "conditions": [{"field": "a", "value": "b"}],
            "correlation_window": 300,
        })
        assert any("sequence" in e for e in errors)

    def test_correlation_missing_window(self):
        errors = validate_rule({
            "name": "r", "type": "correlation",
            "conditions": [{"field": "a", "value": "b"}],
            "sequence": [
                {"conditions": [{"field": "action", "value": "a"}]},
                {"conditions": [{"field": "action", "value": "b"}]},
            ],
        })
        assert any("correlation_window" in e for e in errors)

    def test_correlation_single_step_invalid(self):
        errors = validate_rule({
            "name": "r", "type": "correlation",
            "conditions": [{"field": "a", "value": "b"}],
            "correlation_window": 300,
            "sequence": [
                {"conditions": [{"field": "action", "value": "a"}]},
            ],
        })
        assert any("sequence" in e for e in errors)
