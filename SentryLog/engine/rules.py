"""YAML rule loader and validation."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from sentrylog.storage.models import Severity

log = logging.getLogger(__name__)


VALID_RULE_TYPES = {"single", "threshold", "correlation"}
VALID_FIELDS = {
    "action", "source_ip", "dest_ip", "user", "source", "severity",
    "parsed_fields.method", "parsed_fields.path", "parsed_fields.status",
    "parsed_fields.user_agent", "parsed_fields.command", "parsed_fields.target_user",
    "parsed_fields.service",
}


@dataclass
class RuleCondition:
    field: str
    operator: str  # equals, contains, regex, in, not_equals, gt, lt
    value: Any

    def __post_init__(self):
        if self.operator not in ("equals", "contains", "regex", "in", "not_equals", "gt", "lt"):
            raise ValueError(f"Invalid operator: {self.operator}")


@dataclass
class Rule:
    name: str
    type: str  # single, threshold, correlation
    severity: Severity
    description: str
    conditions: list[RuleCondition]
    mitre_tags: list[str] = field(default_factory=list)
    # threshold-specific
    threshold_count: int = 0
    threshold_window: int = 0  # seconds
    group_by: str | None = None  # field to group events by
    # correlation-specific (Phase 4)
    sequence: list[dict] = field(default_factory=list)
    correlation_window: int = 0
    enabled: bool = True

    def __post_init__(self):
        if self.type not in VALID_RULE_TYPES:
            raise ValueError(f"Invalid rule type: {self.type}. Must be one of {VALID_RULE_TYPES}")
        if self.type == "threshold":
            if self.threshold_count <= 0:
                raise ValueError("Threshold rules require threshold_count > 0")
            if self.threshold_window <= 0:
                raise ValueError("Threshold rules require threshold_window > 0")
        if self.type == "correlation":
            if not self.sequence or len(self.sequence) < 2:
                raise ValueError("Correlation rules require at least 2 sequence steps")
            if self.correlation_window <= 0:
                raise ValueError("Correlation rules require correlation_window > 0")


def _parse_conditions(raw: list[dict]) -> list[RuleCondition]:
    conditions = []
    for c in raw:
        conditions.append(RuleCondition(
            field=c["field"],
            operator=c.get("operator", "equals"),
            value=c["value"],
        ))
    return conditions


def load_rule(data: dict) -> Rule:
    """Parse a rule dict (from YAML) into a Rule object."""
    conditions = _parse_conditions(data.get("conditions", []))
    return Rule(
        name=data["name"],
        type=data["type"],
        severity=Severity(data.get("severity", "medium")),
        description=data.get("description", ""),
        conditions=conditions,
        mitre_tags=data.get("mitre_tags", []),
        threshold_count=data.get("threshold_count", 0),
        threshold_window=data.get("threshold_window", 0),
        group_by=data.get("group_by"),
        sequence=data.get("sequence", []),
        correlation_window=data.get("correlation_window", 0),
        enabled=data.get("enabled", True),
    )


def load_rules_from_file(path: Path) -> list[Rule]:
    """Load one or more rules from a YAML file."""
    try:
        with open(path) as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        log.error("Invalid YAML in rule file %s: %s", path, e)
        raise ValueError(f"Invalid YAML in {path}: {e}") from e
    except OSError as e:
        log.error("Failed to read rule file %s: %s", path, e)
        raise ValueError(f"Cannot read {path}: {e}") from e
    if data is None:
        log.debug("Empty rule file: %s", path)
        return []
    if isinstance(data, dict):
        rule = load_rule(data)
        log.debug("Loaded rule '%s' from %s", rule.name, path.name)
        return [rule]
    if isinstance(data, list):
        rules = [load_rule(r) for r in data]
        log.debug("Loaded %d rules from %s", len(rules), path.name)
        return rules
    raise ValueError(f"Invalid rule file format: {path}")


def load_rules_from_dir(rules_dir: Path) -> list[Rule]:
    """Load all rules from a directory of YAML files."""
    rules = []
    if not rules_dir.exists():
        log.warning("Rules directory does not exist: %s", rules_dir)
        return rules
    yaml_files = sorted(rules_dir.glob("*.yaml")) + sorted(rules_dir.glob("*.yml"))
    for path in yaml_files:
        try:
            loaded = load_rules_from_file(path)
            enabled = [r for r in loaded if r.enabled]
            skipped = len(loaded) - len(enabled)
            if skipped:
                log.info("Skipped %d disabled rule(s) in %s", skipped, path.name)
            rules.extend(enabled)
        except Exception as e:
            log.error("Failed to load rules from %s: %s", path, e)
            raise ValueError(f"Error loading {path}: {e}") from e
    log.info("Loaded %d rule(s) from %s", len(rules), rules_dir)
    return rules


def validate_rule(data: dict) -> list[str]:
    """Validate a rule dict and return a list of error messages."""
    errors = []
    if "name" not in data:
        errors.append("Missing required field: name")
    if "type" not in data:
        errors.append("Missing required field: type")
    elif data["type"] not in VALID_RULE_TYPES:
        errors.append(f"Invalid type: {data['type']}")
    if "conditions" not in data or not data["conditions"]:
        errors.append("Missing or empty conditions")
    else:
        for i, c in enumerate(data["conditions"]):
            if "field" not in c:
                errors.append(f"Condition {i}: missing 'field'")
            if "value" not in c:
                errors.append(f"Condition {i}: missing 'value'")
    if data.get("type") == "threshold":
        if not data.get("threshold_count"):
            errors.append("Threshold rules require threshold_count")
        if not data.get("threshold_window"):
            errors.append("Threshold rules require threshold_window")
    if data.get("type") == "correlation":
        seq = data.get("sequence", [])
        if not seq or len(seq) < 2:
            errors.append("Correlation rules require at least 2 sequence steps")
        else:
            for i, step in enumerate(seq):
                if "conditions" not in step or not step["conditions"]:
                    errors.append(f"Sequence step {i}: missing or empty conditions")
        if not data.get("correlation_window"):
            errors.append("Correlation rules require correlation_window")
    return errors
