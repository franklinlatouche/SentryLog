"""Detection engine — matches events against rules."""

from __future__ import annotations

import logging
import re
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sentrylog.engine.rules import Rule, RuleCondition
from sentrylog.storage.models import Alert, NormalizedEvent

log = logging.getLogger(__name__)


def _get_field_value(event: NormalizedEvent, field: str) -> Any:
    """Extract a field value from an event, supporting dotted paths for parsed_fields."""
    if field.startswith("parsed_fields."):
        key = field[len("parsed_fields."):]
        return event.parsed_fields.get(key)
    return getattr(event, field, None)


def _match_condition(event: NormalizedEvent, condition: RuleCondition) -> bool:
    """Check if a single condition matches an event."""
    value = _get_field_value(event, condition.field)
    if value is None:
        return False

    val_str = str(value)
    cond_val = condition.value

    try:
        match condition.operator:
            case "equals":
                return val_str == str(cond_val)
            case "not_equals":
                return val_str != str(cond_val)
            case "contains":
                return str(cond_val).lower() in val_str.lower()
            case "regex":
                return bool(re.search(str(cond_val), val_str, re.IGNORECASE))
            case "in":
                if isinstance(cond_val, list):
                    return val_str in [str(v) for v in cond_val]
                return val_str in str(cond_val)
            case "gt":
                try:
                    return float(val_str) > float(cond_val)
                except (ValueError, TypeError):
                    return False
            case "lt":
                try:
                    return float(val_str) < float(cond_val)
                except (ValueError, TypeError):
                    return False
    except re.error as e:
        log.warning("Invalid regex in condition field=%s value=%s: %s", condition.field, cond_val, e)
        return False
    except Exception as e:
        log.warning("Error evaluating condition field=%s op=%s: %s", condition.field, condition.operator, e)
        return False
    return False


def _event_matches_conditions(event: NormalizedEvent, conditions: list[RuleCondition]) -> bool:
    """Check if all conditions match an event."""
    return all(_match_condition(event, c) for c in conditions)


class SingleDetector:
    """Detects single-event matches."""

    def __init__(self, rules: list[Rule]):
        self.rules = [r for r in rules if r.type == "single"]

    def check(self, event: NormalizedEvent) -> list[Alert]:
        alerts = []
        for rule in self.rules:
            if _event_matches_conditions(event, rule.conditions):
                log.debug("Single rule '%s' matched event %s (ip=%s action=%s)",
                          rule.name, event.id, event.source_ip, event.action)
                alerts.append(Alert(
                    rule_name=rule.name,
                    severity=rule.severity,
                    description=rule.description,
                    timestamp=event.timestamp,
                    event_ids=[event.id] if event.id else [],
                    mitre_tags=rule.mitre_tags,
                    source_ip=event.source_ip,
                    user=event.user,
                ))
        return alerts


class ThresholdDetector:
    """Detects threshold-based patterns using sliding windows."""

    def __init__(self, rules: list[Rule]):
        self.rules = [r for r in rules if r.type == "threshold"]
        # State: {rule_name: {group_key: deque of (timestamp, event_id)}}
        self._windows: dict[str, dict[str, deque]] = {}
        # Track which (rule, group_key, window_start) combos have already fired
        self._fired: dict[str, set[str]] = {}
        for rule in self.rules:
            self._windows[rule.name] = {}
            self._fired[rule.name] = set()

    def check(self, event: NormalizedEvent) -> list[Alert]:
        alerts = []
        for rule in self.rules:
            if not _event_matches_conditions(event, rule.conditions):
                continue

            # Determine group key
            if rule.group_by:
                group_key = str(_get_field_value(event, rule.group_by) or "unknown")
            else:
                group_key = "__all__"

            # Get or create window
            if group_key not in self._windows[rule.name]:
                self._windows[rule.name][group_key] = deque()
            window = self._windows[rule.name][group_key]

            # Add current event
            window.append((event.timestamp, event.id))

            # Evict old entries outside the window
            cutoff = event.timestamp - timedelta(seconds=rule.threshold_window)
            while window and window[0][0] < cutoff:
                window.popleft()

            # Check threshold
            if len(window) >= rule.threshold_count:
                # Create a fire key to avoid duplicate alerts for the same window
                fire_key = f"{group_key}:{int(event.timestamp.timestamp()) // rule.threshold_window}"
                if fire_key not in self._fired[rule.name]:
                    self._fired[rule.name].add(fire_key)
                    event_ids = [eid for _, eid in window if eid]
                    log.debug("Threshold rule '%s' fired: %d events in %ds (group=%s)",
                              rule.name, len(window), rule.threshold_window, group_key)
                    description = (
                        f"{rule.description} "
                        f"({len(window)} events in {rule.threshold_window}s"
                        f"{f' from {group_key}' if group_key != '__all__' else ''})"
                    )
                    alerts.append(Alert(
                        rule_name=rule.name,
                        severity=rule.severity,
                        description=description,
                        timestamp=event.timestamp,
                        event_ids=event_ids,
                        mitre_tags=rule.mitre_tags,
                        source_ip=event.source_ip if rule.group_by == "source_ip" else None,
                        user=event.user if rule.group_by == "user" else None,
                    ))

        return alerts

    def reset(self):
        """Clear all state."""
        for name in self._windows:
            self._windows[name].clear()
            self._fired[name].clear()


class CorrelationDetector:
    """Detects ordered sequences of events within a time window.

    Each correlation rule defines a sequence of steps (each with conditions).
    Events must match the steps in order, within the correlation_window (seconds),
    optionally grouped by a shared field (group_by).

    State is bounded: per-rule, per-group, only active (non-expired) partial
    sequences are kept, with a cap of MAX_PENDING per group.
    """

    MAX_PENDING = 200  # max partial sequences per (rule, group)

    def __init__(self, rules: list[Rule]):
        self.rules = [r for r in rules if r.type == "correlation"]
        # Pre-parse step conditions
        self._step_conditions: dict[str, list[list[RuleCondition]]] = {}
        for rule in self.rules:
            steps = []
            for step in rule.sequence:
                steps.append(_parse_step_conditions(step))
            self._step_conditions[rule.name] = steps

        # State: {rule_name: {group_key: list of _PendingSequence}}
        self._pending: dict[str, dict[str, list[_PendingSequence]]] = {}
        self._fired: dict[str, set[str]] = {}
        for rule in self.rules:
            self._pending[rule.name] = {}
            self._fired[rule.name] = set()

    def check(self, event: NormalizedEvent) -> list[Alert]:
        alerts = []
        for rule in self.rules:
            group_key = self._group_key(event, rule)
            pending_list = self._pending[rule.name].setdefault(group_key, [])
            step_conds = self._step_conditions[rule.name]
            window = timedelta(seconds=rule.correlation_window)

            # Evict expired partial sequences
            pending_list[:] = [
                p for p in pending_list
                if event.timestamp - p.started <= window
            ]

            # Try to advance existing partial sequences (iterate in reverse for safe removal)
            completed = []
            for p in pending_list:
                next_step = p.step_index
                if next_step < len(step_conds) and _event_matches_conditions(event, step_conds[next_step]):
                    p.step_index += 1
                    p.event_ids.append(event.id)
                    p.last_event = event
                    if p.step_index == len(step_conds):
                        completed.append(p)

            # Remove completed from pending
            for p in completed:
                if p in pending_list:
                    pending_list.remove(p)

            # Start new sequences if event matches step 0
            if step_conds and _event_matches_conditions(event, step_conds[0]):
                new_seq = _PendingSequence(
                    started=event.timestamp,
                    step_index=1,
                    event_ids=[event.id],
                    last_event=event,
                )
                # If only 1 step after step 0 and step_index already == len, it's complete
                if new_seq.step_index == len(step_conds):
                    completed.append(new_seq)
                else:
                    pending_list.append(new_seq)
                    # Enforce cap
                    if len(pending_list) > self.MAX_PENDING:
                        pending_list.pop(0)

            # Generate alerts for completed sequences
            for p in completed:
                fire_key = f"{group_key}:{int(p.started.timestamp()) // max(rule.correlation_window, 1)}"
                if fire_key not in self._fired[rule.name]:
                    self._fired[rule.name].add(fire_key)
                    log.debug("Correlation rule '%s' completed: %d events over %ds (group=%s)",
                              rule.name, len(p.event_ids), rule.correlation_window, group_key)
                    alerts.append(Alert(
                        rule_name=rule.name,
                        severity=rule.severity,
                        description=f"{rule.description} (correlated {len(p.event_ids)} events over {rule.correlation_window}s)",
                        timestamp=p.last_event.timestamp,
                        event_ids=[eid for eid in p.event_ids if eid],
                        mitre_tags=rule.mitre_tags,
                        source_ip=p.last_event.source_ip if rule.group_by == "source_ip" else None,
                        user=p.last_event.user if rule.group_by == "user" else None,
                    ))

        return alerts

    def _group_key(self, event: NormalizedEvent, rule: Rule) -> str:
        if rule.group_by:
            return str(_get_field_value(event, rule.group_by) or "unknown")
        return "__all__"

    def reset(self):
        for name in self._pending:
            self._pending[name].clear()
            self._fired[name].clear()


@dataclass
class _PendingSequence:
    """Tracks a partial sequence match in progress."""
    started: datetime
    step_index: int  # next step to match
    event_ids: list[int]
    last_event: NormalizedEvent


def _parse_step_conditions(step: dict) -> list[RuleCondition]:
    """Parse conditions from a correlation sequence step."""
    conditions = []
    for c in step.get("conditions", []):
        conditions.append(RuleCondition(
            field=c["field"],
            operator=c.get("operator", "equals"),
            value=c["value"],
        ))
    return conditions


class DetectionEngine:
    """Orchestrates all detectors."""

    def __init__(self, rules: list[Rule]):
        self.single = SingleDetector(rules)
        self.threshold = ThresholdDetector(rules)
        self.correlation = CorrelationDetector(rules)
        log.info("Detection engine initialized: %d single, %d threshold, %d correlation rules",
                 len(self.single.rules), len(self.threshold.rules), len(self.correlation.rules))

    def check(self, event: NormalizedEvent) -> list[Alert]:
        alerts = []
        alerts.extend(self.single.check(event))
        alerts.extend(self.threshold.check(event))
        alerts.extend(self.correlation.check(event))
        return alerts

    def check_batch(self, events: list[NormalizedEvent]) -> list[Alert]:
        """Check a batch of events (must be in chronological order)."""
        all_alerts = []
        for event in events:
            all_alerts.extend(self.check(event))
        log.info("Batch scan complete: %d events → %d alerts", len(events), len(all_alerts))
        return all_alerts
