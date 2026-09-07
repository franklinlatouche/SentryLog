"""Core data models."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class NormalizedEvent:
    timestamp: datetime
    source: str  # which log file / source type
    source_ip: str | None = None
    dest_ip: str | None = None
    user: str | None = None
    action: str = ""
    severity: Severity = Severity.INFO
    raw_line: str = ""
    parsed_fields: dict[str, Any] = field(default_factory=dict)
    id: int | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        d["severity"] = self.severity.value
        return d

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> NormalizedEvent:
        parsed = json.loads(row["parsed_fields"]) if row["parsed_fields"] else {}
        return cls(
            id=row["id"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            source=row["source"],
            source_ip=row["source_ip"],
            dest_ip=row["dest_ip"],
            user=row["user"],
            action=row["action"],
            severity=Severity(row["severity"]),
            raw_line=row["raw_line"],
            parsed_fields=parsed,
        )


@dataclass
class Alert:
    rule_name: str
    severity: Severity
    description: str
    timestamp: datetime
    event_ids: list[int] = field(default_factory=list)
    mitre_tags: list[str] = field(default_factory=list)
    source_ip: str | None = None
    user: str | None = None
    acknowledged: bool = False
    id: int | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        d["severity"] = self.severity.value
        return d

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> Alert:
        return cls(
            id=row["id"],
            rule_name=row["rule_name"],
            severity=Severity(row["severity"]),
            description=row["description"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            event_ids=json.loads(row["event_ids"]) if row["event_ids"] else [],
            mitre_tags=json.loads(row["mitre_tags"]) if row["mitre_tags"] else [],
            source_ip=row["source_ip"],
            user=row["user"],
            acknowledged=bool(row["acknowledged"]),
        )
