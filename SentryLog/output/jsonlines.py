"""JSON lines file alert output."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from sentrylog.storage.models import Alert

log = logging.getLogger(__name__)

DEFAULT_ALERT_FILE = Path("alerts.jsonl")


def write_alert(alert: Alert, path: Path = DEFAULT_ALERT_FILE) -> None:
    with open(path, "a") as f:
        f.write(json.dumps(alert.to_dict()) + "\n")


def write_alerts(alerts: list[Alert], path: Path = DEFAULT_ALERT_FILE) -> None:
    try:
        with open(path, "a") as f:
            for alert in alerts:
                f.write(json.dumps(alert.to_dict()) + "\n")
        log.info("Wrote %d alerts to %s", len(alerts), path)
    except OSError as e:
        log.error("Failed to write alerts to %s: %s", path, e)
        raise
