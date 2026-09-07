"""Configuration management."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml

log = logging.getLogger(__name__)


PROJECT_ROOT = Path(__file__).resolve().parent

DEFAULT_DB_PATH = PROJECT_ROOT / "sentrylog.db"
DEFAULT_RULES_DIR = PROJECT_ROOT / "rules"
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "sentrylog.yml"


@dataclass
class Config:
    db_path: Path = DEFAULT_DB_PATH
    rules_dir: Path = DEFAULT_RULES_DIR
    log_sources: list[str] = field(default_factory=list)
    alert_outputs: list[str] = field(default_factory=lambda: ["console"])
    webhook_url: str | None = None
    dashboard_host: str = "0.0.0.0"
    dashboard_port: int = 5000

    @classmethod
    def load(cls, path: Path | None = None) -> Config:
        path = path or DEFAULT_CONFIG_PATH
        if not path.exists():
            log.debug("Config file %s not found, using defaults", path)
            return cls()
        try:
            with open(path) as f:
                data = yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            log.error("Failed to parse config %s: %s", path, e)
            return cls()
        except OSError as e:
            log.error("Failed to read config %s: %s", path, e)
            return cls()
        log.info("Loaded config from %s", path)
        return cls(
            db_path=Path(data.get("db_path", DEFAULT_DB_PATH)),
            rules_dir=Path(data.get("rules_dir", DEFAULT_RULES_DIR)),
            log_sources=data.get("log_sources", []),
            alert_outputs=data.get("alert_outputs", ["console"]),
            webhook_url=data.get("webhook_url"),
            dashboard_host=data.get("dashboard_host", "0.0.0.0"),
            dashboard_port=data.get("dashboard_port", 5000),
        )
