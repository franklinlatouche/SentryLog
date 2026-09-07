"""Base parser interface."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from pathlib import Path

from sentrylog.storage.models import NormalizedEvent

log = logging.getLogger(__name__)


class BaseParser(ABC):
    """Base class for all log parsers."""

    name: str = "base"

    @abstractmethod
    def parse_line(self, line: str) -> NormalizedEvent | None:
        """Parse a single log line into a NormalizedEvent, or None if unparseable."""

    def parse_file(self, path: Path) -> list[NormalizedEvent]:
        """Parse all lines in a file."""
        events = []
        skipped = 0
        try:
            with open(path, errors="replace") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.rstrip("\n")
                    if not line:
                        continue
                    try:
                        event = self.parse_line(line)
                    except Exception as e:
                        skipped += 1
                        log.warning("Failed to parse line %d in %s: %s", line_num, path, e)
                        continue
                    if event is not None:
                        events.append(event)
                    else:
                        skipped += 1
        except OSError as e:
            log.error("Failed to read file %s: %s", path, e)
            return []
        log.info("Parsed %s: %d events, %d skipped (%s parser)", path.name, len(events), skipped, self.name)
        return events

    @abstractmethod
    def can_parse(self, sample_lines: list[str]) -> float:
        """Return confidence 0.0–1.0 that this parser handles the given log format."""
