"""Auto-detect parser based on log file content sampling."""

from __future__ import annotations

import logging
from pathlib import Path

from sentrylog.parsers.base import BaseParser
from sentrylog.parsers.authlog import AuthLogParser
from sentrylog.parsers.apache import ApacheParser
from sentrylog.storage.models import NormalizedEvent

log = logging.getLogger(__name__)

SAMPLE_LINES = 20

# Registry of available parsers
PARSERS: list[BaseParser] = [
    AuthLogParser(),
    ApacheParser(),
]


class AutoParser(BaseParser):
    """Automatically selects the best parser for a given file."""

    name = "auto"

    def __init__(self):
        self._selected: BaseParser | None = None

    def detect(self, path: Path) -> BaseParser | None:
        """Sample the file and pick the best parser."""
        lines = []
        try:
            with open(path, errors="replace") as f:
                for i, line in enumerate(f):
                    if i >= SAMPLE_LINES:
                        break
                    line = line.rstrip("\n")
                    if line:
                        lines.append(line)
        except OSError as e:
            log.error("Failed to read %s for format detection: %s", path, e)
            return None

        if not lines:
            log.debug("No content in %s, skipping", path)
            return None

        best_parser = None
        best_score = 0.0
        for parser in PARSERS:
            score = parser.can_parse(lines)
            log.debug("Parser %s scored %.2f for %s", parser.name, score, path.name)
            if score > best_score:
                best_score = score
                best_parser = parser

        if best_score >= 0.3:
            log.info("Auto-detected %s parser for %s (score=%.2f)", best_parser.name, path.name, best_score)
            return best_parser
        log.warning("No parser matched %s (best score=%.2f)", path.name, best_score)
        return None

    def parse_line(self, line: str) -> NormalizedEvent | None:
        if self._selected is None:
            # Try each parser
            for parser in PARSERS:
                event = parser.parse_line(line)
                if event is not None:
                    self._selected = parser
                    return event
            return None
        return self._selected.parse_line(line)

    def parse_file(self, path: Path) -> list[NormalizedEvent]:
        parser = self.detect(path)
        if parser is None:
            return []
        return parser.parse_file(path)

    def can_parse(self, sample_lines: list[str]) -> float:
        return max((p.can_parse(sample_lines) for p in PARSERS), default=0.0)


def get_parser(name: str) -> BaseParser:
    """Get a parser by name."""
    parser_map = {p.name: p for p in PARSERS}
    parser_map["auto"] = AutoParser()
    if name not in parser_map:
        raise ValueError(f"Unknown parser: {name}. Available: {list(parser_map.keys())}")
    return parser_map[name]
