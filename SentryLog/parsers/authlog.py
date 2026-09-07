"""Parser for Linux auth.log / secure log files."""

from __future__ import annotations

import logging
import re
from datetime import datetime

from sentrylog.parsers.base import BaseParser
from sentrylog.storage.models import NormalizedEvent, Severity

log = logging.getLogger(__name__)

# BSD syslog format (traditional):
# Mar 10 06:42:12 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2
AUTH_BSD_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+(?P<service>\S+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.+)$"
)

# RFC 3339 / ISO 8601 format (Ubuntu 24.04+, newer rsyslog):
# 2026-03-08T00:00:34.746421+00:00 beer1 sshd[12345]: Failed password for root from ...
AUTH_RFC3339_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[+-]\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+(?P<service>\S+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.+)$"
)

FAILED_PASSWORD_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"
)
ACCEPTED_PASSWORD_RE = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+)"
)
SUDO_RE = re.compile(
    r"(?P<user>\S+)\s*:\s*TTY=\S+\s*;\s*PWD=\S+\s*;\s*USER=(?P<target_user>\S+)\s*;\s*COMMAND=(?P<command>.+)"
)
INVALID_USER_RE = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)"
)
SESSION_OPENED_RE = re.compile(
    r"pam_unix\(\S+\):?\s+session opened for user (?P<user>\S+)"
)
SESSION_CLOSED_RE = re.compile(
    r"pam_unix\(\S+\):?\s+session closed for user (?P<user>\S+)"
)


def _parse_bsd_timestamp(month: str, day: str, time_str: str) -> datetime:
    year = datetime.now().year
    ts = datetime.strptime(f"{year} {month} {day} {time_str}", "%Y %b %d %H:%M:%S")
    return ts


def _parse_rfc3339_timestamp(ts_str: str) -> datetime:
    # Python 3.11+ handles this natively, for 3.10 we strip microseconds and tz offset
    # "2026-03-08T00:00:34.746421+00:00" -> datetime
    try:
        return datetime.fromisoformat(ts_str)
    except ValueError:
        # Fallback: strip fractional seconds
        clean = re.sub(r"\.\d+", "", ts_str)
        return datetime.fromisoformat(clean)


def _match_auth_line(line: str) -> tuple[datetime, str, str, str | None, str] | None:
    """Try both syslog formats. Returns (timestamp, hostname, service, pid, message) or None."""
    m = AUTH_BSD_RE.match(line)
    if m:
        ts = _parse_bsd_timestamp(m.group("month"), m.group("day"), m.group("time"))
        return ts, m.group("hostname"), m.group("service"), m.group("pid"), m.group("message")

    m = AUTH_RFC3339_RE.match(line)
    if m:
        ts = _parse_rfc3339_timestamp(m.group("timestamp"))
        return ts, m.group("hostname"), m.group("service"), m.group("pid"), m.group("message")

    return None


class AuthLogParser(BaseParser):
    name = "authlog"

    def parse_line(self, line: str) -> NormalizedEvent | None:
        parsed = _match_auth_line(line)
        if not parsed:
            return None

        ts, hostname, service, pid, message = parsed

        source_ip = None
        user = None
        action = ""
        severity = Severity.INFO
        parsed_fields: dict = {
            "hostname": hostname,
            "service": service,
        }
        if pid:
            parsed_fields["pid"] = pid

        # Failed password
        fm = FAILED_PASSWORD_RE.search(message)
        if fm:
            user = fm.group("user")
            source_ip = fm.group("ip")
            action = "auth_failure"
            severity = Severity.MEDIUM
            parsed_fields["auth_method"] = "password"

        # Accepted password/key
        am = ACCEPTED_PASSWORD_RE.search(message)
        if am:
            user = am.group("user")
            source_ip = am.group("ip")
            action = "auth_success"
            severity = Severity.INFO

        # sudo
        sm = SUDO_RE.search(message)
        if sm:
            user = sm.group("user")
            action = "sudo"
            severity = Severity.MEDIUM
            parsed_fields["target_user"] = sm.group("target_user")
            parsed_fields["command"] = sm.group("command")

        # Invalid user
        iu = INVALID_USER_RE.search(message)
        if iu:
            user = iu.group("user")
            source_ip = iu.group("ip")
            action = "invalid_user"
            severity = Severity.MEDIUM

        # Session opened/closed
        so = SESSION_OPENED_RE.search(message)
        if so:
            user = so.group("user")
            action = "session_opened"

        sc = SESSION_CLOSED_RE.search(message)
        if sc:
            user = sc.group("user")
            action = "session_closed"

        # Fallback: if no specific pattern matched, use generic
        if not action:
            action = "auth_other"
            parsed_fields["raw_message"] = message

        return NormalizedEvent(
            timestamp=ts,
            source=self.name,
            source_ip=source_ip,
            user=user,
            action=action,
            severity=severity,
            raw_line=line,
            parsed_fields=parsed_fields,
        )

    def can_parse(self, sample_lines: list[str]) -> float:
        if not sample_lines:
            return 0.0
        matches = sum(
            1 for line in sample_lines
            if AUTH_BSD_RE.match(line) or AUTH_RFC3339_RE.match(line)
        )
        ratio = matches / len(sample_lines)
        # Boost confidence if we see auth-specific keywords
        has_auth_keywords = any(
            kw in " ".join(sample_lines).lower()
            for kw in ["sshd", "sudo", "pam_unix", "password", "authentication"]
        )
        if has_auth_keywords and ratio > 0.3:
            return min(ratio + 0.2, 1.0)
        return ratio
