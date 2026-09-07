"""Parser for Apache/Nginx combined log format."""

from __future__ import annotations

import logging
import re
from datetime import datetime

from sentrylog.parsers.base import BaseParser
from sentrylog.storage.models import NormalizedEvent, Severity

log = logging.getLogger(__name__)

# Combined Log Format:
# 192.168.1.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://ref" "Mozilla/4.0"
COMBINED_RE = re.compile(
    r'^(?P<ip>[\d.]+)\s+\S+\s+(?P<user>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)

SQLI_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"(?:union[\s+]+select|select[\s+]+.*[\s+]+from)",
        r"(?:'[\s+]*or[\s+]+'|'[\s+]*or[\s+]+1[\s+]*=[\s+]*1)",
        r"(?:;[\s+]*drop[\s+]+table|;[\s+]*delete[\s+]+from)",
        r"(?:--\s*$|/\*.*\*/)",
        r"(?:0x[0-9a-f]+|char\s*\()",
    ]
]

XSS_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"<script[^>]*>",
        r"javascript:",
        r"on(?:error|load|click|mouseover)\s*=",
    ]
]

PATH_TRAVERSAL_RE = re.compile(r"\.\./|\.\.\\")
SCANNER_PATHS = {
    "/wp-admin", "/wp-login", "/phpmyadmin", "/admin", "/.env",
    "/wp-content", "/xmlrpc.php", "/config.php", "/shell",
    "/manager/html", "/solr/", "/actuator",
}


def _classify_request(method: str, path: str, status: int) -> tuple[str, Severity]:
    path_lower = path.lower()

    # SQL injection attempts
    for pat in SQLI_PATTERNS:
        if pat.search(path):
            return "sqli_attempt", Severity.HIGH

    # XSS attempts
    for pat in XSS_PATTERNS:
        if pat.search(path):
            return "xss_attempt", Severity.HIGH

    # Path traversal
    if PATH_TRAVERSAL_RE.search(path):
        return "path_traversal", Severity.HIGH

    # Scanner/recon
    if any(path_lower.startswith(sp) for sp in SCANNER_PATHS):
        return "scanner_probe", Severity.MEDIUM

    # HTTP errors
    if status == 403:
        return "http_forbidden", Severity.LOW
    if status == 404:
        return "http_not_found", Severity.INFO
    if status >= 500:
        return "http_server_error", Severity.MEDIUM
    if status == 401:
        return "http_unauthorized", Severity.LOW

    return "http_request", Severity.INFO


class ApacheParser(BaseParser):
    name = "apache"

    def parse_line(self, line: str) -> NormalizedEvent | None:
        m = COMBINED_RE.match(line)
        if not m:
            return None

        try:
            ts = datetime.strptime(m.group("timestamp").split()[0], "%d/%b/%Y:%H:%M:%S")
        except ValueError:
            return None

        ip = m.group("ip")
        user = m.group("user")
        if user == "-":
            user = None
        method = m.group("method")
        path = m.group("path")
        status = int(m.group("status"))
        size = m.group("size")
        size = int(size) if size != "-" else 0

        action, severity = _classify_request(method, path, status)

        parsed_fields = {
            "method": method,
            "path": path,
            "protocol": m.group("protocol"),
            "status": status,
            "size": size,
        }
        if m.group("referer"):
            parsed_fields["referer"] = m.group("referer")
        if m.group("user_agent"):
            parsed_fields["user_agent"] = m.group("user_agent")

        return NormalizedEvent(
            timestamp=ts,
            source=self.name,
            source_ip=ip,
            user=user,
            action=action,
            severity=severity,
            raw_line=line,
            parsed_fields=parsed_fields,
        )

    def can_parse(self, sample_lines: list[str]) -> float:
        if not sample_lines:
            return 0.0
        matches = sum(1 for line in sample_lines if COMBINED_RE.match(line))
        return matches / len(sample_lines)
