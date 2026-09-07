"""Tests for Apache/Nginx combined log parser."""

from sentrylog.parsers.apache import ApacheParser
from sentrylog.storage.models import Severity


def make_parser():
    return ApacheParser()


class TestApacheParser:
    def test_normal_request(self):
        line = '192.168.1.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326 "http://example.com" "Mozilla/5.0"'
        event = make_parser().parse_line(line)
        assert event is not None
        assert event.source_ip == "192.168.1.1"
        assert event.user == "frank"
        assert event.action == "http_request"
        assert event.severity == Severity.INFO
        assert event.parsed_fields["method"] == "GET"
        assert event.parsed_fields["path"] == "/index.html"
        assert event.parsed_fields["status"] == 200

    def test_404_request(self):
        line = '10.0.0.5 - - [10/Oct/2000:13:55:36 -0700] "GET /nonexistent HTTP/1.1" 404 0 "-" "curl/7.68"'
        event = make_parser().parse_line(line)
        assert event is not None
        assert event.action == "http_not_found"
        assert event.user is None

    def test_sqli_attempt(self):
        line = '10.0.0.5 - - [10/Oct/2000:13:55:36 -0700] "GET /search?q=1%27+OR+1%3D1 HTTP/1.1" 200 0 "-" "sqlmap"'
        # URL-decoded version for direct test
        line2 = "10.0.0.5 - - [10/Oct/2000:13:55:36 -0700] \"GET /search?q=1'+or+1=1 HTTP/1.1\" 200 0 \"-\" \"sqlmap\""
        event = make_parser().parse_line(line2)
        assert event is not None
        assert event.action == "sqli_attempt"
        assert event.severity == Severity.HIGH

    def test_union_select_sqli(self):
        line = '10.0.0.5 - - [10/Oct/2000:13:55:36 -0700] "GET /page?id=1+UNION+SELECT+username,password+FROM+users HTTP/1.1" 200 0 "-" "sqlmap"'
        event = make_parser().parse_line(line)
        assert event is not None
        assert event.action == "sqli_attempt"
        assert event.severity == Severity.HIGH

    def test_xss_attempt(self):
        line = '10.0.0.5 - - [10/Oct/2000:13:55:36 -0700] "GET /page?q=<script>alert(1)</script> HTTP/1.1" 200 0 "-" "Mozilla"'
        event = make_parser().parse_line(line)
        assert event is not None
        assert event.action == "xss_attempt"
        assert event.severity == Severity.HIGH

    def test_path_traversal(self):
        line = '10.0.0.5 - - [10/Oct/2000:13:55:36 -0700] "GET /../../etc/passwd HTTP/1.1" 403 0 "-" "Mozilla"'
        event = make_parser().parse_line(line)
        assert event is not None
        assert event.action == "path_traversal"
        assert event.severity == Severity.HIGH

    def test_scanner_probe(self):
        line = '10.0.0.5 - - [10/Oct/2000:13:55:36 -0700] "GET /wp-admin/ HTTP/1.1" 404 0 "-" "Mozilla"'
        event = make_parser().parse_line(line)
        assert event is not None
        assert event.action == "scanner_probe"
        assert event.severity == Severity.MEDIUM

    def test_server_error(self):
        line = '10.0.0.5 - - [10/Oct/2000:13:55:36 -0700] "POST /api/data HTTP/1.1" 500 1234 "-" "Mozilla"'
        event = make_parser().parse_line(line)
        assert event is not None
        assert event.action == "http_server_error"
        assert event.severity == Severity.MEDIUM

    def test_unparseable(self):
        assert make_parser().parse_line("not a log line") is None

    def test_can_parse_high(self):
        lines = [
            '192.168.1.1 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.1" 200 2326 "-" "Mozilla"',
            '192.168.1.2 - - [10/Oct/2000:13:55:37 -0700] "POST /login HTTP/1.1" 302 0 "-" "Mozilla"',
        ]
        assert make_parser().can_parse(lines) >= 0.8

    def test_can_parse_low(self):
        lines = [
            "Mar 10 06:42:12 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2",
        ]
        assert make_parser().can_parse(lines) < 0.3

    def test_parse_file(self, tmp_path):
        log_file = tmp_path / "access.log"
        log_file.write_text(
            '192.168.1.1 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.1" 200 2326 "-" "Mozilla"\n'
            '192.168.1.2 - - [10/Oct/2000:13:55:37 -0700] "GET /admin HTTP/1.1" 403 0 "-" "Mozilla"\n'
        )
        events = make_parser().parse_file(log_file)
        assert len(events) == 2
