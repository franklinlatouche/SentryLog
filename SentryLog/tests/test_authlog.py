"""Tests for auth.log parser."""

from sentrylog.parsers.authlog import AuthLogParser
from sentrylog.storage.models import Severity


def make_parser():
    return AuthLogParser()


class TestAuthLogParser:
    def test_failed_password(self):
        line = "Mar 10 06:42:12 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2"
        parser = make_parser()
        event = parser.parse_line(line)
        assert event is not None
        assert event.action == "auth_failure"
        assert event.source_ip == "192.168.1.100"
        assert event.user == "root"
        assert event.severity == Severity.MEDIUM

    def test_failed_password_invalid_user(self):
        line = "Mar 10 06:42:12 server sshd[12345]: Failed password for invalid user admin from 10.0.0.5 port 22 ssh2"
        event = make_parser().parse_line(line)
        assert event is not None
        assert event.action == "auth_failure"
        assert event.user == "admin"
        assert event.source_ip == "10.0.0.5"

    def test_accepted_password(self):
        line = "Mar 10 08:15:00 server sshd[5678]: Accepted password for alice from 172.16.0.10 port 54321 ssh2"
        event = make_parser().parse_line(line)
        assert event is not None
        assert event.action == "auth_success"
        assert event.user == "alice"
        assert event.source_ip == "172.16.0.10"
        assert event.severity == Severity.INFO

    def test_accepted_publickey(self):
        line = "Mar 10 08:15:00 server sshd[5678]: Accepted publickey for bob from 172.16.0.11 port 12345 ssh2"
        event = make_parser().parse_line(line)
        assert event is not None
        assert event.action == "auth_success"
        assert event.user == "bob"

    def test_sudo(self):
        line = "Mar 10 09:00:00 server sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash"
        event = make_parser().parse_line(line)
        assert event is not None
        assert event.action == "sudo"
        assert event.user == "alice"
        assert event.severity == Severity.MEDIUM
        assert event.parsed_fields["target_user"] == "root"
        assert event.parsed_fields["command"] == "/bin/bash"

    def test_invalid_user(self):
        line = "Mar 10 07:00:00 server sshd[9999]: Invalid user test from 203.0.113.50"
        event = make_parser().parse_line(line)
        assert event is not None
        assert event.action == "invalid_user"
        assert event.user == "test"
        assert event.source_ip == "203.0.113.50"

    def test_session_opened(self):
        line = "Mar 10 08:00:00 server sshd[1234]: pam_unix(sshd:session): session opened for user alice"
        event = make_parser().parse_line(line)
        assert event is not None
        assert event.action == "session_opened"
        assert event.user == "alice"

    def test_session_closed(self):
        line = "Mar 10 10:00:00 server sshd[1234]: pam_unix(sshd:session): session closed for user alice"
        event = make_parser().parse_line(line)
        assert event is not None
        assert event.action == "session_closed"

    def test_unparseable_line(self):
        event = make_parser().parse_line("random garbage that is not a log line")
        assert event is None

    def test_generic_auth_message(self):
        line = "Mar 10 08:00:00 server systemd-logind[500]: New session 42 of user bob."
        event = make_parser().parse_line(line)
        assert event is not None
        assert event.action == "auth_other"
        assert event.parsed_fields["service"] == "systemd-logind"

    # --- RFC 3339 format (Ubuntu 24.04+) ---

    def test_rfc3339_failed_password(self):
        line = "2026-03-08T03:15:22.123456+00:00 server sshd[12345]: Failed password for root from 203.0.113.42 port 54321 ssh2"
        event = make_parser().parse_line(line)
        assert event is not None
        assert event.action == "auth_failure"
        assert event.source_ip == "203.0.113.42"
        assert event.user == "root"
        assert event.timestamp.year == 2026

    def test_rfc3339_accepted_publickey(self):
        line = "2026-03-08T08:00:01.000000+00:00 beer1 sshd[5678]: Accepted publickey for alice from 192.168.1.10 port 22 ssh2"
        event = make_parser().parse_line(line)
        assert event is not None
        assert event.action == "auth_success"
        assert event.user == "alice"

    def test_rfc3339_sudo(self):
        line = "2026-03-08T09:30:00.500000+00:00 beer1 sudo: bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash"
        event = make_parser().parse_line(line)
        assert event is not None
        assert event.action == "sudo"
        assert event.user == "bob"
        assert event.parsed_fields["command"] == "/bin/bash"

    def test_rfc3339_generic_message(self):
        line = "2026-03-08T00:00:34.746421+00:00 beer1 systemd-logind[855]: Suspending..."
        event = make_parser().parse_line(line)
        assert event is not None
        assert event.action == "auth_other"
        assert event.parsed_fields["service"] == "systemd-logind"

    def test_rfc3339_can_parse(self):
        lines = [
            "2026-03-08T03:15:22.123456+00:00 server sshd[12345]: Failed password for root from 203.0.113.42 port 54321 ssh2",
            "2026-03-08T03:15:23.654321+00:00 server sshd[12345]: Failed password for root from 203.0.113.42 port 54321 ssh2",
            "2026-03-08T08:00:01.000000+00:00 server sshd[5678]: Accepted publickey for alice from 192.168.1.10 port 22 ssh2",
        ]
        score = make_parser().can_parse(lines)
        assert score >= 0.8

    def test_can_parse_high_confidence(self):
        lines = [
            "Mar 10 06:42:12 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2",
            "Mar 10 06:42:13 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2",
            "Mar 10 08:15:00 server sshd[5678]: Accepted password for alice from 172.16.0.10 port 54321 ssh2",
        ]
        score = make_parser().can_parse(lines)
        assert score >= 0.8

    def test_can_parse_low_confidence(self):
        lines = [
            '192.168.1.1 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.0" 200 2326',
            '192.168.1.2 - - [10/Oct/2000:13:55:37 -0700] "GET /foo HTTP/1.0" 404 0',
        ]
        score = make_parser().can_parse(lines)
        assert score < 0.3

    def test_parse_file(self, tmp_path):
        log_file = tmp_path / "auth.log"
        log_file.write_text(
            "Mar 10 06:42:12 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2\n"
            "Mar 10 06:42:13 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2\n"
            "\n"
            "Mar 10 08:15:00 server sshd[5678]: Accepted password for alice from 172.16.0.10 port 54321 ssh2\n"
        )
        events = make_parser().parse_file(log_file)
        assert len(events) == 3
        assert events[0].action == "auth_failure"
        assert events[2].action == "auth_success"
