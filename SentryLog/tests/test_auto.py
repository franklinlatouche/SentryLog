"""Tests for auto-detect parser."""

from sentrylog.parsers.auto import AutoParser, get_parser
from sentrylog.parsers.authlog import AuthLogParser
from sentrylog.parsers.apache import ApacheParser

import pytest


class TestAutoParser:
    def test_detect_authlog(self, tmp_path):
        f = tmp_path / "auth.log"
        f.write_text(
            "Mar 10 06:42:12 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2\n"
            "Mar 10 06:42:13 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2\n"
        )
        auto = AutoParser()
        parser = auto.detect(f)
        assert isinstance(parser, AuthLogParser)

    def test_detect_apache(self, tmp_path):
        f = tmp_path / "access.log"
        f.write_text(
            '192.168.1.1 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.1" 200 2326 "-" "Mozilla"\n'
        )
        auto = AutoParser()
        parser = auto.detect(f)
        assert isinstance(parser, ApacheParser)

    def test_detect_empty(self, tmp_path):
        f = tmp_path / "empty.log"
        f.write_text("")
        auto = AutoParser()
        assert auto.detect(f) is None

    def test_detect_garbage(self, tmp_path):
        f = tmp_path / "garbage.log"
        f.write_text("just some random text\nmore random text\n")
        auto = AutoParser()
        assert auto.detect(f) is None

    def test_parse_file_auto(self, tmp_path):
        f = tmp_path / "auth.log"
        f.write_text(
            "Mar 10 06:42:12 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2\n"
        )
        events = AutoParser().parse_file(f)
        assert len(events) == 1
        assert events[0].action == "auth_failure"

    def test_get_parser_by_name(self):
        assert isinstance(get_parser("authlog"), AuthLogParser)
        assert isinstance(get_parser("apache"), ApacheParser)
        assert isinstance(get_parser("auto"), AutoParser)

    def test_get_parser_unknown(self):
        with pytest.raises(ValueError, match="Unknown parser"):
            get_parser("nonexistent")
