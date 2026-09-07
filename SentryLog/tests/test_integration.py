"""Integration tests — run full pipeline against generated demo data."""

from pathlib import Path

from sentrylog.demo import DemoLogGenerator
from sentrylog.engine.detector import DetectionEngine
from sentrylog.engine.rules import load_rules_from_dir
from sentrylog.parsers.auto import AutoParser
from sentrylog.storage.db import Database
from sentrylog.storage.models import Severity

RULES_DIR = Path(__file__).parent.parent.parent / "rules"


class TestDemoIntegration:
    def setup_method(self, tmp_path_factory=None):
        """Generate demo logs once for all tests in this class."""
        self.gen = DemoLogGenerator()

    def _run_pipeline(self, tmp_path) -> tuple[Database, list]:
        """Run the full ingest + detect pipeline, return db and alerts."""
        # Generate
        auth_path, access_path = self.gen.write(tmp_path / "logs")

        # Parse
        parser = AutoParser()
        auth_events = parser.parse_file(auth_path)
        access_events = parser.parse_file(access_path)
        all_events = auth_events + access_events
        all_events.sort(key=lambda e: e.timestamp)

        # Store
        db = Database(tmp_path / "test.db")
        db.connect()
        db.insert_events(all_events)

        # Detect
        rules = load_rules_from_dir(RULES_DIR)
        engine = DetectionEngine(rules)
        stored_events = db.get_all_events()
        alerts = engine.check_batch(stored_events)

        for alert in alerts:
            db.insert_alert(alert)

        return db, alerts

    def test_demo_generates_logs(self, tmp_path):
        auth_path, access_path = self.gen.write(tmp_path / "logs")
        assert auth_path.exists()
        assert access_path.exists()
        auth_lines = auth_path.read_text().strip().split("\n")
        access_lines = access_path.read_text().strip().split("\n")
        assert len(auth_lines) > 50
        assert len(access_lines) > 100

    def test_demo_logs_are_parseable(self, tmp_path):
        auth_path, access_path = self.gen.write(tmp_path / "logs")
        parser = AutoParser()
        auth_events = parser.parse_file(auth_path)
        access_events = parser.parse_file(access_path)
        assert len(auth_events) > 50
        assert len(access_events) > 100

    def test_pipeline_produces_alerts(self, tmp_path):
        db, alerts = self._run_pipeline(tmp_path)
        assert len(alerts) > 10
        db.close()

    def test_ssh_brute_force_detected(self, tmp_path):
        db, alerts = self._run_pipeline(tmp_path)
        brute_alerts = [a for a in alerts if a.rule_name == "ssh_brute_force"]
        assert len(brute_alerts) >= 1
        # Should reference attacker IP
        assert any(a.source_ip == "203.0.113.42" for a in brute_alerts)
        db.close()

    def test_user_enumeration_detected(self, tmp_path):
        db, alerts = self._run_pipeline(tmp_path)
        enum_alerts = [a for a in alerts if a.rule_name == "user_enumeration"]
        assert len(enum_alerts) >= 1
        db.close()

    def test_sudo_abuse_detected(self, tmp_path):
        db, alerts = self._run_pipeline(tmp_path)
        sudo_shell = [a for a in alerts if a.rule_name == "sudo_to_root_shell"]
        sudo_shadow = [a for a in alerts if a.rule_name == "sudo_shadow_read"]
        assert len(sudo_shell) >= 1
        assert len(sudo_shadow) >= 1
        db.close()

    def test_sqli_detected(self, tmp_path):
        db, alerts = self._run_pipeline(tmp_path)
        sqli = [a for a in alerts if a.rule_name == "sqli_attempt"]
        assert len(sqli) >= 3
        db.close()

    def test_xss_detected(self, tmp_path):
        db, alerts = self._run_pipeline(tmp_path)
        xss = [a for a in alerts if a.rule_name == "xss_attempt"]
        assert len(xss) >= 2
        db.close()

    def test_path_traversal_detected(self, tmp_path):
        db, alerts = self._run_pipeline(tmp_path)
        traversal = [a for a in alerts if a.rule_name == "path_traversal_attempt"]
        assert len(traversal) >= 2
        db.close()

    def test_scanner_probe_detected(self, tmp_path):
        db, alerts = self._run_pipeline(tmp_path)
        scanner = [a for a in alerts if a.rule_name == "web_scanner_probe"]
        assert len(scanner) >= 1
        db.close()

    def test_brute_force_then_success_correlated(self, tmp_path):
        db, alerts = self._run_pipeline(tmp_path)
        corr = [a for a in alerts if a.rule_name == "brute_force_then_success"]
        assert len(corr) >= 1
        # Should reference the attacker IP
        assert any(a.source_ip == "203.0.113.42" for a in corr)
        db.close()

    def test_recon_then_exploit_correlated(self, tmp_path):
        db, alerts = self._run_pipeline(tmp_path)
        corr = [a for a in alerts if a.rule_name == "recon_then_exploit"]
        assert len(corr) >= 1
        # Should reference the attacker IP that did both recon and SQLi
        assert any(a.source_ip == "185.220.101.33" for a in corr)
        db.close()

    def test_mitre_coverage(self, tmp_path):
        db, alerts = self._run_pipeline(tmp_path)
        tags = set()
        for a in alerts:
            tags.update(a.mitre_tags)
        # Should cover at least these techniques (including correlation rule tags)
        expected = {"T1110", "T1190", "T1548.003", "T1003.008", "T1083", "T1078", "T1595"}
        assert expected.issubset(tags), f"Missing MITRE tags: {expected - tags}"
        db.close()

    def test_severity_distribution(self, tmp_path):
        db, alerts = self._run_pipeline(tmp_path)
        severities = {a.severity for a in alerts}
        assert Severity.CRITICAL in severities
        assert Severity.HIGH in severities
        assert Severity.MEDIUM in severities
        db.close()

    def test_alerts_stored_in_db(self, tmp_path):
        db, alerts = self._run_pipeline(tmp_path)
        db_alerts = db.query_alerts(limit=1000)
        assert len(db_alerts) == len(alerts)
        db.close()
