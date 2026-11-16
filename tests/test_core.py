from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from logwatch_agent.core import RuleDetector, parse_log_line
from logwatch_agent.follower import FileFollower
from logwatch_agent.state import StateStore


class ParseLogLineTests(unittest.TestCase):
    def test_parses_iso_syslog_and_detects_firewall_denial(self) -> None:
        event = parse_log_line(
            "2026-11-16T12:00:00Z fw-1 DENY src=192.0.2.10 dst=198.51.100.20 dport=443"
        )
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.category, "firewall_deny")
        self.assertEqual(event.source_ip, "192.0.2.10")
        self.assertEqual(event.hostname, "fw-1")

    def test_parses_rfc3164_authentication_failure(self) -> None:
        event = parse_log_line(
            "Nov 16 12:00:00 auth-1 sshd: Failed password for demo from 192.0.2.11",
            year=2026,
        )
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.category, "authentication_failure")
        self.assertEqual(event.source_ip, "192.0.2.11")

    def test_ignores_blank_and_unparseable_lines(self) -> None:
        self.assertIsNone(parse_log_line(""))
        self.assertIsNone(parse_log_line("not a timestamp"))


class RuleDetectorTests(unittest.TestCase):
    def test_emits_one_alert_at_threshold_with_exact_evidence(self) -> None:
        detector = RuleDetector()
        alerts = []
        for second in range(3):
            event = parse_log_line(
                f"2026-11-16T12:00:0{second}Z fw-1 DENY src=192.0.2.10 dst=198.51.100.20"
            )
            assert event is not None
            alerts.extend(detector.observe(event))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].event_count, 3)
        self.assertEqual(len(alerts[0].evidence), 3)
        self.assertEqual(alerts[0].source_ip, "192.0.2.10")

    def test_does_not_alert_below_threshold_or_across_expired_window(self) -> None:
        detector = RuleDetector()
        for timestamp in ("12:00:00", "12:02:00", "12:04:00"):
            event = parse_log_line(
                f"2026-11-16T{timestamp}Z fw-1 DENY src=192.0.2.10"
            )
            assert event is not None
            self.assertEqual(detector.observe(event), [])


class FileFollowerTests(unittest.TestCase):
    def test_resumes_and_waits_for_a_complete_line(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            log = root / "events.log"
            log.write_text("first line\npartial", encoding="utf-8")
            state = StateStore(root / "state.sqlite3")
            follower = FileFollower(log, state)

            self.assertEqual(follower.read_new_lines(), ["first line"])
            follower.commit()
            with log.open("a", encoding="utf-8") as stream:
                stream.write(" line\nsecond line\n")
            self.assertEqual(
                follower.read_new_lines(), ["partial line", "second line"]
            )
            follower.commit()
            self.assertEqual(follower.read_new_lines(), [])
            follower.commit()
            state.close()

    def test_resumes_after_restart_and_starts_over_after_truncation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            log = root / "events.log"
            log.write_text("a long first line\n", encoding="utf-8")
            state = StateStore(root / "state.sqlite3")
            follower = FileFollower(log, state)
            self.assertEqual(follower.read_new_lines(), ["a long first line"])
            follower.commit()
            state.close()

            state = StateStore(root / "state.sqlite3")
            follower = FileFollower(log, state)
            self.assertEqual(follower.read_new_lines(), [])
            follower.commit()
            log.write_text("new\n", encoding="utf-8")
            self.assertEqual(follower.read_new_lines(), ["new"])
            follower.commit()
            state.close()


if __name__ == "__main__":
    unittest.main()
