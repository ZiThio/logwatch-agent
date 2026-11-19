from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import contextlib
import io
import json
from datetime import datetime, timezone
from unittest import mock

from logwatch_agent.app import DEFAULT_CHAT_MODEL, _write_alert, build_parser
from logwatch_agent.core import RuleDetector, parse_log_line
from logwatch_agent.follower import FileFollower
from logwatch_agent.ollama import (
    DEFAULT_KEEP_ALIVE,
    DEFAULT_TIMEOUT_SECONDS,
    OllamaClient,
    OllamaError,
)
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

    def test_parses_space_separated_iso_timestamp(self) -> None:
        event = parse_log_line("2026-11-16 12:00:05 fw-1 DENY src=192.0.2.10")
        assert event is not None
        self.assertEqual(
            event.timestamp, datetime(2026, 11, 16, 12, 0, 5, tzinfo=timezone.utc)
        )
        self.assertEqual(event.hostname, "fw-1")
        self.assertEqual(event.category, "firewall_deny")

    def test_rejects_date_without_time(self) -> None:
        self.assertIsNone(parse_log_line("2026-11-16 fw-1 DENY src=192.0.2.10"))

    def test_deny_words_in_values_or_benign_text_are_not_denials(self) -> None:
        for line in (
            "2026-11-16T12:00:00Z fw-1 ALLOW src=192.0.2.10 policy=deny-default",
            "2026-11-16T12:00:00Z web-1 client connection dropped normally",
            "2026-11-16T12:00:00Z fw-1 conn action=accept note=blocked-list-check",
        ):
            event = parse_log_line(line)
            assert event is not None
            self.assertEqual(event.category, "other", line)

    def test_detects_explicit_and_free_text_denials(self) -> None:
        for line in (
            "2026-11-16T12:00:00Z fw-1 conn action=drop src=192.0.2.10",
            "2026-11-16T12:00:00Z fw-1 kernel: [UFW BLOCK] IN=eth0 SRC=192.0.2.10",
            "2026-11-16T12:00:00Z proxy-1 request denied by policy",
        ):
            event = parse_log_line(line)
            assert event is not None
            self.assertEqual(event.category, "firewall_deny", line)

    def test_source_ip_must_be_a_real_address(self) -> None:
        event = parse_log_line("Nov 16 12:00:00 web-1 app: request from cafe completed", year=2026)
        assert event is not None
        self.assertIsNone(event.source_ip)
        event = parse_log_line(
            "2026-11-16T12:00:00Z fw-1 DENY src=999.1.1.1 msg from 192.0.2.7"
        )
        assert event is not None
        self.assertEqual(event.source_ip, "192.0.2.7")


class LabLogFormatTests(unittest.TestCase):
    """Lines in the formats the Containerlab lab's rsyslog collector writes."""

    def test_ulogd_firewall_deny_from_router(self) -> None:
        event = parse_log_line(
            "2026-11-19T10:00:01.123456+00:00 router1 ulogd[42]: FW-DENY IN=eth2 OUT=eth3 "
            "MAC=aa:c1:ab:00:00:01 SRC=192.0.2.18 DST=198.51.100.20 LEN=60 PROTO=TCP "
            "SPT=40000 DPT=22 SYN URGP=0"
        )
        assert event is not None
        self.assertEqual(event.category, "firewall_deny")
        self.assertEqual(event.source_ip, "192.0.2.18")
        self.assertEqual(event.hostname, "router1")

    def test_nginx_basic_auth_failures(self) -> None:
        lines = (
            '2026-11-19T10:00:02+00:00 web nginx_error: 2026/11/19 10:00:02 [error] 29#29: '
            '*3 user "admin": password mismatch, client: 192.0.2.18, server: _, '
            'request: "GET /admin/ HTTP/1.1", host: "198.51.100.20"',
            '2026-11-19T10:00:03+00:00 web nginx_error: 2026/11/19 10:00:03 [error] 29#29: '
            '*4 user "root" was not found in "/etc/nginx/htpasswd", client: 192.0.2.18, '
            'server: _, request: "GET /admin/ HTTP/1.1", host: "198.51.100.20"',
        )
        for line in lines:
            with self.subTest(line=line):
                event = parse_log_line(line)
                assert event is not None
                self.assertEqual(event.category, "authentication_failure")
                self.assertEqual(event.source_ip, "192.0.2.18")

    def test_nginx_access_log_is_not_an_alert_category(self) -> None:
        event = parse_log_line(
            '2026-11-19T10:00:04+00:00 web nginx: 192.0.2.2 - - [19/Nov/2026:10:00:04 +0000] '
            '"GET / HTTP/1.1" 200 615 "-" "curl/8.9.1"'
        )
        assert event is not None
        self.assertEqual(event.category, "other")


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

    def test_missing_file_during_rotation_is_not_fatal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            log = root / "events.log"
            log.write_text("one\n", encoding="utf-8")
            state = StateStore(root / "state.sqlite3")
            follower = FileFollower(log, state)
            self.assertEqual(follower.read_new_lines(), ["one"])
            follower.commit()

            log.unlink()
            self.assertEqual(follower.read_new_lines(), [])
            follower.commit()

            log.write_text("two\n", encoding="utf-8")
            self.assertEqual(follower.read_new_lines(), ["two"])
            follower.commit()
            state.close()


class _FailingExplainer:
    def explain(self, alert: object) -> dict[str, object]:
        raise OllamaError("Ollama request failed: connection refused")


class WriteAlertTests(unittest.TestCase):
    def test_alert_is_still_written_when_ai_explanation_fails(self) -> None:
        detector = RuleDetector()
        alerts = []
        for second in range(3):
            event = parse_log_line(f"2026-11-16T12:00:0{second}Z fw-1 DENY src=192.0.2.10")
            assert event is not None
            alerts.extend(detector.observe(event))
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "alerts.jsonl"
            with contextlib.redirect_stderr(io.StringIO()) as stderr:
                _write_alert(
                    alerts[0], output=output, explainer=_FailingExplainer(), emit=lambda _: None
                )
            written = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(written["rule_id"], "firewall-deny-burst")
        self.assertIn("connection refused", written["analysis"]["error"])
        self.assertIn("Warning", stderr.getvalue())


class _FakeResponse:
    def __init__(self, payload: dict[str, object]) -> None:
        self._body = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None


class OllamaClientTests(unittest.TestCase):
    def _capture(self, response: dict[str, object]):
        calls: list[tuple[dict[str, object], float]] = []

        def fake_urlopen(request, timeout):
            calls.append((json.loads(request.data.decode("utf-8")), timeout))
            return _FakeResponse(response)

        return calls, mock.patch("urllib.request.urlopen", side_effect=fake_urlopen)

    def test_chat_disables_thinking_and_keeps_model_loaded(self) -> None:
        calls, patcher = self._capture({"message": {"content": '{"summary": "ok"}'}})
        with patcher:
            client = OllamaClient("http://127.0.0.1:11434", timeout=300)
            result = client.chat_json("qwen2.5:3b", "system", "prompt")
        self.assertEqual(result, {"summary": "ok"})
        payload, timeout = calls[0]
        self.assertIs(payload["think"], False)
        self.assertEqual(payload["keep_alive"], DEFAULT_KEEP_ALIVE)
        self.assertEqual(timeout, 300)

    def test_embed_keeps_model_loaded(self) -> None:
        calls, patcher = self._capture({"embeddings": [[0.1, 0.2]]})
        with patcher:
            OllamaClient().embed("nomic-embed-text", ["text"])
        payload, timeout = calls[0]
        self.assertEqual(payload["keep_alive"], DEFAULT_KEEP_ALIVE)
        self.assertEqual(timeout, DEFAULT_TIMEOUT_SECONDS)

    def test_rejects_non_positive_timeout(self) -> None:
        with self.assertRaises(ValueError):
            OllamaClient(timeout=0)


class CommandLineTests(unittest.TestCase):
    def test_ollama_timeout_defaults_and_can_be_set(self) -> None:
        parser = build_parser()
        replay = parser.parse_args(["replay", "--log", "x.log"])
        self.assertEqual(replay.ollama_timeout, DEFAULT_TIMEOUT_SECONDS)
        self.assertEqual(replay.model, DEFAULT_CHAT_MODEL)
        watch = parser.parse_args(["watch", "--log", "x.log", "--ollama-timeout", "300"])
        self.assertEqual(watch.ollama_timeout, 300.0)
        index = parser.parse_args(["index", "--ollama-timeout", "45.5"])
        self.assertEqual(index.ollama_timeout, 45.5)

    def test_rejects_invalid_ollama_timeout(self) -> None:
        parser = build_parser()
        for value in ("0", "-5", "soon"):
            with self.subTest(value=value):
                with contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit):
                        parser.parse_args(["replay", "--log", "x.log", "--ollama-timeout", value])


if __name__ == "__main__":
    unittest.main()
