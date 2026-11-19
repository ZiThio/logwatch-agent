from __future__ import annotations

import hashlib
import ipaddress
import re
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Deque


_RFC3164_PREFIX = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r"\s+(?P<host>\S+)\s+(?P<message>.*)$"
)
_KEY_VALUE = re.compile(r"""(?P<key>[A-Za-z_][\w.-]*)=(?P<value>"[^"]*"|'[^']*'|\S+)""")
# "from 192.0.2.10" (sshd and others) or "client: 192.0.2.10" (nginx error log).
_SOURCE_IN_MESSAGE = re.compile(
    r"\b(?:from|client:)\s+(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f:]+)\b",
    re.IGNORECASE,
)
_ISO_DATE_ONLY = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_ISO_TIME = re.compile(r"^\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?$")
# Explicit firewall verdicts, from an ``action=`` attribute or the first message token.
_DENY_ACTIONS = {"deny", "denied", "drop", "dropped", "block", "blocked", "reject", "rejected"}
_ALLOW_ACTIONS = {"allow", "allowed", "accept", "accepted", "permit", "permitted", "pass"}
# Free-text fallback: uppercase verdicts (as firewalls usually write them) or
# unambiguous past-tense phrases. Lowercase "drop"/"deny" alone are too common
# in ordinary messages ("connection dropped", "policy=deny-default").
_DENY_UPPER = re.compile(r"\b(DENY|DENIED|DROP|DROPPED|BLOCK|BLOCKED|REJECT|REJECTED)\b")
_DENY_PHRASE = re.compile(r"\b(denied|blocked|rejected)\b", re.IGNORECASE)
# The last two alternatives are nginx basic-auth failures (wrong password, unknown user).
_AUTH_FAILURE = re.compile(
    r"\b(authentication failed|login failed|failed password|invalid password"
    r"|password mismatch|user \"[^\"]*\" was not found)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class LogEvent:
    timestamp: datetime
    hostname: str
    category: str
    source_ip: str | None
    message: str
    raw: str

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["timestamp"] = self.timestamp.isoformat()
        return value


@dataclass
class Alert:
    alert_id: str
    rule_id: str
    title: str
    severity: str
    started_at: datetime
    source_ip: str | None
    event_count: int
    evidence: list[str]
    analysis: dict[str, object] | None = None

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["started_at"] = self.started_at.isoformat()
        return value


def _is_firewall_deny(message: str, attributes: dict[str, str]) -> bool:
    action = attributes.get("action")
    if action is None:
        tokens = message.split(maxsplit=1)
        first = tokens[0].lower() if tokens else ""
        if first in _DENY_ACTIONS or first in _ALLOW_ACTIONS:
            action = first
    if action is not None:
        return action.lower() in _DENY_ACTIONS
    # Ignore key=value pairs so values such as "policy=deny-default" don't match.
    free_text = _KEY_VALUE.sub(" ", message)
    return bool(_DENY_UPPER.search(free_text) or _DENY_PHRASE.search(free_text))


def _valid_ip(candidate: str | None) -> str | None:
    if candidate is None:
        return None
    candidate = candidate.rstrip(",;")
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def parse_log_line(line: str, *, year: int | None = None) -> LogEvent | None:
    """Parse ISO-8601-prefixed and common RFC3164-style syslog lines."""
    raw = line.rstrip("\r\n")
    if not raw.strip():
        return None

    parts = raw.split(maxsplit=2)
    if len(parts) < 3:
        return None

    timestamp_text = parts[0]
    hostname, message = parts[1], parts[2]
    if _ISO_DATE_ONLY.match(parts[0]):
        # "YYYY-MM-DD HH:MM:SS host message": a date alone is never accepted,
        # otherwise every event that day would collapse onto midnight.
        parts = raw.split(maxsplit=3)
        if len(parts) < 4 or not _ISO_TIME.match(parts[1]):
            return None
        timestamp_text = f"{parts[0]}T{parts[1]}"
        hostname, message = parts[2], parts[3]

    timestamp: datetime
    try:
        timestamp = datetime.fromisoformat(timestamp_text.replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
    except ValueError:
        match = _RFC3164_PREFIX.match(raw)
        if match is None:
            return None
        current_year = year or datetime.now(timezone.utc).year
        try:
            timestamp = datetime.strptime(
                f"{current_year} {match.group('timestamp')}", "%Y %b %d %H:%M:%S"
            ).replace(tzinfo=timezone.utc)
        except ValueError:
            return None
        hostname, message = match.group("host"), match.group("message")

    attributes = {
        match.group("key").lower(): match.group("value").strip("\"'")
        for match in _KEY_VALUE.finditer(message)
    }
    if _is_firewall_deny(message, attributes):
        category = "firewall_deny"
    elif _AUTH_FAILURE.search(message):
        category = "authentication_failure"
    else:
        category = "other"

    source_ip = _valid_ip(
        attributes.get("src")
        or attributes.get("src_ip")
        or attributes.get("source_ip")
    )
    if source_ip is None:
        source_ip = next(
            (
                ip
                for found in _SOURCE_IN_MESSAGE.finditer(message)
                if (ip := _valid_ip(found.group("ip"))) is not None
            ),
            None,
        )
    return LogEvent(
        timestamp=timestamp,
        hostname=hostname,
        category=category,
        source_ip=source_ip,
        message=message,
        raw=raw,
    )


@dataclass(frozen=True)
class DetectionRule:
    rule_id: str
    category: str
    threshold: int
    window_seconds: int
    severity: str
    title: str


DEFAULT_RULES = (
    DetectionRule(
        rule_id="firewall-deny-burst",
        category="firewall_deny",
        threshold=3,
        window_seconds=60,
        severity="medium",
        title="Firewall deny burst",
    ),
    DetectionRule(
        rule_id="authentication-failure-burst",
        category="authentication_failure",
        threshold=5,
        window_seconds=60,
        severity="high",
        title="Repeated authentication failures",
    ),
)


class RuleDetector:
    """Detect configured bursts and suppress repeats during a cooldown."""

    def __init__(
        self,
        rules: tuple[DetectionRule, ...] = DEFAULT_RULES,
        *,
        cooldown_seconds: int = 300,
    ) -> None:
        self.rules = rules
        self.cooldown = timedelta(seconds=cooldown_seconds)
        self._events: dict[tuple[str, str], Deque[LogEvent]] = defaultdict(deque)
        self._last_alert: dict[tuple[str, str], datetime] = {}

    def observe(self, event: LogEvent) -> list[Alert]:
        alerts: list[Alert] = []
        for rule in self.rules:
            if event.category != rule.category:
                continue
            source = event.source_ip or event.hostname
            key = (rule.rule_id, source)
            events = self._events[key]
            events.append(event)
            cutoff = event.timestamp - timedelta(seconds=rule.window_seconds)
            while events and events[0].timestamp < cutoff:
                events.popleft()
            if len(events) < rule.threshold:
                continue

            last_alert = self._last_alert.get(key)
            if last_alert is not None and event.timestamp - last_alert < self.cooldown:
                continue

            evidence_events = list(events)[-rule.threshold :]
            started_at = evidence_events[0].timestamp
            digest = hashlib.sha256(
                f"{rule.rule_id}|{source}|{started_at.isoformat()}".encode("utf-8")
            ).hexdigest()[:16]
            alerts.append(
                Alert(
                    alert_id=digest,
                    rule_id=rule.rule_id,
                    title=f"{rule.title} from {source}",
                    severity=rule.severity,
                    started_at=started_at,
                    source_ip=event.source_ip,
                    event_count=len(evidence_events),
                    evidence=[item.raw for item in evidence_events],
                )
            )
            self._last_alert[key] = event.timestamp
        return alerts
