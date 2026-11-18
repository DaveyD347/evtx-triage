"""Core data models shared by loaders, detections and output writers."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any, Dict, List, Optional


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError:
            choices = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity {value!r} (expected one of: {choices})") from None

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name.lower()


@dataclass
class Event:
    """A normalised Windows event, independent of the on-disk format it came from."""

    event_id: int
    timestamp: datetime
    computer: str = ""
    channel: str = ""
    provider: str = ""
    record_id: Optional[int] = None
    data: Dict[str, Any] = field(default_factory=dict)
    source: str = ""  # file the event was read from

    def get(self, key: str, default: str = "") -> str:
        """Return an EventData field as a string ('' when missing or null)."""
        value = self.data.get(key)
        if value is None:
            return default
        return str(value)

    def get_int(self, key: str, default: Optional[int] = None) -> Optional[int]:
        """Return an EventData field as an int, accepting decimal or 0x-prefixed hex."""
        raw = self.data.get(key)
        if raw is None or raw == "":
            return default
        if isinstance(raw, bool):
            return int(raw)
        if isinstance(raw, int):
            return raw
        text = str(raw).strip()
        try:
            return int(text, 16) if text.lower().startswith("0x") else int(text)
        except ValueError:
            return default

    @property
    def ref(self) -> Dict[str, Any]:
        """Compact pointer back to this event, used as finding evidence."""
        return {
            "event_id": self.event_id,
            "timestamp": iso(self.timestamp),
            "computer": self.computer,
            "record_id": self.record_id,
            "source": self.source,
        }


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    timestamp: datetime
    summary: str
    mitre: List[str] = field(default_factory=list)
    host: str = ""
    user: str = ""
    source_ip: str = ""
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": str(self.severity),
            "timestamp": iso(self.timestamp),
            "host": self.host,
            "user": self.user,
            "source_ip": self.source_ip,
            "mitre": list(self.mitre),
            "summary": self.summary,
            "details": self.details,
            "evidence": self.evidence,
        }


def iso(ts: datetime) -> str:
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_timestamp(value: Any) -> datetime:
    """Parse the timestamp formats seen in EVTX/JSON/CSV exports into an aware UTC datetime."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    text = str(value).strip()
    if not text:
        raise ValueError("empty timestamp")
    text = text.replace(" ", "T", 1) if "T" not in text and " " in text else text
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    # Python < 3.11 only accepts up to 6 fractional digits; Windows emits 7 or 9.
    if "." in text:
        head, _, rest = text.partition(".")
        digits = ""
        i = 0
        while i < len(rest) and rest[i].isdigit():
            digits += rest[i]
            i += 1
        text = f"{head}.{(digits + '000000')[:6]}{rest[i:]}"
    ts = datetime.fromisoformat(text)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)
