"""Detection rule base class, shared helpers and tuning configuration."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import ClassVar, FrozenSet, Iterable, Iterator, List, Optional, Sequence, Tuple, TypeVar

from ..models import Event, Finding, Severity

T = TypeVar("T")

NON_USER_ACCOUNTS = {"", "-", "anonymous logon", "system", "local service", "network service"}
LOOPBACK = {"", "-", "127.0.0.1", "::1", "localhost"}


@dataclass
class Config:
    """Thresholds for the stateful rules. Exposed as CLI flags."""

    window: timedelta = timedelta(minutes=10)
    chain_window: timedelta = timedelta(hours=2)
    kerberoast_min_spns: int = 3
    spray_min_accounts: int = 5
    bruteforce_min_failures: int = 10
    fanout_min_hosts: int = 3


class Rule:
    """A detection. Stateless rules emit from ``process``; stateful ones buffer and emit in ``finish``.

    The engine feeds events in timestamp order, only those whose EventID is in
    ``event_ids`` (an empty set means "all events").
    """

    id: ClassVar[str] = ""
    title: ClassVar[str] = ""
    severity: ClassVar[Severity] = Severity.MEDIUM
    tactic: ClassVar[str] = ""
    mitre: ClassVar[Sequence[str]] = ()
    event_ids: ClassVar[FrozenSet[int]] = frozenset()
    description: ClassVar[str] = ""

    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()

    def process(self, event: Event) -> Iterable[Finding]:
        return ()

    def finish(self) -> Iterable[Finding]:
        return ()

    def finding(self, event: Event, summary: str, *, severity: Optional[Severity] = None,
                user: str = "", source_ip: str = "", evidence: Optional[List[Event]] = None,
                timestamp: Optional[datetime] = None, host: Optional[str] = None,
                **details) -> Finding:
        return Finding(
            rule_id=self.id,
            title=self.title,
            severity=severity if severity is not None else self.severity,
            timestamp=timestamp or event.timestamp,
            summary=summary,
            mitre=list(self.mitre),
            host=event.computer if host is None else host,
            user=user,
            source_ip="" if source_ip in LOOPBACK else source_ip,
            evidence=[e.ref for e in (evidence or [event])],
            details={"tactic": self.tactic, **{k: v for k, v in details.items() if v not in (None, "")}},
        )


def account(event: Event, name_field: str = "TargetUserName", domain_field: str = "TargetDomainName") -> str:
    """Return ``DOMAIN\\user`` (or just ``user``) for display."""
    name = event.get(name_field).strip()
    domain = event.get(domain_field).strip()
    if "\\" in name or "@" in name or not domain or domain == "-":
        return name
    return f"{domain}\\{name}"


def norm_user(name: str) -> str:
    """Canonical form used for grouping: lower-case, no domain prefix/suffix."""
    name = name.strip().lower()
    if "\\" in name:
        name = name.rsplit("\\", 1)[1]
    if "@" in name:
        name = name.split("@", 1)[0]
    return name


def is_machine_account(name: str) -> bool:
    return norm_user(name).endswith("$")


def is_interesting_user(name: str) -> bool:
    n = norm_user(name)
    return n not in NON_USER_ACCOUNTS and not n.endswith("$") and not n.startswith("dwm-") and not n.startswith("umfd-")


def windows(items: Sequence[Tuple[datetime, T]], width: timedelta) -> Iterator[List[Tuple[datetime, T]]]:
    """Split time-sorted items into bursts: a new burst starts after a gap wider than ``width``.

    Bursts are what the aggregate rules report on, so one spray campaign yields one
    finding rather than one per sliding-window position.
    """
    burst: List[Tuple[datetime, T]] = []
    for item in items:
        if burst and item[0] - burst[0][0] > width:
            yield burst
            burst = []
        burst.append(item)
    if burst:
        yield burst
