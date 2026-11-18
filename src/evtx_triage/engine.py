"""Runs rules over a timeline of events and correlates findings into attack chains."""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence

from .detections import Config, Rule, build_rules
from .detections.base import norm_user
from .models import Event, Finding, Severity

log = logging.getLogger(__name__)

CHAIN_RULE_ID = "CHAIN-ATTACK-PATH"
CHAIN_TACTICS = ("credential-access", "lateral-movement", "execution", "defense-evasion")


@dataclass
class TriageResult:
    findings: List[Finding]
    events: int
    hosts: List[str]
    first_event: Optional[str] = None
    last_event: Optional[str] = None
    rules: List[str] = field(default_factory=list)

    def counts(self) -> Dict[str, int]:
        out = {str(s): 0 for s in sorted(Severity, reverse=True)}
        for f in self.findings:
            out[str(f.severity)] += 1
        return out


class Engine:
    def __init__(self, rules: Optional[Sequence[Rule]] = None, config: Optional[Config] = None,
                 correlate: bool = True):
        self.config = config or Config()
        self.rules = list(rules) if rules is not None else build_rules(self.config)
        self.correlate = correlate

    def run(self, events: Iterable[Event]) -> TriageResult:
        timeline = sorted(events, key=lambda e: (e.timestamp, e.record_id or 0))
        by_id: Dict[int, List[Rule]] = defaultdict(list)
        catch_all: List[Rule] = []
        for rule in self.rules:
            if rule.event_ids:
                for eid in rule.event_ids:
                    by_id[eid].append(rule)
            else:
                catch_all.append(rule)

        findings: List[Finding] = []
        for event in timeline:
            for rule in by_id.get(event.event_id, []) + catch_all:
                findings.extend(rule.process(event))
        for rule in self.rules:
            findings.extend(rule.finish())
        if self.correlate:
            findings.extend(correlate_chains(findings, self.config))
        findings.sort(key=lambda f: (f.timestamp, -int(f.severity)))
        log.info("triage complete", extra={"events": len(timeline), "findings": len(findings)})
        return TriageResult(
            findings=findings,
            events=len(timeline),
            hosts=sorted({e.computer for e in timeline if e.computer}, key=str.lower),
            first_event=timeline[0].ref["timestamp"] if timeline else None,
            last_event=timeline[-1].ref["timestamp"] if timeline else None,
            rules=[r.id for r in self.rules],
        )


def correlate_chains(findings: List[Finding], config: Config) -> List[Finding]:
    """Raise one critical finding per account whose findings span two or more ATT&CK tactics.

    Example: a Kerberoasting burst followed within the chain window by Pass-the-Hash logons
    and a PsExec service under the same account is a far stronger signal than any single alert.
    """
    by_user: Dict[str, List[Finding]] = defaultdict(list)
    for f in findings:
        user = norm_user(f.user)
        if user and f.details.get("tactic") in CHAIN_TACTICS and f.severity >= Severity.MEDIUM:
            by_user[user].append(f)

    chains: List[Finding] = []
    for items in by_user.values():
        items.sort(key=lambda f: f.timestamp)
        group: List[Finding] = []
        for f in items + [None]:  # sentinel flushes the last group
            if f is not None and (not group or f.timestamp - group[0].timestamp <= config.chain_window):
                group.append(f)
                continue
            tactics = []
            for g in group:
                if g.details["tactic"] not in tactics:
                    tactics.append(g.details["tactic"])
            if len(tactics) >= 2:
                hosts = sorted({h.strip().lower(): h.strip() for g in group
                                for h in g.host.split(",") if h.strip()}.values(), key=str.lower)
                steps = [f"{g.timestamp:%H:%M:%S} {g.rule_id}" for g in group]
                chains.append(Finding(
                    rule_id=CHAIN_RULE_ID,
                    title="Correlated attack chain",
                    severity=Severity.CRITICAL,
                    timestamp=group[0].timestamp,
                    summary=(f"{group[0].user} linked to {len(group)} findings across "
                             f"{' -> '.join(tactics)} on {len(hosts)} host(s)"),
                    mitre=sorted({m for g in group for m in g.mitre}),
                    host=", ".join(hosts),
                    user=group[0].user,
                    source_ip=next((g.source_ip for g in group if g.source_ip), ""),
                    evidence=[],
                    details={"tactic": "correlation", "tactics": tactics, "steps": steps,
                             "rules": sorted({g.rule_id for g in group})},
                ))
            group = [f] if f is not None else []
    return chains
