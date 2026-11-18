"""Credential access: Kerberoasting, AS-REP roasting, LSASS access, password spraying."""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Dict, Iterable, List, Tuple

from ..models import Event, Finding, Severity
from .base import LOOPBACK, Rule, account, is_interesting_user, norm_user, windows

WEAK_KERBEROS_ETYPES = {0x17: "RC4-HMAC", 0x18: "RC4-HMAC-EXP", 0x1: "DES-CBC-CRC", 0x3: "DES-CBC-MD5"}


class Kerberoasting(Rule):
    id = "CRED-KERBEROAST"
    title = "Kerberoasting (RC4 service tickets for user SPNs)"
    severity = Severity.HIGH
    tactic = "credential-access"
    mitre = ("T1558.003",)
    event_ids = frozenset({4769})
    description = (
        "4769 service ticket requests using RC4/DES for non-machine service accounts. One account "
        "requesting tickets for several such SPNs in a short window is the classic Rubeus/"
        "GetUserSPNs pattern; a single request is reported at lower severity."
    )

    def __init__(self, config=None):
        super().__init__(config)
        self.requests: Dict[str, List[Tuple]] = defaultdict(list)

    def process(self, event: Event) -> Iterable[Finding]:
        etype = event.get_int("TicketEncryptionType")
        service = event.get("ServiceName")
        status = event.get_int("Status", 0)
        if etype not in WEAK_KERBEROS_ETYPES or status != 0:
            return ()
        if not service or service.endswith("$") or service.lower() == "krbtgt":
            return ()
        requester = event.get("TargetUserName")
        if not is_interesting_user(requester):
            return ()
        self.requests[norm_user(requester)].append((event.timestamp, event))
        return ()

    def finish(self) -> Iterable[Finding]:
        for items in self.requests.values():
            for burst in windows(items, self.config.window):
                events = [e for _, e in burst]
                services = sorted({e.get("ServiceName") for e in events})
                first = events[0]
                ips = sorted({e.get("IpAddress").replace("::ffff:", "") for e in events} - LOOPBACK)
                aggregated = len(services) >= self.config.kerberoast_min_spns
                yield self.finding(
                    first,
                    (f"{account(first)} requested RC4 service tickets for {len(services)} SPNs "
                     f"in {_span(events)}" if aggregated else
                     f"{account(first)} requested an RC4 service ticket for {', '.join(services)}"),
                    severity=Severity.HIGH if aggregated else Severity.MEDIUM,
                    user=account(first), source_ip=ips[0] if ips else "", evidence=events,
                    services=services, encryption=WEAK_KERBEROS_ETYPES[first.get_int("TicketEncryptionType")],
                )


class AsRepRoasting(Rule):
    id = "CRED-ASREPROAST"
    title = "AS-REP roasting (TGT without pre-authentication)"
    severity = Severity.HIGH
    tactic = "credential-access"
    mitre = ("T1558.004",)
    event_ids = frozenset({4768})
    description = "4768 TGT issued with PreAuthType 0 (DONT_REQ_PREAUTH) and a weak encryption type."

    def process(self, event: Event) -> Iterable[Finding]:
        if event.get("PreAuthType").strip() != "0" or event.get_int("Status", 0) != 0:
            return ()
        etype = event.get_int("TicketEncryptionType")
        if etype not in WEAK_KERBEROS_ETYPES:
            return ()
        ip = event.get("IpAddress").replace("::ffff:", "")
        yield self.finding(
            event, f"TGT for {account(event)} issued without pre-authentication ({WEAK_KERBEROS_ETYPES[etype]})",
            user=account(event), source_ip=ip, encryption=WEAK_KERBEROS_ETYPES[etype],
        )


# Access masks that let a process read LSASS memory (PROCESS_VM_READ = 0x10).
LSASS_READ_MASK = 0x10
LSASS_ALLOWED_SOURCES = re.compile(
    r"\\(msmpeng|mssense|csrss|wininit|lsm|services|svchost|taskmgr|vmtoolsd|wmiprvse|"
    r"senseir|csfalconservice)\.exe$", re.I,
)


class LsassAccess(Rule):
    id = "CRED-LSASS-ACCESS"
    title = "LSASS memory access (credential dumping)"
    severity = Severity.HIGH
    tactic = "credential-access"
    mitre = ("T1003.001",)
    event_ids = frozenset({10})
    description = (
        "Sysmon 10 ProcessAccess on lsass.exe with a VM_READ access mask from an unexpected "
        "process (Mimikatz, procdump, comsvcs MiniDump, etc.)."
    )

    def process(self, event: Event) -> Iterable[Finding]:
        if not event.get("TargetImage").lower().endswith("\\lsass.exe"):
            return ()
        mask = event.get_int("GrantedAccess", 0) or 0
        source = event.get("SourceImage")
        if not mask & LSASS_READ_MASK or LSASS_ALLOWED_SOURCES.search(source):
            return ()
        trace = event.get("CallTrace")
        sev = Severity.CRITICAL if ("dbghelp" in trace.lower() or "dbgcore" in trace.lower()
                                     or mask in (0x1FFFFF, 0x1F3FFF)) else Severity.HIGH
        yield self.finding(
            event, f"{_basename(source)} opened lsass.exe with access 0x{mask:x}",
            severity=sev, user=event.get("SourceUser"), source_image=source, granted_access=f"0x{mask:x}",
        )


CRED_DUMP_CMDLINE = [
    (re.compile(r"comsvcs(\.dll)?[\s,\"']+#?(minidump|24)\b", re.I), "comsvcs.dll MiniDump"),
    (re.compile(r"sekurlsa::|lsadump::|kerberos::(ptt|golden)|privilege::debug", re.I), "Mimikatz command"),
    (re.compile(r"procdump(64)?(\.exe)?\b.*\blsass", re.I), "procdump of lsass"),
    (re.compile(r"\breg(\.exe)?\s+save\s+hklm\\(sam|security|system)\b", re.I), "registry hive export"),
    (re.compile(r"ntdsutil.*\bifm\b|vssadmin.*create\s+shadow", re.I), "NTDS.dit extraction"),
]


class CredentialDumpCommand(Rule):
    id = "CRED-DUMP-CMDLINE"
    title = "Credential dumping command line"
    severity = Severity.CRITICAL
    tactic = "credential-access"
    mitre = ("T1003",)
    event_ids = frozenset({1, 4688})
    description = "Process creation (Sysmon 1 / 4688) whose command line matches known credential dumping tooling."

    def process(self, event: Event) -> Iterable[Finding]:
        cmd = event.get("CommandLine") or event.get("ProcessCommandLine")
        for pattern, label in CRED_DUMP_CMDLINE:
            if pattern.search(cmd):
                yield self.finding(
                    event, f"{label}: {cmd[:160]}",
                    user=event.get("User") or account(event, "SubjectUserName", "SubjectDomainName"),
                    command_line=cmd, technique=label,
                )
                return


class PasswordSpray(Rule):
    id = "CRED-SPRAY"
    title = "Password spraying / brute force"
    severity = Severity.HIGH
    tactic = "credential-access"
    mitre = ("T1110.003", "T1110.001")
    event_ids = frozenset({4625, 4771, 4776, 4624})
    description = (
        "Failed logons (4625/4771/4776) grouped by source. Many distinct accounts from one source "
        "is spraying; many failures for one account is brute force. A successful 4624 from the "
        "same source during the burst escalates the finding to critical."
    )

    def __init__(self, config=None):
        super().__init__(config)
        self.failures: Dict[str, List[Tuple]] = defaultdict(list)
        self.successes: Dict[str, List[Event]] = defaultdict(list)

    @staticmethod
    def _source(event: Event) -> str:
        ip = event.get("IpAddress").replace("::ffff:", "")
        if ip not in LOOPBACK:
            return ip
        return (event.get("WorkstationName") or event.get("Workstation")).strip("\\ ")

    def process(self, event: Event) -> Iterable[Finding]:
        source = self._source(event)
        if not source or source in LOOPBACK:
            return ()
        user = event.get("TargetUserName")
        if event.event_id == 4624:
            if event.get("LogonType") in ("3", "10") and is_interesting_user(user):
                self.successes[source].append(event)
            return ()
        if event.event_id == 4771 and event.get_int("Status") != 0x18:  # 0x18 = bad password
            return ()
        if event.event_id == 4776 and event.get_int("Status", 0) == 0:
            return ()
        if not user or user == "-":
            return ()
        self.failures[source].append((event.timestamp, event))
        return ()

    def finish(self) -> Iterable[Finding]:
        cfg = self.config
        for source, items in self.failures.items():
            for burst in windows(items, cfg.window):
                events = [e for _, e in burst]
                users = sorted({norm_user(e.get("TargetUserName")) for e in events})
                spray = len(users) >= cfg.spray_min_accounts
                brute = not spray and len(events) >= cfg.bruteforce_min_failures
                if not (spray or brute):
                    continue
                start, end = events[0].timestamp, events[-1].timestamp + cfg.window
                hits = [s for s in self.successes.get(source, [])
                        if start <= s.timestamp <= end and norm_user(s.get("TargetUserName")) in users]
                compromised = sorted({account(s) for s in hits})
                kind = "spray" if spray else "brute force"
                summary = (f"{len(events)} failed logons against {len(users)} accounts from {source} "
                           f"in {_span(events)} ({kind})")
                if compromised:
                    summary += f"; followed by successful logon as {', '.join(compromised)}"
                yield self.finding(
                    events[0], summary,
                    severity=Severity.CRITICAL if compromised else (Severity.HIGH if spray else Severity.MEDIUM),
                    user=compromised[0] if compromised else (users[0] if brute else ""),
                    source_ip=source, evidence=events + hits, host=_hosts(events),
                    pattern=kind, targeted_accounts=users, compromised_accounts=compromised,
                )


def _basename(path: str) -> str:
    return path.replace("/", "\\").rsplit("\\", 1)[-1]


def _span(events: List[Event]) -> str:
    seconds = int((events[-1].timestamp - events[0].timestamp).total_seconds())
    return f"{seconds}s" if seconds < 120 else f"{seconds // 60}m"


def _hosts(events: List[Event]) -> str:
    return ", ".join(sorted({e.computer for e in events if e.computer}))
