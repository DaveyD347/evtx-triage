"""Lateral movement: Pass-the-Hash, logon fan-out, remote service creation, admin shares."""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Dict, Iterable, List, Tuple

from ..models import Event, Finding, Severity
from .base import LOOPBACK, Rule, account, is_interesting_user, norm_user, windows


class PassTheHash(Rule):
    id = "LM-PASS-THE-HASH"
    title = "Pass-the-Hash logon"
    severity = Severity.HIGH
    tactic = "lateral-movement"
    mitre = ("T1550.002",)
    event_ids = frozenset({4624})
    description = (
        "Two 4624 patterns: (1) LogonType 9 via the seclogo logon process, which is what "
        "Mimikatz sekurlsa::pth produces on the attacker's machine; (2) network logon (type 3) "
        "using NTLM with KeyLength 0 for a user account, the target-side pattern of hash reuse."
    )

    def process(self, event: Event) -> Iterable[Finding]:
        logon_type = event.get("LogonType").strip()
        user = event.get("TargetUserName")
        process = event.get("LogonProcessName").strip().lower()
        package = event.get("AuthenticationPackageName").strip().lower()
        ip = event.get("IpAddress").replace("::ffff:", "")
        if logon_type == "9" and process == "seclogo" and package == "negotiate":
            subject = account(event, "SubjectUserName", "SubjectDomainName")
            outbound = account(event, "TargetOutboundUserName", "TargetOutboundDomainName")
            target = f" with network credentials of {outbound}" if outbound and outbound != "-" else ""
            yield self.finding(
                event,
                f"NewCredentials logon (type 9, seclogo) by {subject}{target}: "
                "sekurlsa::pth pattern on the source host",
                user=subject, impersonated=outbound, side="source",
            )
        elif (logon_type == "3" and package == "ntlm" and event.get("KeyLength").strip() == "0"
              and process.startswith("ntlmssp") and is_interesting_user(user) and ip not in LOOPBACK):
            yield self.finding(
                event,
                f"NTLM network logon as {account(event)} from {ip or event.get('WorkstationName')} "
                f"with KeyLength 0 (possible hash reuse)",
                severity=Severity.MEDIUM, user=account(event), source_ip=ip,
                workstation=event.get("WorkstationName"), side="target",
            )


class LogonFanOut(Rule):
    id = "LM-LOGON-FANOUT"
    title = "One account logging on to many hosts"
    severity = Severity.HIGH
    tactic = "lateral-movement"
    mitre = ("T1021",)
    event_ids = frozenset({4624})
    description = (
        "Network (3) or RDP (10) logons by one user account to several distinct hosts in a short "
        "window. Stateful: correlates events across every log you feed in at once."
    )

    def __init__(self, config=None):
        super().__init__(config)
        self.logons: Dict[str, List[Tuple]] = defaultdict(list)

    def process(self, event: Event) -> Iterable[Finding]:
        user = event.get("TargetUserName")
        if event.get("LogonType").strip() not in ("3", "10") or not is_interesting_user(user):
            return ()
        if event.get("IpAddress").replace("::ffff:", "") in LOOPBACK:
            return ()
        self.logons[norm_user(user)].append((event.timestamp, event))
        return ()

    def finish(self) -> Iterable[Finding]:
        for items in self.logons.values():
            for burst in windows(items, self.config.window):
                events = [e for _, e in burst]
                hosts = sorted({e.computer.lower(): e.computer for e in events if e.computer}.values(),
                               key=str.lower)
                if len(hosts) < self.config.fanout_min_hosts:
                    continue
                sources = sorted({e.get("IpAddress").replace("::ffff:", "") for e in events} - LOOPBACK)
                first = events[0]
                yield self.finding(
                    first, f"{account(first)} logged on to {len(hosts)} hosts ({', '.join(hosts)}) "
                           f"from {', '.join(sources)}",
                    user=account(first), source_ip=sources[0] if len(sources) == 1 else "",
                    evidence=events, host=", ".join(hosts), targets=hosts, sources=sources,
                )


SUSPICIOUS_SERVICE_PATH = [
    (re.compile(r"%comspec%|cmd(\.exe)?\s+/[ck]\b", re.I), "cmd.exe one-liner"),
    (re.compile(r"powershell|pwsh", re.I), "PowerShell"),
    (re.compile(r"\\\\(127\.0\.0\.1|localhost)\\admin\$|\\admin\$\\", re.I), "ADMIN$ share (Impacket/smbexec style)"),
    (re.compile(r"\\(users\\public|windows\\temp|programdata|appdata\\local\\temp)\\", re.I), "staging directory"),
    (re.compile(r"rundll32|regsvr32|mshta", re.I), "LOLBin"),
]
REMOTE_EXEC_SERVICES = re.compile(r"^(psexesvc|paexec|remcomsvc|csexecsvc|btobto)", re.I)


class RemoteServiceInstall(Rule):
    id = "LM-REMOTE-SERVICE"
    title = "Suspicious service installation"
    severity = Severity.HIGH
    tactic = "lateral-movement"
    mitre = ("T1569.002", "T1021.002")
    event_ids = frozenset({7045, 4697})
    description = (
        "7045 / 4697 service installs whose name matches remote execution tools (PsExec, PAExec, "
        "RemCom) or whose image path runs cmd/PowerShell/LOLBins or lives in a staging directory."
    )

    def process(self, event: Event) -> Iterable[Finding]:
        name = event.get("ServiceName")
        path = event.get("ImagePath") or event.get("ServiceFileName")
        reasons = [label for pattern, label in SUSPICIOUS_SERVICE_PATH if pattern.search(path)]
        if REMOTE_EXEC_SERVICES.search(name):
            reasons.insert(0, "remote execution tool service")
        if not reasons:
            return ()
        user = event.get("AccountName") or account(event, "SubjectUserName", "SubjectDomainName")
        yield self.finding(
            event, f"Service '{name}' installed: {path[:160]} ({'; '.join(reasons)})",
            severity=Severity.CRITICAL if len(reasons) > 1 else Severity.HIGH,
            user=user if user.lower() not in ("localsystem", "") else "",
            service_name=name, image_path=path, reasons=reasons,
        )


class AdminShareAccess(Rule):
    id = "LM-ADMIN-SHARE"
    title = "Remote access to administrative share"
    severity = Severity.MEDIUM
    tactic = "lateral-movement"
    mitre = ("T1021.002",)
    event_ids = frozenset({5140, 5145})
    description = "5140/5145 access to ADMIN$, C$ or IPC$-svcctl from a remote address by a user account."

    def __init__(self, config=None):
        super().__init__(config)
        self.seen = set()

    def process(self, event: Event) -> Iterable[Finding]:
        share = event.get("ShareName").upper()
        target = event.get("RelativeTargetName").lower()
        ip = event.get("IpAddress").replace("::ffff:", "")
        user = event.get("SubjectUserName")
        if ip in LOOPBACK or not is_interesting_user(user):
            return ()
        hit = share.endswith(("\\ADMIN$", "\\C$")) or (share.endswith("\\IPC$") and target == "svcctl")
        if not hit:
            return ()
        key = (norm_user(user), event.computer.lower(), share, ip)
        if key in self.seen:  # 5145 fires per file; report each user/host/share/source once
            return ()
        self.seen.add(key)
        what = "service control manager pipe (svcctl)" if target == "svcctl" else share
        yield self.finding(
            event, f"{account(event, 'SubjectUserName', 'SubjectDomainName')} accessed {what} from {ip}",
            user=account(event, "SubjectUserName", "SubjectDomainName"), source_ip=ip, share=share,
        )
