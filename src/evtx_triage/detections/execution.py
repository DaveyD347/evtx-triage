"""Execution and defence evasion: suspicious PowerShell and event log clearing."""

from __future__ import annotations

import base64
import binascii
import re
from typing import Iterable, List, Optional, Tuple

from ..models import Event, Finding, Severity
from .base import Rule, account

# (pattern, weight, label). Weights are additive; see PowerShellAbuse.score.
POWERSHELL_INDICATORS: List[Tuple[re.Pattern, int, str]] = [
    (re.compile(r"\binvoke-mimikatz\b|sekurlsa::", re.I), 10, "Mimikatz"),
    (re.compile(r"amsiutils|amsiinitfailed|amsiscanbuffer", re.I), 8, "AMSI bypass"),
    (re.compile(r"\b(iex|invoke-expression)\b", re.I), 3, "Invoke-Expression"),
    (re.compile(r"downloadstring|downloadfile|downloaddata|net\.webclient|invoke-webrequest|\biwr\b|"
                r"start-bitstransfer", re.I), 3, "download cradle"),
    (re.compile(r"frombase64string", re.I), 2, "base64 decode"),
    (re.compile(r"reflection\.assembly\]::load|virtualalloc|getprocaddress|kernel32", re.I), 4, "in-memory loader"),
    (re.compile(r"\binvoke-(shellcode|reflectivepeinjection|kerberoast|smbexec|wmiexec|tokenmanipulation)\b|"
                r"\bpowerview\b|get-domainuser\b.*-spn", re.I), 7, "offensive framework cmdlet"),
    (re.compile(r"(?:^|\s)-(?:w|win|window|windowstyle)\s+hid", re.I), 2, "hidden window"),
    (re.compile(r"(?:^|\s)-(?:nop|noprofile)\b", re.I), 1, "no profile"),
    (re.compile(r"(?:^|\s)-(?:ep|exec|executionpolicy)\s+bypass", re.I), 2, "execution policy bypass"),
    (re.compile(r"(?:^|\s)-(?:e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}", re.I), 3, "encoded command"),
    (re.compile(r"\[char\]\s*\d+\s*\+|-join\s*\(?\s*\[char", re.I), 2, "char-code obfuscation"),
]
ENCODED_ARG = re.compile(r"(?:^|\s)-(?:e|ec|enc|encodedcommand)\s+([A-Za-z0-9+/=]{16,})", re.I)
POWERSHELL_IMAGE = re.compile(r"(powershell(_ise)?|pwsh)(\.exe)?\b", re.I)


def decode_encoded_command(text: str) -> Optional[str]:
    """Decode the UTF-16LE base64 payload of ``-EncodedCommand``, if present."""
    match = ENCODED_ARG.search(text)
    if not match:
        return None
    blob = match.group(1)
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
        return raw.decode("utf-16-le", errors="strict")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None


def score(text: str) -> Tuple[int, List[str]]:
    total, labels = 0, []
    for pattern, weight, label in POWERSHELL_INDICATORS:
        if pattern.search(text):
            total += weight
            labels.append(label)
    return total, labels


class PowerShellAbuse(Rule):
    id = "EXEC-POWERSHELL"
    title = "Suspicious PowerShell"
    severity = Severity.MEDIUM
    tactic = "execution"
    mitre = ("T1059.001", "T1027")
    event_ids = frozenset({4104, 4103, 1, 4688})
    description = (
        "Scores PowerShell script blocks (4104) and PowerShell process command lines (Sysmon 1, "
        "4688) against weighted indicators: download cradles, IEX, encoded commands, AMSI "
        "bypasses, in-memory loaders and offensive cmdlets. -EncodedCommand payloads are decoded "
        "and scored too. Score >= 4 is medium, >= 7 high, >= 10 critical."
    )

    def process(self, event: Event) -> Iterable[Finding]:
        if event.event_id in (4104, 4103):
            text = event.get("ScriptBlockText") or event.get("Payload")
            user = event.get("UserId") or event.get("User")
            where = "script block"
        else:
            image = event.get("Image") or event.get("NewProcessName")
            text = event.get("CommandLine") or event.get("ProcessCommandLine")
            if not POWERSHELL_IMAGE.search(image) and not POWERSHELL_IMAGE.search(text.split(" ", 1)[0]):
                return ()
            user = event.get("User") or account(event, "SubjectUserName", "SubjectDomainName")
            where = "command line"
        if not text:
            return ()
        decoded = decode_encoded_command(text)
        points, labels = score(text)
        if decoded:
            extra, extra_labels = score(decoded)
            points += extra
            labels += [f"{label} (decoded)" for label in extra_labels]
        if points < 4:
            return ()
        sev = Severity.CRITICAL if points >= 10 else Severity.HIGH if points >= 7 else Severity.MEDIUM
        yield self.finding(
            event, f"PowerShell {where} scored {points}: {', '.join(labels)}",
            severity=sev, user=user, score=points, indicators=labels,
            snippet=text[:300], decoded_command=(decoded or "")[:500],
        )


class LogCleared(Rule):
    id = "DE-LOG-CLEARED"
    title = "Event log cleared"
    severity = Severity.HIGH
    tactic = "defense-evasion"
    mitre = ("T1070.001",)
    event_ids = frozenset({1102, 104})
    description = "Security log cleared (1102) or another log cleared (System 104)."

    def process(self, event: Event) -> Iterable[Finding]:
        if event.event_id == 104 and "eventlog" not in event.provider.lower():
            return ()
        name = event.get("Channel") or ("Security" if event.event_id == 1102 else "an event log")
        user = account(event, "SubjectUserName", "SubjectDomainName")
        yield self.finding(event, f"{name} log cleared by {user or 'unknown user'}", user=user)
