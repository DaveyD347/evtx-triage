"""Detection rule registry."""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence, Type

from .base import Config, Rule
from .credential_access import AsRepRoasting, CredentialDumpCommand, Kerberoasting, LsassAccess, PasswordSpray
from .execution import LogCleared, PowerShellAbuse
from .lateral_movement import AdminShareAccess, LogonFanOut, PassTheHash, RemoteServiceInstall

ALL_RULES: List[Type[Rule]] = [
    PasswordSpray,
    Kerberoasting,
    AsRepRoasting,
    LsassAccess,
    CredentialDumpCommand,
    PassTheHash,
    LogonFanOut,
    AdminShareAccess,
    RemoteServiceInstall,
    PowerShellAbuse,
    LogCleared,
]
RULES_BY_ID: Dict[str, Type[Rule]] = {r.id: r for r in ALL_RULES}


def build_rules(config: Optional[Config] = None, select: Optional[Sequence[str]] = None,
                exclude: Optional[Sequence[str]] = None) -> List[Rule]:
    """Instantiate rules. ``select``/``exclude`` accept rule IDs or ID prefixes (e.g. ``LM-``)."""

    def matches(rule_id: str, patterns: Sequence[str]) -> bool:
        return any(rule_id.upper().startswith(p.upper()) for p in patterns)

    chosen = []
    for cls in ALL_RULES:
        if select and not matches(cls.id, select):
            continue
        if exclude and matches(cls.id, exclude):
            continue
        chosen.append(cls(config))
    if select and not chosen:
        raise ValueError(f"no rules match {', '.join(select)}")
    return chosen


__all__ = ["ALL_RULES", "RULES_BY_ID", "Config", "Rule", "build_rules"]
