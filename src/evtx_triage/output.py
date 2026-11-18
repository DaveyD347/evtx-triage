"""Report writers: human-readable text, JSON, JSON Lines and CSV."""

from __future__ import annotations

import csv
import io
import json
import os
import sys
from typing import IO, List, Optional

from . import __version__
from .engine import TriageResult
from .models import Finding, Severity, iso

_COLORS = {
    Severity.CRITICAL: "\033[1;97;41m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[37m",
}
_RESET, _DIM, _BOLD = "\033[0m", "\033[2m", "\033[1m"


def use_color(stream: IO[str], mode: str = "auto") -> bool:
    if mode == "always":
        return True
    if mode == "never" or os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def render_text(result: TriageResult, findings: List[Finding], color: bool = False,
                verbose: bool = False) -> str:
    def c(code: str, text: str) -> str:
        return f"{code}{text}{_RESET}" if color else text

    out = io.StringIO()
    counts = {str(s): 0 for s in sorted(Severity, reverse=True)}
    for f in findings:
        counts[str(f.severity)] += 1
    out.write(c(_BOLD, "evtx-triage report") + "\n")
    out.write(f"  events analysed : {result.events}\n")
    out.write(f"  hosts           : {', '.join(result.hosts) or '-'}\n")
    out.write(f"  time range      : {result.first_event or '-'}  ->  {result.last_event or '-'}\n")
    out.write("  findings        : " + "  ".join(
        c(_COLORS[Severity.parse(k)], f"{k} {v}") if v else f"{k} {v}" for k, v in counts.items()) + "\n\n")

    if not findings:
        out.write("No findings at or above the selected severity.\n")
        return out.getvalue()

    for f in findings:
        sev = f"{str(f.severity).upper():<8}"
        out.write(f"{c(_COLORS[f.severity], sev)} {f.timestamp:%Y-%m-%d %H:%M:%S}Z  "
                  f"{c(_BOLD, f.rule_id)}  {f.title}\n")
        out.write(f"         {f.summary}\n")
        meta = []
        if f.host:
            meta.append(f"host={f.host}")
        if f.user:
            meta.append(f"user={f.user}")
        if f.source_ip:
            meta.append(f"src={f.source_ip}")
        if f.mitre:
            meta.append(f"att&ck={','.join(f.mitre)}")
        out.write("         " + c(_DIM, "  ".join(meta)) + "\n")
        if f.rule_id.startswith("CHAIN-"):
            for step in f.details.get("steps", []):
                out.write("           " + c(_DIM, f"- {step}") + "\n")
        if verbose:
            for key, value in f.details.items():
                if key in ("tactic", "steps") or value in ([], "", None):
                    continue
                out.write("         " + c(_DIM, f"{key}: {value}") + "\n")
            for ev in f.evidence[:10]:
                out.write("         " + c(_DIM, f"evidence: {ev['event_id']} rec#{ev['record_id']} "
                                                f"{ev['computer']} {ev['timestamp']}") + "\n")
            if len(f.evidence) > 10:
                out.write("         " + c(_DIM, f"... {len(f.evidence) - 10} more events") + "\n")
        out.write("\n")
    return out.getvalue()


def render_json(result: TriageResult, findings: List[Finding]) -> str:
    counts = {str(s): 0 for s in sorted(Severity, reverse=True)}
    for f in findings:
        counts[str(f.severity)] += 1
    doc = {
        "tool": "evtx-triage",
        "version": __version__,
        "summary": {
            "events": result.events,
            "hosts": result.hosts,
            "first_event": result.first_event,
            "last_event": result.last_event,
            "rules": result.rules,
            "findings": counts,
        },
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(doc, indent=2) + "\n"


def render_jsonl(findings: List[Finding]) -> str:
    return "".join(json.dumps(f.to_dict(), separators=(",", ":")) + "\n" for f in findings)


def render_csv(findings: List[Finding]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(["timestamp", "severity", "rule_id", "title", "host", "user", "source_ip",
                     "mitre", "summary", "evidence_count"])
    for f in findings:
        writer.writerow([iso(f.timestamp), str(f.severity), f.rule_id, f.title, f.host, f.user,
                         f.source_ip, ";".join(f.mitre), f.summary, len(f.evidence)])
    return buf.getvalue()


def write_report(result: TriageResult, findings: List[Finding], fmt: str,
                 stream: Optional[IO[str]] = None, color: str = "auto", verbose: bool = False) -> None:
    stream = stream or sys.stdout
    if fmt == "text":
        stream.write(render_text(result, findings, use_color(stream, color), verbose))
    elif fmt == "json":
        stream.write(render_json(result, findings))
    elif fmt == "jsonl":
        stream.write(render_jsonl(findings))
    elif fmt == "csv":
        stream.write(render_csv(findings))
    else:
        raise ValueError(f"unknown output format {fmt!r}")
