"""Command line interface: ``evtx-triage scan``, ``evtx-triage rules``, ``evtx-triage dump``."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import textwrap
from datetime import timedelta
from typing import List, Optional

from . import __version__, logging_setup
from .detections import ALL_RULES, Config, build_rules
from .engine import CHAIN_RULE_ID, Engine
from .loaders import LoadError, load
from .models import Severity, iso
from .output import write_report

log = logging.getLogger("evtx_triage.cli")

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


def _minutes(value: str) -> timedelta:
    try:
        minutes = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number of minutes: {value!r}") from None
    if minutes <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return timedelta(minutes=minutes)


def _severity(value: str) -> Severity:
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="evtx-triage",
        description="Triage Windows Security / Sysmon event logs for credential theft and lateral movement.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--log-level", default="warning", choices=["debug", "info", "warning", "error"])
    parser.add_argument("--log-format", default="text", choices=["text", "json"],
                        help="format of the tool's own diagnostics on stderr")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="analyse logs and report findings",
                          description="Analyse EVTX / JSON / CSV logs (files or directories) as one timeline.")
    scan.add_argument("paths", nargs="+", help="log files or directories")
    scan.add_argument("-f", "--format", default="text", choices=["text", "json", "jsonl", "csv"])
    scan.add_argument("-o", "--output", help="write the report to a file instead of stdout")
    scan.add_argument("--input-format", default="auto", choices=["auto", "evtx", "json", "csv"])
    scan.add_argument("--min-severity", type=_severity, default=Severity.LOW, metavar="LEVEL",
                      help="hide findings below LEVEL (info|low|medium|high|critical; default low)")
    scan.add_argument("--fail-on", type=_severity, metavar="LEVEL",
                      help="exit with status 1 if any finding is at or above LEVEL (for CI / scripts)")
    scan.add_argument("--rules", nargs="+", metavar="ID", help="only run these rule IDs or prefixes (e.g. LM-)")
    scan.add_argument("--exclude", nargs="+", metavar="ID", help="skip these rule IDs or prefixes")
    scan.add_argument("--no-correlation", action="store_true", help="do not build attack-chain findings")
    scan.add_argument("-v", "--verbose", action="store_true", help="show finding details and evidence")
    scan.add_argument("--color", default="auto", choices=["auto", "always", "never"])
    tuning = scan.add_argument_group("tuning")
    tuning.add_argument("--window", type=_minutes, default=Config.window, metavar="MIN",
                        help="correlation window in minutes for stateful rules (default 10)")
    tuning.add_argument("--chain-window", type=_minutes, default=Config.chain_window, metavar="MIN",
                        help="window in minutes for attack-chain correlation (default 120)")
    tuning.add_argument("--kerberoast-min-spns", type=int, default=Config.kerberoast_min_spns, metavar="N")
    tuning.add_argument("--spray-min-accounts", type=int, default=Config.spray_min_accounts, metavar="N")
    tuning.add_argument("--bruteforce-min-failures", type=int, default=Config.bruteforce_min_failures, metavar="N")
    tuning.add_argument("--fanout-min-hosts", type=int, default=Config.fanout_min_hosts, metavar="N")

    rules = sub.add_parser("rules", help="list detection rules")
    rules.add_argument("--json", action="store_true")

    dump = sub.add_parser("dump", help="print parsed events as JSON Lines (useful for EVTX -> JSON)")
    dump.add_argument("paths", nargs="+")
    dump.add_argument("--input-format", default="auto", choices=["auto", "evtx", "json", "csv"])
    dump.add_argument("--event-id", type=int, nargs="+", metavar="ID", help="only these event IDs")
    return parser


def cmd_scan(args: argparse.Namespace) -> int:
    config = Config(
        window=args.window, chain_window=args.chain_window,
        kerberoast_min_spns=args.kerberoast_min_spns, spray_min_accounts=args.spray_min_accounts,
        bruteforce_min_failures=args.bruteforce_min_failures, fanout_min_hosts=args.fanout_min_hosts,
    )
    rules = build_rules(config, select=args.rules, exclude=args.exclude)
    events = load(args.paths, args.input_format)
    correlate = not args.no_correlation and not (args.exclude and any(
        CHAIN_RULE_ID.startswith(x.upper()) for x in args.exclude))
    result = Engine(rules, config, correlate=correlate).run(events)
    shown = [f for f in result.findings if f.severity >= args.min_severity]
    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="") as fh:
            write_report(result, shown, args.format, fh, color="never", verbose=args.verbose)
    else:
        write_report(result, shown, args.format, sys.stdout, color=args.color, verbose=args.verbose)
    if args.fail_on is not None and any(f.severity >= args.fail_on for f in result.findings):
        return EXIT_FINDINGS
    return EXIT_OK


def cmd_rules(args: argparse.Namespace) -> int:
    rows = [{"id": r.id, "title": r.title, "severity": str(r.severity), "tactic": r.tactic,
             "mitre": list(r.mitre), "event_ids": sorted(r.event_ids), "description": r.description}
            for r in ALL_RULES]
    rows.append({"id": CHAIN_RULE_ID, "title": "Correlated attack chain", "severity": "critical",
                 "tactic": "correlation", "mitre": [], "event_ids": [],
                 "description": "One account with findings in two or more ATT&CK tactics within the chain window."})
    if args.json:
        print(json.dumps(rows, indent=2))
        return EXIT_OK
    for row in rows:
        ids = ",".join(map(str, row["event_ids"])) or "-"
        print(f"{row['id']:<20} {row['severity']:<9} {','.join(row['mitre']) or '-':<20} events {ids}")
        print(f"  {row['title']}")
        for line in textwrap.wrap(row["description"], 92):
            print(f"    {line}")
        print()
    return EXIT_OK


def cmd_dump(args: argparse.Namespace) -> int:
    wanted = set(args.event_id or [])
    for event in load(args.paths, args.input_format):
        if wanted and event.event_id not in wanted:
            continue
        print(json.dumps({
            "EventID": event.event_id, "TimeCreated": iso(event.timestamp), "Computer": event.computer,
            "Channel": event.channel, "Provider": event.provider, "EventRecordID": event.record_id,
            "EventData": event.data,
        }, default=str))
    return EXIT_OK


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    logging_setup.configure(args.log_level, args.log_format)
    try:
        handler = {"scan": cmd_scan, "rules": cmd_rules, "dump": cmd_dump}[args.command]
        return handler(args)
    except BrokenPipeError:  # e.g. piped into `head`: stop quietly
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return EXIT_OK
    except (LoadError, ValueError, OSError) as exc:
        log.error(str(exc))
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
