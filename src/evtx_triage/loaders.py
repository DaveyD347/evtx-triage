"""Load events from EVTX, JSON / JSON Lines and CSV into normalised ``Event`` objects.

Supported JSON shapes (auto-detected per record):

* flat:        {"EventID": 4624, "TimeCreated": "...", "Computer": "...", "EventData": {...}}
                (unknown top-level keys are treated as EventData fields)
* evtx_dump:   {"Event": {"System": {...}, "EventData": {...}}}   (evtx / evtx_dump --format json)
* Winlogbeat:  {"@timestamp": "...", "winlog": {"event_id": 4624, "event_data": {...}, ...}}
"""

from __future__ import annotations

import csv
import json
import logging
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Union

from .evtx import EvtxError, EvtxReader, record_to_dict
from .models import Event, parse_timestamp

log = logging.getLogger(__name__)

_SYSTEM_KEYS = {
    "eventid": "EventID", "event_id": "EventID", "id": "EventID",
    "timecreated": "TimeCreated", "systemtime": "TimeCreated", "timestamp": "TimeCreated",
    "@timestamp": "TimeCreated", "time": "TimeCreated", "utctime_event": "TimeCreated",
    "computer": "Computer", "computername": "Computer", "computer_name": "Computer", "hostname": "Computer",
    "channel": "Channel", "logname": "Channel",
    "provider": "Provider", "providername": "Provider", "provider_name": "Provider", "source": "Provider",
    "eventrecordid": "EventRecordID", "record_id": "EventRecordID", "recordid": "EventRecordID",
    "recordnumber": "EventRecordID",
}
_IGNORED_KEYS = {"message", "level", "keywords", "task", "opcode", "version", "eventdata", "userdata"}


class LoadError(ValueError):
    pass


def detect_format(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".evtx":
        return "evtx"
    if suffix in (".json", ".jsonl", ".ndjson"):
        return "json"
    if suffix in (".csv", ".tsv"):
        return "csv"
    with path.open("rb") as fh:
        head = fh.read(8)
    if head.startswith(b"ElfFile"):
        return "evtx"
    if head.lstrip()[:1] in (b"{", b"["):
        return "json"
    return "csv"


def iter_paths(paths: Iterable[Union[str, Path]]) -> Iterator[Path]:
    exts = {".evtx", ".json", ".jsonl", ".ndjson", ".csv", ".tsv"}
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            yield from sorted(f for f in p.rglob("*") if f.is_file() and f.suffix.lower() in exts)
        elif p.exists():
            yield p
        else:
            raise LoadError(f"no such file or directory: {p}")


def load(paths: Iterable[Union[str, Path]], fmt: str = "auto") -> List[Event]:
    events: List[Event] = []
    for path in iter_paths(paths):
        kind = detect_format(path) if fmt == "auto" else fmt
        before = len(events)
        loader = {"evtx": load_evtx, "json": load_json, "csv": load_csv}.get(kind)
        if loader is None:
            raise LoadError(f"unknown format {kind!r}")
        events.extend(loader(path))
        log.info("loaded events", extra={"file": str(path), "format": kind, "events": len(events) - before})
    return dedupe(events)


def dedupe(events: List[Event]) -> List[Event]:
    """Drop repeats of the same record (e.g. one log exported as both EVTX and JSON, or overlapping exports)."""
    seen = set()
    out: List[Event] = []
    for event in events:
        if event.record_id is not None:
            key = (event.computer.lower(), event.channel.lower(), event.record_id, event.event_id, event.timestamp)
            if key in seen:
                continue
            seen.add(key)
        out.append(event)
    if len(out) != len(events):
        log.info("dropped duplicate records", extra={"duplicates": len(events) - len(out)})
    return out


# --- EVTX ------------------------------------------------------------------------
def load_evtx(path: Path) -> Iterator[Event]:
    try:
        reader = EvtxReader.open(path)
    except EvtxError as exc:
        raise LoadError(f"{path}: {exc}") from exc
    for record in reader.records():
        event = from_mapping(record_to_dict(record), str(path))
        if event is not None:
            yield event
    if reader.stats.warnings:
        log.warning("evtx parse warnings", extra={"file": str(path), "warnings": len(reader.stats.warnings),
                                                  "bad_records": reader.stats.bad_records})


# --- JSON ------------------------------------------------------------------------
def load_json(path: Path) -> Iterator[Event]:
    text = path.read_text(encoding="utf-8-sig")
    stripped = text.lstrip()
    records: Iterable[Any]
    if stripped.startswith("["):
        records = json.loads(stripped)
    else:
        try:  # a single JSON object spanning multiple lines
            records = [json.loads(stripped)] if stripped else []
        except json.JSONDecodeError:
            records = _jsonl(text, path)
    for record in records:
        if isinstance(record, dict):
            event = from_mapping(record, str(path))
            if event is not None:
                yield event


def _jsonl(text: str, path: Path) -> Iterator[Any]:
    for lineno, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError as exc:
            log.warning("skipping bad JSON line", extra={"file": str(path), "line": lineno, "error": str(exc)})


# --- CSV ------------------------------------------------------------------------
def load_csv(path: Path) -> Iterator[Event]:
    with path.open(newline="", encoding="utf-8-sig") as fh:
        sample = fh.read(4096)
        fh.seek(0)
        delimiter = "\t" if path.suffix.lower() == ".tsv" or sample.count("\t") > sample.count(",") else ","
        for row in csv.DictReader(fh, delimiter=delimiter):
            mapping: Dict[str, Any] = {k: v for k, v in row.items() if k is not None}
            blob = mapping.pop("EventData", None)
            if blob:
                try:
                    mapping["EventData"] = json.loads(blob)
                except json.JSONDecodeError:
                    pass
            event = from_mapping(mapping, str(path))
            if event is not None:
                yield event


# --- Normalisation ------------------------------------------------------------------
def from_mapping(record: Dict[str, Any], source: str = "") -> Optional[Event]:
    """Convert any supported record shape into an ``Event`` (None if unusable)."""
    if "Event" in record and isinstance(record["Event"], dict):
        record = _from_evtx_dump(record["Event"])
    elif "winlog" in record and isinstance(record["winlog"], dict):
        record = _from_winlogbeat(record)

    system: Dict[str, Any] = {}
    data: Dict[str, Any] = {}
    for key, value in record.items():
        canon = _SYSTEM_KEYS.get(key.lower())
        if canon and canon not in system:
            system[canon] = value
        elif key.lower() in ("eventdata", "userdata", "event_data") and isinstance(value, dict):
            data.update(value)
        elif key.lower() not in _IGNORED_KEYS:
            data[key] = value

    try:
        event_id = int(str(system.get("EventID", "")).strip())
        timestamp = parse_timestamp(system.get("TimeCreated", ""))
    except (TypeError, ValueError):
        log.debug("skipping record without usable EventID/timestamp", extra={"file": source})
        return None
    record_id = system.get("EventRecordID")
    try:
        record_id = int(record_id) if record_id not in (None, "") else None
    except (TypeError, ValueError):
        record_id = None
    return Event(
        event_id=event_id,
        timestamp=timestamp,
        computer=str(system.get("Computer") or ""),
        channel=str(system.get("Channel") or ""),
        provider=str(system.get("Provider") or ""),
        record_id=record_id,
        data={k: _scalar(v) for k, v in data.items()},
        source=source,
    )


def _scalar(value: Any) -> Any:
    if isinstance(value, dict) and "#text" in value:
        return value["#text"]
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    return value


def _from_evtx_dump(event: Dict[str, Any]) -> Dict[str, Any]:
    system = event.get("System", {}) or {}

    def text(v: Any) -> Any:
        return v.get("#text") if isinstance(v, dict) else v

    def attr(v: Any, name: str) -> Any:
        return v.get("#attributes", {}).get(name) if isinstance(v, dict) else None

    data = event.get("EventData") or {}
    if not isinstance(data, dict):
        data = {}
    data = {k: v for k, v in data.items() if not k.startswith("#")}
    user = event.get("UserData")
    if isinstance(user, dict) and user:
        inner = next(iter(user.values()))
        if isinstance(inner, dict):
            data.update({k: v for k, v in inner.items() if not k.startswith("#")})
    return {
        "EventID": text(system.get("EventID")),
        "TimeCreated": attr(system.get("TimeCreated"), "SystemTime"),
        "Computer": system.get("Computer"),
        "Channel": system.get("Channel"),
        "Provider": attr(system.get("Provider"), "Name"),
        "EventRecordID": system.get("EventRecordID"),
        "EventData": data,
    }


def _from_winlogbeat(record: Dict[str, Any]) -> Dict[str, Any]:
    w = record["winlog"]
    data = dict(w.get("event_data") or {})
    data.update(w.get("user_data") or {})
    return {
        "EventID": w.get("event_id"),
        "TimeCreated": record.get("@timestamp"),
        "Computer": w.get("computer_name"),
        "Channel": w.get("channel"),
        "Provider": w.get("provider_name"),
        "EventRecordID": w.get("record_id"),
        "EventData": data,
    }
