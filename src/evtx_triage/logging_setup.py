"""Structured logging for the tool's own diagnostics (always written to stderr).

``--log-format json`` emits one JSON object per line, with any ``extra={...}`` fields
passed to the logger merged in, so a pipeline can ingest parse warnings alongside the
findings.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone

_STANDARD = set(vars(logging.LogRecord("", 0, "", 0, "", (), None))) | {"message", "asctime"}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        doc = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key, value in vars(record).items():
            if key not in _STANDARD and not key.startswith("_"):
                doc[key] = value
        if record.exc_info:
            doc["exc"] = self.formatException(record.exc_info)
        return json.dumps(doc, default=str)


class KeyValueFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        extras = " ".join(f"{k}={v}" for k, v in vars(record).items()
                          if k not in _STANDARD and not k.startswith("_"))
        return f"[{record.levelname.lower()}] {record.getMessage()}" + (f" {extras}" if extras else "")


def configure(level: str = "warning", fmt: str = "text") -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter() if fmt == "json" else KeyValueFormatter())
    root = logging.getLogger("evtx_triage")
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
    root.propagate = False
