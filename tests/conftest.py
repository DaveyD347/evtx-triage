from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from evtx_triage.models import Event

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"
T0 = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def make(event_id, seconds=0, computer="HOST1.corp.example", **data):
    return Event(event_id=event_id, timestamp=T0 + timedelta(seconds=seconds), computer=computer,
                 channel="Security", provider="Microsoft-Windows-Security-Auditing",
                 record_id=int(seconds) + 1, data={k: str(v) for k, v in data.items()})


@pytest.fixture
def samples_dir():
    return SAMPLES
