import json
import struct
from datetime import datetime, timedelta, timezone

import pytest

from evtx_triage.evtx import EvtxError, EvtxReader, EvtxWriter, WriterEvent, record_to_dict
from evtx_triage.evtx.binxml import decode_value, format_filetime, format_guid, format_sid
from evtx_triage.evtx.reader import CHUNK_SIZE, FILE_HEADER_SIZE

T0 = datetime(2026, 1, 1, 8, 30, 15, 123456, tzinfo=timezone.utc)


def build(n=5, **extra):
    w = EvtxWriter()
    for i in range(n):
        data = {"TargetUserName": f"user{i}", "LogonType": "3", "IpAddress": "192.0.2.5", **extra}
        w.add(WriterEvent(4624, T0 + timedelta(seconds=i), "WS01", "Security",
                          "Microsoft-Windows-Security-Auditing", data))
    return w


def test_roundtrip_fields():
    reader = EvtxReader(build(3).to_bytes())
    records = [record_to_dict(r) for r in reader.records()]
    assert len(records) == 3
    first = records[0]
    assert first["EventID"] == 4624
    assert first["Computer"] == "WS01"
    assert first["Channel"] == "Security"
    assert first["Provider"] == "Microsoft-Windows-Security-Auditing"
    assert first["EventRecordID"] == 1
    assert first["TimeCreated"] == "2026-01-01T08:30:15.1234560Z"
    assert first["EventData"] == {"TargetUserName": "user0", "LogonType": "3", "IpAddress": "192.0.2.5"}
    assert reader.stats.warnings == []


def test_templates_are_shared_and_names_reused():
    # Records after the first reference the template instead of redefining it, so they are smaller.
    w = build(2)
    chunk = w.chunks[0].buf
    first_size = struct.unpack_from("<I", chunk, 512 + 4)[0]
    second_size = struct.unpack_from("<I", chunk, 512 + first_size + 4)[0]
    assert second_size < first_size / 2


def test_empty_values_and_userdata():
    w = EvtxWriter()
    w.add(WriterEvent(1102, T0, "DC01", "Security", "Microsoft-Windows-Eventlog",
                      {"SubjectUserName": "bob", "SubjectDomainName": ""}, user_data="LogFileCleared"))
    rec = record_to_dict(next(EvtxReader(w.to_bytes()).records()))
    assert rec["EventData"] == {"SubjectUserName": "bob", "SubjectDomainName": ""}


def test_multiple_chunks():
    w = build(1200, CommandLine="x" * 40)
    assert len(w.chunks) > 1
    reader = EvtxReader(w.to_bytes())
    ids = [r.record_id for r in reader.records()]
    assert ids == list(range(1, 1201))
    assert reader.stats.chunks == len(w.chunks)


def test_checksum_mismatch_is_reported_but_parsed():
    data = bytearray(build(3).to_bytes())
    # Flip a byte inside the first record's payload (a UTF-16 character of a value).
    idx = data.index("user1".encode("utf-16-le"), FILE_HEADER_SIZE)
    data[idx] = ord("X")
    reader = EvtxReader(bytes(data))
    records = list(reader.records())
    assert len(records) == 3
    assert reader.stats.bad_chunk_checksums == 1
    assert any("checksum" in w for w in reader.stats.warnings)


def test_header_checksum_mismatch():
    data = bytearray(build(1).to_bytes())
    data[16] ^= 0xFF  # last chunk number
    reader = EvtxReader(bytes(data))
    assert not reader.header.checksum_ok
    assert len(list(reader.records())) == 1


def test_truncated_file_yields_complete_chunks_only():
    data = build(1200, CommandLine="x" * 40).to_bytes()
    truncated = data[: FILE_HEADER_SIZE + CHUNK_SIZE + 100]
    reader = EvtxReader(truncated)
    records = list(reader.records())
    assert records and records[-1].record_id < 1200
    assert any("truncated" in w for w in reader.stats.warnings)


def test_not_an_evtx_file():
    with pytest.raises(EvtxError):
        EvtxReader(b"MZ" + bytes(4094))


def test_value_formatting():
    assert format_sid(bytes([1, 5, 0, 0, 0, 0, 0, 5]) + struct.pack("<5I", 21, 1, 2, 3, 500)) == \
        "S-1-5-21-1-2-3-500"
    guid = bytes.fromhex("33221100554477668899aabbccddeeff")
    assert format_guid(guid) == "{00112233-4455-6677-8899-AABBCCDDEEFF}"
    assert format_filetime(116444736000000000) == "1970-01-01T00:00:00.0000000Z"
    assert decode_value(0x14, struct.pack("<I", 0x3E7)) == "0x3e7"
    assert decode_value(0x81, "a\x00bc\x00".encode("utf-16-le")) == ["a", "bc"]
    assert decode_value(0x0D, struct.pack("<I", 1)) is True


def test_cross_check_with_reference_parser(tmp_path):
    """If the Rust-backed `evtx` package is installed, it must agree with our reader byte for byte."""
    evtx = pytest.importorskip("evtx")
    path = tmp_path / "x.evtx"
    build(1200, CommandLine="x" * 40).save(path)
    ours = {r.record_id: record_to_dict(r) for r in EvtxReader.open(path).records()}
    count = 0
    for rec in evtx.PyEvtxParser(str(path)).records_json():
        ref = json.loads(rec["data"])["Event"]
        mine = ours[rec["event_record_id"]]
        assert ref["System"]["EventID"] == mine["EventID"]
        assert ref["System"]["Computer"] == mine["Computer"]
        assert {k: str(v) for k, v in ref["EventData"].items()} == mine["EventData"]
        count += 1
    assert count == 1200
