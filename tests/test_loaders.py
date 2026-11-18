import json

from evtx_triage.loaders import detect_format, from_mapping, load


def test_flat_record_with_top_level_fields():
    e = from_mapping({"EventID": "4624", "TimeCreated": "2026-01-01T10:00:00.1234567Z",
                      "Computer": "WS01", "LogonType": "3", "Message": "ignored"})
    assert e.event_id == 4624
    assert e.timestamp.microsecond == 123456
    assert e.data == {"LogonType": "3"}


def test_evtx_dump_shape():
    rec = {"Event": {"System": {"EventID": {"#text": 4769, "#attributes": {"Qualifiers": 0}},
                                "TimeCreated": {"#attributes": {"SystemTime": "2026-01-01T10:00:00Z"}},
                                "Computer": "DC01", "Channel": "Security",
                                "Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing"}},
                                "EventRecordID": 7},
                     "EventData": {"ServiceName": "svc_sql", "TicketEncryptionType": "0x17"}}}
    e = from_mapping(rec)
    assert (e.event_id, e.computer, e.record_id) == (4769, "DC01", 7)
    assert e.provider == "Microsoft-Windows-Security-Auditing"
    assert e.get_int("TicketEncryptionType") == 0x17


def test_winlogbeat_shape():
    rec = {"@timestamp": "2026-01-01T10:00:00.000Z",
           "winlog": {"event_id": 10, "computer_name": "WS01", "channel": "Microsoft-Windows-Sysmon/Operational",
                      "provider_name": "Microsoft-Windows-Sysmon", "record_id": 99,
                      "event_data": {"TargetImage": "C:\\Windows\\system32\\lsass.exe"}}}
    e = from_mapping(rec)
    assert e.event_id == 10 and e.record_id == 99
    assert e.get("TargetImage").endswith("lsass.exe")


def test_record_without_event_id_is_skipped():
    assert from_mapping({"TimeCreated": "2026-01-01T10:00:00Z"}) is None


def test_json_array_jsonl_and_bad_lines(tmp_path, caplog):
    arr = tmp_path / "a.json"
    arr.write_text(json.dumps([{"EventID": 1, "TimeCreated": "2026-01-01 10:00:00"}]))
    jl = tmp_path / "b.jsonl"
    jl.write_text('{"EventID": 2, "TimeCreated": "2026-01-01T10:00:01Z"}\nnot json\n'
                  '{"EventID": 3, "TimeCreated": "2026-01-01T10:00:02Z"}\n')
    events = load([tmp_path])
    assert sorted(e.event_id for e in events) == [1, 2, 3]


def test_csv_with_eventdata_blob(tmp_path):
    p = tmp_path / "x.csv"
    p.write_text('TimeCreated,EventID,Computer,EventData\n'
                 '2026-01-01T10:00:00Z,4625,DC01,"{""TargetUserName"": ""bob""}"\n')
    (e,) = load([p])
    assert e.event_id == 4625 and e.get("TargetUserName") == "bob"


def test_detect_format_by_content(tmp_path, samples_dir):
    p = tmp_path / "noext"
    p.write_bytes((samples_dir / "attack_scenario.evtx").read_bytes())
    assert detect_format(p) == "evtx"
    p.write_text('{"EventID": 1}')
    assert detect_format(p) == "json"


def test_same_records_in_two_formats_are_deduplicated(samples_dir):
    both = load([samples_dir / "attack_scenario.evtx", samples_dir / "attack_scenario.jsonl"])
    assert len(both) == len(load([samples_dir / "attack_scenario.evtx"]))
