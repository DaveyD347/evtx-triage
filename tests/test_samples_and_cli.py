import importlib.util
import json

import pytest
from conftest import ROOT, SAMPLES

from evtx_triage.cli import main
from evtx_triage.engine import Engine
from evtx_triage.loaders import load

EXPECTED_RULES = {
    "CRED-SPRAY", "CRED-KERBEROAST", "CRED-ASREPROAST", "CRED-LSASS-ACCESS", "CRED-DUMP-CMDLINE",
    "LM-PASS-THE-HASH", "LM-LOGON-FANOUT", "LM-ADMIN-SHARE", "LM-REMOTE-SERVICE",
    "EXEC-POWERSHELL", "DE-LOG-CLEARED", "CHAIN-ATTACK-PATH",
}


def summarize(findings):
    return sorted((f.rule_id, str(f.severity), f.timestamp.isoformat(), f.host, f.user) for f in findings)


@pytest.mark.parametrize("name", ["attack_scenario.evtx", "attack_scenario.jsonl", "attack_scenario.csv"])
def test_scenario_detects_every_stage(name):
    result = Engine().run(load([SAMPLES / name]))
    assert {f.rule_id for f in result.findings} == EXPECTED_RULES
    chains = {f.user for f in result.findings if f.rule_id == "CHAIN-ATTACK-PATH"}
    assert chains == {"CORP\\alice", "CORP\\adm.jsmith"}


def test_all_input_formats_agree():
    results = [summarize(Engine().run(load([SAMPLES / f"attack_scenario.{ext}"])).findings)
               for ext in ("evtx", "jsonl", "csv")]
    assert results[0] == results[1] == results[2]


def test_benign_baseline_is_quiet():
    result = Engine().run(load([SAMPLES / "baseline_benign.evtx"]))
    assert result.events > 20
    assert result.findings == []


def test_samples_are_reproducible(tmp_path):
    spec = importlib.util.spec_from_file_location("make_samples", ROOT / "scripts" / "make_samples.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.write_all(tmp_path)
    for path in SAMPLES.iterdir():
        if path.suffix in (".evtx", ".jsonl", ".csv"):
            assert (tmp_path / path.name).read_bytes() == path.read_bytes(), path.name


# --- CLI ---------------------------------------------------------------------------------
def test_cli_json_report(capsys):
    assert main(["scan", str(SAMPLES / "attack_scenario.evtx"), "-f", "json", "--min-severity", "high"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["summary"]["events"] == 63
    assert doc["findings"] and all(f["severity"] in ("high", "critical") for f in doc["findings"])


def test_cli_fail_on_exit_code(capsys):
    assert main(["scan", str(SAMPLES / "attack_scenario.evtx"), "--fail-on", "critical", "-f", "jsonl"]) == 1
    assert main(["scan", str(SAMPLES / "baseline_benign.evtx"), "--fail-on", "low"]) == 0


def test_cli_text_and_csv_output(tmp_path, capsys):
    assert main(["scan", str(SAMPLES), "--color", "never", "-v"]) == 0
    text = capsys.readouterr().out
    assert "CHAIN-ATTACK-PATH" in text and "evidence:" in text
    out = tmp_path / "r.csv"
    assert main(["scan", str(SAMPLES / "attack_scenario.csv"), "-f", "csv", "-o", str(out)]) == 0
    assert out.read_text().startswith("timestamp,severity,rule_id")


def test_cli_rule_filter(capsys):
    main(["scan", str(SAMPLES / "attack_scenario.evtx"), "-f", "jsonl", "--rules", "CRED-KERBEROAST"])
    rules = {json.loads(line)["rule_id"] for line in capsys.readouterr().out.splitlines()}
    assert rules == {"CRED-KERBEROAST"}


def test_cli_rules_and_dump(capsys):
    assert main(["rules", "--json"]) == 0
    assert len(json.loads(capsys.readouterr().out)) == 12
    assert main(["dump", str(SAMPLES / "attack_scenario.evtx"), "--event-id", "1102"]) == 0
    (line,) = capsys.readouterr().out.splitlines()
    assert json.loads(line)["EventData"]["SubjectUserName"] == "adm.jsmith"


def test_cli_errors(tmp_path):
    assert main(["scan", str(tmp_path / "missing.evtx")]) == 2
    bad = tmp_path / "bad.evtx"
    bad.write_bytes(b"not an evtx file")
    assert main(["scan", str(bad)]) == 2
