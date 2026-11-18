# evtx-triage

[![CI](https://github.com/DaveyD347/evtx-triage/actions/workflows/ci.yml/badge.svg)](https://github.com/DaveyD347/evtx-triage/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.9%E2%80%933.13-blue)
![Dependencies](https://img.shields.io/badge/runtime%20dependencies-0-brightgreen)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**A Windows Security / Sysmon event log parser and attack triage CLI for blue teamers and incident responders.**

Point it at `.evtx` files (or JSON / CSV exports) from one or many hosts. It merges everything into a single timeline, runs stateful detections for credential theft and lateral movement, and then links related alerts into **attack chains** per account. The output is a prioritised report you can read in a terminal, pipe into `jq`, or load into a SIEM.

* **Its own EVTX parser, written in pure Python.** It decodes the binary format directly (file and chunk headers, CRC32 checks, BinXML templates and substitutions), so there is nothing to compile and no Windows APIs are needed. It runs on Linux, macOS or Windows.
* **Stateful correlation.** It finds sprays, Kerberoasting bursts and logon fan-out across hosts and log files, then chains findings like *spray, then Kerberoast, then LSASS dump, then Pass-the-Hash* into one critical finding.
* **Mapped to MITRE ATT&CK.** Every finding carries technique IDs, a severity, the host, user and source IP, and pointers back to the exact evidence records.
* **Synthetic sample datasets included**, so you can see the tool working in about ten seconds without touching real evidence.

---

## Quick start

```bash
git clone https://github.com/DaveyD347/evtx-triage.git
cd evtx-triage
pip install .            # or: pipx install .
evtx-triage scan samples/attack_scenario.evtx
```

```text
evtx-triage report
  events analysed : 63
  hosts           : DC01.corp.example, FS01.corp.example, SQL01.corp.example, WS01.corp.example, WS02.corp.example
  time range      : 2026-03-14T07:50:00.000000Z  ->  2026-03-14T09:45:00.000000Z
  findings        : critical 8  high 7  medium 6  low 0  info 0

CRITICAL 2026-03-14 09:02:00Z  CRED-SPRAY  Password spraying / brute force
         9 failed logons against 9 accounts from 198.51.100.66 in 56s (spray); followed by successful logon as CORP\alice
         host=DC01.corp.example  user=CORP\alice  src=198.51.100.66  att&ck=T1110.003,T1110.001

CRITICAL 2026-03-14 09:02:00Z  CHAIN-ATTACK-PATH  Correlated attack chain
         CORP\alice linked to 6 findings across credential-access -> execution -> lateral-movement on 2 host(s)
         host=DC01.corp.example, WS01.corp.example  user=CORP\alice  src=198.51.100.66  att&ck=T1003,T1003.001,...
           - 09:02:00 CRED-SPRAY
           - 09:10:04 CRED-KERBEROAST
           - 09:20:00 EXEC-POWERSHELL
           - 09:24:00 CRED-DUMP-CMDLINE
           - 09:24:01 CRED-LSASS-ACCESS
           - 09:30:00 LM-PASS-THE-HASH

HIGH     2026-03-14 09:10:04Z  CRED-KERBEROAST  Kerberoasting (RC4 service tickets for user SPNs)
         alice@CORP.EXAMPLE requested RC4 service tickets for 3 SPNs in 2s
         host=DC01.corp.example  user=alice@CORP.EXAMPLE  src=198.51.100.66  att&ck=T1558.003

CRITICAL 2026-03-14 09:20:00Z  EXEC-POWERSHELL  Suspicious PowerShell
         PowerShell command line scored 12: hidden window, no profile, encoded command, Invoke-Expression (decoded), download cradle (decoded)
         host=WS01.corp.example  user=CORP\alice  att&ck=T1059.001,T1027
...
```

Then compare it with a normal morning on the same fictional network, which should produce no findings:

```bash
evtx-triage scan samples/baseline_benign.evtx
```

## Usage

```bash
# Every log under a directory (EVTX, JSON, JSONL and CSV can be mixed), analysed as one timeline
evtx-triage scan ./collected-logs/

# Only high and critical findings, with details and evidence record numbers
evtx-triage scan Security.evtx Sysmon.evtx --min-severity high -v

# Machine-readable output
evtx-triage scan logs/ -f json  -o report.json     # one document with a summary block
evtx-triage scan logs/ -f jsonl | jq 'select(.severity=="critical")'
evtx-triage scan logs/ -f csv   -o findings.csv

# Use it as a gate in scripts or CI: exit code 1 when anything is high or worse
evtx-triage scan logs/ --fail-on high

# Run only some rules (IDs or prefixes), or exclude some
evtx-triage scan logs/ --rules CRED- LM-PASS-THE-HASH
evtx-triage scan logs/ --exclude EXEC-POWERSHELL

# Tune the stateful rules for your environment
evtx-triage scan logs/ --window 30 --spray-min-accounts 10 --fanout-min-hosts 5

# List the rules, or convert EVTX to JSON Lines for other tools
evtx-triage rules
evtx-triage dump Security.evtx --event-id 4624 4625 > logons.jsonl
```

The tool writes its own diagnostics to stderr, so they never mix with the report. Add `--log-format json` to make them structured (one JSON object per line):

```bash
evtx-triage --log-level info --log-format json scan logs/ -f jsonl > findings.jsonl 2> triage.log
```

Exit codes: `0` success, `1` a finding met `--fail-on`, `2` an input or usage error.

## Detections

| Rule | ATT&CK | Event IDs | What it looks for |
|---|---|---|---|
| `CRED-SPRAY` | T1110.003, T1110.001 | 4625, 4771, 4776, 4624 | Many accounts failing from one source (spray) or many failures on one account (brute force). Becomes **critical** if the same source then logs on successfully. |
| `CRED-KERBEROAST` | T1558.003 | 4769 | RC4/DES service tickets for user (non-`$`) service accounts. A burst across several SPNs from one account is **high**. |
| `CRED-ASREPROAST` | T1558.004 | 4768 | TGTs issued with `PreAuthType 0` using weak encryption. |
| `CRED-LSASS-ACCESS` | T1003.001 | Sysmon 10 | Processes that open `lsass.exe` with `PROCESS_VM_READ`, minus known-good security tooling. **Critical** when `dbghelp`/`dbgcore` is in the call trace or the access mask is full. |
| `CRED-DUMP-CMDLINE` | T1003 | Sysmon 1, 4688 | comsvcs `MiniDump`, Mimikatz commands, procdump of lsass, `reg save` of hives, `ntdsutil ifm`. |
| `LM-PASS-THE-HASH` | T1550.002 | 4624 | Source side: logon type 9 via `seclogo` (Mimikatz `sekurlsa::pth`). Target side: NTLM network logon with `KeyLength 0` for a user account. |
| `LM-LOGON-FANOUT` | T1021 | 4624 | One account making network or RDP logons to N or more distinct hosts within the window. |
| `LM-ADMIN-SHARE` | T1021.002 | 5140, 5145 | Remote access to `ADMIN$`, `C$` or the `svcctl` pipe. Each user, host, share and source combination is reported once. |
| `LM-REMOTE-SERVICE` | T1569.002, T1021.002 | 7045, 4697 | Services that match PsExec, PAExec, RemCom or Impacket, or that run `cmd /c`, PowerShell or LOLBins, or live in staging directories. |
| `EXEC-POWERSHELL` | T1059.001, T1027 | 4104, 4103, Sysmon 1, 4688 | Weighted scoring of download cradles, `IEX`, AMSI bypasses, in-memory loaders and offensive cmdlets. It **decodes `-EncodedCommand` payloads** and scores them too. |
| `DE-LOG-CLEARED` | T1070.001 | 1102, 104 | Security or System log cleared. |
| `CHAIN-ATTACK-PATH` | (all of the above) | | One account with medium-or-higher findings in two or more tactics within `--chain-window` (default 2 hours). Always **critical**. |

Run `evtx-triage rules` for the full descriptions.

## Supported inputs

| Format | Notes |
|---|---|
| `.evtx` | Parsed natively. Dirty or partially written logs are fine: chunks are found from the file size rather than trusting the header, and checksum mismatches are logged as warnings without stopping the parse. |
| JSON / JSONL | Supports a JSON array or one object per line, in any of three shapes: flat (`{"EventID":..., "TimeCreated":..., "EventData":{...}}`), `evtx_dump`/`python-evtx` style (`{"Event":{"System":..., "EventData":...}}`), or Winlogbeat/ECS (`{"@timestamp":..., "winlog":{...}}`). |
| CSV / TSV | Columns `TimeCreated`, `EventID`, `Computer`, `Channel`, `Provider`, and either an `EventData` column holding JSON or one column per field. |

When the same record shows up more than once (for example a log exported as both EVTX and JSON, or two overlapping exports), it is deduplicated by host, channel and record ID.

## How it works

```
 .evtx / .json / .csv
          |
          v
 loaders.py ── evtx/reader.py   file header -> 64 KiB chunks -> records, CRC32 checks
          |    evtx/binxml.py   BinXML tokens, per-chunk template and name caches, typed values
          v
 Event (normalised: id, time, host, channel, EventData)
          |   sorted into one timeline
          v
 engine.py ── rules: process(event) for stateless matches, finish() for windowed aggregation
          |   correlate_chains(): group by account, chain tactics within the window
          v
 output.py   text | json | jsonl | csv
```

**EVTX in brief.** A file is a 4 KiB header followed by 64 KiB chunks. Each chunk keeps its own string table and template table. An event record holds a FILETIME and a fragment of *Binary XML*, which is almost always a **template instance**. The template is an XML skeleton with numbered substitution slots, defined once per chunk. The record supplies a typed value array (SIDs, GUIDs, FILETIMEs, hex integers, nested BinXML and so on) that fills those slots. `binxml.py` decodes the token stream, caches templates by chunk offset, and resolves the substitutions into a small element tree. `reader.py` then flattens that tree into System fields plus an `EventData` dictionary.

**Correctness checks.** The reader was compared field by field against the Rust-backed [`evtx`](https://pypi.org/project/evtx/) parser on 146 records from public attack-sample logs, and every field matched. The repository also includes an EVTX **writer** (`evtx/writer.py`) that produces valid chunks, CRCs and shared templates. The test suite round-trips through it, and when the `evtx` package is installed it cross-checks the output against that independent parser.

## Sample datasets

Everything in `samples/` is **synthetic**: a fictional `CORP` domain, documentation-range IPs (RFC 5737), and made-up users. Field names and values follow what Windows and Sysmon really log. Regenerate the files with `python scripts/make_samples.py`; the output is byte-for-byte reproducible and a test checks that.

| File | Contents |
|---|---|
| `baseline_benign.evtx` | 33 events from a normal morning: interactive logons, AES Kerberos, a couple of typos, admin PowerShell, Defender reading LSASS, a vendor updater service. Expected findings: **none**. |
| `attack_scenario.evtx` | The baseline plus a 30 event intrusion: spray, then Kerberoast and AS-REP roast, then an encoded PowerShell stager with an AMSI bypass, then a comsvcs LSASS dump, then Pass-the-Hash to three servers, then PsExec and smbexec-style services, then ntdsutil, then clearing the Security log. |
| `attack_scenario.jsonl` / `.csv` | The same scenario in the flat JSON and CSV formats. The tests assert that all three formats produce identical findings. |

For real-world practice data, the community [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) collection works well with this tool.

## Exporting logs from Windows

```powershell
# Copy live logs (run elevated)
wevtutil epl Security C:\triage\Security.evtx
wevtutil epl "Microsoft-Windows-Sysmon/Operational" C:\triage\Sysmon.evtx
wevtutil epl "Microsoft-Windows-PowerShell/Operational" C:\triage\PowerShell.evtx
wevtutil epl System C:\triage\System.evtx
```

Several detections depend on audit policy. In particular, enable *Audit Kerberos Service Ticket Operations* (4769), *Audit Logon* (4624/4625), *Audit Detailed File Share* (5145), PowerShell Script Block Logging (4104), and Sysmon with ProcessAccess (event 10) configured for `lsass.exe`.

## Development

```bash
pip install -e ".[dev]"
pytest              # 53 tests: parser, loaders, every rule, end-to-end scenario, CLI
ruff check .
```

### Writing a rule

```python
from evtx_triage.detections.base import Rule
from evtx_triage.models import Severity

class NewLocalAdmin(Rule):
    id = "PERSIST-LOCAL-ADMIN"
    title = "User added to local Administrators"
    severity = Severity.MEDIUM
    tactic = "persistence"
    mitre = ("T1098",)
    event_ids = frozenset({4732})

    def process(self, event):
        if event.get("TargetSid") == "S-1-5-32-544":
            yield self.finding(event, f"{event.get('MemberName')} added to Administrators",
                               user=event.get("SubjectUserName"))
```

Add it to `ALL_RULES` in `detections/__init__.py`, then add a positive and a negative test in `tests/test_detections.py`. Stateful rules buffer events in `process()` and emit from `finish()`. The `windows()` helper splits time-sorted events into bursts.

## Limitations

* This is a triage tool, not a SIEM. It loads the selected logs into memory, which is fine for host collections (hundreds of MB) but not for months of domain-wide data.
* Detections are heuristics. Legacy RC4 service accounts, admin tooling such as PsExec, and NTLM-heavy environments can produce true-positive-but-expected findings. Use `--exclude` and the tuning flags.
* Event message strings (the `Message` column in Event Viewer) are not rendered, because those come from provider DLLs on the source system. Only the structured fields are used.

## License

[MIT](LICENSE)
