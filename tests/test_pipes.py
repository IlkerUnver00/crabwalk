import itertools
from datetime import datetime, timedelta, timezone

import pytest

from crabwalk.catalog import SECURITY, SYSMON, SYSTEM
from crabwalk.models import NormalizedEvent
from crabwalk.rules import HuntContext, run_rules
from crabwalk.rules.pipes import NamedPipeExecution, stdio_origin

T0 = datetime(2026, 8, 1, 12, 0, 0, tzinfo=timezone.utc)
_rid = itertools.count(1)


def ev(event_id, *, channel, seconds=0, computer="SRV01", **data):
    return NormalizedEvent(
        timestamp=T0 + timedelta(seconds=seconds), channel=channel, provider="test",
        event_id=event_id, record_id=next(_rid), computer=computer, data=data,
        source_file="test.evtx",
    )


def sysmon_pipe(name, *, connect=True, image="System", seconds=0, computer="SRV01"):
    return ev(18 if connect else 17, channel=SYSMON, seconds=seconds, computer=computer,
              PipeName="\\" + name, Image=image)


def ipc(name, *, ip="10.0.0.5", user="admin", seconds=0, computer="SRV01"):
    return ev(5145, channel=SECURITY, seconds=seconds, computer=computer,
              ShareName="\\\\*\\IPC$", RelativeTargetName=name, IpAddress=ip,
              SubjectUserName=user, SubjectDomainName="CORP")


def cw012(*events):
    return run_rules(HuntContext.build(list(events)), [NamedPipeExecution()])


def test_psexec_default_pipe_is_high():
    (finding,) = cw012(sysmon_pipe("PSEXESVC", connect=False, image=r"C:\Windows\PSEXESVC.exe"))
    assert finding.severity == "high"
    assert finding.techniques == ("T1021.002", "T1569.002")
    assert "PsExec" in finding.summary


def test_renamed_psexec_stdio_names_service_and_source_host():
    events = [
        ipc("updater", seconds=0),
        *(ipc(f"updater-ATTACKER-PC-4242-{s}", seconds=1) for s in ("stdin", "stdout", "stderr")),
    ]
    (finding,) = cw012(*events)
    assert finding.src_ip == "10.0.0.5"
    assert finding.src_host == "ATTACKER-PC"
    assert finding.user == "CORP\\admin"
    assert "service 'updater' (renamed)" in finding.summary


def test_stdio_origin_resolves_dashed_service_names_from_the_main_pipe():
    assert stdio_origin("my-svc-WS-07-99-stdin", {"my-svc"}) == ("my-svc", "WS-07", "99")
    # without a main pipe the first token is taken as the service
    assert stdio_origin("PSEXESVC-WS-07-99-stdout", set()) == ("PSEXESVC", "WS-07", "99")
    assert stdio_origin("lsass", set()) is None


def test_tool_pipe_followed_by_service_install_is_critical():
    (finding,) = cw012(
        sysmon_pipe("PSEXESVC", seconds=0),
        ev(7045, channel=SYSTEM, seconds=3, ServiceName="PSEXESVC", ImagePath=r"%SystemRoot%\PSEXESVC.exe"),
    )
    assert finding.severity == "critical"
    assert "T1543.003" in finding.techniques


def test_remote_svcctl_alone_is_medium():
    (finding,) = cw012(ipc("svcctl"))
    assert finding.severity == "medium"
    assert finding.src_ip == "10.0.0.5"


def test_remote_scm_pipe_plus_command_line_service_is_critical():
    # Metasploit psexec on a Sysmon-only host: SCM pipe, then the ImagePath write.
    (finding,) = cw012(
        sysmon_pipe("ntsvcs", seconds=0),
        ev(13, channel=SYSMON, seconds=1, Image=r"C:\Windows\system32\services.exe",
           TargetObject=r"HKLM\System\CurrentControlSet\services\hello\ImagePath",
           Details="%COMSPEC% /b /c start /b /min powershell.exe -nop -w hidden"),
    )
    assert finding.severity == "critical"
    assert "ImagePath of service 'hello' set to %COMSPEC%" in finding.summary


def test_remote_scm_pipe_plus_ordinary_service_is_high():
    (finding,) = cw012(
        ipc("svcctl", seconds=0),
        ev(7045, channel=SYSTEM, seconds=20, ServiceName="Backup", ImagePath=r"C:\Program Files\b\b.exe"),
    )
    assert finding.severity == "high"


def test_known_tool_binary_dropped_on_admin_share_is_critical():
    drop = ev(5145, channel=SECURITY, seconds=-10, ShareName="\\\\*\\ADMIN$",
              RelativeTargetName=r"System32\RemComSvc.exe", IpAddress="10.0.0.5")
    (finding,) = cw012(drop, ipc("svcctl"))
    assert finding.severity == "critical"
    assert "T1570" in finding.techniques


def test_drop_from_another_source_does_not_corroborate():
    drop = ev(5145, channel=SECURITY, seconds=-10, ShareName="\\\\*\\ADMIN$",
              RelativeTargetName="tool.exe", IpAddress="10.9.9.9")
    (finding,) = cw012(drop, ipc("svcctl"))
    assert finding.severity == "medium"


def test_atsvc_followed_by_task_maps_to_scheduled_task():
    (finding,) = cw012(
        ipc("atsvc", seconds=0),
        ev(4698, channel=SECURITY, seconds=2, TaskName="\\CYAlyNSS", SubjectLogonId="0x1"),
    )
    assert finding.severity == "high"
    assert "T1053.005" in finding.techniques
    assert "T1569.002" not in finding.techniques


def test_local_access_to_control_pipes_is_ignored():
    assert cw012(
        ipc("svcctl", ip="127.0.0.1"),
        ipc("svcctl", ip="::1", seconds=5),
        sysmon_pipe("svcctl", image=r"C:\Windows\system32\services.exe", seconds=9),
    ) == []


def test_random_hex_pipe_only_counts_when_remote():
    (finding,) = cw012(sysmon_pipe("46a676ab7f179e511e30dd2dc41bd388"))
    assert finding.severity == "medium"
    local = sysmon_pipe("46a676ab7f179e511e30dd2dc41bd388", image=r"C:\app\app.exe")
    assert cw012(local) == []


def test_pipe_enumeration_burst_is_not_execution():
    sweep = ["atsvc", "ntsvcs", "lsass", "srvsvc", "wkssvc", "browser", "eventlog"]
    assert cw012(*(sysmon_pipe(p, seconds=i) for i, p in enumerate(sweep))) == []


def test_enumeration_guard_never_hides_tool_pipes():
    sweep = ["lsass", "srvsvc", "wkssvc", "browser", "eventlog", "PSEXESVC"]
    (finding,) = cw012(*(sysmon_pipe(p, seconds=i) for i, p in enumerate(sweep)))
    assert "PsExec" in finding.summary


def test_one_run_is_one_finding_and_separate_runs_are_separate():
    run = [sysmon_pipe("PSEXESVC", connect=False), sysmon_pipe("PSEXESVC")]
    run += [sysmon_pipe(f"PSEXESVC-WS1-77-{s}", connect=c) for s in ("stdin", "stdout") for c in (False, True)]
    later = [sysmon_pipe("PSEXESVC", seconds=600)]
    findings = cw012(*run, *later)
    assert len(findings) == 2


def test_concurrent_clients_are_credited_separately():
    # A monitoring box polls svcctl all hour; mid-hour an attacker drops a binary,
    # opens svcctl and installs a service. The attack must be the attacker's.
    polling = [ipc("svcctl", ip="10.0.0.5", user="svc_mon", seconds=s) for s in range(0, 3600, 60)]
    attack = [
        ev(5145, channel=SECURITY, seconds=1800, ShareName="\\\\*\\ADMIN$",
           RelativeTargetName="evil.exe", IpAddress="10.6.6.6"),
        ipc("svcctl", ip="10.6.6.6", user="eve", seconds=1810),
        ev(7045, channel=SYSTEM, seconds=1811, ServiceName="evilsvc", ImagePath=r"C:\Windows\evil.exe"),
    ]
    findings = {f.src_ip: f for f in cw012(*polling, *attack)}
    eve = findings["10.6.6.6"]
    assert eve.user == "CORP\\eve"
    assert eve.timestamp == T0 + timedelta(seconds=1810)
    assert "evilsvc" in eve.summary and "evil.exe" in eve.summary
    assert {"T1543.003", "T1570"} <= set(eve.techniques)
    poller = findings["10.0.0.5"]
    assert poller.severity == "medium"
    assert "evilsvc" not in poller.summary


@pytest.mark.parametrize("phase", [0, 10, 11, 15, 50])
def test_poller_tick_next_to_the_install_cannot_steal_it(phase):
    polling = [ipc("svcctl", ip="10.0.0.5", user="svc_mon", seconds=s) for s in range(phase, 3600, 60)]
    attack = [
        ipc("svcctl", ip="10.6.6.6", user="eve", seconds=1810),
        ev(7045, channel=SYSTEM, seconds=1811, ServiceName="evilsvc", ImagePath=r"C:\Windows\evil.exe"),
    ]
    findings = {f.src_ip: f for f in cw012(*polling, *attack)}
    assert "evilsvc" in findings["10.6.6.6"].summary
    assert "evilsvc" not in findings["10.0.0.5"].summary


def test_sysmon_and_security_copies_join_their_client_despite_other_clients():
    def both(pipe, ip, seconds, **kw):
        return [ipc(pipe, ip=ip, seconds=seconds, **kw), sysmon_pipe(pipe, seconds=seconds)]

    events = [
        *both("svcctl", "10.0.0.7", 1750, user="ops"),  # unrelated admin
        ev(5145, channel=SECURITY, seconds=1795, ShareName="\\\\*\\ADMIN$",
           RelativeTargetName="PSEXESVC.exe", IpAddress="10.6.6.6"),
        *both("svcctl", "10.6.6.6", 1805, user="eve"),
        ev(7045, channel=SYSTEM, seconds=1806, ServiceName="PSEXESVC", ImagePath=r"%SystemRoot%\PSEXESVC.exe"),
        sysmon_pipe("PSEXESVC", connect=False, image=r"C:\Windows\PSEXESVC.exe", seconds=1806.5),
        *both("PSEXESVC", "10.6.6.6", 1807, user="eve"),
    ]
    findings = cw012(*events)
    assert sorted(f.src_ip for f in findings) == ["10.0.0.7", "10.6.6.6"]  # no address-less twin
    (eve,) = [f for f in findings if f.src_ip == "10.6.6.6"]
    assert eve.severity == "critical"
    assert "PSEXESVC.exe" in eve.summary and "install of service 'PSEXESVC'" in eve.summary


def test_remote_beacon_link_stays_lateral_despite_local_post_ex_pipes():
    events = [
        sysmon_pipe("msagent_4a2b", connect=False, image=r"C:\Windows\System32\rundll32.exe", seconds=0),
        sysmon_pipe("msagent_4a2b", seconds=2),  # linked from another host over SMB
        sysmon_pipe("postex_8f3c", connect=False, image=r"C:\Windows\System32\rundll32.exe", seconds=30),
        sysmon_pipe("postex_8f3c", image=r"C:\Windows\System32\rundll32.exe", seconds=31),
    ]
    (finding,) = cw012(*events)
    assert finding.title == "Remote execution over named pipes"
    assert "T1021.002" in finding.techniques


def test_service_reconfiguration_does_not_corroborate_remote_scm_access():
    image = r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MsMpEng.exe"
    (finding,) = cw012(
        ipc("svcctl", seconds=55),
        ev(13, channel=SYSMON, seconds=90, Image=r"C:\Windows\system32\services.exe",
           TargetObject=r"HKLM\System\CurrentControlSet\Services\WinDefend\ImagePath", Details=image),
    )
    assert finding.severity == "medium"
    assert "T1543.003" not in finding.techniques


def test_other_clients_background_pipes_do_not_hide_an_attack():
    background = [ipc(p, ip=f"10.0.1.{10 + i}", seconds=i * 5)
                  for i, p in enumerate(["lsarpc", "samr", "netlogon", "srvsvc", "wkssvc"])]
    (finding,) = cw012(*background, ipc("svcctl", ip="10.6.6.6", user="eve", seconds=12))
    assert finding.src_ip == "10.6.6.6"


def test_local_psexec_client_marks_local_execution():
    (finding,) = cw012(
        sysmon_pipe("PSEXESVC", connect=False, image=r"C:\Windows\PSEXESVC.exe"),
        sysmon_pipe("PSEXESVC", image=r"C:\Tools\PsExec64.exe", seconds=1),
    )
    assert finding.title.startswith("Local execution")
    assert finding.severity == "medium"
    assert "T1021.002" not in finding.techniques
    assert (finding.src_ip, finding.src_host) == (None, None)
    assert "psexec64.exe" in finding.summary


def test_stdio_pipes_naming_this_host_are_local():
    (finding,) = cw012(
        sysmon_pipe("svc-SRV01-12-stdin", connect=False, image=r"C:\Windows\svc.exe",
                    computer="SRV01.corp.local"),
    )
    assert finding.title.startswith("Local execution")


def test_sysmon_and_security_views_of_one_run_are_one_finding():
    (finding,) = cw012(
        sysmon_pipe("PSEXESVC", connect=False, image=r"C:\Windows\PSEXESVC.exe", seconds=0),
        sysmon_pipe("PSEXESVC", seconds=1),  # arrived over SMB
        ipc("PSEXESVC", ip="10.0.0.5", seconds=1),
    )
    assert finding.src_ip == "10.0.0.5"
    assert "T1021.002" in finding.techniques


def test_ordinary_remote_pipes_are_quiet():
    assert cw012(ipc("srvsvc"), ipc("lsarpc", seconds=1), ipc("samr", seconds=2)) == []


def test_anonymous_pipe_is_ignored():
    assert cw012(ev(17, channel=SYSMON, PipeName="<Anonymous Pipe>", Image="x.exe")) == []
