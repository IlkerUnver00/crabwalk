"""CW-016: RDP session hijacking with tscon."""

import itertools
from datetime import datetime, timedelta, timezone

from crabwalk.catalog import SECURITY, SYSMON, SYSTEM, TS_LSM
from crabwalk.models import NormalizedEvent
from crabwalk.rules import HuntContext, run_rules
from crabwalk.rules.rdp import RdpSessionHijack

T0 = datetime(2026, 8, 1, 12, 0, 0, tzinfo=timezone.utc)
_rid = itertools.count(1)
HIJACK = "cmd.exe /k tscon 2 /dest rdp-tcp#14"


def ev(event_id, *, channel=SECURITY, seconds=0, computer="WEF", **data):
    return NormalizedEvent(
        timestamp=T0 + timedelta(seconds=seconds), channel=channel, provider="test",
        event_id=event_id, record_id=next(_rid), computer=computer, data=data, source_file="test.evtx",
    )


def service(binary=HIJACK, seconds=0, **kw):
    return ev(4697, seconds=seconds, ServiceName="rdphijack2", ServiceFileName=binary,
              SubjectUserName="user", SubjectDomainName="CORP", ServiceAccount="LocalSystem", **kw)


def tscon_4688(command="tscon  2 /dest rdp-tcp#14", seconds=4, logon="0x3e7"):
    return ev(4688, seconds=seconds, NewProcessName=r"C:\Windows\System32\tscon.exe", CommandLine=command,
              ParentProcessName=r"C:\Windows\System32\cmd.exe", SubjectUserName="WEF$",
              SubjectDomainName="CORP", SubjectLogonId=logon)


def reconnect(session="RDP-Tcp#14", seconds=10, account="Administrator"):
    return ev(4778, seconds=seconds, AccountName=account, AccountDomain="CORP", LogonID="0x9deb4d",
              SessionName=session, ClientName="DESKTOP-RKEBDDR", ClientAddress="192.168.56.1")


def cw016(*events):
    return run_rules(HuntContext.build(list(events)), [RdpSessionHijack()])


def test_service_tscon_as_system_and_the_reconnect_are_one_critical_hijack():
    # the shape of Yamato Security's T1563.002 sample
    (finding,) = cw016(service(), tscon_4688(), reconnect())
    assert (finding.rule_id, finding.severity) == ("CW-016", "critical")
    assert finding.techniques == ("T1563.002", "T1543.003")
    assert finding.user == "CORP\\user"  # who installed the service, not SYSTEM
    assert (finding.src_ip, finding.src_host) == ("192.168.56.1", "DESKTOP-RKEBDDR")
    assert finding.action == ("took over CORP\\Administrator's session 2 with tscon as SYSTEM through "
                              "service 'rdphijack2' and attached it to the RDP connection of DESKTOP-RKEBDDR")
    assert [e.event_id for e in finding.evidence] == [4697, 4688, 4778]


def test_sysmon_tscon_as_system_with_a_tsl_reconnect():
    run = ev(1, channel=SYSMON, seconds=1, Image=r"C:\Windows\System32\tscon.exe", CommandLine="tscon.exe 3",
             ParentImage=r"C:\Windows\System32\cmd.exe", User="NT AUTHORITY\\SYSTEM", LogonId="0x3e7")
    back = ev(25, channel=TS_LSM, seconds=3, User="CORP\\alice", SessionID="3", Address="10.0.0.66")
    (finding,) = cw016(run, back)
    assert finding.severity == "critical"
    assert finding.src_ip == "10.0.0.66"
    assert "CORP\\alice's session 3" in finding.action
    assert "TS-LSM 25 shows it reconnected from 10.0.0.66" in finding.summary


def test_a_user_switching_between_their_own_sessions_is_quiet():
    # without SYSTEM or the owner's password tscon can only move the caller's own session
    assert cw016(tscon_4688(command="tscon 3", logon="0x5555")) == []
    assert cw016(tscon_4688(command="tscon 1 /dest:console", logon="0x5555"),
                 ev(4778, seconds=5, AccountName="alice", AccountDomain="CORP", SessionName="Console",
                    ClientName="Unknown", ClientAddress="LOCAL")) == []


def test_tscon_with_a_password_and_no_reconnect_stays_high():
    (finding,) = cw016(tscon_4688(command="tscon 2 /dest:rdp-tcp#5 /password:Summer2026", logon="0x5555"))
    assert finding.severity == "high"
    assert "no reconnect logged" in finding.summary
    assert (finding.src_ip, finding.src_host) == (None, None)


def test_a_service_built_to_run_tscon_counts_when_process_creation_was_not_logged():
    (finding,) = cw016(ev(7045, channel=SYSTEM, ServiceName="sesshijack", ImagePath=HIJACK,
                          AccountName="LocalSystem"))
    assert finding.severity == "high"
    # only the service was logged: it says what the service was built to do, not that it ran
    assert finding.action == "created service 'sesshijack' to run tscon as SYSTEM on session 2 (to rdp-tcp#14)"
    assert "no run or reconnect logged" in finding.summary


def test_the_reconnect_must_be_the_destination_session_and_close_in_time():
    other_session = cw016(service(), tscon_4688(), reconnect(session="RDP-Tcp#3"))
    late = cw016(service(), tscon_4688(), reconnect(seconds=600))
    for (finding,) in (other_session, late):
        assert finding.severity == "high" and finding.src_ip is None


def test_an_unrelated_service_does_not_count():
    assert cw016(service(binary=r"C:\Program Files\Agent\tsconfig.exe")) == []
    assert cw016(service(binary=r"C:\tscon\agent.exe --run")) == []  # a folder named tscon


def test_a_console_reconnect_names_no_source_host():
    back = ev(4778, seconds=5, AccountName="Administrator", AccountDomain="CORP", SessionName="Console",
              ClientName="Unknown", ClientAddress="LOCAL")
    (finding,) = cw016(tscon_4688(command="tscon 2 /dest:console"), back)
    assert (finding.src_ip, finding.src_host) == (None, None)
    assert finding.action.endswith("attached it to the console")


def test_a_system_run_that_only_moves_a_session_back_to_its_owner_is_not_a_takeover():
    # keep-alive tasks move a user's own session around as SYSTEM
    before = ev(4779, seconds=4, AccountName="alice", AccountDomain="CORP", SessionName="RDP-Tcp#14",
                ClientName="ALICE-PC", ClientAddress="10.0.0.21")
    (finding,) = cw016(tscon_4688(), before, reconnect(account="alice"))
    assert finding.severity == "high"
    assert finding.action.startswith("moved CORP\\alice's session 2")


def test_one_run_seen_by_sysmon_and_4688_is_one_finding():
    sysmon = ev(1, channel=SYSMON, seconds=4, Image=r"C:\Windows\System32\tscon.exe",
                CommandLine="tscon  2 /dest rdp-tcp#14", User="NT AUTHORITY\\SYSTEM", LogonId="0x3e7")
    (finding,) = cw016(service(), tscon_4688(), sysmon, reconnect())
    assert sorted(e.event_id for e in finding.evidence) == [1, 4688, 4697, 4778]


def test_the_installer_is_kept_when_7045_and_4697_both_logged_the_service():
    scm = ev(7045, channel=SYSTEM, ServiceName="rdphijack2", ImagePath=HIJACK, AccountName="LocalSystem")
    (finding,) = cw016(scm, service(), tscon_4688(), reconnect())
    assert finding.user == "CORP\\user"


def test_a_service_started_long_after_it_was_created_is_one_finding():
    (finding,) = cw016(service(), tscon_4688(seconds=3600), reconnect(seconds=3606))
    assert finding.severity == "critical" and finding.user == "CORP\\user"


def test_each_reconnect_belongs_to_one_run_only():
    first = tscon_4688(command="tscon 2 /dest rdp-tcp#14", seconds=1)
    second = tscon_4688(command="tscon 2 /dest rdp-tcp#14", seconds=30)
    findings = sorted(cw016(first, second, reconnect(seconds=35)), key=lambda f: f.timestamp)
    # the reconnect follows the second run; the first one is an attempt nothing confirms
    assert [f.severity for f in findings] == ["high", "critical"]


def test_two_runs_and_two_reconnects_pair_each_reconnect_with_the_run_just_before_it():
    runs = [tscon_4688(seconds=0), tscon_4688(seconds=20)]
    backs = [reconnect(seconds=25, account="alice"), reconnect(seconds=60, account="bob")]
    findings = sorted(cw016(*runs, *backs), key=lambda f: f.timestamp)
    assert ["alice" in f.action for f in findings] == [False, True]  # 25 s goes to the run at 20 s
    assert "bob" in findings[0].action


def test_a_renamed_tscon_is_known_by_its_original_file_name():
    run = ev(1, channel=SYSMON, Image=r"C:\Users\Public\svc.exe", OriginalFileName="tscon.exe",
             CommandLine="svc.exe 2 /dest:rdp-tcp#14", User="NT AUTHORITY\\SYSTEM", LogonId="0x3e7")
    (finding,) = cw016(run)
    assert finding.rule_id == "CW-016"
