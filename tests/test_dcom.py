"""CW-013 (DCOM), CW-007's winrs path, and where spawned processes came from."""

import itertools
from datetime import datetime, timedelta, timezone

from crabwalk.catalog import SECURITY, SYSMON
from crabwalk.models import NormalizedEvent
from crabwalk.rules import HuntContext, run_rules
from crabwalk.rules.execution import DcomExec, WinRmExec, WmiExec

T0 = datetime(2026, 8, 1, 12, 0, 0, tzinfo=timezone.utc)
_rid = itertools.count(1)
DCOM_LAUNCH = r"C:\Windows\system32\svchost.exe -k DcomLaunch"


def ev(event_id, *, channel=SYSMON, seconds=0, computer="SRV01", **data):
    return NormalizedEvent(
        timestamp=T0 + timedelta(seconds=seconds), channel=channel, provider="test",
        event_id=event_id, record_id=next(_rid), computer=computer, data=data, source_file="test.evtx",
    )


def proc(image, command, parent, parent_command, *, seconds=0, pid=200, ppid=100, logon="0x1ea3c6"):
    return ev(1, seconds=seconds, Image=image, CommandLine=command, ParentImage=parent,
              ParentCommandLine=parent_command, ProcessId=pid, ParentProcessId=ppid,
              User="CORP\\admin", LogonId=logon)


def conn(image, src, sport, dst, dport, *, seconds=1, pid=100, initiated=False, **names):
    return ev(3, seconds=seconds, Image=image, ProcessId=pid, Initiated=initiated, SourceIp=src,
              SourcePort=sport, DestinationIp=dst, DestinationPort=dport, **names)


def mmc20_child(command=r'"C:\Windows\System32\cmd.exe" /Q /c whoami 1> \\127.0.0.1\ADMIN$\__1 2>&1', **kw):
    return proc(r"C:\Windows\System32\cmd.exe", command, r"C:\Windows\System32\mmc.exe",
                r"C:\Windows\system32\mmc.exe -Embedding", **kw)


def rules(*events, rule=None):
    return run_rules(HuntContext.build(list(events)), [rule or DcomExec()])


def test_mmc20_shell_is_high_dcom_lateral_movement():
    (finding,) = rules(mmc20_child())
    assert (finding.rule_id, finding.severity, finding.techniques) == ("CW-013", "high", ("T1021.003",))
    assert finding.action.startswith("ran '\"C:\\Windows\\System32\\cmd.exe\" /Q /c whoami")
    assert finding.action.endswith("through DCOM (MMC20.Application)")
    assert (finding.src_ip, finding.src_host) == (None, None)  # nothing names the caller


def test_source_is_the_one_remote_address_the_com_server_talked_to():
    # impacket dcomexec on a Sysmon-only host: the SMB server's inbound 445
    # shows this host's address, so the mmc.exe connection's other end is the caller.
    events = [mmc20_child(), conn("System", "10.0.2.18", 445, "10.0.2.19", 45622, pid=4),
              conn(r"C:\Windows\System32\mmc.exe", "10.0.2.18", 49163, "10.0.2.19", 33474)]
    (finding,) = rules(*events)
    assert finding.src_ip == "10.0.2.19"
    assert "it talked to 10.0.2.19" in finding.summary
    assert len(finding.evidence) == 2  # the spawn and the COM server's connection


def test_an_ambiguous_connection_names_no_source():
    # neither a host name, a server port nor a known own address says which end is this host
    (finding,) = rules(mmc20_child(), conn(r"C:\Windows\System32\mmc.exe", "10.0.2.18", 49163,
                                            "10.0.2.19", 33474))
    assert finding.src_ip is None


def test_other_processes_connections_are_not_the_com_servers():
    events = [mmc20_child(), conn("System", "10.0.2.18", 445, "10.0.2.19", 45622, pid=4),
              conn(r"C:\Windows\System32\mmc.exe", "10.0.2.18", 49163, "10.0.2.66", 33474, pid=999)]
    (finding,) = rules(*events)
    assert finding.src_ip is None  # pid 999 is another mmc.exe


def test_a_connection_the_com_server_opened_itself_is_not_its_caller():
    # an HTA fetching its payload from the internet: outbound, so not who activated it
    mshta = proc(r"C:\Windows\System32\mshta.exe", r"C:\Windows\System32\mshta.exe -Embedding",
                 r"C:\Windows\System32\svchost.exe", DCOM_LAUNCH, pid=1932, ppid=596)
    fetch = conn(r"C:\Windows\System32\mshta.exe", "10.0.2.16", 49170, "93.184.216.34", 443, pid=1932,
                 initiated=True, SourceHostname="SRV01")
    (finding,) = rules(mshta, fetch)
    assert finding.src_ip is None and len(finding.evidence) == 1


def test_later_commands_of_one_dcom_shell_keep_the_activations_source():
    # the caller connected right after activation; a command 5 minutes later is the same session
    activation = proc(r"C:\Windows\System32\mmc.exe", r"C:\Windows\system32\mmc.exe -Embedding",
                      r"C:\Windows\System32\svchost.exe", DCOM_LAUNCH, pid=100, ppid=612)
    events = [activation, conn("System", "10.0.2.18", 445, "10.0.2.19", 45622, pid=4),
              conn(r"C:\Windows\System32\mmc.exe", "10.0.2.18", 49163, "10.0.2.19", 33474, seconds=2),
              mmc20_child(seconds=300)]
    (later,) = rules(*events)
    assert later.src_ip == "10.0.2.19"


def test_4688_process_ids_are_read_from_the_right_fields():
    # a 4688's ProcessId is its creator's; NewProcessId is the new process, both in hex
    def p4688(parent, child, command, new_pid, creator_pid, seconds=0):
        return ev(4688, channel=SECURITY, seconds=seconds, NewProcessName=child, ParentProcessName=parent,
                  CommandLine=command, NewProcessId=new_pid, ProcessId=creator_pid,
                  SubjectUserName="admin", SubjectDomainName="CORP", SubjectLogonId="0x9")
    mshta = p4688(r"C:\Windows\System32\svchost.exe", r"C:\Windows\System32\mshta.exe",
                  r"C:\Windows\System32\mshta.exe -Embedding", "0x78c", "0x254")
    own = conn(r"C:\Windows\System32\mshta.exe", "10.0.2.16", 49168, "10.0.2.17", 55683, pid=1932,
               SourceHostname="SRV01")  # 0x78c = 1932
    svchost = conn(r"C:\Windows\System32\mshta.exe", "10.0.2.16", 49169, "10.0.2.66", 55684, pid=596,
                   SourceHostname="SRV01")  # 0x254 = 596, svchost's PID
    (finding,) = rules(mshta, own, svchost)
    assert finding.src_ip == "10.0.2.17"


def test_lethalhta_activation_itself_is_the_finding():
    mshta = proc(r"C:\Windows\System32\mshta.exe", r"C:\Windows\System32\mshta.exe -Embedding",
                 r"C:\Windows\System32\svchost.exe", DCOM_LAUNCH, pid=1932, ppid=596)
    talk = conn(r"C:\Windows\System32\mshta.exe", "10.0.2.16", 49168, "10.0.2.17", 55683, pid=1932,
                SourceHostname="SRV01")
    (finding,) = rules(mshta, talk)
    assert finding.severity == "high"
    assert finding.action == "ran an HTA in mshta.exe through DCOM (htafile, the LethalHTA technique)"
    assert finding.src_ip == "10.0.2.17"


def test_logon_session_names_the_source_when_logged():
    events = [
        ev(4624, channel=SECURITY, TargetLogonId="0x1ea3c6", TargetUserName="admin", TargetDomainName="CORP",
           LogonType="3", IpAddress="10.6.6.6", WorkstationName="ATTACKER", AuthenticationPackageName="NTLM"),
        mmc20_child(seconds=1),
    ]
    (finding,) = rules(*events)
    assert (finding.src_ip, finding.src_host) == ("10.6.6.6", "ATTACKER")


def test_activation_in_a_remote_callers_logon_is_dcom_even_without_a_child():
    # EVTX-to-MITRE-Attack's "DCOMexec process spawned" (4688): MMC20 activated by a
    # caller from 10.23.123.11, no command run in the capture
    logon = ev(4624, channel=SECURITY, TargetLogonId="0x542957e", TargetUserName="admmig",
               TargetDomainName="OFFSEC", LogonType="3", IpAddress="10.23.123.11", WorkstationName="-",
               AuthenticationPackageName="NTLM")
    activation = ev(4688, channel=SECURITY, seconds=1, NewProcessName=r"C:\Windows\System32\mmc.exe",
                    ParentProcessName=r"C:\Windows\System32\svchost.exe",
                    CommandLine=r"C:\Windows\system32\mmc.exe -Embedding", SubjectUserName="SRV$",
                    SubjectLogonId="0x3e7", TargetLogonId="0x542957e", TargetUserName="admmig",
                    TargetDomainName="OFFSEC")
    (finding,) = rules(logon, activation)
    assert (finding.severity, finding.src_ip) == ("high", "10.23.123.11")
    assert finding.action == "activated MMC20.Application through DCOM"
    # the same activation with no remote logon behind it says nothing on its own
    assert rules(activation) == []


def test_local_com_use_is_quiet():
    # a user opens an HTA, or a macro drives Word: no -Embedding activation
    events = [
        proc(r"C:\Windows\SysWOW64\mshta.exe", r'"mshta.exe" "C:\Users\Public\x.hta"',
             r"C:\Windows\explorer.exe", r"C:\Windows\Explorer.EXE"),
        proc(r"C:\Windows\System32\cmd.exe", "cmd /c calc", r"C:\Program Files\Office\WINWORD.EXE",
             r'"WINWORD.EXE" /n "C:\Users\bob\invoice.doc"'),
        proc(r"C:\Windows\System32\cmd.exe", "cmd /c x", r"C:\Windows\System32\mmc.exe",
             r'"C:\Windows\system32\mmc.exe" "C:\Windows\system32\compmgmt.msc"'),
    ]
    assert rules(*events) == []


def test_office_automation_child_counts_only_with_the_embedding_flag():
    (finding,) = rules(proc(r"C:\Windows\System32\cmd.exe", "cmd /c whoami",
                            r"C:\Program Files\Office\EXCEL.EXE",
                            r'"C:\Program Files\Office\EXCEL.EXE" /automation -Embedding'))
    assert "Excel.Application" in finding.action


def test_4688_mmc_spawning_a_shell_counts_but_office_does_not():
    def p4688(parent, child):
        return ev(4688, channel=SECURITY, NewProcessName=child, ParentProcessName=parent,
                  CommandLine=child, SubjectUserName="admin", SubjectDomainName="CORP", SubjectLogonId="0x9")
    assert len(rules(p4688(r"C:\Windows\System32\mmc.exe", r"C:\Windows\System32\cmd.exe"))) == 1
    assert rules(p4688(r"C:\Program Files\Office\EXCEL.EXE", r"C:\Windows\System32\cmd.exe")) == []


def test_winrs_shell_is_winrm():
    child = proc(r"C:\Windows\System32\cmd.exe", r"C:\Windows\system32\cmd.exe /C ipconfig",
                 r"C:\Windows\System32\winrshost.exe", r"C:\Windows\system32\WinrsHost.exe -Embedding")
    (finding,) = rules(child, rule=WinRmExec())
    assert finding.techniques == ("T1021.006",) and finding.severity == "high"
    assert finding.action.endswith("through Windows Remote Shell (winrs over WinRM)")
    assert rules(child) == []  # winrshost is WinRM's, not a DCOM lateral-movement server


def _rdp_logon(logon_id="0x5555", minutes=0):
    return ev(4624, channel=SECURITY, seconds=minutes * 60, TargetLogonId=logon_id, TargetUserName="bob",
              TargetDomainName="CORP", LogonType="10", IpAddress="10.0.0.50", WorkstationName="BOBPC",
              AuthenticationPackageName="Negotiate")


def test_wmi_or_com_inside_an_rdp_session_is_not_movement_from_the_rdp_client():
    # bob RDPs in and drives Excel and WMI from his desktop: local use, no source
    excel = proc(r"C:\Program Files\Office\EXCEL.EXE", r'"EXCEL.EXE" /automation -Embedding',
                 r"C:\Windows\System32\svchost.exe", DCOM_LAUNCH, seconds=60, pid=300, logon="0x5555")
    wmi = proc(r"C:\Windows\System32\notepad.exe", "notepad.exe", r"C:\Windows\System32\wbem\WmiPrvSE.exe",
               r"C:\Windows\system32\wbem\wmiprvse.exe -Embedding", seconds=61, logon="0x5555")
    assert rules(_rdp_logon(), excel) == []  # the activation alone says nothing without a network logon
    (finding,) = rules(_rdp_logon(), wmi, rule=WmiExec())
    assert (finding.src_ip, finding.src_host) == (None, None)


def test_a_logon_id_reused_by_a_later_boot_is_not_the_spawns_session():
    wmi = proc(r"C:\Windows\System32\notepad.exe", "notepad.exe", r"C:\Windows\System32\wbem\WmiPrvSE.exe",
               r"C:\Windows\system32\wbem\wmiprvse.exe -Embedding", logon="0x5555")
    later = ev(4624, channel=SECURITY, seconds=20 * 86400, TargetLogonId="0x5555", TargetUserName="eve",
               TargetDomainName="CORP", LogonType="3", IpAddress="10.0.0.66", WorkstationName="ATTACKER",
               AuthenticationPackageName="NTLM")
    (finding,) = rules(wmi, later, rule=WmiExec())
    assert finding.src_ip is None  # 20 days before that logon existed


def test_the_peer_takes_the_host_name_its_record_gives():
    talk = conn(r"C:\Windows\System32\mmc.exe", "10.0.2.18", 49163, "10.0.2.19", 33474,
                SourceHostname="SRV01", DestinationHostname="KALI.lab")
    (finding,) = rules(mmc20_child(), talk)
    assert (finding.src_ip, finding.src_host) == ("10.0.2.19", "KALI.lab")


def test_an_address_this_host_had_weeks_ago_does_not_decide_the_side():
    # DHCP: WS01 used 10.0.0.9 20 days ago; today the caller has it
    old = conn("svchost.exe", "10.0.0.9", 50000, "10.0.0.2", 389, seconds=-20 * 86400, initiated=True)
    events = [old, mmc20_child(), conn(r"C:\Windows\System32\mmc.exe", "10.0.0.20", 49163, "10.0.0.9", 33474)]
    (finding,) = rules(*events)
    assert finding.src_ip is None  # rather none than this host's own current address


def test_wmi_child_takes_its_source_from_the_network_logon():
    events = [
        ev(4624, channel=SECURITY, TargetLogonId="0x77", TargetUserName="admin", TargetDomainName="CORP",
           LogonType="3", IpAddress="10.6.6.6", WorkstationName="-", AuthenticationPackageName="NTLM"),
        ev(4688, channel=SECURITY, seconds=1, NewProcessName=r"C:\Windows\System32\cmd.exe",
           ParentProcessName=r"C:\Windows\System32\wbem\WmiPrvSE.exe", CommandLine="cmd.exe /Q /c whoami",
           SubjectLogonId="0x3e4", TargetLogonId="0x77", TargetUserName="admin", TargetDomainName="CORP"),
    ]
    (finding,) = rules(*events, rule=WmiExec())
    assert finding.src_ip == "10.6.6.6"
