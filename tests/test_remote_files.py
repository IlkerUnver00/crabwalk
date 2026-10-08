"""CW-014 (Startup folder written from another host), CW-015 (run from
\\\\tsclient), and reading the other end of a Sysmon 3 connection."""

import itertools
from datetime import datetime, timedelta, timezone

from crabwalk.catalog import SECURITY, SYSMON, keep_event
from crabwalk.models import NormalizedEvent
from crabwalk.rules import HuntContext, run_rules
from crabwalk.rules.remote_files import StartupFolderDrop, TsclientExecution

T0 = datetime(2026, 8, 1, 12, 0, 0, tzinfo=timezone.utc)
_rid = itertools.count(1)
STARTUP = r"C:\Users\bob\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"


def ev(event_id, *, channel=SYSMON, seconds=0, computer="WS01", **data):
    return NormalizedEvent(
        timestamp=T0 + timedelta(seconds=seconds), channel=channel, provider="test",
        event_id=event_id, record_id=next(_rid), computer=computer, data=data, source_file="test.evtx",
    )


def file_created(image, path=STARTUP + r"\onedrive.exe", **kw):
    return ev(11, Image=image, TargetFilename=path, **kw)


def conn(image, src, sport, dst, dport, *, seconds=1, initiated=False, **names):
    return ev(3, seconds=seconds, Image=image, Initiated=initiated, SourceIp=src, SourcePort=sport,
              DestinationIp=dst, DestinationPort=dport, **names)


def rules(*events, rule):
    return run_rules(HuntContext.build(list(events)), [rule])


def test_only_startup_folder_files_are_kept_at_parse_time():
    assert keep_event(file_created("System"))
    assert keep_event(file_created("x.exe", path=r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\a.lnk"))
    assert not keep_event(file_created("x.exe", path=r"C:\Users\bob\Downloads\a.exe"))
    assert not keep_event(file_created("x.exe", path=STARTUP))  # the folder itself, no file


def test_smb_write_into_startup_names_the_client():
    events = [file_created("System"), conn("<unknown process>", "10.0.2.17", 49791, "10.0.2.15", 445,
                                            DestinationHostname="WS01")]
    (finding,) = rules(*events, rule=StartupFolderDrop())
    assert (finding.rule_id, finding.severity) == ("CW-014", "high")
    assert finding.techniques == ("T1021.002", "T1570", "T1547.001")
    assert finding.src_ip == "10.0.2.17"
    assert finding.action == "copied 'onedrive.exe' over SMB into bob's Startup folder (runs at logon)"


def test_several_smb_clients_at_once_name_none():
    events = [file_created("System"),
              conn("System", "10.0.2.17", 49791, "10.0.2.15", 445),
              conn("System", "10.0.2.18", 49800, "10.0.2.15", 445)]
    (finding,) = rules(*events, rule=StartupFolderDrop())
    assert finding.src_ip is None
    assert "10.0.2.17 and 10.0.2.18" in finding.summary


def test_5145_write_on_c_share_into_startup():
    share = ev(5145, channel=SECURITY, ShareName="\\\\*\\C$", AccessMask="0x2", IpAddress="10.6.6.6",
               RelativeTargetName=r"Users\bob\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\x.bat",
               SubjectUserName="admin", SubjectDomainName="CORP")
    (finding,) = rules(share, rule=StartupFolderDrop())
    assert (finding.src_ip, finding.user) == ("10.6.6.6", "CORP\\admin")
    assert "over SMB on C$" in finding.summary
    read_only = ev(5145, channel=SECURITY, ShareName="\\\\*\\C$", AccessMask="0x1", IpAddress="10.6.6.6",
                   RelativeTargetName=share.get("RelativeTargetName"))
    assert rules(read_only, rule=StartupFolderDrop()) == []


def test_rdp_client_writing_into_startup_came_from_the_rdp_server():
    events = [conn(r"C:\Windows\system32\mstsc.exe", "10.0.0.10", 50000, "10.9.9.9", 3389,
                   seconds=-600, initiated=True),
              file_created(r"C:\Windows\system32\mstsc.exe", path=STARTUP + r"\cmd.exe")]
    (finding,) = rules(*events, rule=StartupFolderDrop())
    assert finding.techniques == ("T1021.001", "T1547.001")
    assert finding.src_ip == "10.9.9.9"  # the server pushed it back into this client
    assert "(\\\\tsclient; runs at logon)" in finding.action


def test_one_copy_is_one_finding_and_names_the_users_folder():
    path = r"Users\bob\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\x.bat"
    checks = [ev(5145, channel=SECURITY, seconds=s, ShareName="\\\\*\\C$", AccessMask=mask, IpAddress="10.6.6.6",
                 RelativeTargetName=path, SubjectUserName="admin", SubjectDomainName="CORP")
              for s, mask in ((0, "0x2"), (0.5, "0x6"))]
    sysmon = file_created("System", path="C:\\" + path, seconds=0.6)
    (finding,) = rules(*checks, sysmon, rule=StartupFolderDrop())
    assert len(finding.evidence) == 3
    assert "into bob's Startup folder" in finding.action and finding.src_ip == "10.6.6.6"


def test_short_names_of_the_startup_folder_are_caught():
    short = r"C:\Users\bob\AppData\Roaming\MICROS~1\Windows\STARTM~1\Programs\Startup\x.exe"
    assert keep_event(file_created("System", path=short))
    events = [file_created("System", path=short), conn("System", "10.0.2.17", 49791, "10.0.2.15", 445,
                                                       DestinationHostname="WS01")]
    (finding,) = rules(*events, rule=StartupFolderDrop())
    assert finding.src_ip == "10.0.2.17"


def test_this_hosts_own_smb_traffic_is_not_the_writer():
    # loopback (\\localhost\C$) and this host's outbound SMB client connections
    loopback = [file_created("System"), conn("System", "127.0.0.1", 49164, "127.0.0.1", 445)]
    assert rules(*loopback, rule=StartupFolderDrop()) == []
    outbound = [file_created("System"), conn("System", "10.0.2.15", 49800, "10.0.2.50", 445, initiated=True)]
    (finding,) = rules(*outbound, rule=StartupFolderDrop())
    assert finding.src_ip is None
    local_5145 = ev(5145, channel=SECURITY, ShareName="\\\\*\\C$", AccessMask="0x2", IpAddress="::1",
                    RelativeTargetName=r"Users\bob\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\x")
    assert rules(local_5145, rule=StartupFolderDrop()) == []


def test_the_smb_source_carries_the_name_sysmon_resolved():
    events = [file_created("System"), conn("<unknown process>", "10.0.2.17", 49791, "10.0.2.15", 445,
                                           SourceHostname="MSEDGEWIN10CLON", DestinationHostname="WS01")]
    (finding,) = rules(*events, rule=StartupFolderDrop())
    assert (finding.src_ip, finding.src_host) == ("10.0.2.17", "MSEDGEWIN10CLON")


def test_local_startup_persistence_is_not_this_rule():
    events = [file_created(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
              file_created(r"C:\Windows\system32\cmd.exe", path=STARTUP + r"\bs.ps1")]
    assert rules(*events, rule=StartupFolderDrop()) == []


def test_program_run_from_tsclient_takes_the_inbound_rdp_peer():
    events = [conn(r"C:\Windows\System32\svchost.exe", "192.168.56.1", 53627, "192.168.56.101", 3389,
                   DestinationHostname="WS01"),
              ev(1, seconds=2, Image=r"\\tsclient\c\temp\stack\a.exe", CommandLine=r'"\\tsclient\c\temp\stack\a.exe"',
                 ParentImage=r"C:\Windows\explorer.exe", User="WS01\\bob", LogonId="0x3bfab")]
    (finding,) = rules(*events, rule=TsclientExecution())
    assert (finding.rule_id, finding.severity) == ("CW-015", "medium")
    assert finding.src_ip == "192.168.56.1"
    assert "from the RDP client's shared drive" in finding.action


def test_4688_logs_a_tsclient_image_under_device_mup():
    run = ev(4688, channel=SECURITY, NewProcessName=r"\Device\Mup\tsclient\c\temp\a.exe",
             ParentProcessName=r"C:\Windows\explorer.exe", CommandLine=r'"\\tsclient\c\temp\a.exe"',
             SubjectUserName="bob", SubjectDomainName="WS01", SubjectLogonId="0x3bfab")
    (finding,) = rules(run, rule=TsclientExecution())
    assert "from the RDP client's shared drive" in finding.action


def test_this_hosts_own_outbound_rdp_is_not_the_tsclient_source():
    events = [conn(r"C:\Windows\system32\mstsc.exe", "192.168.56.101", 50000, "192.168.56.200", 3389,
                   initiated=True),
              ev(1, seconds=2, Image=r"\\tsclient\c\a.exe", CommandLine=r"\\tsclient\c\a.exe",
                 ParentImage=r"C:\Windows\explorer.exe")]
    (finding,) = rules(*events, rule=TsclientExecution())
    assert finding.src_ip is None


def test_a_local_program_given_a_tsclient_path_is_told_as_such():
    run = ev(1, Image=r"C:\Windows\System32\cmd.exe", CommandLine=r"cmd /c copy \\tsclient\c\a.exe C:\a.exe",
             ParentImage=r"C:\Windows\explorer.exe")
    (finding,) = rules(run, rule=TsclientExecution())
    assert "on a file from the RDP client's shared drive" in finding.action


def test_an_ordinary_unc_path_is_not_tsclient():
    run = ev(1, Image=r"\\fileserver\tools\a.exe", CommandLine=r"\\fileserver\tools\a.exe",
             ParentImage=r"C:\Windows\explorer.exe")
    assert rules(run, rule=TsclientExecution()) == []


def test_connection_peer_reads_the_side_from_the_record_or_known_addresses():
    named = conn("x.exe", "10.0.2.16", 49168, "10.0.2.17", 55683, SourceHostname="WS01")
    outbound = conn("x.exe", "10.0.0.10", 50000, "10.9.9.9", 443, initiated=True)
    server_port = conn("System", "10.0.2.18", 445, "10.0.2.19", 45622)
    unknown = conn("y.exe", "10.0.2.18", 49163, "10.0.2.19", 33474)
    loopback = conn("System", "127.0.0.1", 49164, "127.0.0.1", 445)
    ctx = HuntContext.build([named, outbound, server_port, unknown, loopback])
    assert ctx.connection_peer(named) == "10.0.2.17"
    assert ctx.connection_peer(outbound) == "10.9.9.9"
    assert ctx.connection_peer(server_port) == "10.0.2.19"
    # 10.0.2.18 is a known address of WS01 (its SMB server port), so the other end is the peer
    assert ctx.connection_peer(unknown) == "10.0.2.19"
    assert ctx.connection_peer(loopback) is None
    alone = HuntContext.build([conn("y.exe", "10.0.2.18", 49163, "10.0.2.19", 33474)])
    assert alone.connection_peer(alone.events[0]) is None
