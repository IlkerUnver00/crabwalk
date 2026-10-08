"""Cross-rule merging (rules.merge_overlaps) and the attack narrative."""

import itertools
import json
from datetime import datetime, timedelta, timezone

from crabwalk.catalog import SECURITY, SYSTEM, TS_LSM
from crabwalk.models import NormalizedEvent
from crabwalk.narrative import OTHER_HOSTS_SHOWN, build_story
from crabwalk.rules import merge_overlaps, run_rules
from crabwalk.rules.base import Finding, HuntContext

T0 = datetime(2026, 8, 1, 12, 0, 0, tzinfo=timezone.utc)
_rid = itertools.count(1)


def ev(event_id, *, minutes=0, computer="SRV01", channel=SECURITY, **data):
    return NormalizedEvent(T0 + timedelta(minutes=minutes), channel, "t", event_id, next(_rid),
                           computer, data, "t.evtx")


def finding(rule, evidence, *, severity="high", techniques=("T1021.002",), minutes=0, host="SRV01"):
    return Finding(rule, rule, severity, tuple(techniques), T0 + timedelta(minutes=minutes), host,
                   f"{rule} summary", "CORP\\admin", list(evidence))


SIDS = {"admin": "S-1-5-21-1-2-3-500", "bob": "S-1-5-21-1-2-3-1104", "eve": "S-1-5-21-1-2-3-1105"}


def logon(computer, src_ip, workstation, *, minutes=0, user="admin", logon_id="0x1", **extra):
    data = {"TargetLogonId": logon_id, "TargetUserName": user, "TargetDomainName": "CORP",
            "LogonType": "3", "IpAddress": src_ip, "WorkstationName": workstation,
            "AuthenticationPackageName": "Kerberos", "TargetUserSid": SIDS.get(user, "S-1-5-21-1-2-3-1199")}
    data.update(extra)
    return ev(4624, minutes=minutes, computer=computer, **data)


# -- merging -----------------------------------------------------------------

def share_open(name, share="IPC$", minutes=0.0, computer="SRV01"):
    return ev(5145, minutes=minutes, computer=computer, ShareName="\\\\*\\" + share,
              RelativeTargetName=name, IpAddress="10.0.0.5", SubjectUserName="admin",
              SubjectDomainName="CORP")


def test_the_drop_inside_a_psexec_run_is_told_once():
    events = [share_open("PSEXESVC.exe", "ADMIN$"), share_open("svcctl", minutes=0.01),
              share_open("PSEXESVC", minutes=0.02), share_open("PSEXESVC-WKS66-4242-stdin", minutes=0.03)]
    (psexec,) = run_rules(HuntContext.build(events))
    assert psexec.rule_id == "CW-012" and psexec.severity == "critical"
    (drop,) = psexec.merged
    assert drop.rule_id == "CW-005" and "PSEXESVC.exe" in drop.summary
    assert psexec.to_dict()["merged"][0]["rule_id"] == "CW-005"


def test_a_drop_no_execution_follows_stays_a_finding():
    findings = run_rules(HuntContext.build([share_open("tool.exe", "ADMIN$")]))
    assert [f.rule_id for f in findings] == ["CW-005"] and not findings[0].merged


def test_a_local_account_is_not_the_domain_account_of_the_same_name():
    a, b = ev(5145), ev(5145)
    local = finding("CW-005", [a], techniques=("T1021.002", "T1570"))
    local.user = "SRV01\\Administrator"
    domain = finding("CW-012", [a, b], severity="critical", techniques=("T1021.002", "T1570", "T1569.002"))
    domain.user = "CORP\\Administrator"
    assert len(merge_overlaps([local, domain])) == 2
    dns = finding("CW-005", [a], techniques=("T1021.002", "T1570"))
    dns.user = "CORP.LOCAL\\Administrator"  # the same domain account, DNS-style
    assert len(merge_overlaps([dns, domain])) == 1


def test_merging_needs_the_evidence_techniques_and_severity_all_covered():
    a, b, c = ev(5145), ev(5145), ev(7045, channel=SYSTEM)
    drop = finding("CW-005", [a], techniques=("T1021.002", "T1570"))
    # missing a technique
    assert len(merge_overlaps([drop, finding("CW-012", [a, b], severity="critical")])) == 2
    # less severe
    drop = finding("CW-005", [a], techniques=("T1021.002", "T1570"))
    weaker = finding("CW-012", [a, b], severity="medium", techniques=("T1021.002", "T1570"))
    assert len(merge_overlaps([drop, weaker])) == 2
    # the same rule never absorbs itself
    assert len(merge_overlaps([finding("CW-012", [a]), finding("CW-012", [a, c])])) == 2
    # no evidence: nothing to compare
    assert len(merge_overlaps([finding("CW-002", []), finding("CW-012", [a])])) == 2
    # equal in every respect: neither tells the other
    assert len(merge_overlaps([finding("CW-005", [a]), finding("CW-012", [a])])) == 2


def test_a_merged_finding_lands_under_the_top_one_and_is_never_dropped():
    a, b, c = ev(5145), ev(5145), ev(7045, channel=SYSTEM)
    low = finding("CW-005", [a], severity="medium", techniques=("T1570",))
    mid = finding("CW-012", [a, b], severity="high", techniques=("T1570", "T1569.002"))
    # the top finding is the same rule as `low`, so `low` reaches it only through `mid`
    top = finding("CW-005", [a, b, c], severity="critical", techniques=("T1570", "T1569.002", "T1543.003"))
    (only,) = merge_overlaps([low, mid, top])
    assert only is top and {id(m) for m in top.merged} == {id(low), id(mid)}


def test_a_merge_never_removes_who_or_where():
    # A Sysmon-only CW-012 knows no client; the CW-005 drop it credits does.
    # Merging would erase the attacker's address and account from every output.
    drop = ev(5145, minutes=-0.2, ShareName="\\\\*\\ADMIN$", RelativeTargetName="RemComSvc.exe",
              IpAddress="10.9.9.9", SubjectUserName="mallory", SubjectDomainName="CORP", AccessMask="0x2")
    pipe = ev(18, channel="Microsoft-Windows-Sysmon/Operational", Image="System",
              PipeName="\\RemCom_communicaton")
    findings = run_rules(HuntContext.build([drop, pipe]))
    assert sorted(f.rule_id for f in findings) == ["CW-005", "CW-012"]
    (cw005,) = [f for f in findings if f.rule_id == "CW-005"]
    assert cw005.src_ip == "10.9.9.9" and cw005.user == "CORP\\mallory"


def test_a_merge_keeps_a_finding_tied_to_another_session():
    # CW-004 ties the task to bob's session by LogonId; the atsvc open just
    # before came from another client. They are two findings.
    events = [share_open("atsvc"),
              logon("SRV01", "10.0.0.9", "ROGUE-PC", minutes=0.2, user="bob", logon_id="0x99"),
              ev(4698, minutes=0.5, SubjectLogonId="0x99", SubjectUserName="bob", SubjectDomainName="CORP",
                 TaskName="\\Updater", TaskContent="<Command>C:\\Users\\Public\\b.exe</Command>")]
    findings = run_rules(HuntContext.build(events))
    (task,) = [f for f in findings if f.rule_id == "CW-004"]
    assert task.user == "CORP\\bob" and task.src_ip == "10.0.0.9" and not task.merged


def test_merging_does_not_depend_on_input_order():
    events = [share_open("PSEXESVC.exe", "ADMIN$"), share_open("svcctl", minutes=0.01),
              share_open("PSEXESVC", minutes=0.02), share_open("PSEXESVC-WKS66-4242-stdin", minutes=0.03)]
    ctx = HuntContext.build(events)
    from crabwalk.rules import ALL_RULES
    raw = [f for rule in ALL_RULES for f in rule().evaluate(ctx)]
    forward = merge_overlaps(list(raw))
    shape = sorted((f.rule_id, tuple(m.rule_id for m in f.merged)) for f in forward)
    again = merge_overlaps(list(reversed(raw)))  # also: a second call starts from scratch
    assert sorted((f.rule_id, tuple(m.rule_id for m in f.merged)) for f in again) == shape


def test_an_allow_entry_has_to_cover_what_was_merged():
    from crabwalk.config import parse_config
    events = [share_open("PSEXESVC.exe", "ADMIN$"), share_open("svcctl", minutes=0.01),
              share_open("PSEXESVC", minutes=0.02), share_open("PSEXESVC-WKS66-4242-stdin", minutes=0.03)]
    (psexec,) = run_rules(HuntContext.build(events))
    narrow = parse_config({"allow": [{"reason": "it", "rules": ["CW-012"], "sources": ["10.0.0.5"]}]})
    screened = narrow.screen([psexec])
    assert screened.kept == [psexec]  # the merged CW-005 is outside the entry's rules
    (warning,) = screened.warnings
    assert "also tells CW-005" in warning
    wide = parse_config({"allow": [{"reason": "it", "rules": ["CW-012", "CW-005"], "sources": ["10.0.0.5"]}]})
    assert wide.screen([psexec]).kept == []


def test_a_read_is_not_called_a_copy():
    events = [share_open("tool.exe", "ADMIN$"), share_open("svcctl", minutes=0.01),
              share_open("PSEXESVC", minutes=0.02)]
    events[0].data["AccessMask"] = "0x120089"  # FILE_GENERIC_READ
    (finding,) = [f for f in run_rules(HuntContext.build(events)) if f.rule_id == "CW-012"]
    assert finding.action.startswith("accessed 'tool.exe' on ADMIN$")
    events[0].data["AccessMask"] = "0x120196"  # WriteData among the rights
    (finding,) = [f for f in run_rules(HuntContext.build(events)) if f.rule_id == "CW-012"]
    assert finding.action.startswith("copied 'tool.exe' to ADMIN$")


# -- the story -----------------------------------------------------------------

def chain_events():
    """A -> B (network logon), then B -> C (RDP), then a log clear on C."""
    return [
        logon("HOSTB", "10.0.0.1", "HOSTA", logon_id="0x10"),
        logon("HOSTC", "10.0.0.2", "HOSTB", minutes=30, logon_id="0x20", user="bob", LogonType="10"),
        ev(21, channel=TS_LSM, computer="HOSTC", minutes=30.01, User="CORP.LOCAL\\bob", Address="10.0.0.2"),
        logon("HOSTC", "-", "-", minutes=31, user="ANONYMOUS LOGON", logon_id="0x21",
              TargetDomainName="NT AUTHORITY", TargetUserSid="S-1-5-7"),
        ev(1102, computer="HOSTC", minutes=40, SubjectUserName="bob", SubjectDomainName="CORP"),
    ]


def story_of(events):
    ctx = HuntContext.build(events)
    return build_story(ctx, run_rules(ctx))


def test_a_chain_reads_in_order_from_its_origin():
    story = story_of(chain_events())
    (path,) = story.chapters
    assert path.title() == "HOSTA → HOSTB → HOSTC" and path.hosts == 3
    assert "started from HOSTA" in path.lead
    texts = [(b.source, b.host, b.text) for b in path.beats]
    assert texts[0] == ("HOSTA (10.0.0.1)", "HOSTB", "a network logon")
    assert texts[1][:2] == ("HOSTB (10.0.0.2)", "HOSTC") and "RDP" in texts[1][2]
    assert path.beats[1].users == ("CORP\\bob",)  # one account, however each log wrote it
    assert texts[2] == (None, "HOSTC", "cleared the Security log")
    assert path.beats[2].severity == "high" and path.beats[2].rules == ("CW-009",)
    assert "ANONYMOUS" not in story.to_text()  # a null session is not an actor
    assert story.headline.startswith("1 attack path across 3 hosts")


def test_long_gaps_are_said_out_loud():
    events = chain_events()
    events.append(ev(1102, computer="HOSTC", minutes=60 * 24 * 20, SubjectUserName="bob",
                     SubjectDomainName="CORP"))
    (path,) = story_of(events).chapters
    assert path.beats[-1].after and path.beats[-1].after.days == 19
    text = story_of(events).to_text()
    assert "(19 days later)" in text
    assert path.notes and "this path has gaps of 19 days" in path.notes[0]
    assert text.index("CAUTION") < text.index("a network logon")  # said before the steps


def test_findings_without_movement_are_other_activity():
    events = [ev(1102, computer=f"WKS{i:02}", minutes=i, SubjectUserName="u", SubjectDomainName="CORP")
              for i in range(OTHER_HOSTS_SHOWN + 2)]
    story = story_of(events)
    assert not story.chapters and len(story.other) == OTHER_HOSTS_SHOWN + 2
    assert story.headline.startswith("No host-to-host movement was reconstructed")
    text = story.to_text()
    assert "... and 2 more host(s); see the findings list" in text  # capped, and says so
    markdown = story.to_markdown()
    assert all(f"WKS{i:02}" in markdown for i in range(OTHER_HOSTS_SHOWN + 2))  # never capped


def test_a_burst_of_one_rule_is_shortened_but_never_hides_another_rule():
    drops = [ev(5145, minutes=i / 60, ShareName="\\\\*\\C$", RelativeTargetName=f"tool{i}.exe",
                IpAddress="10.0.0.9", SubjectUserName="eve", SubjectDomainName="CORP")
             for i in range(5)]
    task_logon = logon("SRV01", "10.0.0.9", "ATTACKER", logon_id="0x99", user="eve")
    task = ev(4698, minutes=0.1, SubjectLogonId="0x99", SubjectUserName="eve", SubjectDomainName="CORP",
              TaskName="\\Updater", TaskContent="<Command>cmd.exe</Command>")
    story = story_of([task_logon, *drops, task])
    (path,) = story.chapters
    (step,) = [b for b in path.beats if b.rules]
    assert "accessed executable 'tool0.exe' on C$" in step.text
    assert "3 more like them" in step.text  # five drops: two shown, three counted
    assert "created scheduled task '\\Updater'" in step.text  # CW-004 is not crowded out
    assert step.rules == ("CW-004", "CW-005")


def test_findings_without_a_usable_time_are_counted_not_placed():
    null_time = datetime(1601, 1, 1, tzinfo=timezone.utc)
    undated = Finding("CW-009", "Event log cleared", "high", ("T1070.001",), null_time, "OLD01",
                      "cleared", "CORP\\u", [ev(1102, computer="OLD01")])
    dated = Finding("CW-009", "Event log cleared", "high", ("T1070.001",), T0, "NEW01",
                    "cleared", "CORP\\u", [ev(1102, computer="NEW01")])
    story = build_story(HuntContext.build([]), [undated, dated])
    assert [a.host for a in story.other] == ["NEW01"]
    assert "1 finding without a usable timestamp is left out of the story" in story.headline
    assert "1601" not in story.to_text()


def test_a_logon_is_told_once_and_null_sessions_are_not_admin_logons():
    # The 4624 a pass-the-hash finding cites is that finding, not one more logon.
    ntlm = logon("SRV02", "10.0.0.7", "WKS07", logon_id="0x31", AuthenticationPackageName="NTLM")
    events = [ntlm, ev(4672, computer="SRV02", SubjectLogonId="0x31", SubjectUserName="admin",
                       SubjectDomainName="CORP"),
              logon("SRV02", "10.0.0.7", "WKS07", minutes=0.01, user="ANONYMOUS LOGON", logon_id="0x32",
                    TargetDomainName="NT AUTHORITY", TargetUserSid="S-1-5-7")]
    (path,) = story_of(events).chapters
    (step,) = path.beats
    assert step.text == ("logged on over NTLM with admin rights (possible pass-the-hash), "
                         "then an anonymous null session")
    assert step.users == ("CORP\\admin",)


def _admin_ntlm_logons(n, start, *, minutes_apart, first_id, user="admin"):
    events = []
    for i in range(n):
        lid = f"0x{first_id + i:x}"
        events += [logon("SRV02", "10.0.0.7", "WKS07", minutes=start + i * minutes_apart, logon_id=lid,
                         user=user, AuthenticationPackageName="NTLM"),
                   ev(4672, minutes=start + i * minutes_apart, computer="SRV02", SubjectLogonId=lid,
                      SubjectUserName=user, SubjectDomainName="CORP")]
    return events


def test_bursts_are_counted_by_their_logons_not_by_their_findings():
    # two accounts' CW-003 bursts (2 logons each) in one step: "4 times", never "twice twice"
    events = (_admin_ntlm_logons(2, 0, minutes_apart=0.01, first_id=0x40)
              + _admin_ntlm_logons(2, 1, minutes_apart=0.01, first_id=0x50, user="bob"))
    findings = [f for f in run_rules(HuntContext.build(events)) if f.rule_id == "CW-003"]
    assert [f.count for f in findings] == [2, 2]
    text = story_of(events).to_text()
    assert "twice twice" not in text
    assert "logged on over NTLM with admin rights 4 times (possible pass-the-hash)" in text


def test_a_burst_longer_than_a_visit_is_not_recounted_as_plain_logons():
    # 4 logons 8 min apart: one burst (each within burst_gap) spanning past VISIT_GAP
    events = _admin_ntlm_logons(4, 0, minutes_apart=8, first_id=0x60)
    text = story_of(events).to_text()
    assert "logged on over NTLM with admin rights 4 times" in text
    assert "network logon" not in text  # its later logons are the finding's, not extra logons


def test_local_accounts_of_cloned_hosts_stay_apart():
    # Hosts cloned from one image share local SIDs: IEWIN7\IEUser is not PC01\IEUser.
    shared = "S-1-5-21-321-654-987-1000"
    events = [
        logon("IEWIN7", "10.0.0.1", "ATK", user="IEUser", TargetDomainName="IEWIN7", TargetUserSid=shared,
              logon_id="0x41"),
        logon("PC01", "10.0.0.1", "ATK", minutes=5, user="IEUser", TargetDomainName="PC01",
              TargetUserSid=shared, logon_id="0x42"),
    ]
    (path,) = story_of(events).chapters
    assert {b.host: b.users for b in path.beats} == {"IEWIN7": ("IEWIN7\\IEUser",),
                                                    "PC01": ("PC01\\IEUser",)}


def test_a_name_learned_elsewhere_is_said_to_be():
    # WKS01's name comes from its 4624 to SRV01; the later CW-005 on SRV02
    # records only the address.
    events = [logon("SRV01", "10.0.0.7", "WKS01", logon_id="0x51"),
              ev(5145, computer="SRV02", minutes=30, ShareName="\\\\*\\ADMIN$", RelativeTargetName="x.exe",
                 IpAddress="10.0.0.7", SubjectUserName="admin", SubjectDomainName="CORP")]
    (path,) = story_of(events).chapters
    sources = {b.host: b.source for b in path.beats}
    assert sources == {"SRV01": "WKS01 (10.0.0.7)",
                       "SRV02": "10.0.0.7 (named WKS01 elsewhere in the logs)"}


def test_a_line_that_spans_time_shows_the_span():
    events = [logon("SRV01", "10.0.0.7", "WKS01", logon_id="0x61"),
              logon("SRV01", "10.0.0.7", "WKS01", minutes=8, logon_id="0x62")]
    text = story_of(events).to_text()
    assert "2026-08-01 12:00:00Z–12:08:00Z  WKS01 (10.0.0.7) -> SRV01 as CORP\\admin: 2 network logons" in text


def test_nothing_to_tell():
    story = build_story(HuntContext.build([]), [])
    assert story.headline.startswith("Nothing to tell") and story.to_text().strip() == story.headline


def test_every_rendering_escapes_what_the_logs_say():
    events = [ev(104, channel=SYSTEM, computer="H<script>", Channel="<img src=x>",
                 SubjectUserName="u_1*", SubjectDomainName="CORP")]
    story = story_of(events)
    html = story.to_html()
    assert "<script>" not in html and "<img" not in html and "H&lt;script&gt;" in html
    markdown = story.to_markdown()
    assert "u\\_1\\*" in markdown and "CORP\\\\u" in markdown  # Markdown specials escaped
    json.dumps(story.to_dict())  # serializable as-is
