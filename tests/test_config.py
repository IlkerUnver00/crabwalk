import itertools
import json
import sys
from datetime import date, datetime, timedelta, timezone

import pytest

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from crabwalk.catalog import SECURITY, SYSTEM
from crabwalk.cli import main
from crabwalk.config import (
    Config,
    ConfigError,
    example_config,
    load_config,
    parse_config,
    parse_duration,
)
from crabwalk.models import NormalizedEvent
from crabwalk.report import render_report
from crabwalk.rules import ALL_RULES, run_rules
from crabwalk.rules.base import Finding, HuntContext

T0 = datetime(2026, 8, 1, 12, 0, 0, tzinfo=timezone.utc)
_rid = itertools.count(1)


def ev(event_id, *, minutes=0, computer="SRV01", channel=SECURITY, **data):
    return NormalizedEvent(T0 + timedelta(minutes=minutes), channel, "t", event_id, next(_rid),
                           computer, data, "t.evtx")


def finding(rule="CW-012", *, user="CORP\\admin", host="SRV01.corp.local", severity="high",
            src_ip=None, src_host=None, evidence=()):
    return Finding(rule, "t", severity, ("T1021.002",), T0, host, "summary", user,
                   list(evidence), src_ip, src_host)


def allow(**entry):
    return parse_config({"allow": [{"reason": "known good", **entry}]}).allow[0]


# -- durations ----------------------------------------------------------------

@pytest.mark.parametrize("raw, seconds", [
    ("90s", 90), ("10m", 600), ("6h", 21600), ("1d", 86400), ("250ms", 0.25),
    ("1.5m", 90), (" 2 H ", 7200), (45, 45), (0, 0),
])
def test_parse_duration(raw, seconds):
    assert parse_duration(raw, "x") == timedelta(seconds=seconds)


@pytest.mark.parametrize("raw", [
    "10 minutes", "-5m", "", True, None, [10],
    float("nan"), float("inf"), 1e20, 9223372036854775807, "99999999999d", "400d",
])
def test_parse_duration_rejects(raw):
    # always a ConfigError, never a raw OverflowError/ValueError traceback
    with pytest.raises(ConfigError, match="x"):
        parse_duration(raw, "x")


def test_empty_disable_list_is_fine():
    assert parse_config({"rules": {"disable": []}}).disable == frozenset()


def test_valid_sources_still_parse():
    entry = allow(sources=["10.0.5.*", "SCCM*", "fe80::/64", "192.168.1.7", "sccm01.corp.local"])
    assert [str(n) for n in entry.networks] == ["fe80::/64", "192.168.1.7/32"]
    assert entry.source_hosts == ("10.0.5.*", "SCCM*", "sccm01.corp.local")


@pytest.mark.parametrize("source, src_ip, src_host", [
    ("::ffff:10.0.5.1", "::ffff:10.0.5.1", None),  # as copied from a 4624 IpAddress
    ("::ffff:10.0.5.0/120", "10.0.5.77", None),  # an IPv4-mapped network
    ("2001:db8::*", "2001:db8::5", None),  # IPv6 address glob
    ("ÇAĞRI-PC", None, "ÇAĞRI-PC"),  # localized computer name
    ("sccm01.corp.local.", None, "sccm01.corp.local"),  # FQDN root dot
    ("SCCM01$", None, "SCCM01"),  # copied from a machine-account field
])
def test_source_forms_analysts_paste_actually_match(source, src_ip, src_host):
    assert allow(sources=[source]).matches(finding(src_ip=src_ip, src_host=src_host))


def test_ipv4_mapped_sources_are_stored_as_ipv4():
    entry = allow(sources=["::ffff:10.0.5.0/120"])
    assert [str(n) for n in entry.networks] == ["10.0.5.0/24"]


@pytest.mark.parametrize("hosts", [["SCCM 01"], ["10.0.5.300"], ["srv,01"]])
def test_hosts_get_the_same_validation_as_sources(hosts):
    with pytest.raises(ConfigError, match="hosts"):
        parse_config({"allow": [{"reason": "x", "hosts": hosts}]})


def test_hosts_accept_localized_names_and_normalize():
    entry = allow(hosts=["ÇAĞRI-PC", "dc01.corp.local."])
    assert entry.hosts == ("ÇAĞRI-PC", "dc01.corp.local")
    assert entry.matches(finding(host="ÇAĞRI-PC"))


@pytest.mark.parametrize("rule, name, value", [
    ("CW-002", "window", 0), ("CW-001", "window", "0.5s"), ("CW-012", "cluster_gap", "0s"),
])
def test_a_zero_window_is_refused(rule, name, value):
    with pytest.raises(ConfigError, match="must be at least 1s; use rules.disable"):
        parse_config({"rules": {rule: {name: value}}})


def test_a_zero_tolerance_is_allowed():
    config = parse_config({"rules": {"CW-012": {"skew": 0}}})
    assert config.tunables["CW-012"]["skew"] == timedelta(0)


def test_console_output_never_crashes_on_unencodable_text(tmp_path):
    # Windows redirects stdout in the locale code page (cp1254 here) with strict errors.
    import os
    import subprocess

    path = tmp_path / "c.toml"
    path.write_text('[[allow]]\nreason = "SCCM push → ccmsetup ✓"\nusers = ["svc"]\n',
                    encoding="utf-8")
    env = dict(os.environ, PYTHONIOENCODING="cp1254")
    run = subprocess.run([sys.executable, "-m", "crabwalk.cli", "config", str(path)],
                         capture_output=True, env=env)
    assert run.returncode == 0, run.stderr.decode("cp1254", "replace")
    assert b"\\u2192" in run.stdout


def test_extension_tunable_is_normalized():
    config = parse_config({"rules": {"CW-005": {"extensions": ["EXE", ".Dll", "ps1"]}}})
    assert config.tunables["CW-005"]["extensions"] == (".exe", ".dll", ".ps1")


# -- structure and validation -----------------------------------------------

@pytest.mark.parametrize("data, message", [
    ({"rule": {}}, "unknown top-level key"),
    ({"rules": {"disabled": ["CW-003"]}}, "unknown key 'rules.disabled'"),
    ({"rules": {"disable": ["CW-999"]}}, "unknown rule id"),
    ({"rules": {"only": "CW-012x"}}, "unknown rule id"),
    ({"rules": {"min_severity": "urgent"}}, "expected one of low, medium, high, critical"),
    ({"rules": {"CW-001": {"windw": "5m"}}}, "CW-001 accepts: window"),
    ({"rules": {"CW-001": {"window": "soon"}}}, "rules.CW-001.window"),
    ({"rules": {"CW-003": {"privileged_ntlm": "no"}}}, "expected true or false"),
    ({"rules": {"CW-012": {"enum_distinct_pipes": 0}}}, "whole number >= 1"),
    ({"rules": {"CW-009": {"window": "1m"}}}, "CW-009 has no tunable settings"),
    ({"allow": {"reason": "x"}}, r"\[\[allow\]\]"),
    ({"allow": [{"users": ["x"]}]}, "'reason' is required"),
    ({"allow": [{"reason": "x"}]}, "needs at least one of"),
    ({"allow": [{"reason": "x", "rules": ["CW-001"]}]}, "needs at least one of"),
    ({"allow": [{"reason": "x", "user": ["bob"]}]}, "unknown key"),
    ({"allow": [{"reason": "x", "sources": ["10.0.5.0/33"]}]}, "not a valid CIDR"),
    # a CIDR with host bits would silently widen (10.0.5.0/2 == 0.0.0.0/2): refuse it
    ({"allow": [{"reason": "x", "sources": ["10.0.5.0/2"]}]}, "host bits set.*0.0.0.0/2"),
    ({"allow": [{"reason": "x", "sources": ["10.0.5.9/8"]}]}, "host bits set.*10.0.0.0/8"),
    # address-shaped typos must not become host globs that never match
    ({"allow": [{"reason": "x", "sources": ["10.0.5.300"]}]}, "looks like an address"),
    ({"allow": [{"reason": "x", "sources": ["10.0.5"]}]}, "looks like an address"),
    ({"allow": [{"reason": "x", "sources": ["10.0.5.0-10.0.5.255"]}]}, "looks like an address"),
    ({"allow": [{"reason": "x", "sources": ["10.0.5.1:445"]}]}, "looks like an address"),
    ({"allow": [{"reason": "x", "sources": ["SCCM 01"]}]}, "not an IP, CIDR or host name glob"),
    ({"allow": [{"reason": "x", "users": ["a"], "rules": []}]}, "must name at least one rule"),
    ({"allow": [{"reason": "x", "users": []}]}, "must not be an empty list"),
    ({"rules": {"only": []}}, "must not be an empty list"),
    ({"rules": {"CW-005": {"extensions": []}}}, "use rules.disable to turn CW-005 off"),
    ({"rules": {"CW-005": {"extensions": ["*.exe"]}}}, "not a file extension"),
    ({"rules": {"CW-012": {"drop_window": "1000000d"}}}, "longer than 366 days"),
    ({"allow": [{"reason": "x", "fields": {"ServiceName": "(unclosed"}}]}, "invalid regex"),
    ({"allow": [{"reason": "x", "users": ["a"], "expires": "someday"}]}, "expected a date"),
    ({"allow": [{"reason": "x", "users": ["a"], "rules": ["CW-404"]}]}, "unknown rule id"),
])
def test_invalid_configs_are_rejected_with_a_pointer(data, message):
    with pytest.raises(ConfigError, match=message):
        parse_config(data)


def test_nothing_left_to_run_is_an_error():
    config = parse_config({"rules": {"only": ["CW-012"], "disable": ["CW-012"]}})
    with pytest.raises(ConfigError, match="no rules left"):
        config.build_rules()


def test_build_rules_applies_selection_and_tunables():
    config = parse_config({"rules": {"disable": ["CW-009"], "CW-001": {"window": "15m"},
                                     "CW-012": {"skew": 2, "enum_distinct_pipes": 8}}})
    rules = {r.id: r for r in config.build_rules()}
    assert "CW-009" not in rules and len(rules) == len(ALL_RULES) - 1
    assert rules["CW-001"].window == timedelta(minutes=15)
    assert rules["CW-012"].windows().skew == timedelta(seconds=2)
    assert rules["CW-012"].windows().enum_distinct_pipes == 8
    # class defaults stay untouched for the next run
    assert type(rules["CW-001"]).window == timedelta(minutes=10)


def test_command_line_overrides_layer_over_the_file():
    config = parse_config({"rules": {"only": ["CW-001", "CW-012"], "disable": ["CW-001"]}})
    assert config.with_overrides().rule_ids() == ["CW-012"]
    assert config.with_overrides(only=["cw-005"]).rule_ids() == ["CW-005"]
    assert config.with_overrides(disable=["CW-012"]).rule_ids() == []
    assert config.with_overrides(min_severity="high").min_severity == "high"
    with pytest.raises(ConfigError, match="command line"):
        config.with_overrides(disable=["CW-77"])


# -- allowlist matching --------------------------------------------------------

@pytest.mark.parametrize("pattern, user, hit", [
    ("CORP\\svc_sccm", "CORP\\svc_sccm", True),
    ("corp\\SVC_SCCM", "CORP\\svc_sccm", True),
    ("CORP\\svc_sccm", "LAB\\svc_sccm", False),
    ("svc_sccm", "LAB\\svc_sccm", True),  # bare name: any domain
    ("svc_*", "CORP\\svc_backup", True),
    ("svc_sccm", "svc_sccm@corp.local", True),
    ("svc_sccm@corp.local", "svc_sccm@CORP.LOCAL", True),
    ("svc_sccm", "CORP\\admin", False),
    # a domain-qualified pattern matches either notation of the same domain...
    ("CORP\\svc_sccm", "svc_sccm@CORP.LOCAL", True),
    ("svc_sccm@corp.local", "CORP\\svc_sccm", True),
    ("CORP\\svc_sccm", "svc_sccm@LAB.LOCAL", False),
    # ...but never a record that cannot show its domain
    ("CORP\\svc_sccm", "svc_sccm", False),
    ("CORP\\*", "S-1-5-21-1-2-3-500", False),
    # DNS-form domains as Kerberos logons record them (corpus: WINLAB.LOCAL\Administrator)
    ("WINLAB\\Administrator", "WINLAB.LOCAL\\Administrator", True),
    ("Administrator@winlab.local", "WINLAB.LOCAL\\Administrator", True),
    ("lgrove@THREEBEESCO.COM", "THREEBEESCO.COM\\lgrove", True),
    ("CORP.LOCAL\\svc", "CORP\\svc", True),
    # a written realm never reaches into another forest or collapses to a wildcard
    ("svc@corp.contoso.com", "svc@corp.fabrikam.com", False),
    ("svc@*.contoso.com", "svc@x.contoso.com", True),
    ("svc@*.contoso.com", "FABRIKAM\\svc", False),
    ("svc@*.contoso.com", "CONTOSO\\svc", False),  # a glob realm cannot be proven from NetBIOS
    # NetBIOS names that differ from the DNS label cannot be related: documented, list both
    ("3B\\lgrove", "lgrove@THREEBEESCO.COM", False),
])
def test_user_patterns(pattern, user, hit):
    assert allow(users=[pattern]).matches(finding(user=user)) is hit


@pytest.mark.parametrize("pattern, host, hit", [
    ("SRV01", "SRV01.corp.local", True),
    ("srv*", "SRV01.corp.local", True),
    ("*.corp.local", "SRV01.corp.local", True),
    ("SRV02", "SRV01.corp.local", False),
])
def test_host_patterns(pattern, host, hit):
    assert allow(hosts=[pattern]).matches(finding(host=host)) is hit


@pytest.mark.parametrize("pattern, src_ip, src_host, hit", [
    ("10.0.5.0/24", "10.0.5.9", None, True),
    ("10.0.5.0/24", "::ffff:10.0.5.9", None, True),  # session-layer form
    ("10.0.5.0/24", "10.0.6.9", None, False),
    ("10.0.5.7", "10.0.5.7", None, True),
    ("10.0.5.*", "10.0.5.200", None, True),  # glob on the address
    ("SCCM*", None, "SCCM01", True),
    ("SCCM*", "10.0.5.9", None, False),
    ("10.0.5.0/24", None, None, False),  # no source known: never matches
    ("SCCM01.corp.local", None, "SCCM01", True),  # FQDN vs the NetBIOS name logs keep
    ("SCCM01.corp.local", None, "SCCM01.lab.local", False),
    ("10.0.5.0/24", "45.1.2.3", None, False),
])
def test_source_patterns(pattern, src_ip, src_host, hit):
    assert allow(sources=[pattern]).matches(finding(src_ip=src_ip, src_host=src_host)) is hit


def test_field_regex_matches_evidence_and_all_criteria_must_hold():
    install = ev(7045, channel=SYSTEM, ServiceName="ccmsetup", ImagePath=r"C:\ccm\ccmsetup.exe")
    entry = allow(rules=["CW-001"], users=["svc_sccm"], fields={"ServiceName": "^CCMSETUP$"})
    good = finding("CW-001", user="CORP\\svc_sccm", evidence=[install])
    assert entry.matches(good)
    assert not entry.matches(finding("CW-012", user="CORP\\svc_sccm", evidence=[install]))  # scope
    assert not entry.matches(finding("CW-001", user="CORP\\eve", evidence=[install]))  # user
    other = ev(7045, channel=SYSTEM, ServiceName="evilsvc", ImagePath=r"C:\evil.exe")
    assert not entry.matches(finding("CW-001", user="CORP\\svc_sccm", evidence=[other]))  # field
    assert not entry.matches(finding("CW-001", user="CORP\\svc_sccm"))  # no evidence to check


def pipe_open(name, seconds=0):
    return ev(5145, minutes=seconds / 60, ShareName="\\\\*\\IPC$", RelativeTargetName=name,
              IpAddress="10.0.0.5", SubjectUserName="admin", SubjectDomainName="CORP")


def test_one_benign_evidence_event_does_not_excuse_the_rest():
    # A PsExec run also opens svcctl. An entry meant for svcctl-only monitoring
    # must not swallow the whole critical cluster.
    events = [pipe_open("svcctl"), pipe_open("PSEXESVC", 1), pipe_open("PSEXESVC-WKS66-4242-stdin", 1),
              ev(7045, channel=SYSTEM, minutes=2 / 60, ServiceName="PSEXESVC", ImagePath=r"C:\p.exe")]
    (psexec,) = [f for f in run_rules(HuntContext.build(events)) if f.rule_id == "CW-012"]
    assert not allow(rules=["CW-012"], fields={"RelativeTargetName": "^svcctl$"}).matches(psexec)
    covering = allow(rules=["CW-012"], fields={"RelativeTargetName": "^(svcctl|psexesvc.*)$"})
    assert covering.matches(psexec)


def test_field_names_match_case_insensitively():
    install = ev(7045, channel=SYSTEM, ServiceName="ccmsetup", ImagePath=r"C:\ccm\ccmsetup.exe")
    assert allow(fields={"servicename": "^ccmsetup$"}).matches(finding(evidence=[install]))


def test_misspelled_field_name_is_reported():
    install = ev(7045, channel=SYSTEM, ServiceName="ccmsetup", ImagePath=r"C:\ccm\ccmsetup.exe")
    config = parse_config({"allow": [{"reason": "sccm", "users": ["svc_sccm"],
                                      "fields": {"SvcName": "^ccmsetup$"}}]})
    screened = config.screen([finding(user="CORP\\svc_sccm", evidence=[install])])
    assert len(screened.kept) == 1
    (warning,) = screened.warnings
    assert "'svcname' appears in no evidence" in warning


def test_rules_report_domain_qualified_users_so_qualified_patterns_work():
    drop = ev(5145, ShareName="\\\\*\\ADMIN$", RelativeTargetName="ccmsetup.exe", IpAddress="10.0.5.9",
              SubjectUserName="svc_sccm", SubjectDomainName="CORP")
    (cw005,) = [f for f in run_rules(HuntContext.build([drop])) if f.rule_id == "CW-005"]
    assert cw005.user == "CORP\\svc_sccm"
    assert allow(users=["CORP\\svc_sccm"]).matches(cw005)


def test_screen_suppresses_filters_and_reports_expired_entries():
    config = parse_config({
        "rules": {"min_severity": "high"},
        "allow": [
            {"reason": "backup agent", "users": ["svc_backup"]},
            {"reason": "retired exception", "users": ["eve"], "expires": date(2026, 1, 31)},
        ],
    })
    findings = [
        finding(user="CORP\\svc_backup", severity="critical"),
        finding(user="CORP\\eve", severity="critical"),  # expired entry: kept
        finding(user="CORP\\bob", severity="medium"),  # below the floor
        finding(user="CORP\\svc_backup", severity="low"),  # allowlisted first
    ]
    screened = config.screen(findings, today=date(2026, 10, 8))
    assert [f.user for f in screened.kept] == ["CORP\\eve"]
    assert [(f.user, e.index) for f, e in screened.suppressed] == [
        ("CORP\\svc_backup", 1), ("CORP\\svc_backup", 1)]
    assert screened.below_min_severity == 1
    assert [e.index for e in screened.expired] == [2]
    assert config.screen(findings, today=date(2026, 1, 31)).expired == []  # last valid day


# -- tunables change behavior ---------------------------------------------------

def remote_logon(minutes=0, **extra):
    data = {"TargetLogonId": "0x3E7A", "TargetUserName": "admin", "TargetDomainName": "CORP",
            "LogonType": "3", "IpAddress": "10.0.0.5", "WorkstationName": "WS01",
            "AuthenticationPackageName": "NTLM"}
    data.update(extra)
    return ev(4624, minutes=minutes, **data)


def fired(events, config):
    return {f.rule_id for f in run_rules(HuntContext.build(events), config.build_rules())}


def test_window_tunable_changes_what_correlates():
    events = [remote_logon(), ev(7045, channel=SYSTEM, minutes=8, ServiceName="X", ImagePath=r"C:\x.exe")]
    assert "CW-001" in fired(events, Config())
    assert "CW-001" not in fired(events, parse_config({"rules": {"CW-001": {"window": "5m"}}}))


def test_privileged_ntlm_switch_keeps_the_seclogo_signature():
    events = [remote_logon(), ev(4672, SubjectLogonId="0x3E7A"),
              ev(4624, TargetUserName="victim", LogonType="9", LogonProcessName="seclogo",
                 TargetLogonId="0x99", TargetOutboundUserName="DA")]
    quiet = parse_config({"rules": {"only": ["CW-003"], "CW-003": {"privileged_ntlm": False}}})
    loud = parse_config({"rules": {"only": ["CW-003"]}})
    summaries = lambda c: sorted(f.summary[:12] for f in run_rules(HuntContext.build(events), c.build_rules()))  # noqa: E731
    assert len(summaries(loud)) == 2
    assert summaries(quiet) == ["Logon type 9"]


# -- the example file and the CLI ---------------------------------------------

def test_example_config_is_valid_inert_and_complete():
    text = example_config()
    config = parse_config(tomllib.loads(text))
    assert config.rule_ids() == [cls.id for cls in ALL_RULES]
    assert config.tunables == {} and config.allow == []
    for cls in ALL_RULES:
        for name in cls.tunables:
            assert f"# {name} = " in text, f"{cls.id}.{name} missing from the example"
    # uncommenting the per-rule block reproduces every default exactly
    block = text[text.index("# [rules."):text.index("# Suppress known-good")]
    uncommented = "\n".join(line[2:] if line.startswith("# ") else line for line in block.splitlines())
    config = parse_config(tomllib.loads(uncommented))
    assert set(config.tunables) == {cls.id for cls in ALL_RULES if cls.tunables}
    for rule in config.build_rules():
        for name in rule.tunables:
            assert getattr(rule, name) == getattr(type(rule), name), f"{rule.id}.{name}"


def test_cli_config_example_and_check(tmp_path, capsys):
    assert main(["config", "--example"]) == 0
    example = capsys.readouterr().out
    path = tmp_path / "crabwalk.toml"
    path.write_text(example.replace("# disable = [", "disable = ["), encoding="utf-8")
    assert main(["config", str(path)]) == 0
    out = capsys.readouterr().out
    assert "(valid)" in out and "not run    : CW-003" in out
    path.write_text('[rules]\ndisable = ["CW-3"]\n', encoding="utf-8")
    assert main(["config", str(path)]) == 2
    assert "unknown rule id" in capsys.readouterr().err


def test_cli_hunt_rejects_a_bad_config_before_reading_evidence(tmp_path, capsys):
    path = tmp_path / "bad.toml"
    path.write_text("[rules\n", encoding="utf-8")
    assert main(["hunt", str(tmp_path), "--config", str(path)]) == 2
    assert "not valid TOML" in capsys.readouterr().err
    assert main(["hunt", str(tmp_path), "--disable", "CW-404"]) == 2
    assert main(["hunt", str(tmp_path), "--config", str(tmp_path / "missing.toml")]) == 2


@pytest.mark.parametrize("encoding", ["utf-8", "utf-8-sig", "utf-16", "utf-16-be"])
def test_load_config_accepts_what_windows_shells_write(tmp_path, encoding):
    # PowerShell 5.1: `>` writes UTF-16 LE with BOM, Out-File -Encoding utf8 adds a BOM
    path = tmp_path / "c.toml"
    text = '[rules]\ndisable = ["CW-003"]\n'
    data = text.encode(encoding) if encoding != "utf-16-be" else b"\xfe\xff" + text.encode("utf-16-be")
    path.write_bytes(data)
    assert load_config(path).disable == {"CW-003"}


def test_example_config_is_ascii():
    assert example_config().isascii()


def test_load_config_reads_toml_dates_and_escapes(tmp_path):
    path = tmp_path / "c.toml"
    path.write_text('[[allow]]\nreason = "r"\nusers = ["CORP\\\\svc"]\nexpires = 2026-12-31\n',
                    encoding="utf-8")
    (entry,) = load_config(path).allow
    assert entry.users == ("CORP\\svc",) and entry.expires == date(2026, 12, 31)


def test_report_lists_suppressed_findings_with_reasons():
    entry = allow(users=["svc_backup"])
    html = render_report(HuntContext.build([]), [], suppressed=[(finding(user="CORP\\svc_backup"), entry)])
    assert "Suppressed by allowlist" in html and "allow[1] known good" in html


def test_json_output_records_suppressions_and_settings(tmp_path, monkeypatch):
    import crabwalk.cli as cli

    events = [remote_logon(), ev(7045, channel=SYSTEM, minutes=1, ServiceName="X", ImagePath=r"C:\x.exe")]
    monkeypatch.setattr(cli, "iter_events", lambda paths, stats: iter(events))
    cfg = tmp_path / "c.toml"
    cfg.write_text('[rules.CW-001]\nwindow = "20m"\n[[allow]]\nreason = "deploy"\nsources = ["10.0.0.0/8"]\n',
                   encoding="utf-8")
    out = tmp_path / "f.json"
    assert main(["hunt", str(tmp_path), "--config", str(cfg), "--out", str(out)]) == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["findings"] == []
    (suppressed,) = [s for s in payload["suppressed"] if s["rule_id"] == "CW-001"]
    assert suppressed["allow_reason"] == "deploy"
    assert payload["settings"]["tunables"] == {"CW-001": {"window": "20m"}}
