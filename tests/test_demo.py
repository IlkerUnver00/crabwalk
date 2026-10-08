"""The bundled demo logs (demo/evtx, GPL-3.0 data from EVTX-ATTACK-SAMPLES).

Unlike the corpus tests these always run, CI included: real EVTX files go
through the whole pipeline on every push, and what demo/README.md promises a
first-time user is checked here.
"""

from pathlib import Path

from crabwalk.cli import main
from crabwalk.graph import build_graph
from crabwalk.narrative import build_story
from crabwalk.parser import ParseStats, iter_events
from crabwalk.rules import hunt

DEMO = Path(__file__).resolve().parent.parent / "demo" / "evtx"


def demo_hunt():
    stats = ParseStats()
    ctx, findings = hunt(iter_events([DEMO], stats=stats))
    return stats, ctx, findings


def test_demo_parses_cleanly_and_matches_the_readme():
    stats, _, findings = demo_hunt()
    assert (stats.files, stats.records, stats.kept) == (9, 129, 123)
    assert stats.file_errors == stats.damaged_files == stats.read_errors == stats.skipped == 0
    by_severity = {s: sum(f.severity == s for f in findings) for s in ("critical", "high", "medium")}
    assert by_severity == {"critical": 4, "high": 6, "medium": 4}


def test_renamed_psexec_source_host_is_recovered():
    _, _, findings = demo_hunt()
    (psexec,) = [f for f in findings if f.rule_id == "CW-012" and f.host == "IEWIN7"
                 and f.src_host == "NLLT108334"]
    assert psexec.severity == "critical"
    assert psexec.src_ip == "10.0.2.16"
    # the ADMIN$ drop CW-005 also reports is told inside this finding, not twice
    assert [m.rule_id for m in psexec.merged] == ["CW-005"]
    assert not any(f.rule_id == "CW-005" and f.host == "IEWIN7" for f in findings)


def test_story_tells_the_intrusion_in_order():
    _, ctx, findings = demo_hunt()
    story = build_story(ctx, findings)
    (path,) = story.chapters
    assert path.title() == ("NLLT108334 → PC01.example.corp → WIN-77LTAPHIQ1R.example.corp "
                            "(also: IEWIN7)")
    first = path.beats[0]
    assert first.source == "NLLT108334 (10.0.2.16)" and first.users == ("IEWIN7\\IEUser",)
    assert first.text == ("copied 'blabla.exe' to ADMIN$, then ran it through PsExec "
                          "with its service renamed to 'blabla'")
    # PC01's step names only an address; the name comes from IEWIN7's records, and says so
    assert path.beats[1].source == "10.0.2.16 (named NLLT108334 elsewhere in the logs)"
    lines = [b.text for b in path.beats]
    assert any("sekurlsa::pth" in text for text in lines)
    assert any("'\\CYAlyNSS' to run 'cmd.exe'" in text for text in lines)
    assert [b.when for b in path.beats] == sorted(b.when for b in path.beats)
    assert path.notes and "gaps of 28 days, 29 days and 42 days" in path.notes[0]
    assert {a.host for a in story.other} == {"DC1.insecurebank.local", "MSEDGEWIN10"}
    text = story.to_text()
    assert "ANONYMOUS" not in text and "→" not in text  # ASCII arrows on the console
    assert "no other host involved" in text  # the local PsExec run says so


def test_dcsync_and_local_psexec_contrast():
    _, _, findings = demo_hunt()
    assert any(f.rule_id == "CW-011" and f.severity == "critical" for f in findings)
    (local,) = [f for f in findings if f.host == "MSEDGEWIN10" and f.rule_id == "CW-012"]
    assert local.title.startswith("Local execution") and "T1021.002" not in local.techniques


def test_attack_graph_shows_the_multi_hop_path():
    _, ctx, findings = demo_hunt()
    graph = build_graph(ctx, findings)
    edges = {(e.src, e.dst) for e in graph.edges}
    assert {("nllt108334", "iewin7"), ("nllt108334", "pc01"), ("pc01", "win-77ltaphiq1r")} <= edges
    assert graph.nodes["win-77ltaphiq1r"].depth == 2
    # the 4648 on PC01 and the 4624s on WIN-77LTAPHIQ1R are one edge
    (wmi,) = [e for e in graph.edges if (e.src, e.dst) == ("pc01", "win-77ltaphiq1r")]
    assert {"explicit creds", "logon"} <= set(wmi.kinds())


def test_pages_site_builds_with_a_working_navigator_link(tmp_path):
    import importlib.util
    import json

    spec = importlib.util.spec_from_file_location(
        "build_site", Path(__file__).resolve().parent.parent / "scripts" / "build_site.py")
    build_site = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(build_site)

    build_site.build(tmp_path, "https://example.github.io/crabwalk/")
    names = {p.name for p in tmp_path.iterdir()}
    assert {"index.html", "report.html", "attack-paths.html", "findings.json", "story.md",
            "navigator-layer.json", ".nojekyll"} <= names
    index = (tmp_path / "index.html").read_text(encoding="utf-8")
    assert ("attack-navigator/#layerURL=https%3A%2F%2Fexample.github.io%2Fcrabwalk%2Fnavigator-layer.json"
            in index)
    assert "What happened" in index and "service renamed to" in index
    assert index.index("separate public lab recordings") < index.index("Path 1")  # caveat first
    layer = json.loads((tmp_path / "navigator-layer.json").read_text(encoding="utf-8"))
    assert layer["domain"] == "enterprise-attack" and layer["techniques"]


def test_quickstart_command_from_the_readme(tmp_path, capsys):
    report, graph = tmp_path / "report.html", tmp_path / "attack-paths.html"
    story = tmp_path / "story.md"
    assert main(["hunt", str(DEMO), "--report", str(report), "--graph", str(graph),
                 "--story", str(story)]) == 0
    html = report.read_text(encoding="utf-8")
    assert "Attack paths" in html and "What happened" in html
    assert html.index("What happened") < html.index("Attack paths")  # the story leads
    assert "NLLT108334" in graph.read_text(encoding="utf-8")
    assert story.read_text(encoding="utf-8").startswith("# What happened")
    assert "ATTACK STORY" in capsys.readouterr().out
