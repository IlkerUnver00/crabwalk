import itertools
import json
import re
from datetime import datetime, timedelta, timezone

import pytest

from crabwalk.catalog import SECURITY
from crabwalk.cli import main
from crabwalk.graph import build_graph, render_page, render_svg
from crabwalk.models import NormalizedEvent
from crabwalk.report import render_report
from crabwalk.rules.base import Finding, HuntContext

T0 = datetime(2026, 8, 1, 12, 0, 0, tzinfo=timezone.utc)
_rid = itertools.count(1)


def ev(event_id, *, minutes=0, computer, **data):
    return NormalizedEvent(
        timestamp=T0 + timedelta(minutes=minutes), channel=SECURITY, provider="t",
        event_id=event_id, record_id=next(_rid), computer=computer, data=data,
        source_file="t.evtx",
    )


def logon(dst, *, ip, workstation="-", user="admin", minutes=0, logon_type="3", logon_id=None):
    return ev(4624, minutes=minutes, computer=dst, TargetUserName=user, TargetDomainName="CORP",
              TargetLogonId=logon_id or hex(next(_rid)), LogonType=logon_type,
              IpAddress=ip, WorkstationName=workstation)


def finding(host, *, src_ip=None, src_host=None, severity="high", rule="CW-012", minutes=0):
    return Finding(rule, "t", severity, ("T1021.002",), T0 + timedelta(minutes=minutes), host,
                   "summary", "CORP\\admin", [], src_ip, src_host)


def chain_events():
    """WS01 -> SRV01 (network) -> DC01 (RDP); each hop logged on its target."""
    return [
        logon("SRV01.corp.local", ip="10.0.0.5", workstation="WS01", minutes=0),
        logon("DC01.corp.local", ip="10.0.0.6", workstation="SRV01", minutes=30, logon_type="10"),
    ]


def graph_of(events, findings=()):
    return build_graph(HuntContext.build(events), list(findings))


def test_chain_reads_left_to_right():
    graph = graph_of(chain_events())
    depth = {k: n.depth for k, n in graph.nodes.items()}
    assert depth == {"ws01": 0, "srv01": 1, "dc01": 2}
    assert [k for k, n in graph.nodes.items() if n.origin] == ["ws01"]
    assert graph.nodes["srv01"].label == "SRV01.corp.local"
    assert graph.nodes["srv01"].addresses == ["10.0.0.6"]


def test_outbound_and_inbound_half_edges_become_one_edge():
    events = [
        ev(4648, computer="WS01.corp.local", SubjectLogonId="0x1", TargetUserName="admin",
           TargetDomainName="CORP", TargetServerName="SRV01.corp.local"),
        logon("SRV01.corp.local", ip="10.0.0.5", workstation="WS01"),
    ]
    (edge,) = graph_of(events).edges
    assert (edge.src, edge.dst) == ("ws01", "srv01")
    assert edge.kinds() == {"explicit creds": 1, "logon": 1}


def test_finding_source_ip_resolves_through_learned_name():
    graph = graph_of(chain_events(), [finding("SRV01.corp.local", src_ip="10.0.0.5", minutes=1)])
    (edge,) = [e for e in graph.edges if e.dst == "srv01"]
    assert edge.src == "ws01"
    assert edge.severity == "high"
    assert {m.kind for m in edge.movements} == {"network", "CW-012"}


def test_unknown_external_source_is_an_address_node():
    graph = graph_of([], [finding("SRV01", src_ip="8.8.8.8")])
    node = graph.nodes["ip:8.8.8.8"]
    assert node.address_class == "external"
    assert "external address" in node.subtitle()
    assert node.origin


def test_self_edges_and_machine_accounts_are_dropped():
    events = [logon("SRV01", ip="10.0.0.5", workstation="WS01", user="WS01$")]
    graph = graph_of(events, [finding("SRV01", src_host="SRV01")])
    assert graph.edges == []
    included = build_graph(HuntContext.build(events), [], include_machine=True)
    assert len(included.edges) == 1


def test_cycle_keeps_time_order_for_depth():
    events = [
        logon("B", ip="10.0.0.1", workstation="A", minutes=0),
        logon("A", ip="10.0.0.2", workstation="B", minutes=5),  # B back to A
    ]
    graph = graph_of(events)
    assert (graph.nodes["a"].depth, graph.nodes["b"].depth) == (0, 1)
    assert render_svg(graph).count('class="ge"') == 2  # back edge is still drawn


def test_node_severity_is_worst_and_isolated_hosts_are_banded():
    graph = graph_of(
        chain_events(),
        [finding("DC01.corp.local", severity="medium"),
         finding("DC01.corp.local", severity="critical"),
         finding("LONELY", severity="high")],
    )
    assert graph.nodes["dc01"].severity == "critical"
    assert graph.nodes["lonely"].component == -1
    assert "LONELY" not in render_svg(graph, connected_only=True)
    assert "NO OBSERVED MOVEMENT" in render_svg(graph)


def test_dot_escapes_and_json_round_trips():
    graph = graph_of([], [finding('SRV"01', src_host="WS\\01")])
    dot = graph.to_dot()
    assert dot.startswith("digraph crabwalk {")
    assert '"ws\\\\01" -> "srv\\"01"' in dot
    data = json.loads(graph.to_json())
    assert {n["id"] for n in data["nodes"]} == {"ws\\01", 'srv"01'}
    assert data["edges"][0]["movements"][0]["kind"] == "CW-012"


def test_page_is_self_contained_and_escaped():
    graph = graph_of([], [finding("<script>alert(1)</script>", src_host="WS01")])
    page = render_page(graph)
    assert "<script>alert(1)" not in page
    assert re.search(r"<(?:script|img|iframe|link)\b[^>]*\s(?:src|href)=", page) is None
    assert re.findall(r"https?://[^\s\"'<>]+", page) == ["http://www.w3.org/2000/svg"]


def test_output_is_deterministic():
    findings = [finding("SRV01.corp.local", src_ip="10.0.0.5", minutes=1)]
    a, b = graph_of(chain_events(), findings), graph_of(list(reversed(chain_events())), findings)
    assert a.to_dot() == b.to_dot()
    assert render_svg(a) == render_svg(b)


def _view_height(svg: str) -> float:
    return float(re.search(r'viewBox="0 0 [\d.]+ ([\d.]+)"', svg).group(1))


def _sample_path(d: str, steps: int = 24) -> list[tuple[float, float]]:
    """Points along an SVG path made of M, L, Q and C commands."""
    tokens = re.findall(r"[MLQC]|-?\d+(?:\.\d+)?", d)
    points: list[tuple[float, float]] = []
    cur = (0.0, 0.0)
    i = 0

    def take(n):
        nonlocal i
        vals = [float(v) for v in tokens[i:i + 2 * n]]
        i += 2 * n
        return [(vals[2 * k], vals[2 * k + 1]) for k in range(n)]

    while i < len(tokens):
        cmd = tokens[i]
        i += 1
        ts = [s / steps for s in range(1, steps + 1)]
        if cmd == "M":
            (cur,) = take(1)
            points.append(cur)
        elif cmd == "L":
            (end,) = take(1)
            points += [(cur[0] + (end[0] - cur[0]) * t, cur[1] + (end[1] - cur[1]) * t) for t in ts]
            cur = end
        elif cmd == "Q":
            c, end = take(2)
            points += [tuple((1 - t) ** 2 * a + 2 * (1 - t) * t * b + t ** 2 * e
                             for a, b, e in zip(cur, c, end)) for t in ts]
            cur = end
        elif cmd == "C":
            c1, c2, end = take(3)
            points += [tuple((1 - t) ** 3 * a + 3 * (1 - t) ** 2 * t * b + 3 * (1 - t) * t ** 2 * c
                             + t ** 3 * e for a, b, c, e in zip(cur, c1, c2, end)) for t in ts]
            cur = end
    return points


def _curves(svg: str) -> list[list[tuple[float, float]]]:
    return [_sample_path(d) for d in re.findall(r'class="line" d="([^"]+)"', svg)]


def _label_boxes(svg: str) -> list[tuple[float, float, float, float]]:
    return [tuple(map(float, m)) for m in re.findall(
        r'<g class="ge elabel"[^>]*><rect x="([\d.]+)" y="(-?[\d.]+)" width="([\d.]+)" height="([\d.]+)"', svg)]


def _node_boxes(svg: str) -> dict[str, tuple[float, float]]:
    return {k: (float(x), float(y)) for k, x, y in re.findall(
        r'<g class="gn" data-id="([^"]+)">.*?<rect class="box" x="([\d.]+)" y="([\d.]+)"', svg, re.S)}


def test_back_edge_loop_stays_on_the_canvas():
    events = [
        logon("SRV01", ip="10.0.0.5", workstation="WS01", minutes=0),
        logon("WS01", ip="10.0.0.6", workstation="SRV01", minutes=30),  # and back
    ]
    svg = render_svg(graph_of(events), connected_only=True)
    height = _view_height(svg)
    assert all(0 <= y <= height for curve in _curves(svg) for _, y in curve)
    assert all(y >= 0 and y + h <= height for _, y, _, h in _label_boxes(svg))


def test_column_skipping_edge_arcs_over_the_intermediate_host():
    events = chain_events() + [
        logon("DC01.corp.local", ip="10.0.0.5", workstation="WS01", user="eve", minutes=40),
    ]
    svg = render_svg(graph_of(events), connected_only=True)
    nodes = _node_boxes(svg)
    mx, my = nodes["srv01"]
    for curve in _curves(svg):
        inside = [(x, y) for x, y in curve if mx < x < mx + 178 and my < y < my + 52]
        assert not inside, "an edge runs through the intermediate node"
    for x, y, w, h in _label_boxes(svg):
        overlaps = x < mx + 178 and mx < x + w and y < my + 52 and my < y + h
        assert not overlaps, "an edge label hides behind/over a node"
    assert all(y >= 0 for x, y, w, h in _label_boxes(svg))


def _hops(*pairs: str) -> list:
    """'A>B' strings -> logons on B from A, one minute apart, in order."""
    events = []
    for minute, pair in enumerate(pairs):
        src, dst = pair.split(">")
        events.append(logon(dst, ip=f"10.9.{ord(src[0]) % 250}.{len(src) * 10 + int(src[1:] or 0)}",
                            workstation=src, minutes=minute))
    return events


def _all(src_group: str, dst_group: str) -> list[str]:
    return [f"{s}>{d}" for s in src_group.split() for d in dst_group.split()]


TOPOLOGIES = {
    "chain-with-skip": ["A>B", "B>C", "A>C"],
    "lower-row-skip": ["A>B1", "A>B2", "A>B3", *_all("B1 B2 B3", "C1 C2 C3"),
                       *_all("C1 C2 C3", "D"), "B3>D"],
    "long-lower-row-skip": ["A>B1", "A>B2", "A>B3", *_all("B1 B2 B3", "C1 C2 C3"),
                            *_all("C1 C2 C3", "D"), "B3>D", *_all("D", "E1 E2 E3"), "B3>E1"],
    "back-edge-over-lower-row": ["A>B", "B>C1", "B>C2", "C1>A"],
    "back-edge-past-sibling": ["A1>B", "A2>B", "B>A1"],
    "two-cycle": ["A>B", "B>A"],
    "stacked-skips": ["A>B1", "A>B2", "A>B3", *_all("B1 B2 B3", "C"), "C>D", "A>C", "A>D",
                      "B3>D", "B2>D"],
}


@pytest.mark.parametrize("name", TOPOLOGIES)
def test_drawing_never_crosses_hosts_or_collides(name):
    svg = render_svg(graph_of(_hops(*TOPOLOGIES[name])), connected_only=True)
    width = float(re.search(r'viewBox="0 0 ([\d.]+)', svg).group(1))
    height = _view_height(svg)
    boxes = [(x, y, 178.0, 52.0) for x, y in _node_boxes(svg).values()]
    labels = _label_boxes(svg)

    for curve in _curves(svg):
        for x, y in curve:
            assert 0 <= x <= width and 0 <= y <= height, f"{name}: edge off canvas at {(x, y)}"
            for bx, by, bw, bh in boxes:
                inside = bx + 1 < x < bx + bw - 1 and by + 1 < y < by + bh - 1
                assert not inside, f"{name}: edge crosses the host box at {(bx, by)}"
    for i, (x, y, w, h) in enumerate(labels):
        assert x >= 0 and y >= 0 and x + w <= width and y + h <= height, f"{name}: label off canvas"
        for bx, by, bw, bh in boxes:
            assert not (x < bx + bw and bx < x + w and y < by + bh and by < y + h), \
                f"{name}: label over a host box"
        for ox, oy, ow, oh in labels[i + 1:]:
            assert not (x < ox + ow and ox < x + w and y < oy + oh and oy < y + h), \
                f"{name}: two labels overlap"


def test_loopback_source_is_not_an_origin_host():
    events = [logon("SRV01", ip="::ffff:127.0.0.1", workstation="-")]
    graph = graph_of(events, [finding("SRV01", src_ip="127.0.0.2")])
    assert graph.edges == []
    assert not any(k.startswith("ip:127.") for k in graph.nodes)
    assert HuntContext.build(events).tracking.remote_sessions() == []


def test_findings_without_movement_spread_across_the_page():
    graph = graph_of([], [finding(f"HOST{i}") for i in range(6)])
    svg = render_svg(graph)
    width = float(re.search(r'viewBox="0 0 ([\d.]+)', svg).group(1))
    assert width >= 4 * 178
    assert len({x for x, _ in _node_boxes(svg).values()}) >= 4


def test_report_shows_attack_paths_only_when_there_is_movement():
    ctx = HuntContext.build(chain_events())
    assert "Attack paths" in render_report(ctx, [])
    assert "Attack paths" not in render_report(HuntContext.build([]), [])


def test_cli_graph_rejects_unknown_extension(tmp_path, capsys):
    assert main(["hunt", str(tmp_path), "--graph", str(tmp_path / "g.png")]) == 2
    assert "--graph needs" in capsys.readouterr().err
