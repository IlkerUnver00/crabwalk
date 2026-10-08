"""Attack-path graph: machines as nodes, lateral movement as directed edges.

The session layer already reconstructs host-to-host movement (4624/4648/RDP).
Findings that know where their activity came from — a 5145 IpAddress, the
source host PsExec writes into its pipe names — add edges no logon event shows.
Both collapse onto one node per machine through HostResolver, and the result is
laid out left to right so an intrusion reads as a path: origin, hops, targets.

Exports: Graphviz DOT, JSON (nodes/edges for Cytoscape, vis.js, ...), an
inline SVG for the HTML report, and a standalone interactive HTML page.
"""

from __future__ import annotations

import html
import json
import math
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .hosts import HostResolver, classify_ip
from .rules.base import SEVERITY_RANK, Finding, HuntContext, evidence_key
from .style import SEVERITY_COLOR, SEVERITY_ORDER, page_head

#: Short names for session-layer movement kinds; rule ids pass through as-is.
#: Kept terse: they label edges that sit between node columns.
KIND_LABELS = {
    "network": "logon",
    "network-cleartext": "cleartext logon",
    "rdp": "RDP",
    "rdp-session": "RDP",
    "rdp-reconnect": "RDP",
    "explicit-credentials": "explicit creds",  # 4648: not only runas
    "interactive": "interactive",
}
EDGE_LABEL_MAX = 24


@dataclass(slots=True)
class Movement:
    """One observation behind an edge: a logon, or a finding with a known source."""

    timestamp: datetime
    kind: str  # session kind ("network", "rdp", ...) or a rule id ("CW-012")
    user: str
    privileged: bool = False
    severity: str | None = None  # set when the movement comes from a finding
    title: str | None = None
    finding: Finding | None = None  # the finding itself, for the narrative
    # What this observation itself says about its source (the node may know
    # more, learned elsewhere), and the records behind it.
    src_ip: str | None = None
    src_host: str | None = None
    records: frozenset = frozenset()

    @property
    def label(self) -> str:
        return KIND_LABELS.get(self.kind, self.kind)


@dataclass
class GraphEdge:
    src: str
    dst: str
    movements: list[Movement] = field(default_factory=list)

    @property
    def first(self) -> datetime:
        return min(m.timestamp for m in self.movements)

    @property
    def last(self) -> datetime:
        return max(m.timestamp for m in self.movements)

    @property
    def severity(self) -> str | None:
        """Worst finding severity carried by the edge; None for logons only."""
        rated = [m.severity for m in self.movements if m.severity]
        return max(rated, key=lambda s: SEVERITY_RANK.get(s, 0)) if rated else None

    @property
    def privileged(self) -> bool:
        return any(m.privileged for m in self.movements)

    @property
    def users(self) -> list[str]:
        return sorted({m.user for m in self.movements if m.user and m.user != "-"})

    def kinds(self) -> Counter[str]:
        return Counter(m.label for m in self.movements)

    def label(self) -> str:
        """Compact edge caption: top kinds, count, and 'admin' for privileged
        logons. The full breakdown lives in the tooltip and tables."""
        kinds = self.kinds()
        ranked = sorted(kinds, key=lambda k: (-kinds[k], k))
        tail = (f" ×{len(self.movements)}" if len(self.movements) > 1 else "")
        tail += " · admin" if self.privileged else ""
        head = " · ".join(ranked[:2]) + (f" +{len(ranked) - 2}" if len(ranked) > 2 else "")
        if len(head) + len(tail) > EDGE_LABEL_MAX:
            head = ranked[0] + (f" +{len(ranked) - 1}" if len(ranked) > 1 else "")
        return _clip(head + tail, EDGE_LABEL_MAX)


@dataclass
class GraphNode:
    key: str
    label: str
    addresses: list[str] = field(default_factory=list)
    findings: Counter[str] = field(default_factory=Counter)  # rule id -> count
    severity: str | None = None
    first_seen: datetime | None = None
    depth: int = 0
    component: int = -1  # -1: no movement observed
    origin: bool = False  # sends movement but never receives any
    hits: list[Finding] = field(default_factory=list)  # the findings counted in `findings`

    @property
    def address_class(self) -> str | None:
        """internal / external / loopback, for nodes known only by address."""
        return classify_ip(self.key[3:]) if self.key.startswith("ip:") else None

    def subtitle(self) -> str:
        bits: list[str] = []
        if self.addresses and self.addresses[0] != self.label:
            bits.append(self.addresses[0] + (f" +{len(self.addresses) - 1}" if len(self.addresses) > 1 else ""))
        if self.address_class == "external":
            bits.append("external address")
        if self.origin:
            bits.append("origin")
        return " · ".join(bits)


@dataclass
class AttackGraph:
    nodes: dict[str, GraphNode]
    edges: list[GraphEdge]

    @property
    def connected(self) -> list[GraphNode]:
        return [n for n in self._ordered() if n.component >= 0]

    @property
    def isolated(self) -> list[GraphNode]:
        return [n for n in self._ordered() if n.component < 0]

    def _ordered(self) -> list[GraphNode]:
        def order(n: GraphNode) -> tuple[bool, int, int, float, str]:
            when = n.first_seen.timestamp() if n.first_seen else math.inf
            return (n.component < 0, n.component, n.depth, when, n.key)

        return sorted(self.nodes.values(), key=order)

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [
                {
                    "id": n.key,
                    "label": n.label,
                    "addresses": n.addresses,
                    "address_class": n.address_class,
                    "severity": n.severity,
                    "findings": dict(sorted(n.findings.items())),
                    "origin": n.origin,
                    "component": n.component,
                    "depth": n.depth,
                    "first_seen": n.first_seen.isoformat() if n.first_seen else None,
                }
                for n in sorted(self.nodes.values(), key=lambda n: n.key)
            ],
            "edges": [
                {
                    "source": e.src,
                    "target": e.dst,
                    "label": e.label(),
                    "count": len(e.movements),
                    "kinds": dict(sorted(e.kinds().items())),
                    "users": e.users,
                    "privileged": e.privileged,
                    "severity": e.severity,
                    "first": e.first.isoformat(),
                    "last": e.last.isoformat(),
                    "movements": [
                        {
                            "timestamp": m.timestamp.isoformat(),
                            "kind": m.kind,
                            "user": m.user,
                            "privileged": m.privileged,
                            "severity": m.severity,
                            "title": m.title,
                        }
                        for m in sorted(e.movements, key=lambda m: (m.timestamp, m.kind))
                    ],
                }
                for e in self.edges
            ],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)

    def to_dot(self) -> str:
        lines = [
            "digraph crabwalk {",
            '  graph [rankdir=LR, fontname="Helvetica", bgcolor="white", pad=0.3];',
            '  node [shape=box, style="rounded,filled", fillcolor="#fcfcfb", '
            'color="#c3c2b7", fontname="Helvetica", fontsize=11];',
            '  edge [fontname="Helvetica", fontsize=9, color="#898781", fontcolor="#52514e"];',
        ]
        for node in sorted(self.nodes.values(), key=lambda n: n.key):
            label = "\n".join(x for x in (node.label, node.subtitle(), _findings_text(node)) if x)
            attrs = [f"label={_dot_str(label)}"]
            if node.severity:
                attrs += [f'color="{SEVERITY_COLOR[node.severity]}"', "penwidth=2.5"]
            lines.append(f"  {_dot_str(node.key)} [{', '.join(attrs)}];")
        for edge in self.edges:
            attrs = [f"label={_dot_str(edge.label())}", f"penwidth={_stroke(edge):.1f}"]
            if edge.severity:
                attrs.append(f'color="{SEVERITY_COLOR[edge.severity]}"')
            lines.append(f"  {_dot_str(edge.src)} -> {_dot_str(edge.dst)} [{', '.join(attrs)}];")
        lines.append("}")
        return "\n".join(lines) + "\n"


def build_graph(
    ctx: HuntContext, findings: Iterable[Finding], *, include_machine: bool = False
) -> AttackGraph:
    findings = list(findings)
    movement_edges = [e for e in ctx.tracking.edges if include_machine or not e.is_machine_account]

    hosts = HostResolver()
    # Every session (machine accounts included) is valid IP<->name evidence.
    for session in ctx.tracking.sessions.values():
        hosts.learn(session.source_ip, session.source_host)
        hosts.learn(name=session.computer)
    for edge in movement_edges:
        hosts.learn(edge.src_ip, edge.src_host)
        hosts.learn(name=edge.dst)
    for finding in findings:
        hosts.learn(finding.src_ip, finding.src_host)
        hosts.learn(name=finding.host)

    edges: dict[tuple[str, str], GraphEdge] = {}

    def add(src: str | None, dst: str | None, movement: Movement) -> None:
        if src and dst and src != dst:
            edges.setdefault((src, dst), GraphEdge(src, dst)).movements.append(movement)

    for edge in movement_edges:
        add(hosts.key(edge.src_ip, edge.src_host), hosts.key(name=edge.dst),
            Movement(edge.timestamp, edge.kind, edge.user, edge.privileged,
                     src_ip=edge.src_ip, src_host=edge.src_host,
                     records=frozenset({evidence_key(edge.event)}) if edge.event else frozenset()))
    for finding in findings:
        if finding.src_ip or finding.src_host:
            add(hosts.key(finding.src_ip, finding.src_host), hosts.key(name=finding.host),
                Movement(finding.timestamp, finding.rule_id, finding.user,
                         severity=finding.severity, title=finding.title, finding=finding,
                         src_ip=finding.src_ip, src_host=finding.src_host,
                         records=frozenset(evidence_key(e) for e in finding.evidence)))

    nodes: dict[str, GraphNode] = {}

    def node(key: str) -> GraphNode:
        if key not in nodes:
            nodes[key] = GraphNode(key, hosts.display(key), hosts.addresses(key))
        return nodes[key]

    def seen(n: GraphNode, when: datetime) -> None:
        if n.first_seen is None or when < n.first_seen:
            n.first_seen = when

    for edge in edges.values():
        seen(node(edge.src), edge.first)
        seen(node(edge.dst), edge.first)
    for finding in findings:
        key = hosts.key(name=finding.host)
        if not key:
            continue
        n = node(key)
        n.findings[finding.rule_id] += 1
        n.hits.append(finding)
        seen(n, finding.timestamp)
        if n.severity is None or SEVERITY_RANK[finding.severity] > SEVERITY_RANK[n.severity]:
            n.severity = finding.severity

    ordered_edges = sorted(edges.values(), key=lambda e: (e.first, e.src, e.dst))
    _layout(nodes, ordered_edges)
    return AttackGraph(nodes, ordered_edges)


def _layout(nodes: dict[str, GraphNode], edges: list[GraphEdge]) -> None:
    """Components, origins and left-to-right depth (longest path on a DAG).

    Edges are taken in time order; one that would close a cycle is drawn as a
    back edge and ignored for depth, so A->B->C always reads 0, 1, 2.
    """
    succ: dict[str, set[str]] = defaultdict(set)

    def reaches(a: str, b: str) -> bool:
        stack, visited = [a], {a}
        while stack:
            cur = stack.pop()
            if cur == b:
                return True
            for nxt in succ[cur] - visited:
                visited.add(nxt)
                stack.append(nxt)
        return False

    forward: list[GraphEdge] = []
    for edge in edges:
        if not reaches(edge.dst, edge.src):
            succ[edge.src].add(edge.dst)
            forward.append(edge)

    connected = sorted({e.src for e in edges} | {e.dst for e in edges})
    indegree = Counter(e.dst for e in forward)
    depth = dict.fromkeys(connected, 0)
    queue = [k for k in connected if indegree[k] == 0]
    while queue:
        cur = queue.pop(0)
        for nxt in sorted(succ[cur]):
            depth[nxt] = max(depth[nxt], depth[cur] + 1)
            indegree[nxt] -= 1
            if indegree[nxt] == 0:
                queue.append(nxt)

    receivers = {e.dst for e in edges}
    parent = {k: k for k in connected}

    def find(k: str) -> str:
        while parent[k] != k:
            parent[k] = parent[parent[k]]
            k = parent[k]
        return k

    for edge in edges:
        parent[find(edge.src)] = find(edge.dst)
    groups: dict[str, list[str]] = defaultdict(list)
    for key in connected:
        groups[find(key)].append(key)
    ranked = sorted(groups.values(), key=lambda g: (min(_when(nodes[k]) for k in g), min(g)))
    for index, members in enumerate(ranked):
        for key in members:
            nodes[key].component = index
            nodes[key].depth = depth[key]
            nodes[key].origin = key not in receivers


def _when(node: GraphNode) -> datetime:
    assert node.first_seen is not None
    return node.first_seen


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------

NODE_W, NODE_H = 178, 52
COL_GAP, ROW_GAP, BAND_GAP, PAD = 172, 22, 34, 14  # COL_GAP fits an EDGE_LABEL_MAX caption
CHAR_W = 6.3  # approximate advance of an 11px system-ui glyph, for label boxes
LANE_STEP = 22  # spacing of stacked over/under lanes; > the 18px label height
GUTTER_STEP = 7  # horizontal spacing of vertical runs sharing a gutter
ISO_GAP, ISO_MIN_PER_ROW = 18, 4
ISO_HEADER = "HOSTS WITH FINDINGS, NO OBSERVED MOVEMENT"


@dataclass(frozen=True)
class _Route:
    """An orthogonal detour around the band: 'over' for column-skipping edges,
    'under' for back and same-column edges. ``lane`` is the y of the run that
    clears the band (and of the label); ``index`` spreads parallel runs."""

    side: str
    lane: float
    index: int


def render_svg(graph: AttackGraph, *, connected_only: bool = False, interactive: bool = False) -> str:
    """The graph as inline SVG; colors come from the page's CSS variables.

    Every component is a band of columns (one per depth). Edges to the next
    column are plain curves between facing sides. Edges that skip columns, and
    back/same-column edges, leave through the gutter beside their column, run
    in a lane above (or below) the band, and come back down a gutter. Gutters
    and lanes hold no nodes, so no edge can cross a host box, and each band
    reserves its lanes, so nothing is drawn off the canvas.
    """
    connected = graph.connected
    isolated = [] if connected_only else graph.isolated
    if not connected and not isolated:
        return ""

    positions: dict[str, tuple[float, float]] = {}
    routes: dict[tuple[str, str], _Route] = {}
    max_depth = max((n.depth for n in connected), default=0)
    width = PAD * 2 + (max_depth + 1) * NODE_W + max_depth * COL_GAP
    if isolated:
        shown = min(len(isolated), ISO_MIN_PER_ROW)
        width = max(width, PAD * 2 + shown * (NODE_W + ISO_GAP) - ISO_GAP,
                    PAD * 2 + len(ISO_HEADER) * 7.4)

    by_component: dict[int, list[GraphNode]] = defaultdict(list)
    for n in connected:
        by_component[n.component].append(n)
    edges_of: dict[int, list[GraphEdge]] = defaultdict(list)
    for edge in graph.edges:
        src, dst = graph.nodes[edge.src], graph.nodes[edge.dst]
        if src.component >= 0 and src.component == dst.component:
            edges_of[src.component].append(edge)

    y = float(PAD)
    for component in sorted(by_component):
        depth = {n.key: n.depth for n in by_component[component]}
        order = lambda e: (abs(depth[e.dst] - depth[e.src]), e.src, e.dst)  # noqa: E731
        overs = sorted((e for e in edges_of[component] if depth[e.dst] - depth[e.src] > 1), key=order)
        unders = sorted((e for e in edges_of[component] if depth[e.dst] <= depth[e.src]), key=order)
        top = y + (LANE_STEP * len(overs) + 8 if overs else 0)
        columns: dict[int, list[GraphNode]] = defaultdict(list)
        for n in by_component[component]:
            columns[n.depth].append(n)
        rows = max(len(c) for c in columns.values())
        band = rows * NODE_H + (rows - 1) * ROW_GAP
        for col, members in columns.items():
            members.sort(key=lambda n: (_when(n), n.key))
            offset = (band - (len(members) * NODE_H + (len(members) - 1) * ROW_GAP)) / 2
            for row, n in enumerate(members):
                positions[n.key] = (PAD + col * (NODE_W + COL_GAP), top + offset + row * (NODE_H + ROW_GAP))
        for k, edge in enumerate(overs):
            routes[(edge.src, edge.dst)] = _Route("over", top - 14 - LANE_STEP * k, k)
        for k, edge in enumerate(unders):
            routes[(edge.src, edge.dst)] = _Route("under", top + band + 14 + LANE_STEP * k, k)
        y = top + band + (LANE_STEP * len(unders) + 8 if unders else 0) + BAND_GAP
    if any(r.side == "under" for r in routes.values()):
        width += COL_GAP / 2  # back edges use the gutter right of their column, the last one too

    iso_header_y = None
    if isolated:
        per_row = max(1, int((width - 2 * PAD + ISO_GAP) // (NODE_W + ISO_GAP)))
        iso_header_y = y + (4 if connected else 0)
        y = iso_header_y + 18
        for i, n in enumerate(isolated):
            r, c = divmod(i, per_row)
            positions[n.key] = (PAD + c * (NODE_W + ISO_GAP), y + r * (NODE_H + 14))
        y += math.ceil(len(isolated) / per_row) * (NODE_H + 14) - 14 + BAND_GAP
    height = y - BAND_GAP + PAD

    out = [
        f'<svg class="attack-graph" viewBox="0 0 {width:.0f} {height:.0f}" width="{width:.0f}" '
        f'height="{height:.0f}" role="img" aria-label="Attack path graph" '
        f'xmlns="http://www.w3.org/2000/svg"{" data-interactive" if interactive else ""}>',
        "<defs>",
    ]
    for name, color in [("neutral", "var(--ink-3)"), *SEVERITY_COLOR.items()]:
        # userSpaceOnUse: arrowheads stay one size however thick the edge is.
        out.append(
            f'<marker id="cwg-arrow-{name}" viewBox="0 0 10 10" refX="9" refY="5" '
            f'markerUnits="userSpaceOnUse" markerWidth="11" markerHeight="11" '
            f'orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="{color}"/></marker>'
        )
    out.append("</defs>")
    if iso_header_y is not None:
        out.append(f'<text x="{PAD}" y="{iso_header_y + 8}" font-size="11.5" fill="var(--ink-3)" '
                   f'font-weight="600">{ISO_HEADER}</text>')

    anchors: list[tuple[GraphEdge, float, float]] = []
    for edge in graph.edges:
        if edge.src in positions and edge.dst in positions:
            path, mx, my = _edge_svg(edge, positions, routes.get((edge.src, edge.dst)))
            out.append(path)
            anchors.append((edge, mx, my))
    boxes = [(x, y0, NODE_W, NODE_H) for x, y0 in positions.values()]
    out.extend(_place_labels(anchors, boxes, width, height))  # labels above every line
    for n in connected + isolated:
        out.append(_node_svg(n, *positions[n.key]))
    out.append("</svg>")
    return "".join(out)


def _gutter_offset(index: int) -> float:
    return min(16 + GUTTER_STEP * index, COL_GAP / 2 - 8)


def _rounded_path(points: list[tuple[float, float]], radius: float = 8.0) -> str:
    """SVG path through the points with each corner rounded by a quadratic."""
    pts = [points[0]] + [p for prev, p in zip(points, points[1:]) if p != prev]
    d = [f"M{pts[0][0]:.1f},{pts[0][1]:.1f}"]
    for (ax, ay), (bx, by), (cx, cy) in zip(pts, pts[1:], pts[2:]):
        before, after = math.hypot(bx - ax, by - ay), math.hypot(cx - bx, cy - by)
        r = min(radius, before / 2, after / 2)
        p1 = (bx - (bx - ax) / before * r, by - (by - ay) / before * r)
        p2 = (bx + (cx - bx) / after * r, by + (cy - by) / after * r)
        d.append(f"L{p1[0]:.1f},{p1[1]:.1f} Q{bx:.1f},{by:.1f} {p2[0]:.1f},{p2[1]:.1f}")
    d.append(f"L{pts[-1][0]:.1f},{pts[-1][1]:.1f}")
    return " ".join(d)


def _edge_svg(
    edge: GraphEdge, positions: dict[str, tuple[float, float]], route: _Route | None
) -> tuple[str, float, float]:
    """The edge path, and the anchor point of its caption."""
    sx, sy = positions[edge.src]
    dx, dy = positions[edge.dst]
    color = SEVERITY_COLOR[edge.severity] if edge.severity else "var(--ink-3)"
    marker = edge.severity or "neutral"
    # detours attach to the upper ("over") or lower ("under") half of a side,
    # so they never share an attachment point with a straight edge
    shift = {None: 0.0, "over": -12.0, "under": 12.0}[route.side if route else None]
    src_mid, dst_mid = sy + NODE_H / 2 + shift, dy + NODE_H / 2 + shift
    if route is not None and route.side == "over":
        # right gutter of src -> lane above the band -> left gutter of dst
        g1 = sx + NODE_W + _gutter_offset(route.index)
        g2 = dx - _gutter_offset(route.index)
        d = _rounded_path([(sx + NODE_W, src_mid), (g1, src_mid), (g1, route.lane),
                           (g2, route.lane), (g2, dst_mid), (dx - 2, dst_mid)])
        mx, my = (g1 + g2) / 2, route.lane
    elif route is not None:
        # back/same column: right gutter of src -> lane under the band ->
        # right gutter of dst -> into dst from its right side
        g1 = sx + NODE_W + _gutter_offset(route.index)
        g2 = dx + NODE_W + _gutter_offset(route.index)
        d = _rounded_path([(sx + NODE_W, src_mid), (g1, src_mid), (g1, route.lane),
                           (g2, route.lane), (g2, dst_mid), (dx + NODE_W + 2, dst_mid)])
        mx, my = (g1 + g2) / 2, route.lane
    else:  # next column: right side of src to left side of dst
        x1, y1, x2, y2 = sx + NODE_W, src_mid, dx - 2, dst_mid
        bend = max(40.0, (x2 - x1) / 2)
        d = f"M{x1:.1f},{y1:.1f} C{x1 + bend:.1f},{y1:.1f} {x2 - bend:.1f},{y2:.1f} {x2:.1f},{y2:.1f}"
        mx, my = (x1 + x2) / 2, (y1 + y2) / 2
    tip = [f"{edge.src} -> {edge.dst}"] + [
        f"{m.timestamp:%Y-%m-%d %H:%M:%S}Z  {m.label}  {m.user}" + (f"  [{m.severity}] {m.title}" if m.severity else "")
        + ("  (privileged)" if m.privileged else "")
        for m in sorted(edge.movements, key=lambda m: (m.timestamp, m.kind))[:12]
    ]
    if len(edge.movements) > 12:
        tip.append(f"… {len(edge.movements) - 12} more")
    dash = ' stroke-dasharray="5 4"' if edge.severity is None and not edge.privileged else ""
    path = (
        f'<g class="ge" data-src="{_esc(edge.src)}" data-dst="{_esc(edge.dst)}">'
        f"<title>{_esc(chr(10).join(tip))}</title>"
        f'<path class="line" d="{d}" stroke="{color}" stroke-width="{_stroke(edge):.1f}"{dash} '
        f'marker-end="url(#cwg-arrow-{marker})"/></g>'
    )
    return path, mx, my


LABEL_H = 18


def _nudges(w: float) -> list[tuple[float, float]]:
    """Caption offsets, nearest first: vertical in 5px steps, then sideways."""
    offsets = [(dx, float(dy)) for dy in range(-250, 251, 5) for dx in (0.0, -(w + 4), w + 4)]
    return sorted(offsets, key=lambda o: (abs(o[1]) + 1.5 * abs(o[0]), o))


def _overlaps(a: tuple[float, float, float, float], b: tuple[float, float, float, float]) -> bool:
    return a[0] < b[0] + b[2] and b[0] < a[0] + a[2] and a[1] < b[1] + b[3] and b[1] < a[1] + a[3]


def _place_labels(
    anchors: list[tuple[GraphEdge, float, float]],
    boxes: list[tuple[float, float, float, float]],
    width: float,
    height: float,
) -> list[str]:
    """Edge captions, each moved vertically to the nearest spot that touches
    no other caption and no host box and stays on the canvas. Dense crossings
    (many hosts to many hosts) would otherwise stack captions on one point."""
    placed: list[tuple[float, float, float, float]] = []
    out = []
    for edge, mx, my in anchors:
        text = edge.label()
        w = len(text) * CHAR_W + 12
        first = rect = (mx - w / 2, my - LABEL_H / 2, w, float(LABEL_H))
        for dx, dy in _nudges(w):
            candidate = (first[0] + dx, first[1] + dy, w, float(LABEL_H))
            on_canvas = candidate[0] >= 0 and candidate[1] >= 0 and candidate[0] + w <= width \
                and candidate[1] + LABEL_H <= height
            if on_canvas and not any(_overlaps(candidate, o) for o in placed + boxes):
                rect = candidate
                break
        placed.append(rect)
        x, y, _, _ = rect
        out.append(
            f'<g class="ge elabel" data-src="{_esc(edge.src)}" data-dst="{_esc(edge.dst)}">'
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{LABEL_H}" rx="9"/>'
            f'<text x="{x + w / 2:.1f}" y="{y + 13:.1f}" text-anchor="middle" font-size="11" '
            f'fill="var(--ink-2)">{_esc(text)}</text></g>'
        )
    return out


def _node_svg(n: GraphNode, x: float, y: float) -> str:
    stroke = SEVERITY_COLOR[n.severity] if n.severity else "var(--axis)"
    width = 2.4 if n.severity else 1.4
    tip = [n.label] + n.addresses
    if n.address_class:
        tip.append(f"{n.address_class} address")
    if n.origin:
        tip.append("origin: sends movement, receives none")
    tip += [f"{rule} ×{count}" for rule, count in sorted(n.findings.items())]
    total = sum(n.findings.values())
    badge = str(total) if total and n.severity else ""
    badge_w = 10 + len(badge) * 7 if badge else 0
    title_room = NODE_W - 24 - (badge_w + 6 if badge else 0)
    parts = [
        f'<g class="gn" data-id="{_esc(n.key)}"><title>{_esc(chr(10).join(tip))}</title>',
        f'<rect class="box" x="{x:.1f}" y="{y:.1f}" width="{NODE_W}" height="{NODE_H}" rx="10" '
        f'stroke="{stroke}" stroke-width="{width}"/>',
        f'<text x="{x + 12:.1f}" y="{y + 21:.1f}" font-size="12.5" font-weight="650" '
        f'fill="var(--ink-1)">{_esc(_clip(n.label, int(title_room / 7.6)))}</text>',
    ]
    subtitle = n.subtitle()
    if subtitle:
        parts.append(f'<text x="{x + 12:.1f}" y="{y + 38:.1f}" font-size="11" '
                     f'fill="var(--ink-3)">{_esc(_clip(subtitle, int((NODE_W - 24) / CHAR_W)))}</text>')
    if badge:
        bx = x + NODE_W - badge_w - 8
        parts.append(
            f'<rect x="{bx:.1f}" y="{y + 9:.1f}" width="{badge_w}" height="17" rx="8.5" '
            f'fill="{SEVERITY_COLOR[n.severity or "low"]}"/>'
            f'<text x="{bx + badge_w / 2:.1f}" y="{y + 21.5:.1f}" text-anchor="middle" font-size="11" '
            f'font-weight="700" fill="#fff">{badge}</text>'
        )
    parts.append("</g>")
    return "".join(parts)


def legend_html() -> str:
    severities = "".join(
        f'<span class="lg"><span class="swatch" style="border-color:{SEVERITY_COLOR[s]}"></span>'
        f"{s.capitalize()} finding</span>"
        for s in SEVERITY_ORDER
    )
    return (
        '<div class="legend">'
        '<span class="lg"><span class="swatch" style="border-color:var(--ink-3);'
        'border-top-style:dashed"></span>Logon / session movement</span>'
        f"{severities}"
        '<span class="lg"><span class="swatch box" style="border-color:var(--axis)"></span>'
        "Host border = worst finding on it; badge = finding count</span>"
        "</div>"
    )


def render_page(graph: AttackGraph, *, title: str = "crabwalk — Attack Paths") -> str:
    """Standalone page: the graph, its edges as a table, hover/click to focus."""
    svg = render_svg(graph, interactive=True)
    rows = "".join(
        f"<tr><td class='mono'>{e.first:%Y-%m-%d %H:%M:%S}Z</td>"
        f"<td class='mono'>{_esc(graph.nodes[e.src].label)}</td>"
        f"<td class='mono'>{_esc(graph.nodes[e.dst].label)}</td>"
        f"<td>{_esc(e.label())}</td><td>{_esc(', '.join(e.users))}</td></tr>"
        for e in graph.edges
    )
    table = (
        "<table><thead><tr><th>First seen</th><th>Source</th><th>Destination</th>"
        f"<th>Movement</th><th>Users</th></tr></thead><tbody>{rows}</tbody></table>"
        if rows else '<p class="muted">No host-to-host movement observed.</p>'
    )
    return f"""{page_head(_esc(title))}
<header class="hero"><div class="crab">\U0001f980</div><div><h1>{_esc(title)}</h1>
<p class="muted">{len(graph.connected)} hosts on paths &middot; {len(graph.edges)} edges &middot;
{sum(n.origin for n in graph.nodes.values())} origin(s). Hover or click a host to focus its paths.</p></div></header>
<section class="card"><div class="scroll">{svg or '<p class="muted">Nothing to draw.</p>'}</div>{legend_html()}</section>
<section class="card"><h2>Edges</h2>{table}</section>
<script>{_FOCUS_JS}</script>"""


_FOCUS_JS = """
(function(){
  var svg=document.querySelector('svg.attack-graph'); if(!svg) return;
  var pinned=null;
  function focus(id){
    svg.classList.toggle('focusing', !!id);
    var near={}; if(id) near[id]=1;
    svg.querySelectorAll('.ge').forEach(function(e){
      var on=!!id && (e.dataset.src===id || e.dataset.dst===id);
      e.classList.toggle('on', on);
      if(on){ near[e.dataset.src]=1; near[e.dataset.dst]=1; }
    });
    svg.querySelectorAll('.gn').forEach(function(n){ n.classList.toggle('on', !!near[n.dataset.id]); });
  }
  svg.querySelectorAll('.gn').forEach(function(n){
    n.addEventListener('mouseenter', function(){ if(!pinned) focus(n.dataset.id); });
    n.addEventListener('mouseleave', function(){ if(!pinned) focus(null); });
    n.addEventListener('click', function(ev){
      ev.stopPropagation(); pinned = pinned===n.dataset.id ? null : n.dataset.id; focus(pinned);
    });
  });
  document.addEventListener('click', function(){ pinned=null; focus(null); });
})();
"""


def _stroke(edge: GraphEdge) -> float:
    return 1.6 + min(2.4, math.log2(len(edge.movements))) + (0.6 if edge.privileged else 0.0)


def _findings_text(node: GraphNode) -> str:
    return ", ".join(f"{rule}×{count}" for rule, count in sorted(node.findings.items()))


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _dot_str(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return f'"{escaped}"'
