"""Self-contained HTML report: summary, attack paths, ATT&CK coverage,
timeline, findings.

Everything is inlined (CSS + SVG attack graph and timeline generated here in
Python), so the output is a single file an analyst can email or attach to a
case. No JS, no external assets — it renders the same on an air-gapped DFIR box
as anywhere.
"""

from __future__ import annotations

import html
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any

from .attack import technique_name
from .graph import AttackGraph, build_graph, legend_html, render_svg
from .narrative import build_story
from .rules.base import SEVERITY_RANK, Finding, HuntContext
from .style import SEVERITY_COLOR, SEVERITY_ORDER, SEVERITY_TEXT, page_head

# Findings with a FILETIME-null timestamp land here; excluded from the plot.
_MIN_PLOT_YEAR = 2000


def _esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def render_report(
    ctx: HuntContext,
    findings: list[Finding],
    *,
    stats: Any = None,
    suppressed: list[tuple[Finding, Any]] | None = None,
    title: str = "crabwalk — Lateral Movement Report",
) -> str:
    """``suppressed`` pairs each allowlisted finding with its allow entry
    (anything with ``index`` and ``reason``); they are listed, never hidden."""
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    by_sev = Counter(f.severity for f in findings)
    graph = build_graph(ctx, findings)
    story = build_story(ctx, findings, graph)
    parts = [
        _HEAD.replace("__TITLE__", _esc(title)),
        _header(title, generated),
        _stat_row(ctx, findings, stats),
        _severity_bar(by_sev, len(findings)),
        story.to_html() if findings or graph.edges else "",
        _graph_section(graph),
        _attack_section(findings),
        _timeline_section(findings),
        _movement_section(ctx),
        _findings_section(findings),
        _suppressed_section(suppressed or []),
        _FOOT,
    ]
    return "\n".join(parts)


def _header(title: str, generated: str) -> str:
    return f"""<header class="hero">
  <div class="crab">\U0001f980</div>
  <div>
    <h1>{_esc(title)}</h1>
    <p class="muted">Generated {generated} &middot; crabwalk EVTX lateral movement hunter</p>
  </div>
</header>"""


def _stat_row(ctx: HuntContext, findings: list[Finding], stats: Any) -> str:
    remote = len(ctx.tracking.remote_sessions())
    tiles = [
        ("Files", getattr(stats, "files", "—")),
        ("Events kept", getattr(stats, "kept", len(ctx.events))),
        ("Sessions", f"{len(ctx.tracking.sessions)}"),
        ("Remote sessions", remote),
        ("Movement edges", len(ctx.tracking.edges)),
        ("Findings", len(findings)),
    ]
    cells = "\n".join(
        f'<div class="tile"><div class="tile-v">{_esc(v)}</div>'
        f'<div class="tile-k">{_esc(k)}</div></div>'
        for k, v in tiles
    )
    return f'<section class="tiles">{cells}</section>'


def _severity_bar(by_sev: Counter, total: int) -> str:
    if not total:
        return '<section class="card"><p class="muted">No findings.</p></section>'
    segments = []
    legend = []
    for sev in SEVERITY_ORDER:
        count = by_sev.get(sev, 0)
        if not count:
            continue
        pct = 100 * count / total
        color = SEVERITY_COLOR[sev]
        segments.append(
            f'<div class="seg" style="width:{pct:.3f}%;background:{color}" '
            f'title="{sev}: {count}"></div>'
        )
        legend.append(
            f'<span class="lg"><span class="dot" style="background:{color}"></span>'
            f'{sev.capitalize()} <b>{count}</b></span>'
        )
    return f"""<section class="card">
  <h2>Severity</h2>
  <div class="sevbar">{''.join(segments)}</div>
  <div class="legend">{''.join(legend)}</div>
</section>"""


def _graph_section(graph: AttackGraph) -> str:
    if not graph.edges:
        return ""
    origins = sum(n.origin for n in graph.connected)
    note = f"{len(graph.connected)} hosts &middot; {len(graph.edges)} edges &middot; {origins} origin(s)"
    if graph.isolated:
        note += f" &middot; {len(graph.isolated)} more host(s) with findings but no observed movement"
    return f"""<section class="card">
  <h2>Attack paths <span class="muted">({note})</span></h2>
  <div class="scroll">{render_svg(graph, connected_only=True)}</div>
  {legend_html()}
</section>"""


def _attack_section(findings: list[Finding]) -> str:
    counts = Counter(t for f in findings for t in f.techniques)
    if not counts:
        return ""
    rows = []
    for technique_id, count in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
        rules = sorted({f.rule_id for f in findings if technique_id in f.techniques})
        url = f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"
        rows.append(
            f"<tr><td><a href='{url}'>{_esc(technique_id)}</a></td>"
            f"<td>{_esc(technique_name(technique_id))}</td>"
            f"<td class='num'>{count}</td>"
            f"<td class='muted'>{_esc(', '.join(rules))}</td></tr>"
        )
    return f"""<section class="card">
  <h2>ATT&amp;CK coverage <span class="muted">({len(counts)} techniques)</span></h2>
  <table>
    <thead><tr><th>Technique</th><th>Name</th><th class="num">Findings</th><th>Rules</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</section>"""


def _timeline_section(findings: list[Finding]) -> str:
    plottable = [f for f in findings if f.timestamp.year >= _MIN_PLOT_YEAR]
    excluded = len(findings) - len(plottable)
    note = (
        f' <span class="muted">({excluded} finding(s) with null timestamps omitted)</span>'
        if excluded
        else ""
    )
    if len(plottable) < 1:
        return ""
    svg = _timeline_svg(plottable)
    return f"""<section class="card">
  <h2>Timeline{note}</h2>
  <div class="scroll">{svg}</div>
</section>"""


def _timeline_svg(findings: list[Finding]) -> str:
    """Swimlane timeline: one row per host, one dot per finding, colored by severity."""
    hosts = sorted({f.host for f in findings})
    lane_h = 34
    pad_l, pad_r, pad_t, pad_b = 200, 40, 46, 44
    width = 1080
    height = pad_t + pad_b + lane_h * len(hosts)
    plot_w = width - pad_l - pad_r

    times = [f.timestamp for f in findings]
    t_min, t_max = min(times), max(times)
    span = (t_max - t_min).total_seconds() or 1.0

    def x(ts: datetime) -> float:
        return pad_l + plot_w * (ts - t_min).total_seconds() / span

    def lane_y(host: str) -> float:
        return pad_t + lane_h * hosts.index(host) + lane_h / 2

    parts = [
        f'<svg viewBox="0 0 {width} {height}" width="{width}" height="{height}" '
        f'role="img" xmlns="http://www.w3.org/2000/svg" font-family="var(--font)">'
    ]

    # lane backgrounds + host labels
    for i, host in enumerate(hosts):
        y = pad_t + lane_h * i
        if i % 2:
            parts.append(
                f'<rect x="0" y="{y}" width="{width}" height="{lane_h}" '
                f'fill="var(--stripe)"/>'
            )
        label = host if len(host) <= 30 else host[:29] + "…"
        parts.append(
            f'<text x="{pad_l - 12}" y="{y + lane_h / 2 + 4}" text-anchor="end" '
            f'font-size="12" fill="var(--ink-2)">{_esc(label)}</text>'
        )

    # x-axis ticks (evenly spaced dates)
    ticks = 6
    for k in range(ticks + 1):
        frac = k / ticks
        tx = pad_l + plot_w * frac
        ts = datetime.fromtimestamp(
            t_min.timestamp() + span * frac, tz=timezone.utc
        )
        parts.append(
            f'<line x1="{tx:.1f}" y1="{pad_t - 8}" x2="{tx:.1f}" '
            f'y2="{height - pad_b}" stroke="var(--grid)" stroke-width="1"/>'
        )
        parts.append(
            f'<text x="{tx:.1f}" y="{height - pad_b + 18}" text-anchor="middle" '
            f'font-size="11" fill="var(--ink-3)">{ts:%Y-%m-%d}</text>'
        )

    # dots, drawn least-severe first so criticals sit on top
    for f in sorted(findings, key=lambda f: SEVERITY_RANK.get(f.severity, 0)):
        cx, cy = x(f.timestamp), lane_y(f.host)
        color = SEVERITY_COLOR.get(f.severity, "#888")
        tip = f"{f.timestamp:%Y-%m-%d %H:%M:%S}Z  {f.rule_id} {f.title}  ({f.severity})"
        parts.append(
            f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="5.5" fill="{color}" '
            f'stroke="var(--surface)" stroke-width="1.5">'
            f'<title>{_esc(tip)}</title></circle>'
        )

    parts.append("</svg>")
    legend = "".join(
        f'<span class="lg"><span class="dot" style="background:{SEVERITY_COLOR[s]}"></span>'
        f'{s.capitalize()}</span>'
        for s in SEVERITY_ORDER
    )
    return "".join(parts) + f'<div class="legend">{legend}</div>'


def _movement_section(ctx: HuntContext) -> str:
    edges = [e for e in ctx.tracking.edges if not e.is_machine_account]
    if not edges:
        return ""
    rows = "".join(
        f"<tr><td class='mono'>{e.timestamp:%Y-%m-%d %H:%M:%S}Z</td>"
        f"<td>{_esc(e.user)}</td><td class='mono'>{_esc(e.src)}</td>"
        f"<td class='mono'>{_esc(e.dst)}</td>"
        f"<td>{_esc(e.kind)}{' <b>priv</b>' if e.privileged else ''}</td></tr>"
        for e in edges
    )
    return f"""<section class="card">
  <h2>Host-to-host movement <span class="muted">({len(edges)} edges)</span></h2>
  <table>
    <thead><tr><th>Time</th><th>User</th><th>Source</th><th>Destination</th><th>Kind</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</section>"""


def _findings_section(findings: list[Finding]) -> str:
    if not findings:
        return ""
    items = []
    for f in findings:
        color = SEVERITY_COLOR.get(f.severity, "#888")
        techs = " ".join(
            f'<a class="chip" href="https://attack.mitre.org/techniques/'
            f'{t.replace(".", "/")}/">{_esc(t)}</a>'
            for t in f.techniques
        )
        items.append(
            f"""<div class="finding" style="--sev:{color}">
  <div class="f-head">
    <span class="badge" style="background:{color};color:{SEVERITY_TEXT.get(f.severity, '#fff')}">{_esc(f.severity.upper())}</span>
    <span class="rule">{_esc(f.rule_id)}</span>
    <span class="f-title">{_esc(f.title)}</span>
    <span class="f-time mono">{f.timestamp:%Y-%m-%d %H:%M:%S}Z</span>
  </div>
  <div class="f-meta"><b>host</b> {_esc(f.host)} &nbsp; <b>user</b> {_esc(f.user)} &nbsp; {techs}</div>
  <div class="f-sum">{_esc(f.summary)}</div>{_merged_html(f)}
</div>"""
        )
    return f"""<section class="card">
  <h2>Findings <span class="muted">({len(findings)})</span></h2>
  {''.join(items)}
</section>"""


def _merged_html(finding: Finding) -> str:
    """Findings of other rules this one already tells, kept visible under it."""
    if not finding.merged:
        return ""
    rows = "".join(
        f'<div class="f-also"><b>also matched</b> <span class="rule">{_esc(m.rule_id)}</span> '
        f"{_esc(m.title)} ({_esc(m.severity)}) <span class=\"mono\">{m.timestamp:%H:%M:%S}Z</span> "
        f"<b>user</b> {_esc(m.user)}: {_esc(m.summary)}</div>"
        for m in finding.merged
    )
    return "\n  " + rows


def _suppressed_section(suppressed: list[tuple[Finding, Any]]) -> str:
    if not suppressed:
        return ""
    rows = "".join(
        f"<tr><td class='mono'>{f.timestamp:%Y-%m-%d %H:%M:%S}Z</td>"
        f"<td class='mono'>{_esc(f.rule_id)}"
        f"{_esc(' (+' + ', '.join(m.rule_id for m in f.merged) + ')') if f.merged else ''}</td>"
        f"<td>{_esc(f.severity)}</td>"
        f"<td>{_esc(f.host)}</td><td>{_esc(f.user)}</td>"
        f"<td>allow[{_esc(entry.index)}] {_esc(entry.reason)}</td></tr>"
        for f, entry in suppressed
    )
    return f"""<section class="card">
  <h2>Suppressed by allowlist <span class="muted">({len(suppressed)})</span></h2>
  <table>
    <thead><tr><th>Time</th><th>Rule</th><th>Severity</th><th>Host</th><th>User</th><th>Allowed because</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</section>"""


_HEAD = page_head("__TITLE__") + '\n<div class="viz-root">'

_FOOT = "</div>"
