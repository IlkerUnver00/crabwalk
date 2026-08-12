"""Self-contained HTML report: summary, ATT&CK coverage, timeline, findings.

Everything is inlined (CSS + an SVG timeline generated here in Python), so the
output is a single file an analyst can email or attach to a case. No JS, no
external assets — it renders the same on an air-gapped DFIR box as anywhere.
"""

from __future__ import annotations

import html
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any

from .attack import technique_name
from .rules.base import SEVERITY_RANK, Finding, HuntContext

# Severity -> status palette (status is a *state* encoding, fixed, never themed).
SEVERITY_COLOR = {
    "critical": "#d03b3b",
    "high": "#ec835a",
    "medium": "#fab219",
    "low": "#0ca30c",
}
SEVERITY_ORDER = ("critical", "high", "medium", "low")

# Findings with a FILETIME-null timestamp land here; excluded from the plot.
_MIN_PLOT_YEAR = 2000


def _esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def render_report(
    ctx: HuntContext,
    findings: list[Finding],
    *,
    stats: Any = None,
    title: str = "crabwalk — Lateral Movement Report",
) -> str:
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    by_sev = Counter(f.severity for f in findings)
    parts = [
        _HEAD.replace("__TITLE__", _esc(title)),
        _header(title, generated),
        _stat_row(ctx, findings, stats),
        _severity_bar(by_sev, len(findings)),
        _attack_section(findings),
        _timeline_section(findings),
        _movement_section(ctx),
        _findings_section(findings),
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
    <span class="badge" style="background:{color}">{_esc(f.severity.upper())}</span>
    <span class="rule">{_esc(f.rule_id)}</span>
    <span class="f-title">{_esc(f.title)}</span>
    <span class="f-time mono">{f.timestamp:%Y-%m-%d %H:%M:%S}Z</span>
  </div>
  <div class="f-meta"><b>host</b> {_esc(f.host)} &nbsp; <b>user</b> {_esc(f.user)} &nbsp; {techs}</div>
  <div class="f-sum">{_esc(f.summary)}</div>
</div>"""
        )
    return f"""<section class="card">
  <h2>Findings <span class="muted">({len(findings)})</span></h2>
  {''.join(items)}
</section>"""


_HEAD = """<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
:root{
  --font: system-ui,-apple-system,"Segoe UI",sans-serif;
  --page:#f9f9f7; --surface:#fcfcfb; --ink-1:#0b0b0b; --ink-2:#52514e;
  --ink-3:#898781; --grid:#e1e0d9; --stripe:#f2f1ec; --border:rgba(11,11,11,.10);
}
@media (prefers-color-scheme: dark){:root:not([data-theme="light"]){
  --page:#0d0d0d; --surface:#1a1a19; --ink-1:#fff; --ink-2:#c3c2b7;
  --ink-3:#898781; --grid:#2c2c2a; --stripe:#222220; --border:rgba(255,255,255,.10);
}}
:root[data-theme="dark"]{
  --page:#0d0d0d; --surface:#1a1a19; --ink-1:#fff; --ink-2:#c3c2b7;
  --ink-3:#898781; --grid:#2c2c2a; --stripe:#222220; --border:rgba(255,255,255,.10);
}
*{box-sizing:border-box}
body{margin:0;background:var(--page);color:var(--ink-1);font-family:var(--font);
  line-height:1.5;padding:24px;max-width:1180px;margin:0 auto}
h1{font-size:22px;margin:0 0 2px}
h2{font-size:16px;margin:0 0 14px;font-weight:600}
.muted{color:var(--ink-3);font-weight:400}
a{color:#2a78d6;text-decoration:none}a:hover{text-decoration:underline}
.hero{display:flex;gap:16px;align-items:center;margin-bottom:20px}
.crab{font-size:40px;line-height:1}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));
  gap:12px;margin-bottom:16px}
.tile{background:var(--surface);border:1px solid var(--border);border-radius:12px;
  padding:14px 16px}
.tile-v{font-size:26px;font-weight:650;font-variant-numeric:tabular-nums}
.tile-k{color:var(--ink-3);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.card{background:var(--surface);border:1px solid var(--border);border-radius:14px;
  padding:20px;margin-bottom:16px}
.scroll{overflow-x:auto}
.sevbar{display:flex;height:16px;border-radius:8px;overflow:hidden;gap:2px;
  background:var(--stripe)}
.seg{min-width:3px}
.legend{display:flex;flex-wrap:wrap;gap:16px;margin-top:12px;font-size:13px;color:var(--ink-2)}
.lg{display:inline-flex;align-items:center;gap:6px}
.dot{width:10px;height:10px;border-radius:50%;display:inline-block}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;color:var(--ink-3);font-weight:600;padding:6px 10px;
  border-bottom:1px solid var(--border);white-space:nowrap}
td{padding:6px 10px;border-bottom:1px solid var(--grid);vertical-align:top}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}
.mono{font-family:ui-monospace,"Cascadia Code",Consolas,monospace;font-size:12px}
.finding{border-left:3px solid var(--sev);padding:10px 14px;margin:10px 0;
  background:var(--page);border-radius:0 8px 8px 0}
.f-head{display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
.badge{color:#fff;font-size:11px;font-weight:700;padding:1px 7px;border-radius:5px;
  letter-spacing:.03em}
.rule{font-family:ui-monospace,monospace;font-size:12px;color:var(--ink-3)}
.f-title{font-weight:600}
.f-time{margin-left:auto;color:var(--ink-3)}
.f-meta{font-size:13px;color:var(--ink-2);margin:6px 0}
.f-meta b{color:var(--ink-3);font-weight:600}
.f-sum{font-size:13px;color:var(--ink-1)}
.chip{display:inline-block;font-family:ui-monospace,monospace;font-size:11px;
  background:var(--stripe);border:1px solid var(--border);border-radius:5px;
  padding:0 6px;margin-left:4px}
</style>
<div class="viz-root">"""

_FOOT = "</div>"
