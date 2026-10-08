"""Shared visual language of the HTML outputs (report and attack graph)."""

from __future__ import annotations

# Severity -> status palette (status is a *state* encoding, fixed, never themed).
SEVERITY_COLOR = {
    "critical": "#d03b3b",
    "high": "#ec835a",
    "medium": "#fab219",
    "low": "#0ca30c",
}
SEVERITY_ORDER = ("critical", "high", "medium", "low")

PAGE_CSS = """
:root{
  --font: system-ui,-apple-system,"Segoe UI",sans-serif;
  --page:#f9f9f7; --surface:#fcfcfb; --ink-1:#0b0b0b; --ink-2:#52514e;
  --ink-3:#898781; --grid:#e1e0d9; --stripe:#f2f1ec; --border:rgba(11,11,11,.10);
  --axis:#c3c2b7;
}
@media (prefers-color-scheme: dark){:root:not([data-theme="light"]){
  --page:#0d0d0d; --surface:#1a1a19; --ink-1:#fff; --ink-2:#c3c2b7;
  --ink-3:#898781; --grid:#2c2c2a; --stripe:#222220; --border:rgba(255,255,255,.10);
  --axis:#4a4a46;
}}
:root[data-theme="dark"]{
  --page:#0d0d0d; --surface:#1a1a19; --ink-1:#fff; --ink-2:#c3c2b7;
  --ink-3:#898781; --grid:#2c2c2a; --stripe:#222220; --border:rgba(255,255,255,.10);
  --axis:#4a4a46;
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
.swatch{width:22px;height:0;border-top:2.5px solid;display:inline-block}
.swatch.box{width:16px;height:12px;border:2px solid;border-radius:3px}
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
svg.attack-graph{display:block;max-width:none}
svg.attack-graph text{font-family:var(--font)}
.attack-graph .box{fill:var(--surface)}
.attack-graph .line{fill:none}
.attack-graph .elabel rect{fill:var(--surface);stroke:var(--border)}
.attack-graph .gn,.attack-graph .ge{transition:opacity .15s}
.attack-graph.focusing .gn:not(.on),.attack-graph.focusing .ge:not(.on){opacity:.15}
.attack-graph[data-interactive] .gn{cursor:pointer}
"""


def page_head(title_html: str) -> str:
    """<head> content shared by every HTML page crabwalk writes."""
    return (
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{title_html}</title>\n<style>{PAGE_CSS}</style>"
    )
