"""Build the GitHub Pages site: the project page, and the live demo from demo/evtx.

    python scripts/build_site.py --out site --base-url https://<user>.github.io/crabwalk

Writes index.html, the project page (Turkish, filled in from project_page.html),
and the demo under demo/: index.html (landing page), report.html,
attack-paths.html, findings.json, story.md and navigator-layer.json. The base
URL lets both pages open the layer directly in the ATT&CK Navigator
(#layerURL=...). The demo used to be the site root, so report.html and
attack-paths.html there redirect to demo/, and a copy of navigator-layer.json
stays there for Navigator links made before the move (a JSON fetch cannot be
redirected).
"""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import quote

from crabwalk import __version__
from crabwalk.graph import build_graph, render_page
from crabwalk.narrative import build_story
from crabwalk.navigator import build_layer
from crabwalk.parser import ParseStats, iter_events
from crabwalk.report import render_report
from crabwalk.rules import ALL_RULES, hunt
from crabwalk.style import SEVERITY_COLOR, SEVERITY_ORDER, SEVERITY_TEXT, page_head

ROOT = Path(__file__).resolve().parent.parent
esc = html.escape
REPO = "https://github.com/IlkerUnver00/crabwalk"
NAVIGATOR = "https://mitre-attack.github.io/attack-navigator/"
PROJECT_PAGE = Path(__file__).resolve().parent / "project_page.html"
DEMO = "demo"  # the demo's folder on the site
SEVERITY_TR = {"critical": "kritik", "high": "yüksek", "medium": "orta", "low": "düşük"}


def build(out: Path, base_url: str | None) -> dict[str, int]:
    demo = out / DEMO
    demo.mkdir(parents=True, exist_ok=True)
    stats = ParseStats()
    ctx, findings = hunt(iter_events([ROOT / "demo" / "evtx"], stats=stats))
    graph = build_graph(ctx, findings)
    story = build_story(ctx, findings, graph)
    layer = build_layer(findings, name="crabwalk demo")

    (demo / "report.html").write_text(
        render_report(ctx, findings, stats=stats, title="crabwalk — demo report"), encoding="utf-8")
    (demo / "attack-paths.html").write_text(
        render_page(graph, title="crabwalk — demo attack paths"), encoding="utf-8")
    (demo / "navigator-layer.json").write_text(json.dumps(layer, indent=2), encoding="utf-8")
    (demo / "findings.json").write_text(
        json.dumps({"story": story.to_dict(), "findings": [f.to_dict() for f in findings]},
                   indent=2), encoding="utf-8")
    (demo / "story.md").write_text(story.to_markdown(), encoding="utf-8")

    by_severity = Counter(f.severity for f in findings)
    scored = sum(1 for t in layer["techniques"] if "score" in t)  # parents are layout-only
    navigator = None
    if base_url:  # a local build has no public URL the Navigator could fetch
        layer_url = f"{base_url.rstrip('/')}/{DEMO}/navigator-layer.json"
        navigator = NAVIGATOR + "#layerURL=" + quote(layer_url, safe="")
    (demo / "index.html").write_text(
        _landing(stats, len(findings), by_severity, len(graph.edges), scored, navigator,
                 story.to_html(
                     intro='<p class="muted story-lead">These nine demo files are separate public lab '
                           'recordings, not one intrusion. crabwalk joins them where host names and '
                           'addresses repeat, which is why it flags the weeks-long gaps below.</p>',
                     footer='<p class="muted story-more">Generated from the findings and the attack '
                            'graph, not written by hand. The same story in Markdown, as <code>crabwalk '
                            'hunt --story</code> writes it for a ticket or case file: '
                            '<a href="story.md">story.md</a>.</p>')),
        encoding="utf-8")
    (out / "index.html").write_text(_project_page({
        "version": esc(__version__),
        "rule_count": len(ALL_RULES),
        "demo_files": stats.files,
        "demo_records": stats.records,
        "demo_findings": len(findings),
        "demo_edges": len(graph.edges),
        "demo_techniques": scored,
        "severity_bar": _severity_bar(by_severity),
        "navigator_href": esc(navigator or f"{DEMO}/navigator-layer.json"),
        "navigator_card": (
            '<h3>Navigator ısı haritası <span class="go">→</span></h3><p>Bulguların arkasındaki '
            "teknikler, ATT&amp;CK matrisinde bir katman olarak.</p>" if navigator else
            '<h3>Navigator katmanı (JSON) <span class="go">→</span></h3><p>İndirip ATT&amp;CK '
            "Navigator'da açın.</p>"),
    }), encoding="utf-8")
    for name in ("report.html", "attack-paths.html"):
        (out / name).write_text(_redirect(f"{DEMO}/{name}"), encoding="utf-8")
    (out / "navigator-layer.json").write_text(json.dumps(layer, indent=2), encoding="utf-8")
    (out / ".nojekyll").write_text("", encoding="utf-8")
    return {"findings": len(findings), "edges": len(graph.edges), "techniques": scored}


def _project_page(fields: dict[str, object]) -> str:
    """project_page.html with each {{name}} replaced; every name must be in ``fields``."""
    template = PROJECT_PAGE.read_text(encoding="utf-8")
    missing = set(re.findall(r"\{\{(\w+)\}\}", template)) - set(fields)
    if missing:
        raise KeyError(f"project page fields without a value: {sorted(missing)}")
    return re.sub(r"\{\{(\w+)\}\}", lambda m: str(fields[m.group(1)]), template)


def _severity_bar(by_severity: Counter) -> str:
    present = [s for s in reversed(SEVERITY_ORDER) if by_severity[s]]  # mildest first
    segments = "".join(
        f'<div style="flex:{by_severity[s]};background:{SEVERITY_COLOR[s]};color:{SEVERITY_TEXT[s]}">'
        f"{s.upper()}&nbsp;{by_severity[s]}</div>"
        for s in present
    )
    label = ", ".join(f"{SEVERITY_TR[s]} {by_severity[s]}" for s in present)
    return (f'<div class="bar" role="img" aria-label="Demo bulguları, önem derecesine göre: {label}">'
            f"{segments}</div>")


def _redirect(target: str) -> str:
    target = esc(target)
    return (f'<!doctype html>\n<html lang="en">\n<meta charset="utf-8">\n'
            '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
            f'<title>crabwalk — moved</title>\n'
            f'<meta http-equiv="refresh" content="0; url={target}">\n'
            f'<link rel="canonical" href="{target}">\n'
            f'<p>The crabwalk demo moved to <a href="{target}">{target}</a>.</p>\n')


def _landing(stats: ParseStats, total: int, by_severity: Counter, edges: int, techniques: int,
             navigator_href: str | None, story_html: str) -> str:
    severities = "".join(
        f'<span class="lg"><span class="dot" style="background:{SEVERITY_COLOR[s]}"></span>'
        f"{s.capitalize()} <b>{by_severity[s]}</b></span>"
        for s in SEVERITY_ORDER if by_severity[s]
    )
    if navigator_href:
        navigator = (f'<a class="card link" href="{esc(navigator_href)}">'
                     "<h2>ATT&amp;CK Navigator</h2><p class=\"muted\">The techniques behind these findings as a "
                     "heatmap on the ATT&amp;CK matrix, opened straight from this site.</p></a>")
    else:  # local build: no public URL the Navigator could fetch
        navigator = ('<a class="card link" href="navigator-layer.json"><h2>ATT&amp;CK Navigator layer</h2>'
                     '<p class="muted">Download and open it in the ATT&amp;CK Navigator.</p></a>')
    return f"""{page_head("crabwalk — live demo")}
<style>
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:14px;margin:16px 0}}
.link{{display:block;color:inherit;text-decoration:none}}
.link:hover{{border-color:#2a78d6;text-decoration:none}}
.link h2{{color:#2a78d6;margin-bottom:6px}}
.link p{{margin:0}}
.back{{margin:4px 0 0;color:var(--ink-2)}}
.back a{{color:#1f66c1;text-decoration:underline}}
@media (prefers-color-scheme: dark){{:root:not([data-theme="light"]) .back a{{color:#5aa0d6}}}}
:root[data-theme="dark"] .back a{{color:#5aa0d6}}
</style>
<header class="hero"><div class="crab">\U0001f980</div><div>
<h1>crabwalk — live demo</h1>
<p class="muted">Windows EVTX lateral-movement hunter: stateful cross-host correlation, an attack-path graph,
and MITRE ATT&amp;CK mapping. Generated by crabwalk {esc(__version__)} from the bundled demo logs.</p>
<p class="back"><a href="../index.html">&larr; Project page</a> (in Turkish)</p>
</div></header>
<section class="tiles">
<div class="tile"><div class="tile-v">{stats.files}</div><div class="tile-k">EVTX files</div></div>
<div class="tile"><div class="tile-v">{stats.records}</div><div class="tile-k">Records</div></div>
<div class="tile"><div class="tile-v">{total}</div><div class="tile-k">Findings</div></div>
<div class="tile"><div class="tile-v">{edges}</div><div class="tile-k">Attack-path edges</div></div>
<div class="tile"><div class="tile-v">{techniques}</div><div class="tile-k">ATT&amp;CK techniques</div></div>
</section>
<section class="card"><div class="legend" style="margin-top:0">{severities}</div></section>
{story_html}
<div class="grid">
<a class="card link" href="report.html"><h2>Report</h2><p class="muted">The self-contained HTML report:
the story, attack paths, severity, ATT&amp;CK coverage, timeline and every finding.</p></a>
<a class="card link" href="attack-paths.html"><h2>Attack paths</h2><p class="muted">The interactive graph:
hover or click a host to follow where the attacker came from and went next.</p></a>
{navigator}
<a class="card link" href="findings.json"><h2>findings.json</h2><p class="muted">The raw findings and
the story: the <code>findings</code> and <code>story</code> keys of <code>crabwalk hunt --out</code>.</p></a>
</div>
<section class="card">
<h2>About this data</h2>
<p>Nine unmodified recordings from the public
<a href="https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES">EVTX-ATTACK-SAMPLES</a> corpus (GPL-3.0),
bundled in the repository's <a href="{REPO}/tree/main/demo">demo folder</a>. They are separate lab captures,
not one intrusion — <a href="{REPO}/blob/main/demo/README.md">what each file shows</a>.
Rebuilt on every push to <a href="{REPO}">the repository</a>; run it yourself with
<code>crabwalk hunt demo/evtx --report report.html</code>.</p>
</section>"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=Path("site"))
    parser.add_argument("--base-url", help="public URL of the site, for the Navigator link")
    args = parser.parse_args(argv)
    summary = build(args.out, args.base_url)
    print(f"site -> {args.out}: {summary['findings']} findings, {summary['edges']} edges, "
          f"{summary['techniques']} techniques")
    return 0


if __name__ == "__main__":
    sys.exit(main())
