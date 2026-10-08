"""Run crabwalk, Hayabusa and Chainsaw on the same EVTX samples and compare.

    python scripts/benchmark.py --samples samples/EVTX-ATTACK-SAMPLES \\
        --hayabusa samples/tools/hayabusa --chainsaw samples/tools/chainsaw/chainsaw \\
        --out docs/benchmark/results.json

    python scripts/benchmark.py --samples samples/EVTX-to-MITRE-Attack --folder . \\
        --hayabusa samples/tools/hayabusa --chainsaw samples/tools/chainsaw/chainsaw \\
        --skip-timing --out docs/benchmark/results-evtx-to-mitre-attack.json

Each tool runs on each file under ``--folder`` (default: the corpus's "Lateral
Movement" folder, subfolders included) on its own, with the rule set its
release ships and its documented default invocation (no rule update, no
tuning):

* Hayabusa: ``dfir-timeline -f FILE -w`` (no wizard: all levels, noisy,
  deprecated and unsupported rules left off, as shipped), JSONL, verbose profile;
* Chainsaw: ``hunt FILE -s sigma/ --mapping sigma-event-logs-all.yml -r rules/``,
  JSONL;
* crabwalk: ``hunt`` on the same file, in process.

Every alert is reduced to its level, rule title and ATT&CK tags. Raw alert
text is never written to disk: the samples hold real malware command lines,
which the tools copy into their output and antivirus flags, so stdout is
parsed in memory. The same criteria apply to every tool:

* *alert at medium or above*: level medium, high or critical (Hayabusa's
  "emergency" counts as critical);
* *lateral-movement alert*: tagged with the ATT&CK tactic lateral movement
  (TA0008) or a technique of it (T1021, T1570, T1550, T1563, T1210, T1534,
  T1080, T1072).

The script also times one run of each tool over the whole corpus folder.
It needs the two tools' release folders; nothing is downloaded. After a
change to crabwalk alone, ``--reuse`` keeps the engines' rows of an earlier
run of the same corpus and engine versions and reruns only crabwalk.
"""

from __future__ import annotations

import argparse
import json
import platform
import re
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from statistics import median

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from crabwalk import __version__  # noqa: E402
from crabwalk.parser import iter_events  # noqa: E402
from crabwalk.rules import hunt  # noqa: E402

LEVELS = ("informational", "low", "medium", "high", "critical")
MEDIUM_PLUS = {"medium", "high", "critical"}
LM_TECHNIQUES = ("T1021", "T1570", "T1550", "T1563", "T1210", "T1534", "T1080", "T1072")
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def level(raw: str) -> str:
    text = str(raw or "").strip().lower()
    aliases = {"info": "informational", "med": "medium", "crit": "critical", "emergency": "critical",
               "emer": "critical"}
    text = aliases.get(text, text)
    return text if text in LEVELS else "informational"


def is_lateral(tactics: list[str], techniques: list[str]) -> bool:
    if any(re.sub(r"[^a-z]", "", t.lower()) in ("lateralmovement", "latmov", "ta0008") for t in tactics):
        return True
    return any(t.upper().startswith(LM_TECHNIQUES) for t in techniques)


def alert(level_: str, title: str, tactics: list[str], techniques: list[str]) -> dict:
    return {"level": level(level_), "title": title, "lateral": is_lateral(tactics, techniques)}


# --------------------------------------------------------------------------
# the three tools
# --------------------------------------------------------------------------


def run_hayabusa(home: Path, target: Path, directory: bool = False) -> list[dict]:
    exe = next(home.glob("hayabusa-*.exe"), None) or next(home.glob("hayabusa-*"))
    cmd = [str(exe), "dfir-timeline", "-d" if directory else "-f", str(target), "-w", "-q", "-N",
           "-Q", "-K", "-U", "-O", "-b", "-p", "verbose", "-t", "jsonl",
           "-r", str(home / "rules"), "-c", str(home / "rules" / "config")]
    out = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace").stdout
    alerts = []
    for line in out.splitlines():
        line = _ANSI.sub("", line).strip()
        if not line.startswith("{"):
            continue
        record = json.loads(line)
        techniques = [t for t in record.get("MitreTags", []) if re.match(r"T\d{4}", str(t))]
        alerts.append(alert(record.get("Level"), record.get("RuleTitle", "?"),
                            record.get("MitreTactics", []), techniques))
    return alerts


def run_chainsaw(home: Path, target: Path) -> list[dict]:
    exe = next(home.glob("chainsaw_x86_64-pc-windows-msvc.exe"), None) or next(home.glob("chainsaw_*linux*"))
    cmd = [str(exe), "hunt", str(target), "-s", str(home / "sigma"), "--mapping",
           str(home / "mappings" / "sigma-event-logs-all.yml"), "-r", str(home / "rules"),
           "--jsonl", "-q", "--skip-errors"]
    out = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace").stdout
    alerts = []
    for line in out.splitlines():
        if not line.strip().startswith("{"):
            continue
        record = json.loads(line)
        tags = [str(t) for t in record.get("tags") or []]
        tactics = [t.split(".", 1)[1] for t in tags if t.startswith("attack.") and not re.match(r"attack\.t\d", t)]
        techniques = [t.split(".", 1)[1].upper() for t in tags if re.match(r"attack\.t\d", t)]
        alerts.append(alert(record.get("level"), record.get("name", "?"), tactics, techniques))
    return alerts


def run_crabwalk(target: Path) -> list[dict]:
    _, findings = hunt(iter_events([target]))
    return [alert(f.severity, f"{f.rule_id} {f.title}", [], list(f.techniques)) for f in findings]


def tool_versions(hayabusa: Path, chainsaw: Path) -> dict:
    def first_line(cmd: list[str]) -> str:
        out = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
        return _ANSI.sub("", (out.stdout or out.stderr)).strip().splitlines()[0]

    hb = next(hayabusa.glob("hayabusa-*.exe"), None) or next(hayabusa.glob("hayabusa-*"))
    cs = next(chainsaw.glob("chainsaw_x86_64-pc-windows-msvc.exe"), None) or next(chainsaw.glob("chainsaw_*linux*"))
    return {"crabwalk": __version__, "hayabusa": first_line([str(hb), "help"]),
            "chainsaw": first_line([str(cs), "--version"])}


# --------------------------------------------------------------------------
# measuring
# --------------------------------------------------------------------------


def summarize(alerts: list[dict]) -> dict:
    by_level = Counter(a["level"] for a in alerts)
    strong = [a for a in alerts if a["level"] in MEDIUM_PLUS]
    return {
        "alerts": len(alerts),
        "by_level": {lv: by_level[lv] for lv in LEVELS if by_level[lv]},
        "medium_plus": len(strong),
        "lateral_medium_plus": sum(a["lateral"] for a in strong),
        "titles_medium_plus": _top(a["title"] for a in strong),
        "titles_lateral_medium_plus": _top(a["title"] for a in strong if a["lateral"]),
    }


def _top(titles) -> list:
    return sorted(Counter(titles).items(), key=lambda kv: (-kv[1], kv[0]))[:8]


def aggregate(files: list[dict], tool: str) -> dict:
    rows = [f["tools"][tool] for f in files]
    detected = [r for r in rows if r["medium_plus"]]
    return {
        "files": len(rows),
        "files_with_medium_plus": len(detected),
        "files_with_lateral_medium_plus": sum(1 for r in rows if r["lateral_medium_plus"]),
        "files_with_any_alert": sum(1 for r in rows if r["alerts"]),
        "alerts_total": sum(r["alerts"] for r in rows),
        "medium_plus_total": sum(r["medium_plus"] for r in rows),
        "median_medium_plus_per_detected_file": median([r["medium_plus"] for r in detected]) if detected else 0,
        "max_medium_plus_in_a_file": max((r["medium_plus"] for r in rows), default=0),
    }


def timed(fn, *args) -> tuple[float, object]:
    start = time.perf_counter()
    result = fn(*args)
    return round(time.perf_counter() - start, 1), result


def group_of(name: str) -> str:
    """The top-level subfolder a file sits in ("." for files directly in the folder)."""
    return name.split("/", 1)[0] if "/" in name else "."


def git_info(repo: Path) -> tuple[str, str]:
    def git(*args: str) -> str:
        return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True).stdout.strip()

    url = git("remote", "get-url", "origin")
    name = re.sub(r"\.git$", "", url.rstrip("/")).split("github.com/")[-1] if url else repo.name
    return name, git("rev-parse", "HEAD")


def _reusable_rows(path: Path, corpus_commit: str, versions: dict) -> dict[str, dict]:
    """file -> {hayabusa, chainsaw} rows of an earlier run, which a crabwalk
    change cannot affect. Refused unless corpus and engine versions match."""
    prior = json.loads(path.read_text(encoding="utf-8"))
    meta = prior["meta"]
    if meta["corpus_commit"] != corpus_commit or any(
            meta["versions"][tool] != versions[tool] for tool in ("hayabusa", "chainsaw")):
        raise SystemExit(f"{path}: other corpus commit or engine versions; rerun the engines")
    return {f["file"]: {tool: f["tools"][tool] for tool in ("hayabusa", "chainsaw")} for f in prior["files"]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--samples", type=Path, required=True, help="EVTX corpus clone (a git checkout)")
    parser.add_argument("--folder", default="Lateral Movement",
                        help="folder under --samples to run on, subfolders included ('.' = whole corpus)")
    parser.add_argument("--hayabusa", type=Path, required=True, help="unpacked Hayabusa release folder")
    parser.add_argument("--chainsaw", type=Path, required=True, help="unpacked Chainsaw release folder")
    parser.add_argument("--out", type=Path, default=ROOT / "docs" / "benchmark" / "results.json")
    parser.add_argument("--skip-timing", action="store_true", help="skip the whole-corpus timing runs")
    parser.add_argument("--reuse", type=Path,
                        help="earlier results file of the same corpus commit and tool versions: "
                             "its Hayabusa and Chainsaw rows are kept and only crabwalk is rerun")
    args = parser.parse_args(argv)

    folder = args.samples / args.folder
    samples = sorted(folder.rglob("*.evtx"), key=lambda p: p.relative_to(folder).as_posix().lower())
    corpus, corpus_commit = git_info(args.samples)
    versions = tool_versions(args.hayabusa, args.chainsaw)
    reused = _reusable_rows(args.reuse, corpus_commit, versions) if args.reuse else {}
    files = []
    for i, sample in enumerate(samples, 1):
        name = sample.relative_to(folder).as_posix()
        print(f"[{i}/{len(samples)}] {name}", file=sys.stderr)
        engines = reused.get(name) or {
            "hayabusa": summarize(run_hayabusa(args.hayabusa, sample)),
            "chainsaw": summarize(run_chainsaw(args.chainsaw, sample)),
        }
        files.append({"file": name, "tools": {"crabwalk": summarize(run_crabwalk(sample)), **engines}})

    timing = {}
    if not args.skip_timing:
        print("timing whole-corpus runs ...", file=sys.stderr)
        for tool, fn in (("crabwalk", lambda: run_crabwalk(args.samples)),
                         ("hayabusa", lambda: run_hayabusa(args.hayabusa, args.samples, directory=True)),
                         ("chainsaw", lambda: run_chainsaw(args.chainsaw, args.samples))):
            seconds, alerts = timed(fn)
            timing[tool] = {"seconds": seconds, **{k: v for k, v in summarize(alerts).items()
                                                    if k != "titles_medium_plus"}}

    tools = ("crabwalk", "hayabusa", "chainsaw")
    groups = sorted({group_of(f["file"]) for f in files})
    result = {
        "meta": {
            "versions": versions,
            "engine_rows_reused_from": args.reuse.name if reused else None,
            "corpus": corpus, "corpus_commit": corpus_commit,
            "folder": args.folder, "files": len(samples),
            "platform": f"{platform.system()} {platform.release()}, Python {platform.python_version()}",
            "criteria": {"medium_plus": sorted(MEDIUM_PLUS), "lateral": "tactic lateral movement or "
                         + ", ".join(LM_TECHNIQUES)},
        },
        "summary": {tool: aggregate(files, tool) for tool in tools},
        "summary_by_subfolder": {} if groups == ["."] else {
            g: {tool: aggregate([f for f in files if group_of(f["file"]) == g], tool) for tool in tools}
            for g in groups},
        "timing_whole_corpus": timing,
        "files": files,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], indent=2))
    print(json.dumps(timing, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
