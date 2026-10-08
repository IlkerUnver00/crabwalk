"""Command line entry point."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import timedelta
from pathlib import Path

from . import __version__
from .attack import technique_name
from .catalog import describe
from .config import Config, ConfigError, example_config, format_duration, load_config
from .graph import build_graph, render_page
from .models import NormalizedEvent
from .navigator import build_layer
from .parser import ParseStats, iter_events
from .report import render_report
from .rules import ALL_RULES, run_rules
from .rules.base import HuntContext


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="crabwalk",
        description="EVTX lateral movement hunter: parse, correlate, map to ATT&CK.",
    )
    parser.add_argument("--version", action="version", version=f"crabwalk {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    parse_cmd = sub.add_parser(
        "parse",
        help="parse EVTX files into a normalized, time-sorted JSONL stream",
    )
    parse_cmd.add_argument("paths", nargs="+", help=".evtx files or directories to scan")
    parse_cmd.add_argument(
        "--all",
        action="store_true",
        help="keep every event instead of only the lateral-movement catalog",
    )
    parse_cmd.add_argument(
        "--event-id",
        type=int,
        action="append",
        dest="event_ids",
        metavar="ID",
        help="keep only this event ID (repeatable)",
    )
    parse_cmd.add_argument(
        "--channel",
        action="append",
        dest="channels",
        metavar="NAME",
        help="keep only this channel (repeatable)",
    )
    parse_cmd.add_argument("--out", type=Path, help="write events as JSONL to this file")
    parse_cmd.set_defaults(func=_cmd_parse)

    sessions_cmd = sub.add_parser(
        "sessions",
        help="reconstruct logon sessions and host-to-host movement edges",
    )
    sessions_cmd.add_argument("paths", nargs="+", help=".evtx files or directories to scan")
    sessions_cmd.add_argument(
        "--include-machine",
        action="store_true",
        help="also list machine-account ($) edges, which are mostly noise",
    )
    sessions_cmd.add_argument(
        "--out", type=Path, help="write sessions and edges as JSON to this file"
    )
    sessions_cmd.set_defaults(func=_cmd_sessions)

    hunt_cmd = sub.add_parser(
        "hunt",
        help="run all detection rules and report findings mapped to ATT&CK",
    )
    hunt_cmd.add_argument("paths", nargs="+", help=".evtx files or directories to scan")
    hunt_cmd.add_argument("--out", type=Path, help="write findings as JSON to this file")
    hunt_cmd.add_argument(
        "--report", type=Path, metavar="FILE.html",
        help="write a self-contained HTML report",
    )
    hunt_cmd.add_argument(
        "--layer", type=Path, metavar="FILE.json",
        help="write an ATT&CK Navigator layer",
    )
    hunt_cmd.add_argument(
        "--graph", type=Path, metavar="FILE",
        help="write the attack-path graph; format by extension: "
             ".html (interactive page), .dot/.gv (Graphviz) or .json",
    )
    tuning = hunt_cmd.add_argument_group("tuning (override the --config file)")
    tuning.add_argument("--config", type=Path, metavar="FILE.toml",
                        help="rule selection, windows and allowlist; see `crabwalk config --example`")
    tuning.add_argument("--rule", action="append", dest="rules", metavar="ID",
                        help="run only this rule (repeatable)")
    tuning.add_argument("--disable", action="append", metavar="ID",
                        help="do not run this rule (repeatable)")
    tuning.add_argument("--min-severity", choices=("low", "medium", "high", "critical"),
                        help="hide findings below this severity")
    tuning.add_argument("--show-suppressed", action="store_true",
                        help="also list the findings the allowlist suppressed")
    hunt_cmd.set_defaults(func=_cmd_hunt)

    config_cmd = sub.add_parser(
        "config",
        help="check a config file, or print a commented example",
    )
    config_cmd.add_argument("file", nargs="?", type=Path, help="config file to validate")
    config_cmd.add_argument("--example", action="store_true",
                            help="print an example config listing every setting and its default")
    config_cmd.set_defaults(func=_cmd_config)
    return parser


GRAPH_FORMATS = {".html": "html", ".htm": "html", ".dot": "dot", ".gv": "dot", ".json": "json"}


def _cmd_parse(args: argparse.Namespace) -> int:
    stats = ParseStats()
    try:
        events = list(
            iter_events(
                args.paths,
                keep_all=args.all,
                event_ids=set(args.event_ids) if args.event_ids else None,
                channels=set(args.channels) if args.channels else None,
                stats=stats,
            )
        )
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    events.sort(key=lambda e: (e.timestamp, e.computer, e.record_id))

    if args.out:
        with args.out.open("w", encoding="utf-8") as fh:
            for event in events:
                fh.write(event.to_json() + "\n")

    _print_summary(events, stats, out_path=args.out)
    _print_errors(stats)
    return _exit_code(stats)


def _cmd_sessions(args: argparse.Namespace) -> int:
    stats = ParseStats()
    try:
        result = HuntContext.build(iter_events(args.paths, stats=stats)).tracking
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.out:
        payload = {
            "sessions": [s.to_dict() for s in result.sessions.values()],
            "edges": [e.to_dict() for e in result.edges],
        }
        args.out.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    remote = result.remote_sessions()
    priv_remote = result.privileged_remote_sessions()
    _print_parse_stats(stats)
    print(
        f"sessions   : {len(result.sessions)} total"
        f" | {len(remote)} remote | {len(priv_remote)} privileged+remote"
    )

    edges = result.edges if args.include_machine else [
        e for e in result.edges if not e.is_machine_account
    ]
    hidden = len(result.edges) - len(edges)
    print(f"edges      : {len(edges)} shown"
          + (f" ({hidden} machine-account edges hidden, --include-machine)" if hidden else ""))

    if edges:
        print("\nHOST-TO-HOST MOVEMENT")
        user_w = max(len(e.user) for e in edges)
        src_w = max(len(e.src) for e in edges)
        dst_w = max(len(e.dst) for e in edges)
        for e in edges:
            flags = " priv" if e.privileged else ""
            print(
                f"{e.timestamp:%Y-%m-%d %H:%M:%S}Z  {e.user:<{user_w}}  "
                f"{e.src:<{src_w}} -> {e.dst:<{dst_w}}  {e.kind}{flags}"
            )
    if args.out:
        print(f"\nwrote {len(result.sessions)} sessions, {len(result.edges)} edges -> {args.out}")
    _print_errors(stats)
    return _exit_code(stats)


def _cmd_hunt(args: argparse.Namespace) -> int:
    graph_format = None
    if args.graph:
        graph_format = GRAPH_FORMATS.get(args.graph.suffix.lower())
        if graph_format is None:
            print(f"error: --graph needs a .html, .dot, .gv or .json file, got {args.graph}",
                  file=sys.stderr)
            return 2
    try:
        config = load_config(args.config) if args.config else Config()
        config = config.with_overrides(only=args.rules, disable=args.disable,
                                       min_severity=args.min_severity)
        rules = config.build_rules()
    except ConfigError as exc:
        print(f"error: config: {exc}", file=sys.stderr)
        return 2
    stats = ParseStats()
    try:
        ctx = HuntContext.build(iter_events(args.paths, stats=stats))
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    screened = config.screen(run_rules(ctx, rules))
    findings = screened.kept

    if args.out:
        payload = {
            "findings": [f.to_dict() for f in findings],
            "suppressed": [
                {**f.to_dict(), "allow_entry": entry.index, "allow_reason": entry.reason}
                for f, entry in screened.suppressed
            ],
            "below_min_severity": screened.below_min_severity,
            "settings": config.describe(),
        }
        args.out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    if args.layer:
        args.layer.write_text(json.dumps(build_layer(findings), indent=2), encoding="utf-8")
    if args.report:
        html = render_report(ctx, findings, stats=stats, suppressed=screened.suppressed)
        args.report.write_text(html, encoding="utf-8")
    if args.graph:
        graph = build_graph(ctx, findings)
        text = {"html": render_page, "dot": lambda g: g.to_dot(), "json": lambda g: g.to_json()}[
            graph_format
        ](graph)
        args.graph.write_text(text, encoding="utf-8")

    by_severity = Counter(f.severity for f in findings)
    _print_parse_stats(stats)
    print(
        f"sessions   : {len(ctx.tracking.sessions)}"
        f" | edges: {len(ctx.tracking.edges)}"
    )
    severity_parts = ", ".join(
        f"{name} {by_severity[name]}"
        for name in ("critical", "high", "medium", "low")
        if by_severity[name]
    )
    print(f"findings   : {len(findings)}" + (f"  ({severity_parts})" if findings else ""))
    ran = config.rule_ids()
    if len(ran) < len(ALL_RULES):
        skipped = [cls.id for cls in ALL_RULES if cls.id not in ran]
        print(f"rules      : {len(ran)} of {len(ALL_RULES)} (not run: {', '.join(skipped)})")
    if screened.suppressed:
        hint = "" if args.show_suppressed else "  (--show-suppressed to list)"
        print(f"suppressed : {len(screened.suppressed)} by allowlist{hint}")
    if screened.below_min_severity:
        print(f"hidden     : {screened.below_min_severity} below {config.min_severity} severity")

    for f in findings:
        print()
        print(f"[{f.severity.upper()}] {f.timestamp:%Y-%m-%d %H:%M:%S}Z  {f.rule_id}  {f.title}")
        print(f"    host: {f.host}   user: {f.user}   ATT&CK: {', '.join(f.techniques)}")
        print(f"    {f.summary}")

    if args.show_suppressed and screened.suppressed:
        print("\nSUPPRESSED BY ALLOWLIST")
        for f, entry in screened.suppressed:
            print(f"  [{f.severity.upper()}] {f.timestamp:%Y-%m-%d %H:%M:%S}Z  {f.rule_id}  "
                  f"host: {f.host}  user: {f.user}  -> {entry.label}")

    if findings:
        print("\nATT&CK SUMMARY")
        technique_counts = Counter(t for f in findings for t in f.techniques)
        for technique_id, count in sorted(technique_counts.items()):
            print(f"{technique_id:<10} {technique_name(technique_id):<60} {count:>4}")
    outputs = (("findings", args.out), ("layer", args.layer), ("report", args.report),
               ("graph", args.graph))
    for label, path in outputs:
        if path:
            print(f"wrote {label} -> {path}")
    for entry in screened.expired:
        print(f"warning: {entry.label} expired on {entry.expires} and was not applied",
              file=sys.stderr)
    for warning in screened.warnings:
        print(f"warning: {warning}", file=sys.stderr)
    _print_errors(stats)
    return _exit_code(stats)


def _cmd_config(args: argparse.Namespace) -> int:
    if args.example:
        print(example_config(), end="")
        return 0
    if args.file is None:
        print("error: give a config file to check, or use --example", file=sys.stderr)
        return 2
    try:
        config = load_config(args.file)
        config.build_rules()
    except ConfigError as exc:
        print(f"error: config: {exc}", file=sys.stderr)
        return 2
    ran = config.rule_ids()
    print(f"config     : {args.file}  (valid)")
    print(f"rules      : {', '.join(ran)}")
    skipped = [cls.id for cls in ALL_RULES if cls.id not in ran]
    if skipped:
        print(f"not run    : {', '.join(skipped)}")
    print(f"min sev.   : {config.min_severity or 'none'}")
    for rule_id, values in sorted(config.tunables.items()):
        cls = next(c for c in ALL_RULES if c.id == rule_id)
        for name, value in values.items():
            print(f"setting    : {rule_id}.{name} = {_show(value)}  (default {_show(getattr(cls, name))})")
    for entry in config.allow:
        scope = ", ".join(sorted(entry.rules)) if entry.rules is not None else "all rules"
        expiry = f", expires {entry.expires}" if entry.expires else ""
        print(f"allow      : [{entry.index}] {entry.reason!r} on {scope}{expiry}")
    return 0


def _show(value: object) -> str:
    if isinstance(value, timedelta):
        return format_duration(value)
    if isinstance(value, tuple):
        return ", ".join(value)
    return str(value).lower() if isinstance(value, bool) else str(value)


def _print_parse_stats(stats: ParseStats) -> None:
    damage = [f"unreadable: {stats.file_errors}"] if stats.file_errors else []
    damage += [f"damaged: {stats.damaged_files}"] if stats.damaged_files else []
    print(f"files      : {stats.files}" + (f"  ({', '.join(damage)})" if damage else ""))
    unreadable = f", unreadable chunks: {stats.read_errors}" if stats.read_errors else ""
    print(f"records    : {stats.records}  (kept: {stats.kept}, unparsable: {stats.skipped}{unreadable})")


def _print_errors(stats: ParseStats) -> None:
    if stats.file_problems:
        print(f"\ndamaged or unreadable files ({len(stats.file_problems)}):", file=sys.stderr)
        for line in stats.file_problems:
            print(f"  {line}", file=sys.stderr)
    if stats.errors:
        print(f"\nread/decode problems (first {len(stats.errors)} shown):", file=sys.stderr)
        for line in stats.errors:
            print(f"  {line}", file=sys.stderr)


def _exit_code(stats: ParseStats) -> int:
    """1 when there was damage and not one record could be decoded, else 0.

    Partial damage is normal in triage and does not fail the run; decoding
    nothing usually means a wrong path, a non-EVTX input or a wrecked file. A
    clean but empty input (no .evtx files, or empty logs) is not a failure.
    """
    damaged = stats.file_errors or stats.read_errors or stats.skipped
    return 1 if damaged and stats.decoded == 0 else 0


def _print_summary(
    events: list[NormalizedEvent], stats: ParseStats, *, out_path: Path | None
) -> None:
    _print_parse_stats(stats)
    if events:
        first, last = events[0].timestamp, events[-1].timestamp
        print(f"time range : {first:%Y-%m-%d %H:%M:%S}Z .. {last:%Y-%m-%d %H:%M:%S}Z")
        computers = sorted({e.computer for e in events if e.computer})
        print(f"computers  : {', '.join(computers) if computers else '-'}")
        print()
        counts = Counter((e.channel, e.event_id) for e in events)
        width = max(len(channel) for channel, _ in counts)
        for (channel, event_id), count in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
            label = describe(channel, event_id) or ""
            print(f"{channel:<{width}}  {event_id:>6}  {count:>8}  {label}")
    if out_path:
        print(f"\nwrote {len(events)} events -> {out_path}")


if __name__ == "__main__":
    raise SystemExit(main())
