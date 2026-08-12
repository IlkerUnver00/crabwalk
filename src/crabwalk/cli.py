"""Command line entry point."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from . import __version__
from .attack import technique_name
from .catalog import describe
from .models import NormalizedEvent
from .navigator import build_layer
from .parser import ParseStats, iter_events
from .report import render_report
from .rules import hunt
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
    hunt_cmd.set_defaults(func=_cmd_hunt)
    return parser


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
    return 0


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
    print(f"files      : {stats.files}")
    print(f"records    : {stats.records}  (kept: {stats.kept}, unparsable: {stats.skipped})")
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
    return 0


def _cmd_hunt(args: argparse.Namespace) -> int:
    stats = ParseStats()
    try:
        ctx, findings = hunt(iter_events(args.paths, stats=stats))
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.out:
        payload = {"findings": [f.to_dict() for f in findings]}
        args.out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    if args.layer:
        args.layer.write_text(json.dumps(build_layer(findings), indent=2), encoding="utf-8")
    if args.report:
        html = render_report(ctx, findings, stats=stats)
        args.report.write_text(html, encoding="utf-8")

    by_severity = Counter(f.severity for f in findings)
    print(f"files      : {stats.files}")
    print(f"records    : {stats.records}  (kept: {stats.kept}, unparsable: {stats.skipped})")
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

    for f in findings:
        print()
        print(f"[{f.severity.upper()}] {f.timestamp:%Y-%m-%d %H:%M:%S}Z  {f.rule_id}  {f.title}")
        print(f"    host: {f.host}   user: {f.user}   ATT&CK: {', '.join(f.techniques)}")
        print(f"    {f.summary}")

    if findings:
        print("\nATT&CK SUMMARY")
        technique_counts = Counter(t for f in findings for t in f.techniques)
        for technique_id, count in sorted(technique_counts.items()):
            print(f"{technique_id:<10} {technique_name(technique_id):<60} {count:>4}")
    for label, path in (("findings", args.out), ("layer", args.layer), ("report", args.report)):
        if path:
            print(f"wrote {label} -> {path}")
    return 0


def _print_summary(
    events: list[NormalizedEvent], stats: ParseStats, *, out_path: Path | None
) -> None:
    print(f"files      : {stats.files}")
    print(f"records    : {stats.records}  (kept: {stats.kept}, unparsable: {stats.skipped})")
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
    if stats.errors:
        print(f"\nfirst unparsable records ({len(stats.errors)} shown):", file=sys.stderr)
        for line in stats.errors:
            print(f"  {line}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
