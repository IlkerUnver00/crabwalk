"""EVTX parsing: turns raw .evtx files into a stream of NormalizedEvent objects.

Uses pyevtx-rs (the ``evtx`` package, Rust-backed) for speed. Records that
fail to decode are counted, never fatal — forensic inputs are routinely dirty.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from evtx import PyEvtxParser

from .catalog import is_interesting
from .models import NormalizedEvent



@dataclass
class ParseStats:
    files: int = 0
    records: int = 0
    kept: int = 0
    skipped: int = 0
    errors: list[str] = field(default_factory=list)

    _MAX_ERRORS = 20

    def note_error(self, message: str) -> None:
        self.skipped += 1
        if len(self.errors) < self._MAX_ERRORS:
            self.errors.append(message)


def expand_paths(paths: Iterable[str | Path]) -> list[Path]:
    """Resolve files and directories (recursive) into a sorted list of .evtx files."""
    found: set[Path] = set()
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            found.update(p for p in path.rglob("*.evtx") if p.is_file())
        elif path.is_file():
            found.add(path)
        else:
            raise FileNotFoundError(f"no such file or directory: {path}")
    return sorted(found)


def iter_events(
    paths: Iterable[str | Path],
    *,
    keep_all: bool = False,
    event_ids: set[int] | None = None,
    channels: set[str] | None = None,
    stats: ParseStats | None = None,
) -> Iterator[NormalizedEvent]:
    """Yield normalized events from the given files/directories.

    Default behavior keeps only events in the lateral-movement catalog;
    explicit ``event_ids``/``channels`` filters replace the catalog filter,
    and ``keep_all`` disables filtering entirely.
    """
    stats = stats if stats is not None else ParseStats()
    for file in expand_paths(paths):
        stats.files += 1
        parser = PyEvtxParser(str(file))
        for record in parser.records_json():
            stats.records += 1
            try:
                event = parse_record(record, source_file=str(file))
            except Exception as exc:  # dirty inputs: count and move on
                stats.note_error(f"{file.name}#{record.get('event_record_id')}: {exc}")
                continue
            if not _selected(event, keep_all=keep_all, event_ids=event_ids, channels=channels):
                continue
            stats.kept += 1
            yield event


def _selected(
    event: NormalizedEvent,
    *,
    keep_all: bool,
    event_ids: set[int] | None,
    channels: set[str] | None,
) -> bool:
    if channels and event.channel not in channels:
        return False
    if event_ids and event.event_id not in event_ids:
        return False
    if keep_all or event_ids or channels:
        return True
    return is_interesting(event.channel, event.event_id)


def dedup_events(events: Iterable[NormalizedEvent]) -> list[NormalizedEvent]:
    """Drop copies of the same physical event.

    EventRecordID is monotonic per (host, channel), so ``(computer, channel,
    record_id, timestamp)`` identifies one physical event. Overlapping EVTX
    exports — common in sample corpora and in multi-tool acquisitions — carry
    the same record twice; without this, correlation rules double-count.
    """
    seen: set[tuple[str, str, int, Any]] = set()
    out: list[NormalizedEvent] = []
    for event in events:
        key = (event.computer, event.channel, event.record_id, event.timestamp)
        if key in seen:
            continue
        seen.add(key)
        out.append(event)
    return out


def attributes(node: Any) -> dict[str, Any]:
    """Return an element's XML attributes.

    pyevtx-rs nests them under ``#attributes`` (e.g. Provider, TimeCreated,
    Security). Older/legacy conversions flattened them as ``@name`` keys, so we
    accept both.
    """
    if not isinstance(node, dict):
        return {}
    if isinstance(node.get("#attributes"), dict):
        return node["#attributes"]
    return {k[1:]: v for k, v in node.items() if k.startswith("@")}


def parse_record(record: dict[str, Any], *, source_file: str) -> NormalizedEvent:
    """Convert one pyevtx-rs JSON record into a NormalizedEvent."""
    event = json.loads(record["data"])["Event"]
    system = event["System"]
    return NormalizedEvent(
        timestamp=event_timestamp(system, record),
        channel=str(system.get("Channel") or ""),
        provider=str(attributes(system.get("Provider")).get("Name") or ""),
        event_id=int(scalar(system["EventID"])),
        record_id=int(record["event_record_id"]),
        computer=str(system.get("Computer") or ""),
        data=flatten_payload(event),
        source_file=source_file,
        user_sid=attributes(system.get("Security")).get("UserID"),
    )


def event_timestamp(system: dict[str, Any], record: dict[str, Any]) -> datetime:
    """Authoritative event time: System/TimeCreated/@SystemTime.

    The record-level ``timestamp`` pyevtx-rs exposes is null (FILETIME 0 ->
    1601-01-01) for a sizeable fraction of real records, so we prefer the
    SystemTime attribute and only fall back to the record timestamp.
    """
    system_time = attributes(system.get("TimeCreated")).get("SystemTime")
    if system_time:
        try:
            return parse_timestamp(str(system_time))
        except ValueError:
            pass
    return parse_timestamp(record["timestamp"])


def parse_timestamp(value: str) -> datetime:
    """Parse pyevtx-rs timestamps.

    These appear as '2021-03-29 21:19:10.696640 UTC', ISO
    '2019-02-13T15:14:52.409734Z', or with FILETIME's 100ns precision
    '2026-08-07T19:00:02.0206079Z UTC' (7 fractional digits — more than
    fromisoformat accepts on 3.10).
    """
    text = value.strip().removesuffix(" UTC").removesuffix("Z")
    if "." in text:
        head, _, frac = text.rpartition(".")
        text = f"{head}.{frac[:6].ljust(6, '0')}"
    try:
        return datetime.fromisoformat(text).replace(tzinfo=timezone.utc)
    except ValueError:
        raise ValueError(f"unrecognized timestamp: {value!r}") from None


def scalar(value: Any) -> Any:
    """Unwrap the {'#text': x} scalars the binary-XML conversion produces."""
    if isinstance(value, dict) and "#text" in value:
        return value["#text"]
    return value


def flatten_payload(event: dict[str, Any]) -> dict[str, Any]:
    """Merge EventData and UserData into a single flat field dict."""
    out: dict[str, Any] = {}
    for section in ("EventData", "UserData"):
        payload = event.get(section)
        if not isinstance(payload, dict):
            continue
        # UserData wraps its fields in one named element (e.g. <EventXML>).
        if section == "UserData" and len(payload) == 1:
            (inner,) = payload.values()
            if isinstance(inner, dict):
                payload = inner
        for key, value in payload.items():
            if key.startswith(("@", "#")):
                continue
            out[key] = scalar(value)
    return out
