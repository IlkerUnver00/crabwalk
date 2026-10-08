"""EVTX parsing: turns raw .evtx files into a stream of NormalizedEvent objects.

Uses pyevtx-rs (the ``evtx`` package, Rust-backed) for speed. Nothing about a
single input is fatal — forensic inputs are routinely dirty: a file that cannot
be opened (bad header, zero bytes, locked, not EVTX at all) is reported and
skipped, and so is a record that cannot be read or decoded.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from evtx import PyEvtxParser

from .catalog import keep_event
from .models import NormalizedEvent

EVTX_HEADER = 4096
EVTX_CHUNK = 65536
#: Read failures tolerated per file beyond one per chunk. pyevtx-rs raises once
#: per damaged chunk and then moves on, so a reader that fails more often than
#: the file has chunks is no longer advancing and is abandoned.
READ_ERROR_SLACK = 16


@dataclass
class ParseStats:
    files: int = 0
    records: int = 0  # records the reader produced
    kept: int = 0
    skipped: int = 0  # produced but could not be decoded
    read_errors: int = 0  # damaged chunks/records the reader could not produce
    file_errors: int = 0  # files that yielded nothing at all
    damaged_files: int = 0  # files read only in part
    errors: list[str] = field(default_factory=list)  # record-level, capped
    file_problems: list[str] = field(default_factory=list)  # one per file, never capped

    _MAX_ERRORS = 20

    @property
    def decoded(self) -> int:
        return self.records - self.skipped

    def note_error(self, message: str) -> None:
        self.skipped += 1
        self._remember(message)

    def note_read_error(self, message: str) -> None:
        self.read_errors += 1
        self._remember(message)

    def note_file_error(self, message: str) -> None:
        self.file_errors += 1
        self.file_problems.append(message)

    def note_damaged_file(self, message: str) -> None:
        self.damaged_files += 1
        self.file_problems.append(message)

    def _remember(self, message: str) -> None:
        if len(self.errors) < self._MAX_ERRORS:
            self.errors.append(message)


def read_error_budget(file: Path) -> int:
    """How many read failures a file may produce before the reader is stuck."""
    try:
        size = file.stat().st_size
    except OSError:
        size = 0
    return max(0, size - EVTX_HEADER) // EVTX_CHUNK + 1 + READ_ERROR_SLACK


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
        for record in _read_records(file, stats):
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


def _read_records(file: Path, stats: ParseStats) -> Iterator[dict[str, Any]]:
    """Yield the raw records of one file; damage is reported, never raised.

    Opening fails on a bad header, an empty or locked file, or a non-EVTX file.
    Reading fails per damaged chunk (occasionally per record) inside an
    otherwise valid file; pyevtx-rs then continues with the next chunk, so we
    keep reading — good chunks after a damaged span are evidence too. Only a
    reader that fails more often than the file has chunks is given up on.
    """
    try:
        records = PyEvtxParser(str(file)).records_json()
    except Exception as exc:
        stats.note_file_error(f"{file.name}: cannot open: {exc}")
        return
    budget = read_error_budget(file)
    produced = failures = 0
    abandoned = False
    while True:
        try:
            record = next(records)
        except StopIteration:
            break
        except Exception as exc:
            failures += 1
            stats.note_read_error(f"{file.name}: unreadable chunk/record: {exc}")
            if failures > budget:
                abandoned = True
                break
            continue
        produced += 1
        yield record
    if not failures:
        return
    if produced == 0:
        stats.note_file_error(f"{file.name}: opened, but no record could be read "
                              f"({failures} read failures)")
    else:
        verdict = "abandoned after" if abandoned else "partially read,"
        stats.note_damaged_file(f"{file.name}: {verdict} {failures} unreadable chunks/records")


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
    return keep_event(event)


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
