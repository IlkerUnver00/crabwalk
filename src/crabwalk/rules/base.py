"""Rule interface, Finding model and the context rules evaluate against."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ..models import NormalizedEvent
from ..parser import dedup_events
from ..sessions import LogonSession, TrackResult, build_sessions, norm_logon_id

SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}


@dataclass(slots=True)
class Finding:
    rule_id: str
    title: str
    severity: str  # low | medium | high | critical
    techniques: tuple[str, ...]
    timestamp: datetime
    host: str
    summary: str
    user: str = "-"
    evidence: list[NormalizedEvent] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "techniques": list(self.techniques),
            "timestamp": self.timestamp.isoformat(),
            "host": self.host,
            "user": self.user,
            "summary": self.summary,
            "evidence": [
                {
                    "timestamp": e.timestamp.isoformat(),
                    "channel": e.channel,
                    "event_id": e.event_id,
                    "record_id": e.record_id,
                    "computer": e.computer,
                    "source_file": e.source_file,
                }
                for e in self.evidence
            ],
        }


class HuntContext:
    """Everything a rule may look at: sorted events, sessions, movement edges."""

    def __init__(self, events: list[NormalizedEvent], tracking: TrackResult) -> None:
        self.events = events
        self.tracking = tracking
        self._index: dict[tuple[str, int], list[NormalizedEvent]] = {}
        for event in events:
            self._index.setdefault((event.channel, event.event_id), []).append(event)

    @classmethod
    def build(cls, events: Iterable[NormalizedEvent]) -> "HuntContext":
        ordered = sorted(
            dedup_events(events), key=lambda e: (e.timestamp, e.computer, e.record_id)
        )
        return cls(ordered, build_sessions(ordered))

    def events_for(self, channel: str, *event_ids: int) -> list[NormalizedEvent]:
        """Time-sorted events matching any of the given IDs on one channel."""
        if len(event_ids) == 1:
            return self._index.get((channel, event_ids[0]), [])
        merged = [e for eid in event_ids for e in self._index.get((channel, eid), [])]
        merged.sort(key=lambda e: e.timestamp)
        return merged

    def session_for(self, computer: str, logon_id_value: Any) -> LogonSession | None:
        logon_id = norm_logon_id(logon_id_value)
        if logon_id is None:
            return None
        return self.tracking.sessions.get((computer, logon_id))


class Rule(ABC):
    """A detection rule. Subclasses set the class attributes and evaluate()."""

    id: str
    title: str
    severity: str
    techniques: tuple[str, ...]

    @abstractmethod
    def evaluate(self, ctx: HuntContext) -> Iterator[Finding]: ...

    def finding(self, **kwargs: Any) -> Finding:
        """Build a Finding pre-filled with this rule's metadata."""
        kwargs.setdefault("rule_id", self.id)
        kwargs.setdefault("title", self.title)
        kwargs.setdefault("severity", self.severity)
        kwargs.setdefault("techniques", self.techniques)
        return Finding(**kwargs)


def basename(path: Any) -> str:
    """Lower-case file name from a Windows path-ish value."""
    return str(path or "").replace("/", "\\").rsplit("\\", 1)[-1].lower()
