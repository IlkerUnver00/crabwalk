"""Rule interface, Finding model and the context rules evaluate against."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from ..catalog import SECURITY, SERVICE_IMAGE_PATH, SYSMON, SYSTEM
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
    # Where the activity came from, when the evidence says so. Lets the attack
    # graph draw the finding as a src -> host edge instead of a lone node.
    src_ip: str | None = None
    src_host: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "techniques": list(self.techniques),
            "timestamp": self.timestamp.isoformat(),
            "host": self.host,
            "user": self.user,
            "src_ip": self.src_ip,
            "src_host": self.src_host,
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


#: The same install seen by several logs within this window is one install.
SERVICE_DEDUP_WINDOW = timedelta(seconds=10)
_SOURCE_RANK = {"7045": 0, "4697": 1, "sysmon13": 2}


@dataclass(slots=True)
class ServiceInstall:
    """A service install, whichever log saw it.

    ``source`` is "7045", "4697" or "sysmon13". A Sysmon 13 entry is only an
    ImagePath write: a new service *or* a reconfiguration of an existing one.
    """

    timestamp: datetime
    computer: str
    name: str
    image: str
    event: NormalizedEvent
    source: str = "7045"

    def describe(self) -> str:
        if self.source == "sysmon13":
            return f"ImagePath of service '{self.name}' set to {self.image[:80]}"
        return f"install of service '{self.name}' ({self.image[:80]})"


class HuntContext:
    """Everything a rule may look at: sorted events, sessions, movement edges."""

    def __init__(self, events: list[NormalizedEvent], tracking: TrackResult) -> None:
        self.events = events
        self.tracking = tracking
        self._index: dict[tuple[str, int], list[NormalizedEvent]] = {}
        for event in events:
            self._index.setdefault((event.channel, event.event_id), []).append(event)
        self._service_installs: list[ServiceInstall] | None = None

    @property
    def service_installs(self) -> list[ServiceInstall]:
        """Time-sorted service installs from System 7045, Security 4697 and
        Sysmon 13 (the Services\\<name>\\ImagePath write), so service-based
        rules work on Sysmon-only exports too. One install logged by several
        of them collapses to a single entry, preferring 7045, then 4697."""
        if self._service_installs is None:
            installs = [
                ServiceInstall(e.timestamp, e.computer, str(e.get("ServiceName") or "?"),
                               str(e.get("ImagePath") or "?"), e, "7045")
                for e in self.events_for(SYSTEM, 7045)
            ]
            installs += [
                ServiceInstall(e.timestamp, e.computer, str(e.get("ServiceName") or "?"),
                               str(e.get("ServiceFileName") or "?"), e, "4697")
                for e in self.events_for(SECURITY, 4697)
            ]
            for e in self.events_for(SYSMON, 13):
                target = str(e.get("TargetObject") or "")
                if SERVICE_IMAGE_PATH.search(target):
                    name = target.replace("/", "\\").rsplit("\\", 2)[-2]
                    installs.append(ServiceInstall(
                        e.timestamp, e.computer, name, str(e.get("Details") or "?"), e, "sysmon13"
                    ))
            self._service_installs = _collapse_installs(installs)
        return self._service_installs

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


def _collapse_installs(installs: list[ServiceInstall]) -> list[ServiceInstall]:
    """Merge the cross-log copies of one install: same (host, service), each
    within the dedup window of the previous copy, at most one entry per log.
    Two installs seen by the same log are always two installs (PsExec removes
    its service on exit, so back-to-back runs reinstall it)."""
    installs.sort(key=lambda i: (i.computer, i.name.lower(), i.timestamp, _SOURCE_RANK[i.source]))
    groups: list[list[ServiceInstall]] = []
    for install in installs:
        group = groups[-1] if groups else None
        if (
            group is not None
            and group[-1].computer == install.computer
            and group[-1].name.lower() == install.name.lower()
            and install.timestamp - group[-1].timestamp <= SERVICE_DEDUP_WINDOW
            and install.source not in {i.source for i in group}
        ):
            group.append(install)
        else:
            groups.append([install])
    merged = [min(group, key=lambda i: (_SOURCE_RANK[i.source], i.timestamp)) for group in groups]
    merged.sort(key=lambda i: (i.timestamp, i.computer, i.name))
    return merged


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
