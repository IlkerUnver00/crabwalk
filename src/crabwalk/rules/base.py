"""Rule interface, Finding model and the context rules evaluate against."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, ClassVar

from ..catalog import SECURITY, SERVICE_IMAGE_PATH, SYSMON, SYSTEM
from ..hosts import clean_ip, is_local_address, short_host
from ..models import NormalizedEvent
from ..parser import dedup_events
from ..sessions import LogonSession, TrackResult, build_sessions, norm_logon_id

SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}

#: Ports a Windows host listens on for the remote services crabwalk follows
#: (RPC endpoint mapper, NetBIOS, SMB, RDP, WinRM).
SERVER_PORTS = frozenset({135, 139, 445, 3389, 5985, 5986})
#: How far from a connection a host's other records may tell its address.
KNOWN_ADDRESS_WINDOW = timedelta(days=1)


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
    # What was done, as a past-tense phrase without host or time ("installed
    # service 'x' (c:\x.exe)"), for the attack narrative. Empty: use the title.
    action: str = ""
    # Findings of other rules whose evidence this one already cites in full,
    # with at least their techniques and severity: one story, told once.
    merged: list[Finding] = field(default_factory=list)
    # How many occurrences of `action` this finding stands for (a burst of 14
    # logons is one finding of count 14), so the story counts them, not it.
    count: int = 1

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
            "action": self.action,
            "count": self.count,
            # each merged finding in full: its own time, account, source and records
            "merged": [m.to_dict() for m in self.merged],
            "evidence": [
                {
                    "timestamp": e.timestamp.isoformat(),
                    "channel": e.channel,
                    "event_id": e.event_id,
                    "record_id": e.record_id,
                    "record_number": e.record_number,
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
        self._host_addresses: dict[str, list[tuple[datetime, str]]] | None = None

    @property
    def host_addresses(self) -> dict[str, list[tuple[datetime, str]]]:
        """(time, address) each host (by short name) is seen using, as its
        Sysmon 3 records show: see ``_own_side``."""
        if self._host_addresses is None:
            found: dict[str, list[tuple[datetime, str]]] = {}
            for event in self.events_for(SYSMON, 3):
                host, own = short_host(event.computer), _own_side(event)
                if host and own:
                    found.setdefault(host, []).append((event.timestamp, own))
            self._host_addresses = found
        return self._host_addresses

    def connection_peer(self, event: NormalizedEvent) -> str | None:
        """The other machine's address in a Sysmon 3 connection, or None if
        it is local or the record does not say which side is this host."""
        return self.connection_peer_side(event)[0]

    def sole_peer(self, connections: list[NormalizedEvent]
                  ) -> tuple[str | None, str | None, list[NormalizedEvent], list[str]]:
        """The one remote machine some connections name: (address, name, the
        records naming it, every peer address). With none or several peers
        there is no address and no record to cite, only the list."""
        sides = [(c, *self.connection_peer_side(c)) for c in connections]
        peers = sorted({ip for _, ip, _ in sides if ip})
        if len(peers) != 1:
            return None, None, [], peers
        cited = [c for c, ip, _ in sides if ip == peers[0]]
        names = {name.lower(): name for _, ip, name in sides if ip == peers[0] and name}
        return peers[0], (next(iter(names.values())) if len(names) == 1 else None), cited, peers

    def connection_peer_side(self, event: NormalizedEvent) -> tuple[str | None, str | None]:
        """(address, host name) of the other machine in a Sysmon 3 record.

        Sysmon does not put the local side in a fixed field on inbound
        connections, so the side is decided by ``_own_side`` and, failing
        that, by the addresses this host is seen using in its other records
        within a day (DHCP hands addresses on). The name is the one Sysmon
        resolved for that side, when it is a host name other than this one."""
        own = _own_side(event)
        sides = [clean_ip(event.get("SourceIp")), clean_ip(event.get("DestinationIp"))]
        if own is None:
            seen = self.host_addresses.get(short_host(event.computer) or "", [])
            known = {ip for when, ip in seen if abs(when - event.timestamp) <= KNOWN_ADDRESS_WINDOW}
            mine = [ip for ip in sides if ip in known]
            own = mine[0] if len(mine) == 1 else None
        if own is None or own not in sides:
            return None, None
        peer_is_source = sides[1] == own
        peer = sides[0] if peer_is_source else sides[1]
        if not peer or is_local_address(peer):
            return None, None
        name = event.get("SourceHostname" if peer_is_source else "DestinationHostname")
        named = short_host(name)
        return peer, (str(name).strip() if named and named != short_host(event.computer) else None)

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
    """A detection rule. Subclasses set the class attributes and evaluate().

    ``tunables`` names the instance attributes an analyst may override from a
    config file (correlation windows, thresholds, switches). Each has a
    class-level default whose type decides how the configured value is read.
    """

    id: str
    title: str
    severity: str
    techniques: tuple[str, ...]
    tunables: ClassVar[tuple[str, ...]] = ()
    zero_ok_tunables: ClassVar[tuple[str, ...]] = ()  # durations allowed to be 0 (tolerances)

    @abstractmethod
    def evaluate(self, ctx: HuntContext) -> Iterator[Finding]: ...

    @classmethod
    def check_tunable(cls, name: str, value: Any) -> Any:
        """Validate/normalize a configured tunable; raise ValueError to reject."""
        return value

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


def share_label(share: Any) -> str:
    """'\\\\*\\ADMIN$' -> 'ADMIN$': the share as an analyst names it."""
    return str(share or "?").replace("/", "\\").rsplit("\\", 1)[-1] or "?"


def clip(text: Any, limit: int = 80) -> str:
    """One line for a narrative phrase. A longer value is cut at a word
    boundary and says how much was left out, so a reader knows to look at
    the finding (a clipped command line can hide the interesting part)."""
    flat = " ".join(str(text or "").split())
    if len(flat) <= limit:
        return flat
    head = flat[:limit]
    cut = head.rfind(" ")
    if cut >= limit // 2:  # end on a whole word unless that loses more than half
        head = head[:cut]
    return f"{head}… (+{len(flat) - len(head)} chars)"


def asks_write(event: NormalizedEvent) -> bool:
    """Did a 5145 ask for write access (WriteData 0x2 or AppendData 0x4)?
    A 5145 is an access check; without a write bit the file was only read."""
    try:
        return bool(int(str(event.get("AccessMask") or "0"), 16) & 0x6)
    except ValueError:
        return False


def evidence_key(event: NormalizedEvent) -> tuple[str, str, int, datetime]:
    """Identity of a record across findings (the dedup_events key)."""
    return (event.computer, event.channel, event.record_id, event.timestamp)


def _own_side(event: NormalizedEvent) -> str | None:
    """This host's address in a Sysmon 3 record, when the record itself shows
    it: the side named with this host's name, the source of a connection the
    host initiated, or, on an inbound one, the only side on a server port."""
    host = short_host(event.computer)
    src, dst = clean_ip(event.get("SourceIp")), clean_ip(event.get("DestinationIp"))
    for ip, name in ((src, event.get("SourceHostname")), (dst, event.get("DestinationHostname"))):
        if ip and host and short_host(name) == host:
            return ip
    initiated = str(event.get("Initiated")).strip().lower()
    if initiated == "true":
        return src
    if initiated == "false":
        on_server_port = (_port(event.get("SourcePort")) in SERVER_PORTS,
                          _port(event.get("DestinationPort")) in SERVER_PORTS)
        if on_server_port == (True, False):
            return src
        if on_server_port == (False, True):
            return dst
    return None


def _port(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
