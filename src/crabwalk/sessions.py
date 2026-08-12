"""Logon session tracking: LogonId lifecycles and host-to-host movement edges.

This is the stateful layer the detection rules build on. It turns the flat
event stream into:

* per-host logon sessions keyed by ``(computer, logon_id)`` — LogonIds are
  only unique per host per boot, never across hosts;
* ``MovementEdge`` records for every inbound remote logon (Security 4624 with
  a non-local source address, RDP session events) and outbound explicit-
  credential use (Security 4648).

The tracker is order-tolerant: 4672 (privileges) routinely arrives around the
matching 4624, and events from multiple files interleave unsorted.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .catalog import SECURITY, TS_LSM
from .models import NormalizedEvent

#: Placeholder / loopback values that mean "not a remote source".
LOCAL_SOURCES = {"", "-", "127.0.0.1", "::1", "localhost", "local"}

LOGON_TYPE_LABELS = {
    2: "interactive",
    3: "network",
    4: "batch",
    5: "service",
    7: "unlock",
    8: "network-cleartext",
    9: "new-credentials",
    10: "rdp",
    11: "cached-interactive",
}


def norm_logon_id(value: Any) -> str | None:
    """Normalize LogonId values ('0x3E7', '999', 999) to lowercase hex."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return hex(value)
    text = str(value).strip().lower()
    if not text or text == "-":
        return None
    try:
        return hex(int(text, 0))
    except ValueError:
        return text


def display_user(domain: Any, user: Any) -> str:
    user = str(user or "").strip()
    domain = str(domain or "").strip()
    if domain and domain != "-":
        return f"{domain}\\{user}"
    return user or "-"


def _to_int(value: Any) -> int | None:
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return None


def _is_local(address: str | None) -> bool:
    return address is None or address.strip().lower() in LOCAL_SOURCES


@dataclass(slots=True)
class LogonSession:
    computer: str
    logon_id: str
    user: str = "-"
    user_sid: str | None = None
    logon_type: int | None = None
    start: datetime | None = None
    end: datetime | None = None
    source_ip: str | None = None
    source_host: str | None = None
    auth_package: str | None = None
    logon_process: str | None = None
    privileged: bool = False
    event_count: int = 0

    @property
    def is_remote(self) -> bool:
        return not _is_local(self.source_ip)

    @property
    def is_machine_account(self) -> bool:
        return self.user.endswith("$")

    @property
    def duration_seconds(self) -> float | None:
        if self.start and self.end and self.end >= self.start:
            return (self.end - self.start).total_seconds()
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "computer": self.computer,
            "logon_id": self.logon_id,
            "user": self.user,
            "user_sid": self.user_sid,
            "logon_type": self.logon_type,
            "start": self.start.isoformat() if self.start else None,
            "end": self.end.isoformat() if self.end else None,
            "source_ip": self.source_ip,
            "source_host": self.source_host,
            "auth_package": self.auth_package,
            "logon_process": self.logon_process,
            "privileged": self.privileged,
            "remote": self.is_remote,
            "machine_account": self.is_machine_account,
        }


@dataclass(slots=True)
class MovementEdge:
    timestamp: datetime
    user: str
    src_ip: str | None
    src_host: str | None
    dst: str
    logon_type: int | None
    kind: str  # network / rdp / rdp-session / explicit-credentials / ...
    logon_id: str | None = None
    privileged: bool = False  # backfilled when 4672 is seen for the session

    @property
    def is_machine_account(self) -> bool:
        return self.user.endswith("$")

    @property
    def src(self) -> str:
        if self.src_ip and self.src_host:
            return f"{self.src_ip} ({self.src_host})"
        return self.src_ip or self.src_host or "?"

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "user": self.user,
            "src_ip": self.src_ip,
            "src_host": self.src_host,
            "dst": self.dst,
            "logon_type": self.logon_type,
            "kind": self.kind,
            "logon_id": self.logon_id,
            "privileged": self.privileged,
            "machine_account": self.is_machine_account,
        }


@dataclass
class TrackResult:
    sessions: dict[tuple[str, str], LogonSession] = field(default_factory=dict)
    edges: list[MovementEdge] = field(default_factory=list)

    def remote_sessions(self) -> list[LogonSession]:
        return [s for s in self.sessions.values() if s.is_remote]

    def privileged_remote_sessions(self) -> list[LogonSession]:
        return [s for s in self.sessions.values() if s.is_remote and s.privileged]


def build_sessions(events: Iterable[NormalizedEvent]) -> TrackResult:
    """Consume normalized events and reconstruct sessions + movement edges."""
    tracker = _Tracker()
    for event in events:
        tracker.feed(event)
    tracker.result.edges.sort(key=lambda e: e.timestamp)
    return tracker.result


class _Tracker:
    def __init__(self) -> None:
        self.result = TrackResult()
        # session key -> edges created from it, for privilege backfill
        self._session_edges: dict[tuple[str, str], list[MovementEdge]] = {}

    def feed(self, event: NormalizedEvent) -> None:
        if event.channel == SECURITY:
            handler = {
                4624: self._on_logon,
                4672: self._on_special_privileges,
                4634: self._on_logoff,
                4647: self._on_logoff,
                4648: self._on_explicit_credentials,
            }.get(event.event_id)
        elif event.channel == TS_LSM:
            handler = self._on_rdp_session if event.event_id in (21, 25) else None
        else:
            handler = None
        if handler is not None:
            handler(event)

    # --- Security channel -------------------------------------------------

    def _session(self, computer: str, logon_id: str) -> LogonSession:
        key = (computer, logon_id)
        session = self.result.sessions.get(key)
        if session is None:
            session = LogonSession(computer=computer, logon_id=logon_id)
            self.result.sessions[key] = session
            self._session_edges[key] = []
        return session

    def _on_logon(self, event: NormalizedEvent) -> None:
        logon_id = norm_logon_id(event.get("TargetLogonId"))
        if logon_id is None:
            return
        session = self._session(event.computer, logon_id)
        session.event_count += 1
        session.user = display_user(event.get("TargetDomainName"), event.get("TargetUserName"))
        session.user_sid = event.get("TargetUserSid") or session.user_sid
        session.logon_type = _to_int(event.get("LogonType"))
        session.auth_package = event.get("AuthenticationPackageName") or session.auth_package
        session.logon_process = event.get("LogonProcessName") or session.logon_process
        if session.start is None or event.timestamp < session.start:
            session.start = event.timestamp

        ip = str(event.get("IpAddress") or "").strip()
        workstation = str(event.get("WorkstationName") or "").strip()
        if not _is_local(ip):
            session.source_ip = ip
        if workstation and workstation != "-":
            session.source_host = workstation

        if session.is_remote:
            edge = MovementEdge(
                timestamp=event.timestamp,
                user=session.user,
                src_ip=session.source_ip,
                src_host=session.source_host,
                dst=event.computer,
                logon_type=session.logon_type,
                kind=LOGON_TYPE_LABELS.get(
                    session.logon_type or -1, f"type-{session.logon_type}"
                ),
                logon_id=logon_id,
                privileged=session.privileged,
            )
            self.result.edges.append(edge)
            self._session_edges[(event.computer, logon_id)].append(edge)

    def _on_special_privileges(self, event: NormalizedEvent) -> None:
        logon_id = norm_logon_id(event.get("SubjectLogonId"))
        if logon_id is None:
            return
        session = self._session(event.computer, logon_id)
        session.event_count += 1
        session.privileged = True
        if session.user == "-":
            session.user = display_user(
                event.get("SubjectDomainName"), event.get("SubjectUserName")
            )
        for edge in self._session_edges[(event.computer, logon_id)]:
            edge.privileged = True

    def _on_logoff(self, event: NormalizedEvent) -> None:
        logon_id = norm_logon_id(event.get("TargetLogonId"))
        if logon_id is None:
            return
        session = self._session(event.computer, logon_id)
        session.event_count += 1
        if session.end is None or event.timestamp > session.end:
            session.end = event.timestamp

    def _on_explicit_credentials(self, event: NormalizedEvent) -> None:
        """4648: outbound view — this host used explicit creds against a target."""
        target = str(event.get("TargetServerName") or "").strip()
        if _is_local(target) or target.lower() == event.computer.lower():
            return
        self.result.edges.append(
            MovementEdge(
                timestamp=event.timestamp,
                user=display_user(event.get("TargetDomainName"), event.get("TargetUserName")),
                src_ip=None,
                src_host=event.computer,
                dst=target,
                logon_type=None,
                kind="explicit-credentials",
                logon_id=norm_logon_id(event.get("SubjectLogonId")),
            )
        )

    # --- TerminalServices-LocalSessionManager ------------------------------

    def _on_rdp_session(self, event: NormalizedEvent) -> None:
        address = str(event.get("Address") or "").strip()
        if _is_local(address):
            return
        self.result.edges.append(
            MovementEdge(
                timestamp=event.timestamp,
                user=str(event.get("User") or "-"),
                src_ip=address,
                src_host=None,
                dst=event.computer,
                logon_type=10,
                kind="rdp-session" if event.event_id == 21 else "rdp-reconnect",
            )
        )
