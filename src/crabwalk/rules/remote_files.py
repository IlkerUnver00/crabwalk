"""Files that cross hosts: autostart drops written by another machine, and
programs run straight from an RDP client's drive.

CW-014  a file created in a Startup folder by the SMB server (Sysmon 11 by
        "System", or a 5145 write on a share) or by mstsc.exe: the RDP client
        writing what the server it is connected to pushed through the
        client's shared drive (\\\\tsclient). It runs at the next logon.
CW-015  a process started from \\\\tsclient\\..., the drive the connecting RDP
        client shares: a tool copied over RDP and run (SharpRDP does this).
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from datetime import timedelta

from ..catalog import SECURITY, STARTUP_FOLDER, SYSMON
from ..hosts import clean_ip, is_local_address, remote_ip
from ..models import NormalizedEvent
from ..sessions import display_user
from .base import Finding, HuntContext, Rule, asks_write, basename, clip, share_label
from .execution import RDP_LOGONS, _process_pairs, _spawn_source

# A UNC path into the client's drives, or how Security 4688 logs one (\Device\Mup\...).
TSCLIENT = re.compile(r"(?:\\\\|\\device\\mup\\)tsclient\\", re.IGNORECASE)
SMB_WRITERS = {"system", "<unknown process>"}  # the SMB server writing for a client
_PROFILE = re.compile(r"\\([^\\]+)\\appdata\\(?:roaming|roamin~\d+)\\", re.IGNORECASE)


def _startup_owner(path: str) -> str:
    """Whose Startup folder: "bob's" for ...\\bob\\AppData\\Roaming\\..., 'the
    all-users' under ProgramData, else 'a' (a profile store, another layout)."""
    match = _PROFILE.search("\\" + path)
    if match:
        return f"{match.group(1)}'s"
    return "the all-users" if "\\programdata\\" in ("\\" + path).lower() else "a"


def _file_name(path: str) -> str:
    return path.replace("/", "\\").rsplit("\\", 1)[-1]


def _inbound(event: NormalizedEvent) -> bool:
    return str(event.get("Initiated")).strip().lower() == "false"


def _outbound(event: NormalizedEvent) -> bool:
    return str(event.get("Initiated")).strip().lower() == "true"


def _loopback(event: NormalizedEvent) -> bool:
    ips = [clean_ip(event.get("SourceIp")), clean_ip(event.get("DestinationIp"))]
    return all(ip is not None and is_local_address(ip) for ip in ips)


def _port_of(event: NormalizedEvent, port: int) -> bool:
    """Is either end of a Sysmon 3 connection on this port?"""
    return str(port) in (str(event.get("SourcePort")), str(event.get("DestinationPort")))


def _connections(ctx: HuntContext, event: NormalizedEvent, keep: Callable[[NormalizedEvent], bool],
                 before: timedelta, after: timedelta) -> list[NormalizedEvent]:
    lo, hi = event.timestamp - before, event.timestamp + after
    return [c for c in ctx.events_for(SYSMON, 3)
            if c.computer == event.computer and lo <= c.timestamp <= hi and keep(c)]


class StartupFolderDrop(Rule):
    id = "CW-014"
    title = "Startup folder written from another host"
    severity = "high"
    techniques = ("T1547.001",)
    peer_window = timedelta(seconds=60)  # records of one copy, and its inbound SMB connection
    rdp_window = timedelta(hours=12)  # mstsc.exe connection the write came through
    tunables = ("peer_window", "rdp_window")

    def evaluate(self, ctx: HuntContext) -> Iterator[Finding]:
        writes: list[tuple[NormalizedEvent, str, str]] = []  # (record, path, "smb" | "rdp")
        for event in ctx.events_for(SYSMON, 11):
            writer = basename(event.get("Image"))
            if writer in SMB_WRITERS or writer == "mstsc.exe":
                path = str(event.get("TargetFilename") or "")
                writes.append((event, path, "rdp" if writer == "mstsc.exe" else "smb"))
        for event in ctx.events_for(SECURITY, 5145):
            path = str(event.get("RelativeTargetName") or "")
            if (str(event.get("ShareName") or "").upper().endswith("IPC$") or not asks_write(event)
                    or not STARTUP_FOLDER.search("\\" + path) or is_local_address(event.get("IpAddress"))):
                continue  # a client on this host itself (loopback) did not come from elsewhere
            writes.append((event, path, "smb"))
        # One copy is several records (5145 access checks, the Sysmon 11): one finding.
        groups: list[list[tuple[NormalizedEvent, str, str]]] = []
        for write in sorted(writes, key=lambda w: w[0].timestamp):
            key = _drop_key(*write)
            for group in reversed(groups):
                if (_drop_key(*group[-1]) == key
                        and write[0].timestamp - group[-1][0].timestamp <= self.peer_window):
                    group.append(write)
                    break
            else:
                groups.append([write])
        for group in groups:
            finding = self._rdp(ctx, group) if group[0][2] == "rdp" else self._smb(ctx, group)
            if finding is not None:
                yield finding

    def _smb(self, ctx: HuntContext, group: list[tuple[NormalizedEvent, str, str]]) -> Finding | None:
        records = [event for event, _, _ in group]
        shares = [e for e in records if e.channel == SECURITY]
        peers = sorted({ip for e in shares if (ip := remote_ip(e.get("IpAddress")))})
        src_ip = peers[0] if len(peers) == 1 else None
        src_host: str | None = None
        cited: list[NormalizedEvent] = []
        if not shares:  # Sysmon only: the inbound SMB connections around the write
            contact = _connections(ctx, records[0], lambda c: _inbound(c) and _port_of(c, 445),
                                   self.peer_window, self.peer_window)
            if contact and all(_loopback(c) for c in contact):
                return None  # written through \\localhost: a process on this host
            src_ip, src_host, cited, peers = ctx.sole_peer(contact)
        first, path = records[0], group[0][1]
        users = [display_user(e.get("SubjectDomainName"), e.get("SubjectUserName")) for e in shares]
        name, owner = _file_name(path), _startup_owner(path)
        where = f" on {share_label(shares[0].get('ShareName'))}" if shares else ""
        source = f" from {' and '.join(peers)}" if peers else ""
        return self.finding(
            techniques=("T1021.002", "T1570", "T1547.001"),
            timestamp=first.timestamp,
            host=first.computer,
            user=users[0] if users else "-",
            summary=f"'{name}' written over SMB{where} into {owner} Startup folder{source}: {path}",
            action=f"copied '{clip(name, 60)}' over SMB into {owner} Startup folder (runs at logon)",
            evidence=[*records, *cited],
            src_ip=src_ip,
            src_host=src_host,
        )

    def _rdp(self, ctx: HuntContext, group: list[tuple[NormalizedEvent, str, str]]) -> Finding:
        # The RDP client writes it: the server it is connected to pushed it
        # through the client's shared drive. That server is where it came from.
        first, path = group[0][0], group[0][1]
        sessions = _connections(ctx, first, lambda c: basename(c.get("Image")) == "mstsc.exe"
                                and _outbound(c) and _port_of(c, 3389), self.rdp_window, timedelta(0))
        latest = [c for c in sessions if ctx.connection_peer(c)][-1:]
        server, server_name = ctx.connection_peer_side(latest[0]) if latest else (None, None)
        name, owner = _file_name(path), _startup_owner(path)
        via = f" of {server}" if server else ""
        return self.finding(
            techniques=("T1021.001", "T1547.001"),
            timestamp=first.timestamp,
            host=first.computer,
            user=str(first.get("User") or "-"),
            summary=(f"mstsc.exe (RDP client) wrote '{name}' into {owner} Startup folder: pushed by "
                     f"the RDP server{via} through the client's shared drive (\\\\tsclient): {path}"),
            action=(f"pushed '{clip(name, 60)}' into {owner} Startup folder through the RDP "
                    f"client's shared drive (\\\\tsclient; runs at logon)"),
            evidence=[event for event, _, _ in group] + latest,
            src_ip=server,
            src_host=server_name,
        )


def _drop_key(event: NormalizedEvent, path: str, kind: str) -> tuple[str, str, str, str]:
    """One file in one Startup folder on one host, however the record spells its path."""
    return (event.computer.lower(), kind, _startup_owner(path).lower(), _file_name(path).lower())


class TsclientExecution(Rule):
    id = "CW-015"
    title = "Program run from an RDP client's drive"
    severity = "medium"
    techniques = ("T1021.001", "T1570")
    rdp_window = timedelta(hours=12)  # inbound RDP connection the run belongs to
    tunables = ("rdp_window",)

    def evaluate(self, ctx: HuntContext) -> Iterator[Finding]:
        for event, _parent, child, user in _process_pairs(ctx):
            image = str(event.get("Image") or event.get("NewProcessName") or "")
            command = str(event.get("CommandLine") or image)
            on_client = bool(TSCLIENT.search(image))
            if not (on_client or TSCLIENT.search(command)):
                continue
            # \\tsclient exists inside an RDP session: the session's 4624 names the client
            src_ip, src_host = _spawn_source(ctx, event, RDP_LOGONS)
            contact: list[NormalizedEvent] = []
            if not (src_ip or src_host):
                # the RDP session's connection: inbound to this host's 3389
                inbound = _connections(ctx, event, lambda c: _inbound(c) and _port_of(c, 3389)
                                       and ctx.connection_peer(c) is not None, self.rdp_window, timedelta(0))
                contact = inbound[-1:]
                if contact:
                    src_ip, src_host = ctx.connection_peer_side(contact[0])
            if on_client:
                summary = f"'{command[:160]}' started from the connecting RDP client's drive (\\\\tsclient)"
                action = f"ran '{clip(command, 90)}' from the RDP client's shared drive (\\\\tsclient)"
            else:  # a local program handed a path on the client's drive
                summary = f"'{command[:160]}' run with a path on the connecting RDP client's drive (\\\\tsclient)"
                action = f"ran '{clip(command, 90)}' on a file from the RDP client's shared drive (\\\\tsclient)"
            yield self.finding(
                timestamp=event.timestamp,
                host=event.computer,
                user=user,
                summary=summary,
                action=action,
                evidence=[event, *contact],
                src_ip=src_ip,
                src_host=src_host,
            )
