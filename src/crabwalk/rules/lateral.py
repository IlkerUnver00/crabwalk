"""Lateral movement rules: PsExec pattern, RDP chains, PtH, shares, tasks."""

from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import timedelta

from ..catalog import SECURITY, SYSTEM
from ..sessions import MovementEdge
from .base import Finding, HuntContext, Rule

#: Service names dropped by common remote-execution tools.
KNOWN_REMOTE_EXEC_SERVICES = re.compile(r"psexe|paexec|remcom|csexec|winexe", re.IGNORECASE)

_TASK_COMMAND = re.compile(r"<Command>([^<]+)</Command>", re.IGNORECASE)


def _shortname(host: str | None) -> str:
    return (host or "").split(".", 1)[0].lower()


def _inbound_edges_to(ctx: HuntContext, computer: str) -> list[MovementEdge]:
    """Non-machine-account remote logons observed on ``computer`` itself."""
    return [
        e
        for e in ctx.tracking.edges
        if e.dst == computer
        and e.kind != "explicit-credentials"
        and not e.is_machine_account
    ]


class PsExecPattern(Rule):
    """Remote logon followed shortly by a service install on the same host."""

    id = "CW-001"
    title = "Remote logon followed by service install"
    severity = "high"
    techniques = ("T1021.002", "T1543.003")
    window = timedelta(minutes=10)

    def evaluate(self, ctx: HuntContext) -> Iterator[Finding]:
        installs = ctx.events_for(SYSTEM, 7045) + ctx.events_for(SECURITY, 4697)
        for install in installs:
            edges = [
                e
                for e in _inbound_edges_to(ctx, install.computer)
                if timedelta(0) <= install.timestamp - e.timestamp <= self.window
            ]
            if not edges:
                continue
            edge = max(edges, key=lambda e: e.timestamp)  # closest preceding logon
            name = str(install.get("ServiceName") or "?")
            image = install.get("ImagePath") or install.get("ServiceFileName") or "?"
            delta = int((install.timestamp - edge.timestamp).total_seconds())
            known_tool = bool(KNOWN_REMOTE_EXEC_SERVICES.search(f"{name} {image}"))
            yield self.finding(
                severity="critical" if known_tool else "high",
                timestamp=install.timestamp,
                host=install.computer,
                user=edge.user,
                summary=(
                    f"Remote {edge.kind} logon from {edge.src} followed {delta}s later "
                    f"by install of service '{name}' ({image})"
                    + (" — known remote-exec tool" if known_tool else "")
                ),
                evidence=[install],
            )


class RdpChain(Rule):
    """RDP hop A -> B followed by RDP hop B -> C within the window."""

    id = "CW-002"
    title = "RDP chain across hosts"
    severity = "high"
    techniques = ("T1021.001",)
    window = timedelta(hours=6)

    def evaluate(self, ctx: HuntContext) -> Iterator[Finding]:
        rdp = [e for e in ctx.tracking.edges if e.logon_type == 10]
        # Learn ip -> hostname from edges that carry both.
        ip_names = {
            e.src_ip: _shortname(e.src_host) for e in rdp if e.src_ip and e.src_host
        }
        seen: set[tuple[str, str, str, str]] = set()
        for first in rdp:
            middle = _shortname(first.dst)
            for second in rdp:
                delta = second.timestamp - first.timestamp
                if not timedelta(0) < delta <= self.window:
                    continue
                second_src = _shortname(second.src_host) or ip_names.get(second.src_ip or "", "")
                if second_src != middle or _shortname(second.dst) == middle:
                    continue
                key = (first.src, middle, _shortname(second.dst), second.user)
                if key in seen:
                    continue
                seen.add(key)
                yield self.finding(
                    timestamp=second.timestamp,
                    host=second.dst,
                    user=second.user,
                    summary=(
                        f"RDP chain: {first.src} -> {first.dst} ({first.user}, "
                        f"{first.timestamp:%H:%M:%S}) -> {second.dst} ({second.user}, "
                        f"{second.timestamp:%H:%M:%S})"
                    ),
                )


class PassTheHash(Rule):
    """4624 patterns typical for pass-the-hash tooling."""

    id = "CW-003"
    title = "Pass-the-hash indicators"
    severity = "medium"
    techniques = ("T1550.002",)

    def evaluate(self, ctx: HuntContext) -> Iterator[Finding]:
        for event in ctx.events_for(SECURITY, 4624):
            logon_type = str(event.get("LogonType") or "")
            process = str(event.get("LogonProcessName") or "").strip().lower()
            package = str(event.get("AuthenticationPackageName") or "").upper()
            user = str(event.get("TargetUserName") or "")
            if user.endswith("$") or "ANONYMOUS" in user.upper():
                continue

            if logon_type == "9" and process == "seclogo":
                outbound = str(event.get("TargetOutboundUserName") or "?")
                yield self.finding(
                    severity="high",
                    timestamp=event.timestamp,
                    host=event.computer,
                    user=user,
                    summary=(
                        f"Logon type 9 via seclogo with outbound credentials "
                        f"'{outbound}' (sekurlsa::pth signature)"
                    ),
                    evidence=[event],
                )
            elif logon_type == "3" and package == "NTLM":
                session = ctx.session_for(event.computer, event.get("TargetLogonId"))
                if session is not None and session.privileged:
                    yield self.finding(
                        timestamp=event.timestamp,
                        host=event.computer,
                        user=user,
                        summary=(
                            f"Privileged NTLM network logon from "
                            f"{event.get('IpAddress') or '?'} "
                            f"(workstation: {event.get('WorkstationName') or '?'})"
                        ),
                        evidence=[event],
                    )


class RemoteScheduledTask(Rule):
    """Scheduled task created/updated from a remote logon session."""

    id = "CW-004"
    title = "Scheduled task created from remote session"
    severity = "high"
    techniques = ("T1053.005",)

    def evaluate(self, ctx: HuntContext) -> Iterator[Finding]:
        for event in ctx.events_for(SECURITY, 4698, 4702):
            session = ctx.session_for(event.computer, event.get("SubjectLogonId"))
            if session is None or not session.is_remote:
                continue
            task = str(event.get("TaskName") or "?")
            match = _TASK_COMMAND.search(str(event.get("TaskContent") or ""))
            command = f", runs '{match.group(1).strip()}'" if match else ""
            action = "created" if event.event_id == 4698 else "updated"
            yield self.finding(
                timestamp=event.timestamp,
                host=event.computer,
                user=session.user,
                summary=(
                    f"Task '{task}' {action} from remote session "
                    f"({session.source_ip or session.source_host}){command}"
                ),
                evidence=[event],
            )


class AdminShareExecutable(Rule):
    """Executable content touched on ADMIN$/C$ — classic lateral tool transfer."""

    id = "CW-005"
    title = "Executable on administrative share"
    severity = "high"
    techniques = ("T1021.002", "T1570")
    extensions = (".exe", ".dll", ".bat", ".ps1", ".cmd")

    def evaluate(self, ctx: HuntContext) -> Iterator[Finding]:
        seen: set[tuple[str, str, str, str]] = set()
        for event in ctx.events_for(SECURITY, 5145):
            share = str(event.get("ShareName") or "")
            target = str(event.get("RelativeTargetName") or "")
            if not share.upper().endswith(("ADMIN$", "C$")):
                continue
            if not target.lower().endswith(self.extensions):
                continue
            user = str(event.get("SubjectUserName") or "-")
            key = (event.computer, share, target.lower(), user)
            if key in seen:
                continue
            seen.add(key)
            yield self.finding(
                timestamp=event.timestamp,
                host=event.computer,
                user=user,
                summary=(
                    f"'{target}' accessed on {share} from "
                    f"{event.get('IpAddress') or '?'}"
                ),
                evidence=[event],
            )
