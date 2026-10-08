"""Lateral movement rules: PsExec pattern, RDP chains, PtH, shares, tasks."""

from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import timedelta
from typing import Any

from ..catalog import SECURITY
from ..hosts import HostResolver, is_machine_account, remote_ip, remote_name, short_host
from ..sessions import MovementEdge, display_user
from .base import Finding, HuntContext, Rule, ServiceInstall

#: Service names dropped by common remote-execution tools.
KNOWN_REMOTE_EXEC_SERVICES = re.compile(r"psexe|paexec|remcom|csexec|winexe", re.IGNORECASE)

# A service image that is a command line rather than a binary: the
# Metasploit/impacket-smbexec/Cobalt "jump psexec_psh" shape.
SUSPICIOUS_SERVICE_IMAGE = re.compile(
    r"%comspec%|cmd(?:\.exe)?\s+/[ckq]|powershell|-enc(?:odedcommand)?\s|-nop\b"
    r"|\\\\127\.0\.0\.1\\|\\admin\$\\|\\windows\\temp\\|\\users\\public\\",
    re.IGNORECASE,
)


def looks_like_remote_exec(install: ServiceInstall) -> bool:
    return bool(
        SUSPICIOUS_SERVICE_IMAGE.search(install.image)
        or KNOWN_REMOTE_EXEC_SERVICES.search(f"{install.name} {install.image}")
    )


def credible_installs(ctx: HuntContext) -> list[ServiceInstall]:
    """Installs a correlation rule may lean on.

    SCM records (7045/4697) always count. A Sysmon 13 ImagePath write left
    without an SCM copy is just as often an existing service being
    reconfigured (updates rewrite ImagePath constantly), so it only counts when
    the image itself looks like remote execution. That keeps the
    Metasploit-psexec shape on Sysmon-only hosts — or where the System log was
    cleared — while a WinDefend platform update stays silent. A renamed tool
    with a plain binary, seen only through Sysmon 13, is the accepted miss.
    """
    return [i for i in ctx.service_installs if i.source != "sysmon13" or looks_like_remote_exec(i)]

_TASK_COMMAND = re.compile(r"<Command>([^<]+)</Command>", re.IGNORECASE)


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
    window = timedelta(minutes=10)  # logon -> install
    tunables = ("window",)

    def evaluate(self, ctx: HuntContext) -> Iterator[Finding]:
        for install in credible_installs(ctx):
            edges = [
                e
                for e in _inbound_edges_to(ctx, install.computer)
                if timedelta(0) <= install.timestamp - e.timestamp <= self.window
            ]
            if not edges:
                continue
            edge = max(edges, key=lambda e: e.timestamp)  # closest preceding logon
            delta = int((install.timestamp - edge.timestamp).total_seconds())
            known_tool = bool(KNOWN_REMOTE_EXEC_SERVICES.search(f"{install.name} {install.image}"))
            yield self.finding(
                severity="critical" if known_tool else "high",
                timestamp=install.timestamp,
                host=install.computer,
                user=edge.user,
                summary=(
                    f"Remote {edge.kind} logon from {edge.src} followed {delta}s later "
                    f"by {install.describe()}"
                    + (" — known remote-exec tool" if known_tool else "")
                ),
                evidence=[install.event],
                src_ip=edge.src_ip,
                src_host=edge.src_host,
            )


class RdpChain(Rule):
    """RDP hop A -> B followed by RDP hop B -> C within the window."""

    id = "CW-002"
    title = "RDP chain across hosts"
    severity = "high"
    techniques = ("T1021.001",)
    window = timedelta(hours=6)  # first hop -> second hop
    tunables = ("window",)

    def evaluate(self, ctx: HuntContext) -> Iterator[Finding]:
        rdp = [e for e in ctx.tracking.edges if e.logon_type == 10]
        # Learn ip -> hostname from edges that carry both.
        hosts = HostResolver()
        for edge in rdp:
            hosts.learn(edge.src_ip, edge.src_host)
        seen: set[tuple[str, str, str, str]] = set()
        for first in rdp:
            middle = short_host(first.dst) or ""
            for second in rdp:
                delta = second.timestamp - first.timestamp
                if not timedelta(0) < delta <= self.window:
                    continue
                second_src = hosts.key(second.src_ip, second.src_host) or ""
                target = short_host(second.dst) or ""
                if not middle or second_src != middle or target == middle:
                    continue
                key = (first.src, middle, target, second.user)
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
                    src_ip=second.src_ip,
                    src_host=second.src_host or first.dst,
                )


class PassTheHash(Rule):
    """4624 patterns typical for pass-the-hash tooling."""

    id = "CW-003"
    title = "Pass-the-hash indicators"
    severity = "medium"
    techniques = ("T1550.002",)
    # The seclogo/LT9 signature is precise. Privileged NTLM network logons are
    # a weaker tell that admin tooling produces all day on real AD; this
    # switch keeps the signature and drops that half.
    privileged_ntlm = True
    tunables = ("privileged_ntlm",)

    def evaluate(self, ctx: HuntContext) -> Iterator[Finding]:
        for event in ctx.events_for(SECURITY, 4624):
            logon_type = str(event.get("LogonType") or "")
            process = str(event.get("LogonProcessName") or "").strip().lower()
            package = str(event.get("AuthenticationPackageName") or "").upper()
            account = str(event.get("TargetUserName") or "")
            if is_machine_account(account) or "ANONYMOUS" in account.upper():
                continue
            user = display_user(event.get("TargetDomainName"), account)

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
            elif self.privileged_ntlm and logon_type == "3" and package == "NTLM":
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
                        src_ip=remote_ip(event.get("IpAddress")),
                        src_host=remote_name(event.get("WorkstationName")),
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
                src_ip=session.source_ip,
                src_host=session.source_host,
            )


class AdminShareExecutable(Rule):
    """Executable content touched on ADMIN$/C$ — classic lateral tool transfer."""

    id = "CW-005"
    title = "Executable on administrative share"
    severity = "high"
    techniques = ("T1021.002", "T1570")
    extensions = (".exe", ".dll", ".bat", ".ps1", ".cmd")
    tunables = ("extensions",)

    @classmethod
    def check_tunable(cls, name: str, value: Any) -> Any:
        if name == "extensions":
            normalized = []
            for ext in value:
                if not re.fullmatch(r"\.?[A-Za-z0-9]+", ext):
                    raise ValueError(f"{ext!r} is not a file extension (write '.exe' or 'exe', no globs)")
                normalized.append("." + ext.lstrip(".").lower())
            return tuple(normalized)
        return value

    def evaluate(self, ctx: HuntContext) -> Iterator[Finding]:
        seen: set[tuple[str, str, str, str]] = set()
        for event in ctx.events_for(SECURITY, 5145):
            share = str(event.get("ShareName") or "")
            target = str(event.get("RelativeTargetName") or "")
            if not share.upper().endswith(("ADMIN$", "C$")):
                continue
            if not target.lower().endswith(tuple(e.lower() for e in self.extensions)):
                continue
            user = display_user(event.get("SubjectDomainName"), event.get("SubjectUserName"))
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
                src_ip=remote_ip(event.get("IpAddress")),
            )
