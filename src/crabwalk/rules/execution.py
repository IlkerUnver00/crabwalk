"""Remote execution rules: WMI, WinRM, DCOM, suspicious PowerShell."""

from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import datetime, timedelta

from ..catalog import POWERSHELL, SECURITY, SYSMON, WINRM
from ..models import NormalizedEvent
from ..sessions import display_user
from .base import Finding, HuntContext, Rule, basename, clip

SHELLS = {
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "mshta.exe",
}

#: (label, pattern, severity) — matched case-insensitively against 4104 script blocks.
POWERSHELL_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("credential theft tooling", re.compile(r"invoke-mimikatz|sekurlsa|lsadump", re.I), "critical"),
    ("AMSI bypass", re.compile(r"amsiutils|amsiinitfailed", re.I), "high"),
    ("download cradle", re.compile(
        r"downloadstring|downloadfile|net\.webclient|invoke-webrequest|start-bitstransfer", re.I
    ), "high"),
    ("base64 decode + invoke", re.compile(r"frombase64string", re.I), "medium"),
    ("invoke-expression", re.compile(r"\biex\b|invoke-expression", re.I), "medium"),
)


def _and(items: list[str]) -> str:
    """'a', 'a and b', 'a, b and c'."""
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def _process_pairs(ctx: HuntContext) -> Iterator[tuple[NormalizedEvent, str, str, str]]:
    """Yield (event, parent_basename, child_basename, user) from Sysmon 1 and 4688."""
    for event in ctx.events_for(SYSMON, 1):
        yield (
            event,
            basename(event.get("ParentImage")),
            basename(event.get("Image")),
            str(event.get("User") or "-"),
        )
    for event in ctx.events_for(SECURITY, 4688):
        # A v2 4688 names the account the new process runs as in Target*; the
        # Subject is whoever created it (often the machine account for WMI).
        target = str(event.get("TargetUserName") or "").strip()
        if target and target != "-":
            user = display_user(event.get("TargetDomainName"), target)
        else:
            user = display_user(event.get("SubjectDomainName"), event.get("SubjectUserName"))
        yield (
            event,
            basename(event.get("ParentProcessName")),
            basename(event.get("NewProcessName")),
            user,
        )


def _logon_id(event: NormalizedEvent) -> object:
    """The logon session a new process runs in: Sysmon 1 LogonId; for a v2
    4688 the Target (the account it runs as), else the Subject."""
    if event.channel == SYSMON:
        return event.get("LogonId")
    target = event.get("TargetLogonId")
    return target if str(target or "0x0").lower() not in ("0x0", "-", "") else event.get("SubjectLogonId")


#: Logon types a remote caller's process runs in: network (3) and
#: network-cleartext (8). An RDP session (10) is a person at this host, so a
#: WMI or COM call they make here is local.
NETWORK_LOGONS = frozenset({3, 8})
#: RemoteInteractive (10) and its reconnect/unlock (7): an RDP session.
RDP_LOGONS = frozenset({7, 10})
#: A spawn this long before its session's 4624 is a LogonId reused across boots.
_SESSION_SKEW = timedelta(seconds=5)


def _spawn_source(ctx: HuntContext, event: NormalizedEvent,
                  logon_types: frozenset[int] = NETWORK_LOGONS) -> tuple[str | None, str | None]:
    """(src_ip, src_host) of the remote logon a spawned process runs in.

    WMI, WinRM and DCOM start the requested process in the caller's own
    network logon session, so when its 4624 was logged the session names the
    machine the command came from. The session must be of one of
    ``logon_types`` and live at the spawn: LogonIds repeat across boots."""
    session = ctx.session_for(event.computer, _logon_id(event))
    if (session is None or not session.is_remote or session.logon_type not in logon_types
            or (session.start is not None and event.timestamp < session.start - _SESSION_SKEW)
            or (session.end is not None and event.timestamp > session.end + _SESSION_SKEW)):
        return None, None
    return session.source_ip, session.source_host


class _SpawnedByRule(Rule):
    """Shared logic: flag children of a remote-execution host process."""

    #: parent image -> (label for summaries, narrative: "ran 'x' through <...>")
    parents: dict[str, tuple[str, str]]

    def evaluate(self, ctx: HuntContext) -> Iterator[Finding]:
        for event, parent, child, user in _process_pairs(ctx):
            if parent not in self.parents:
                continue
            via, through = self.parents[parent]
            command = str(event.get("CommandLine") or child)
            src_ip, src_host = _spawn_source(ctx, event)
            yield self.finding(
                severity="high" if child in SHELLS else self.severity,
                timestamp=event.timestamp,
                host=event.computer,
                user=user,
                summary=f"{via} spawned '{command[:160]}'",
                action=f"ran '{clip(command, 90)}' through {through}",
                evidence=[event],
                src_ip=src_ip,
                src_host=src_host,
            )


class WmiExec(_SpawnedByRule):
    id = "CW-006"
    title = "Process spawned via WMI"
    severity = "medium"
    techniques = ("T1047",)
    parents = {"wmiprvse.exe": ("WmiPrvSE.exe (WMI)", "WMI")}


class WinRmExec(_SpawnedByRule):
    id = "CW-007"
    title = "Remote execution via WinRM"
    severity = "medium"
    techniques = ("T1021.006",)
    parents = {
        "wsmprovhost.exe": ("wsmprovhost.exe (WinRM)", "PowerShell remoting (WinRM)"),
        "winrshost.exe": ("winrshost.exe (WinRM)", "Windows Remote Shell (winrs over WinRM)"),
    }

    def evaluate(self, ctx: HuntContext) -> Iterator[Finding]:
        yield from super().evaluate(ctx)
        for event in ctx.events_for(WINRM, 91):
            yield self.finding(
                timestamp=event.timestamp,
                host=event.computer,
                user=event.user_sid or "-",
                summary="WinRM shell created on host (event 91)",
                action="opened a WinRM shell",
                evidence=[event],
            )


#: COM servers activated from another host for lateral movement, by image.
#: Activation starts them with "-Embedding" (Office: "/automation -Embedding").
DCOM_SERVERS = {
    "mmc.exe": "MMC20.Application",
    "mshta.exe": "htafile, the LethalHTA technique",
    "excel.exe": "Excel.Application",
    "winword.exe": "Word.Application",
    "outlook.exe": "Outlook.Application",
}
#: Without the parent's command line (4688) only an MMC console spawning a
#: shell is telling; Office spawning one is just as often a local macro.
_BARE_PARENT_OK = {"mmc.exe"}


class DcomExec(Rule):
    """A process started by a COM server that DCOM activated.

    Remote DCOM starts the server under svchost (DcomLaunch) with
    ``-Embedding``. The finding is a child the server spawned (MMC20's
    ExecuteShellCommand, Office automation), or the activation itself: for
    mshta.exe always (an HTA run through DCOM), for the other servers when
    the server runs in a remote caller's network logon. The source is the
    network logon the process runs in or, on Sysmon-only hosts, the one
    remote address the COM server talked to around the activation."""

    id = "CW-013"
    title = "Execution through DCOM"
    severity = "medium"
    techniques = ("T1021.003",)
    peer_window = timedelta(seconds=60)
    tunables = ("peer_window",)

    def evaluate(self, ctx: HuntContext) -> Iterator[Finding]:
        pairs = list(_process_pairs(ctx))
        # when each COM server process was started: (host, pid) -> start times
        started: dict[tuple[str, int], list[datetime]] = {}
        for event, _parent, child, _user in pairs:
            pid = _pid(event)
            if child in DCOM_SERVERS and pid is not None:
                started.setdefault((event.computer, pid), []).append(event.timestamp)
        for event, parent, child, user in pairs:
            command = str(event.get("CommandLine") or child)
            if child in DCOM_SERVERS and parent == "svchost.exe" and _embedding(command):
                # The activation itself. mshta.exe runs the HTA right away; the
                # others say something only when the server runs in a remote
                # caller's network logon, which is what remote activation does.
                if child != "mshta.exe" and _spawn_source(ctx, event) == (None, None):
                    continue
                server, pid, spawned, since = child, _pid(event), None, event.timestamp
            elif parent in DCOM_SERVERS and (
                    _embedding(event.get("ParentCommandLine")) if event.channel == SYSMON
                    else parent in _BARE_PARENT_OK and child in SHELLS):
                server, pid, spawned = parent, _parent_pid(event), command
                # a shell's later commands still belong to the server's activation
                starts = [t for t in started.get((event.computer, pid), []) if t <= event.timestamp]
                since = max(starts) if starts and pid is not None else event.timestamp - self.peer_window
            else:
                continue
            src_ip, src_host = _spawn_source(ctx, event)
            cited: list[NormalizedEvent] = []
            peers: list[str] = []
            if not (src_ip or src_host):
                src_ip, src_host, cited, peers = ctx.sole_peer(self._contacts(ctx, event, server, pid, since))
            obj = DCOM_SERVERS[server]
            what = f"spawned '{command[:160]}'" if spawned else f"started as '{command[:160]}'"
            talked = f"; it talked to {' and '.join(peers)}" if peers else ""
            yield self.finding(
                severity="high" if child in SHELLS or not spawned else self.severity,
                timestamp=event.timestamp,
                host=event.computer,
                user=user,
                summary=f"{server} activated through DCOM ({obj}) {what}{talked}",
                action=(f"ran '{clip(spawned, 90)}' through DCOM ({obj})" if spawned
                        else f"ran an HTA in mshta.exe through DCOM ({obj})" if server == "mshta.exe"
                        else f"activated {obj} through DCOM"),
                evidence=[event, *cited],
                src_ip=src_ip,
                src_host=src_host,
            )

    def _contacts(self, ctx: HuntContext, event: NormalizedEvent, server: str, pid: int | None,
                  since: datetime) -> list[NormalizedEvent]:
        """Inbound connections to the COM server process, from its activation
        to ``peer_window`` after the event: the activating client calls in.
        A connection the server opened itself (an HTA fetching its payload,
        Office reaching a file share) says nothing about who activated it."""
        hi = event.timestamp + self.peer_window
        return [c for c in ctx.events_for(SYSMON, 3)
                if c.computer == event.computer and since <= c.timestamp <= hi
                and basename(c.get("Image")) == server
                and str(c.get("Initiated")).strip().lower() == "false"
                and pid is not None and _int(c.get("ProcessId")) == pid]  # that process, not its namesakes


def _embedding(command: object) -> bool:
    return "-embedding" in str(command or "").lower()


def _int(value: object) -> int | None:
    """A process ID as Sysmon (decimal) or Security (hex, '0x1a4') logs it."""
    text = str(value if value is not None else "").strip().lower()
    try:
        return int(text, 16) if text.startswith("0x") else int(text)
    except ValueError:
        return None


def _pid(event: NormalizedEvent) -> int | None:
    """The new process's ID: Sysmon 1 ProcessId, 4688 NewProcessId (a 4688's
    ProcessId is its creator's)."""
    return _int(event.get("ProcessId") if event.channel == SYSMON else event.get("NewProcessId"))


def _parent_pid(event: NormalizedEvent) -> int | None:
    return _int(event.get("ParentProcessId") if event.channel == SYSMON else event.get("ProcessId"))


class SuspiciousPowerShell(Rule):
    id = "CW-008"
    title = "Suspicious PowerShell script block"
    severity = "medium"
    techniques = ("T1059.001",)

    def evaluate(self, ctx: HuntContext) -> Iterator[Finding]:
        for event in ctx.events_for(POWERSHELL, 4104):
            text = str(event.get("ScriptBlockText") or "")
            if not text:
                continue
            labels = []
            worst = None
            for label, pattern, severity in POWERSHELL_PATTERNS:
                if pattern.search(text):
                    labels.append(label)
                    if worst is None:  # patterns are ordered worst-first
                        worst = severity
            if not labels:
                continue
            snippet = " ".join(text.split())[:120]
            yield self.finding(
                severity=worst or self.severity,
                timestamp=event.timestamp,
                host=event.computer,
                user=event.user_sid or "-",
                summary=f"Script block matches [{', '.join(labels)}]: {snippet}",
                action=f"ran a PowerShell script block with {_and(labels)}",
                evidence=[event],
            )
