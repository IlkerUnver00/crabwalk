"""Remote execution rules: WMI, WinRM, suspicious PowerShell."""

from __future__ import annotations

import re
from collections.abc import Iterator

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


class _SpawnedByRule(Rule):
    """Shared logic: flag children of a given remote-execution host process."""

    parent: str  # e.g. "wmiprvse.exe"
    via: str  # label for summaries
    through: str  # narrative: "ran 'x' through <through>"

    def evaluate(self, ctx: HuntContext) -> Iterator[Finding]:
        for event, parent, child, user in _process_pairs(ctx):
            if parent != self.parent:
                continue
            command = str(event.get("CommandLine") or child)
            yield self.finding(
                severity="high" if child in SHELLS else self.severity,
                timestamp=event.timestamp,
                host=event.computer,
                user=user,
                summary=f"{self.via} spawned '{command[:160]}'",
                action=f"ran '{clip(command, 90)}' through {self.through}",
                evidence=[event],
            )


class WmiExec(_SpawnedByRule):
    id = "CW-006"
    title = "Process spawned via WMI"
    severity = "medium"
    techniques = ("T1047",)
    parent = "wmiprvse.exe"
    via = "WmiPrvSE.exe (WMI)"
    through = "WMI"


class WinRmExec(_SpawnedByRule):
    id = "CW-007"
    title = "Remote execution via WinRM"
    severity = "medium"
    techniques = ("T1021.006",)
    parent = "wsmprovhost.exe"
    via = "wsmprovhost.exe (WinRM)"
    through = "PowerShell remoting (WinRM)"

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
