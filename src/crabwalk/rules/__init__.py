"""Detection rules registry."""

from __future__ import annotations

from collections.abc import Iterable

from ..models import NormalizedEvent
from .antiforensics import EventLogCleared
from .base import SEVERITY_RANK, Finding, HuntContext, Rule
from .credentials import DCSync, Kerberoasting
from .execution import SuspiciousPowerShell, WinRmExec, WmiExec
from .lateral import (
    AdminShareExecutable,
    PassTheHash,
    PsExecPattern,
    RdpChain,
    RemoteScheduledTask,
)
from .pipes import NamedPipeExecution

ALL_RULES: tuple[type[Rule], ...] = (
    PsExecPattern,
    RdpChain,
    PassTheHash,
    RemoteScheduledTask,
    AdminShareExecutable,
    WmiExec,
    WinRmExec,
    SuspiciousPowerShell,
    EventLogCleared,
    Kerberoasting,
    DCSync,
    NamedPipeExecution,
)


def run_rules(
    ctx: HuntContext, rules: Iterable[Rule] | None = None
) -> list[Finding]:
    """Evaluate rules and return findings, worst first, deduplicated.

    Duplicates happen when the same activity is captured in overlapping log
    exports; identical (rule, time, host, user, summary) findings collapse.
    """
    active = list(rules) if rules is not None else [cls() for cls in ALL_RULES]
    findings: list[Finding] = []
    seen: set[tuple] = set()
    for rule in active:
        for finding in rule.evaluate(ctx):
            key = (finding.rule_id, finding.timestamp, finding.host, finding.user, finding.summary)
            if key in seen:
                continue
            seen.add(key)
            findings.append(finding)
    findings.sort(key=lambda f: (-SEVERITY_RANK.get(f.severity, 0), f.timestamp))
    return findings


def hunt(events: Iterable[NormalizedEvent]) -> tuple[HuntContext, list[Finding]]:
    """Convenience wrapper: build context and run every registered rule."""
    ctx = HuntContext.build(events)
    return ctx, run_rules(ctx)
