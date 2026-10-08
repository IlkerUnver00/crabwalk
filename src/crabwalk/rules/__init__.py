"""Detection rules registry."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import timedelta

from ..hosts import account_key, clean_ip, short_host
from ..models import NormalizedEvent
from .antiforensics import EventLogCleared
from .base import SEVERITY_RANK, Finding, HuntContext, Rule, evidence_key
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
    A finding that another rule's finding already tells in full is merged
    into it (see :func:`merge_overlaps`).
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
    findings = merge_overlaps(findings)
    findings.sort(key=lambda f: (-SEVERITY_RANK.get(f.severity, 0), f.timestamp))
    return findings


#: A merged finding is told at its absorber's time; never further apart than this.
MERGE_WINDOW = timedelta(minutes=10)


def merge_overlaps(findings: list[Finding]) -> list[Finding]:
    """Fold a finding into another rule's finding that already tells it.

    B tells A when every record A cites is cited by B, B claims at least A's
    techniques, B is at least as severe, and B is a different rule that adds
    something (more records, techniques or severity). Example: the ADMIN$
    drop CW-005 reports is the same record CW-012 credits to a PsExec run, and
    CW-012 already maps it to T1570. A goes into B.merged, so it is shown
    under B (summary kept) instead of as a second finding about one event.

    B must also say the same who and where: same host, A's account and
    source either unknown or the same as B's, and A no more than MERGE_WINDOW
    from B. Two rules that disagree about who did it, or from where, are two
    findings; a merge never removes an actor, a source or a time from the
    output. Findings without evidence are never merged. Each finding's
    ``merged`` list is rebuilt, so the result does not depend on earlier calls
    or on input order.
    """
    for f in findings:
        f.merged = []
    cited = [frozenset(evidence_key(e) for e in f.evidence) for f in findings]
    citing: dict[tuple, list[int]] = {}
    for j, records in enumerate(cited):
        for record in records:
            citing.setdefault(record, []).append(j)

    def tells(i: int, j: int) -> bool:
        """Does finding j tell finding i?"""
        a, b = findings[i], findings[j]
        if a.rule_id == b.rule_id or not cited[i] <= cited[j]:
            return False
        rank_a, rank_b = SEVERITY_RANK.get(a.severity, 0), SEVERITY_RANK.get(b.severity, 0)
        if rank_b < rank_a or not set(a.techniques) <= set(b.techniques):
            return False
        if not _same_who_and_where(a, b):
            return False
        return (cited[i] < cited[j] or set(a.techniques) < set(b.techniques) or rank_a < rank_b)

    def strength(k: int) -> tuple:  # content only: the outcome never depends on input order
        f = findings[k]
        return (SEVERITY_RANK.get(f.severity, 0), len(cited[k]), f.rule_id,
                -f.timestamp.timestamp(), f.host, f.summary)

    absorbers: dict[int, list[int]] = {}
    for i, records in enumerate(cited):
        if not records:
            continue
        anchor = next(iter(records))  # every absorber cites all of i's records, this one too
        found = [j for j in citing[anchor] if j != i and tells(i, j)]
        if found:
            absorbers[i] = found
    parent = {i: max(js, key=strength) for i, js in absorbers.items()}

    def root(i: int) -> int:
        # every step adds records, techniques or severity, so this ends
        while i in parent:
            i = parent[i]
        return i

    for i in parent:  # never dropped: a merged finding lands under its root
        findings[root(i)].merged.append(findings[i])
    top = [i for i in range(len(findings)) if i not in parent]
    for i in top:
        findings[i].merged.sort(key=lambda m: (m.timestamp, m.rule_id, m.summary))
    return [findings[i] for i in top]


def _same_who_and_where(a: Finding, b: Finding) -> bool:
    """May ``b`` speak for ``a`` without losing an actor, a source or a time?"""
    if short_host(a.host) != short_host(b.host) or abs(a.timestamp - b.timestamp) > MERGE_WINDOW:
        return False
    if a.user not in ("", "-") and account_key(a.user) != account_key(b.user):
        return False  # domain-aware: a local SRV01\x is not the domain's CORP\x
    if a.src_ip and clean_ip(a.src_ip) != clean_ip(b.src_ip):
        return False
    if a.src_host and short_host(a.src_host) != short_host(b.src_host):
        return False
    return True


def hunt(events: Iterable[NormalizedEvent]) -> tuple[HuntContext, list[Finding]]:
    """Convenience wrapper: build context and run every registered rule."""
    ctx = HuntContext.build(events)
    return ctx, run_rules(ctx)
