"""Anti-forensics rules: log clearing."""

from __future__ import annotations

from collections.abc import Iterator

from ..catalog import SECURITY, SYSTEM
from ..sessions import display_user
from .base import Finding, HuntContext, Rule


class EventLogCleared(Rule):
    id = "CW-009"
    title = "Event log cleared"
    severity = "high"
    techniques = ("T1070.001",)

    def evaluate(self, ctx: HuntContext) -> Iterator[Finding]:
        for event in ctx.events_for(SECURITY, 1102):
            user = display_user(event.get("SubjectDomainName"), event.get("SubjectUserName"))
            yield self.finding(
                timestamp=event.timestamp,
                host=event.computer,
                user=user,
                summary="Security audit log cleared (1102)",
                evidence=[event],
            )
        for event in ctx.events_for(SYSTEM, 104):
            channel = event.get("Channel") or event.get("BackupPath") or "?"
            user = display_user(event.get("SubjectDomainName"), event.get("SubjectUserName"))
            yield self.finding(
                timestamp=event.timestamp,
                host=event.computer,
                user=user,
                summary=f"Event log '{channel}' cleared (104)",
                evidence=[event],
            )
