"""Anti-forensics rules: log clearing."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta

from ..catalog import SECURITY, SYSTEM
from ..hosts import account_key
from ..models import NormalizedEvent
from ..sessions import display_user
from .base import Finding, HuntContext, Rule

CHANNELS_NAMED = 3  # a mass clear lists this many channels, then counts the rest


class EventLogCleared(Rule):
    """Security 1102 and System 104. A tool that clears every log (``wevtutil
    cl`` in a loop) leaves one record per channel: clears on one host by one
    account, each within ``burst_gap`` of the previous, are one finding."""

    id = "CW-009"
    title = "Event log cleared"
    severity = "high"
    techniques = ("T1070.001",)
    burst_gap = timedelta(seconds=60)
    tunables = ("burst_gap",)

    def evaluate(self, ctx: HuntContext) -> Iterator[Finding]:
        clears = sorted(ctx.events_for(SECURITY, 1102) + ctx.events_for(SYSTEM, 104),
                        key=lambda e: (e.timestamp, e.record_id))
        bursts: list[list[NormalizedEvent]] = []
        open_bursts: dict[tuple[str, tuple[str, str | None]], list[NormalizedEvent]] = {}
        for event in clears:
            key = (event.computer.lower(), account_key(_user(event)))
            burst = open_bursts.get(key)
            if burst and event.timestamp - burst[-1].timestamp <= self.burst_gap:
                # dedup_events drops exported copies; this is for a copy with no
                # EventRecordID, which falls back to its position in its file
                if not any(e.timestamp == event.timestamp and _channel(e) == _channel(event) for e in burst):
                    burst.append(event)
            else:
                open_bursts[key] = [event]
                bursts.append(open_bursts[key])
        for burst in bursts:
            yield self._finding(burst)

    def _finding(self, burst: list[NormalizedEvent]) -> Finding:
        first = burst[0]
        names = list(dict.fromkeys(_channel(e) for e in burst))
        if len(names) == 1:
            name = names[0]
            summary = ("Security audit log cleared (1102)" if first.event_id == 1102
                       else f"Event log '{name}' cleared (104)")
            action = "cleared the Security log" if name == "Security" else f"cleared the '{name}' log"
        else:
            shown = ", ".join(names[:CHANNELS_NAMED])
            rest = f" and {len(names) - CHANNELS_NAMED} more" if len(names) > CHANNELS_NAMED else ""
            summary = f"{len(names)} event logs cleared within {_span(burst)}: {shown}{rest}"
            action = f"cleared {len(names)} event logs ({shown}{rest})"
        return self.finding(
            timestamp=first.timestamp,
            host=first.computer,
            user=_user(first),
            summary=summary,
            action=action,
            evidence=burst,
        )


def _user(event: NormalizedEvent) -> str:
    return display_user(event.get("SubjectDomainName"), event.get("SubjectUserName"))


def _channel(event: NormalizedEvent) -> str:
    if event.event_id == 1102:
        return "Security"
    return str(event.get("Channel") or event.get("BackupPath") or "?")


def _span(burst: list[NormalizedEvent]) -> str:
    seconds = int((burst[-1].timestamp - burst[0].timestamp).total_seconds())
    return "a second" if seconds < 1 else f"{seconds} s" if seconds < 120 else f"{seconds // 60} min"
