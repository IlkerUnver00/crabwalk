"""RDP session hijacking (CW-016).

``tscon <id> /dest:<session>`` attaches session <id> to another session.
Windows asks for the target session owner's password (``/password``) unless
the caller runs as SYSTEM, so whoever holds SYSTEM on a Remote Desktop host
can take over any other user's session, logged on as them. The usual way to
get SYSTEM is a service whose binary runs tscon. Windows then logs the
victim's session being reconnected (Security 4778, TerminalServices-LSM 25)
with the client name and address of the connection it was handed to.

Hijacks that do not run tscon.exe (Mimikatz ``ts::remote``, tools calling
WTSConnectSession directly) leave only the reconnect, which an ordinary
reconnect also leaves: they are not reported.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from ..catalog import SECURITY, SYSMON, TS_LSM
from ..hosts import account_key, remote_ip, remote_name
from ..models import NormalizedEvent
from ..sessions import display_user, norm_logon_id
from .base import Finding, HuntContext, Rule, ServiceInstall, basename, clip
from .execution import _logon_id, _process_pairs

# tscon as the program a command runs: "tscon 2", "C:\...\tscon.exe" 2, not C:\tscon\x.exe
TSCON = re.compile(r"(?:^|[\\/\s\"'])tscon(?:\.exe)?(?=[\"'\s]|$)", re.IGNORECASE)
TARGET = re.compile(r"\btscon(?:\.exe)?[\"']?\s+(?P<id>\d+)", re.IGNORECASE)
DEST = re.compile(r"[/-]dest[:\s]\s*[\"']?(?P<dest>[^\s\"'&|<>]+)", re.IGNORECASE)
PASSWORD = re.compile(r"[/-]password\b", re.IGNORECASE)
SYSTEM_LOGON = "0x3e7"
SYSTEM_ACCOUNTS = {"localsystem", "nt authority\\system", "system", ".\\localsystem"}
_SAME_RUN = timedelta(seconds=5)  # one run seen by both Sysmon 1 and 4688
_LINK = timedelta(days=1)  # a tscon service may be started well after it was created


@dataclass
class _Run:
    """One tscon execution, from one or both process logs."""

    host: str
    when: datetime
    command: str
    system: bool
    runner: str  # account the process ran as ("-" when SYSTEM or unknown)
    events: list[NormalizedEvent] = field(default_factory=list)


def _tscon_arguments(command: str) -> tuple[str | None, str | None]:
    """(session ID, lower-case destination) of a tscon command line."""
    target, dest = TARGET.search(command), DEST.search(command)
    return (target.group("id") if target else None, dest.group("dest").lower() if dest else None)


class RdpSessionHijack(Rule):
    id = "CW-016"
    title = "RDP session hijacking"
    severity = "high"
    techniques = ("T1563.002",)
    window = timedelta(minutes=2)  # tscon -> the reconnect it causes
    tunables = ("window",)

    def evaluate(self, ctx: HuntContext) -> Iterator[Finding]:
        installs = [i for i in ctx.service_installs if TSCON.search(i.image)]
        # Without SYSTEM or the owner's password tscon can only move the caller's
        # own session: a user switching between their sessions is not reported.
        runs = [r for r in self._runs(ctx) if r.system or PASSWORD.search(r.command)]
        linked = [self._install_for(installs, run) for run in runs]
        # a service built to run tscon, where process creation was not logged
        alone = [i for i in installs if all(i is not link for link in linked)]
        claims = [(run.host, run.when, run.command) for run in runs]
        claims += [(i.computer, i.timestamp, i.image) for i in alone]
        reconnects = self._assign(ctx, claims)
        found = []
        for run, install, reconnect in zip(runs, linked, reconnects):
            found.append(self._finding(ctx, run.host, run.when, run.command, run.system, run.runner,
                                       install, run.events, reconnect))
        for install, reconnect in zip(alone, reconnects[len(runs):]):
            account = str(install.event.get("ServiceAccount") or install.event.get("AccountName") or "LocalSystem")
            found.append(self._finding(ctx, install.computer, install.timestamp, install.image,
                                       account.strip().lower() in SYSTEM_ACCOUNTS, "-", install, [], reconnect))
        yield from sorted(found, key=lambda f: f.timestamp)

    def _runs(self, ctx: HuntContext) -> list[_Run]:
        runs: list[_Run] = []
        for event, _parent, child, user in _process_pairs(ctx):
            original = basename(event.get("OriginalFileName")) if event.channel == SYSMON else ""
            if child != "tscon.exe" and original != "tscon.exe":
                continue
            command = str(event.get("CommandLine") or child)
            system = norm_logon_id(_logon_id(event)) == SYSTEM_LOGON
            same = [r for r in runs if r.host == event.computer and abs(r.when - event.timestamp) <= _SAME_RUN
                    and _tscon_arguments(r.command) == _tscon_arguments(command)
                    and all(e.channel != event.channel for e in r.events)]
            if same:
                same[0].events.append(event)
                same[0].system = same[0].system or system
                continue
            runs.append(_Run(event.computer, event.timestamp, command, system,
                             "-" if system else user, [event]))
        return runs

    @staticmethod
    def _install_for(installs: list[ServiceInstall], run: _Run) -> ServiceInstall | None:
        """The tscon service that started this run: same host, created before
        it (a service may be started long after it was created), asking tscon
        for the same session and destination."""
        wanted = _tscon_arguments(run.command)
        candidates = [i for i in installs if i.computer == run.host
                      and run.when - _LINK <= i.timestamp <= run.when
                      and _tscon_arguments(i.image) == wanted]
        return candidates[-1] if candidates else None

    def _candidates(self, ctx: HuntContext, host: str, when: datetime,
                    command: str) -> list[NormalizedEvent]:
        """Reconnects tscon may have caused, on this host within ``window``
        after it: a 4778 for the destination session name, or a TS-LSM 25 for
        the hijacked session ID. Without either to match on, only a lone
        reconnect counts."""
        session_id, dest = _tscon_arguments(command)
        lo, hi = when, when + self.window

        def near(events: list[NormalizedEvent]) -> list[NormalizedEvent]:
            return [e for e in events if e.computer == host and lo <= e.timestamp <= hi]

        security, lsm = near(ctx.events_for(SECURITY, 4778)), near(ctx.events_for(TS_LSM, 25))
        chosen = [e for e in security if str(e.get("SessionName") or "").lower() == dest] if dest else []
        if not chosen and session_id:
            chosen = [e for e in lsm if str(e.get("SessionID") or "") == session_id]
        if not chosen and not dest and not session_id and len(security) + len(lsm) == 1:
            chosen = security + lsm
        return chosen

    def _assign(self, ctx: HuntContext,
                claims: list[tuple[str, datetime, str]]) -> list[NormalizedEvent | None]:
        """Credit each reconnect to one claim (a tscon run or service): the
        latest one before it that it matches, so an earlier attempt that failed
        does not take the reconnect of the run that worked."""
        options = [self._candidates(ctx, host, when, command) for host, when, command in claims]
        result: list[NormalizedEvent | None] = [None] * len(claims)
        pending = {id(e): e for found in options for e in found}
        for reconnect in sorted(pending.values(), key=lambda e: (e.timestamp, e.record_id)):
            open_claims = [k for k, found in enumerate(options)
                           if result[k] is None and any(e is reconnect for e in found)]
            if open_claims:
                result[max(open_claims, key=lambda k: claims[k][1])] = reconnect
        return result

    def _finding(self, ctx: HuntContext, host: str, when: datetime, command: str, system: bool,
                 runner: str, install: ServiceInstall | None, runs: list[NormalizedEvent],
                 reconnect: NormalizedEvent | None) -> Finding:
        session_id, dest = _tscon_arguments(command)
        actor = runner if runner and runner != "-" else (_installer(ctx, install) or "-")
        victim = client = address = None
        console = False
        if reconnect is not None:
            if reconnect.event_id == 4778:
                victim = display_user(reconnect.get("AccountDomain"), reconnect.get("AccountName"))
                client, address = reconnect.get("ClientName"), reconnect.get("ClientAddress")
                console = str(reconnect.get("SessionName") or "").lower() == "console"
            else:
                victim, address = str(reconnect.get("User") or "") or None, reconnect.get("Address")
        # a console reconnect logs ClientName "Unknown" and ClientAddress "LOCAL"
        client = None if str(client or "").strip().lower() in ("unknown", "") else str(client)
        src_ip, src_host = remote_ip(address), remote_name(client)
        previous = self._previous_owner(ctx, host, reconnect)
        moved = victim is not None and previous is not None and account_key(victim) == account_key(previous)
        own = victim is not None and actor != "-" and account_key(victim) == account_key(actor)

        if victim:
            owner = f"{victim}'s session {session_id}" if session_id else f"{victim}'s session"
        else:
            owner = f"session {session_id}" if session_id else "a session"
        how = "tscon as SYSTEM" if system else "tscon with a password"
        through = f" through service '{install.name}'" if install is not None else ""
        if console:
            landing = "the console"
        elif client or src_ip:
            landing = f"the RDP connection of {client or src_ip}"
        else:
            landing = dest or "another session"
        if reconnect is None:
            seen = "no reconnect logged"
        elif reconnect.event_id == 4778:
            where = "the console" if console else (client or "?") + (f" ({src_ip})" if src_ip else "")
            seen = f"4778 shows it reconnected to {where}"
        else:
            seen = f"TS-LSM 25 shows it reconnected from {address or '?'}"
        verb = "moved" if (moved or own) else "took over"
        summary = f"{how}{through} attached {owner} to {dest or '?'} ('{clip(command, 100)}'); {seen}"
        action = f"{verb} {owner} with {how}{through} and attached it to {landing}"
        if not runs and reconnect is None and install is not None:
            # only the service was logged: say what it was built to do, not that it ran
            runner_as = "tscon as SYSTEM" if system else "tscon"
            summary = (f"service '{install.name}' created to run {runner_as} on {owner} to {dest or '?'} "
                       f"('{clip(command, 100)}'); no run or reconnect logged")
            action = f"created service '{install.name}' to run {runner_as} on {owner}" + (
                f" (to {dest})" if dest else "")
        return self.finding(
            severity="critical" if reconnect is not None and not (moved or own) else self.severity,
            techniques=self.techniques + (("T1543.003",) if install is not None else ()),
            timestamp=when,
            host=host,
            user=actor,
            summary=summary,
            action=action,
            evidence=[e for e in (install.event if install else None, *runs, reconnect) if e is not None],
            src_ip=None if console else src_ip,
            src_host=None if console else src_host,
        )

    def _previous_owner(self, ctx: HuntContext, host: str,
                        reconnect: NormalizedEvent | None) -> str | None:
        """Who held the destination session before: the 4779 that
        disconnected that session name just before the reconnect."""
        if reconnect is None or reconnect.event_id != 4778:
            return None
        name = str(reconnect.get("SessionName") or "").lower()
        before = [e for e in ctx.events_for(SECURITY, 4779) if e.computer == host
                  and reconnect.timestamp - self.window <= e.timestamp <= reconnect.timestamp
                  and str(e.get("SessionName") or "").lower() == name]
        if not before:
            return None
        return display_user(before[-1].get("AccountDomain"), before[-1].get("AccountName"))


def _installer(ctx: HuntContext, install: ServiceInstall | None) -> str | None:
    """The account that created the service: Security 4697 names it; a
    System 7045 does not, so look for the 4697 copy of the same install."""
    if install is None:
        return None
    copies = [install.event] + [e for e in ctx.events_for(SECURITY, 4697)
                                if e.computer == install.computer
                                and str(e.get("ServiceName") or "").lower() == install.name.lower()
                                and abs(e.timestamp - install.timestamp) <= timedelta(seconds=10)]
    for event in copies:
        if event.event_id == 4697 and event.get("SubjectUserName"):
            return display_user(event.get("SubjectDomainName"), event.get("SubjectUserName"))
    return None
