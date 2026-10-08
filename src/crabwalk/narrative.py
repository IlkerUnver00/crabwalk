"""Attack narrative: the attack graph and the findings, told as a dated story.

A rule engine hands an analyst a list of events. What an incident ticket has
to say is a story: where it started, how it moved, what it did on each host,
in what order. This module writes that story from the attack graph
(graph.py) and the rules' findings, deterministically: every line is one
movement step on a graph edge or one burst of a rule on a host, so it traces
back to findings and their records.

It says what the records show and no more. A source is named the way the
step's own records name it (a name learned elsewhere is said to be), a line
that spans time shows the span, a record is never counted twice, long gaps
are flagged before the steps, and hosts are said to be joined by name and
address, not by case.
"""

from __future__ import annotations

import html
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from .graph import AttackGraph, GraphEdge, GraphNode, Movement, build_graph
from .hosts import (
    ANONYMOUS_SID,
    account_key,
    classify_ip,
    clean_ip,
    is_anonymous,
    is_local_address,
    short_host,
)
from .models import NormalizedEvent
from .rules.base import SEVERITY_RANK, Finding, HuntContext
from .sessions import display_user
from .style import SEVERITY_COLOR, SEVERITY_TEXT

VISIT_GAP = timedelta(minutes=10)  # one edge's movements this soon after a step's first are that step
SAME_MOMENT = timedelta(seconds=60)  # one rule's findings on a host this soon after the first share a line
NOTE_GAP = timedelta(days=1)  # a line this long after the previous one says so
CAVEAT_GAP = timedelta(days=7)  # a path with a gap this long gets a caution before its steps
PHRASES_PER_RULE = 2  # different phrases of one rule in a line before "and N more like them"
MIN_YEAR = 2000  # earlier record times are FILETIME-null placeholders (1601)
OTHER_HOSTS_SHOWN = 10  # console: hosts listed under "findings on hosts not on a path"
PER_HOST_SHOWN = 3  # console and HTML: lines per such host

#: (one, several) for a logon kind; "{n}" is the count.
LOGON_WORDS = {
    "network": ("a network logon", "{n} network logons"),
    "network-cleartext": ("a cleartext network logon", "{n} cleartext network logons"),
    "rdp": ("an RDP logon", "{n} RDP logons"),
    "rdp-session": ("an RDP session", "{n} RDP sessions"),
    "rdp-reconnect": ("an RDP reconnect", "{n} RDP reconnects"),
    # 4648 is logged on the source when it uses typed-in credentials against
    # the target (runas /netonly, net use /user, WMIC /user, PsExec -u, ...)
    "explicit-credentials": ("used explicit credentials (4648)", "used explicit credentials (4648) {n} times"),
    "interactive": ("an interactive logon", "{n} interactive logons"),
    "batch": ("a batch logon", "{n} batch logons"),
    "service": ("a service logon", "{n} service logons"),
    "unlock": ("an unlock", "{n} unlocks"),
    "new-credentials": ("a new-credentials logon", "{n} new-credentials logons"),
    "cached-interactive": ("a cached interactive logon", "{n} cached interactive logons"),
    "null-session": ("an anonymous null session", "{n} anonymous null sessions"),
}


@dataclass
class Beat:
    """One dated line: a step from one host to another, or a burst of
    findings on a host. ``text`` is what happened, without time, host or users."""

    when: datetime
    host: str
    text: str
    source: str | None = None  # where a step came from, as its own records name it
    users: tuple[str, ...] = ()
    severity: str | None = None  # worst finding behind the line; None for logons only
    rules: tuple[str, ...] = ()
    techniques: tuple[str, ...] = ()
    until: datetime | None = None  # last record of the line, when it spans time
    after: timedelta | None = None  # time since the previous line, when long
    unsourced: bool = False  # remote activity whose source the records do not name

    def to_dict(self) -> dict[str, Any]:
        return {
            "time": self.when.isoformat(),
            "until": self.until.isoformat() if self.until else None,
            "source": self.source,
            "host": self.host,
            "users": list(self.users),
            "text": self.text,
            "severity": self.severity,
            "rules": list(self.rules),
            "techniques": list(self.techniques),
            "after_seconds": int(self.after.total_seconds()) if self.after else None,
            "source_unknown": self.unsourced,
        }


@dataclass
class Chapter:
    """One attack path: a connected group of hosts in the attack graph."""

    chain: list[str]  # the longest time-ordered chain of hosts, origin first
    also: list[str]  # the path's other hosts
    lead: str  # hosts, dates, origin, worst severity
    beats: list[Beat]
    notes: list[str] = field(default_factory=list)

    @property
    def hosts(self) -> int:
        return len(self.chain) + len(self.also)

    def title(self, arrow: str = "→") -> str:
        head = f" {arrow} ".join(self.chain)
        if not self.also:
            return head
        if len(self.also) <= 3:
            return f"{head} (also: {', '.join(self.also)})"
        return f"{head} (+{len(self.also)} more hosts)"


@dataclass
class HostActivity:
    """Findings on a host that no reconstructed movement reaches."""

    host: str
    severity: str | None
    beats: list[Beat]


@dataclass
class Story:
    headline: str
    chapters: list[Chapter]
    other: list[HostActivity]

    def to_dict(self) -> dict[str, Any]:
        return {
            "headline": self.headline,
            "paths": [
                {"title": c.title(), "chain": c.chain, "also": c.also, "lead": c.lead,
                 "notes": c.notes, "beats": [b.to_dict() for b in c.beats]}
                for c in self.chapters
            ],
            "other": [
                {"host": a.host, "severity": a.severity, "beats": [b.to_dict() for b in a.beats]}
                for a in self.other
            ],
        }

    def to_text(self) -> str:
        """Plain text for the console (ASCII arrows: a redirected Windows
        console may not encode '→'). Other hosts are capped, and say so."""
        lines = [self.headline]
        for i, chapter in enumerate(self.chapters, 1):
            lines += ["", f"Path {i}: {chapter.title('->')}", f"  {chapter.lead}"]
            lines += [f"  CAUTION: {note}" for note in chapter.notes]
            lines += [f"  {_when(b)}  {_line(b, '->')}{_tag(b)}" for b in chapter.beats]
        if self.other:
            lines += ["", "Findings on hosts not on a path (no reconstructed step leads to them):"]
            for activity in self.other[:OTHER_HOSTS_SHOWN]:
                lines += [f"  {_when(b)}  {_line(b, '->')}{_tag(b)}" for b in activity.beats[:PER_HOST_SHOWN]]
                if len(activity.beats) > PER_HOST_SHOWN:
                    lines.append(f"  ... and {len(activity.beats) - PER_HOST_SHOWN} more line(s) "
                                 f"on {activity.host}")
            hidden = len(self.other) - OTHER_HOSTS_SHOWN
            if hidden > 0:
                lines.append(f"  ... and {hidden} more host(s); see the findings list")
        return "\n".join(lines) + "\n"

    def to_markdown(self) -> str:
        """Markdown for a ticket or a case file; nothing is capped."""
        out = ["# What happened", "", _md(self.headline)]
        for i, chapter in enumerate(self.chapters, 1):
            out += ["", f"## Path {i}: {_md(chapter.title())}", "", f"*{_md(chapter.lead)}*", ""]
            out += [f"> **Caution:** {_md(note)}\n" for note in chapter.notes]
            out += [f"- **{_when(b)}** {_md(_line(b))}{_md_tag(b)}" for b in chapter.beats]
        if self.other:
            out += ["", "## Findings on hosts not on a path", "",
                    "*No reconstructed step leads to these hosts; each line says what its records "
                    "show about where the activity came from.*", ""]
            for activity in self.other:
                out += [f"- **{_when(b)}** {_md(_line(b))}{_md_tag(b)}" for b in activity.beats]
        return "\n".join(out) + "\n"

    def to_html(self, intro: str = "", footer: str = "") -> str:
        """A report card ("What happened"); every value is escaped. ``intro``
        and ``footer`` are trusted HTML placed at the top and bottom of it."""
        parts = ['<section class="card story">', "<h2>What happened</h2>", intro,
                 f'<p class="story-head">{_esc(self.headline)}</p>']
        for i, chapter in enumerate(self.chapters, 1):
            parts.append(f"<h3>Path {i}: {_esc(chapter.title())}</h3>")
            parts.append(f'<p class="muted story-lead">{_esc(chapter.lead)}</p>')
            parts += [f'<p class="story-note"><b>Caution:</b> {_esc(n)}</p>' for n in chapter.notes]
            parts.append(_html_beats(chapter.beats))
        if self.other:
            parts.append("<h3>Findings on hosts not on a path</h3>")
            parts.append('<p class="muted story-lead">No reconstructed step leads to these hosts; each '
                         "line says what its records show about where the activity came from.</p>")
            for activity in self.other:
                shown = activity.beats[:PER_HOST_SHOWN]
                parts.append(_html_beats(shown))
                if len(activity.beats) > len(shown):
                    parts.append(f'<p class="muted story-more">… and {len(activity.beats) - len(shown)} '
                                 f"more line(s) on {_esc(activity.host)} (see Findings)</p>")
        parts += [footer, "</section>"]
        return "\n".join(p for p in parts if p)


def build_story(
    ctx: HuntContext, findings: Iterable[Finding], graph: AttackGraph | None = None
) -> Story:
    findings = list(findings)
    graph = graph or build_graph(ctx, findings)
    nodes = graph.nodes
    accounts = _Accounts(ctx.events)
    for edge in graph.edges:
        accounts.observe(m.user for m in edge.movements)
    accounts.observe(f.user for f in findings)
    on_edges = {id(m.finding) for e in graph.edges for m in e.movements if m.finding is not None}

    chapters: list[Chapter] = []
    for members in _components(graph):
        keys = {n.key for n in members}
        beats = [b for e in graph.edges if e.src in keys for b in _edge_beats(e, nodes, accounts)]
        for n in members:
            beats += _host_beats(n.label, [f for f in n.hits
                                           if id(f) not in on_edges and _dated(f.timestamp)], accounts)
        if not beats:  # every record of this path lacks a usable time
            continue
        beats.sort(key=lambda b: (b.when, b.host, b.text))
        _mark_gaps(beats)
        chapters.append(_chapter(graph, members, beats))

    other: list[HostActivity] = []
    for n in graph.isolated:
        dated = [f for f in n.hits if _dated(f.timestamp)]
        if dated:
            other.append(HostActivity(n.label, _worst(dated), _host_beats(n.label, dated, accounts)))
    # A finding whose host resolves to no graph node (an address placeholder)
    # still belongs in the story: nothing is dropped silently.
    placed = on_edges | {id(f) for n in nodes.values() for f in n.hits}
    stray: dict[str, list[Finding]] = {}
    for f in findings:
        if id(f) not in placed and _dated(f.timestamp):
            stray.setdefault(f.host or "?", []).append(f)
    for host, items in stray.items():
        other.append(HostActivity(host, _worst(items), _host_beats(host, items, accounts)))
    for activity in other:
        _mark_gaps(activity.beats)
    other.sort(key=lambda a: (-SEVERITY_RANK.get(a.severity or "", -1), a.beats[0].when, a.host))
    undated = (sum(not _dated(f.timestamp) for f in findings),
               sum(not _dated(m.timestamp) for e in graph.edges for m in e.movements if m.finding is None))
    return Story(_headline(findings, chapters, other, undated), chapters, other)


# --------------------------------------------------------------------------
# accounts
# --------------------------------------------------------------------------


class _Accounts:
    """One account, one name, across the whole story.

    Logs spell an account several ways (CORP\\x, CORP.LOCAL\\x, x@corp.local,
    and on some channels only its SID). Records that pair a domain account's
    SID with a name (4624 Target*, Subject* on most Security events) tie those
    spellings together, also for records without a SID (a 4648's target).
    Local accounts (domain = the record's own host) are never joined by SID:
    hosts cloned from one image share local SIDs, and IEWIN7\\IEUser is not
    PC01\\IEUser. Otherwise spellings that agree on the name and the domain's
    first label are one account. Each account is shown in its most common
    spelling, and a SID by its name when the records give one.
    """

    def __init__(self, events: Iterable[NormalizedEvent]) -> None:
        self._sid_of: dict[str, str] = {}
        by_name: dict[tuple, set[str]] = {}
        for event in events:
            host = short_host(event.computer)
            for prefix in ("Target", "Subject"):
                sid = str(event.get(f"{prefix}UserSid") or "").strip().upper()
                name = str(event.get(f"{prefix}UserName") or "").strip()
                domain = str(event.get(f"{prefix}DomainName") or "").strip()
                if not sid.startswith("S-1-") or not name or name == "-":
                    continue
                if domain and domain.split(".", 1)[0].lower() == host:
                    continue  # a local account
                form = display_user(domain, name)
                self._sid_of.setdefault(form.lower(), sid)
                by_name.setdefault(_name_key(form), set()).add(sid)
        # a spelling seen without a SID joins the SID its name and domain had
        # elsewhere, unless that name stood for more than one SID
        self._sid_by_name = {k: next(iter(s)) for k, s in by_name.items() if len(s) == 1}
        self._forms: dict[tuple, Counter[str]] = {}

    def key(self, user: str) -> tuple:
        text = str(user or "").strip()
        if text.upper().startswith("S-1-"):
            return ("sid", text.upper())
        sid = self._sid_of.get(text.lower()) or self._sid_by_name.get(_name_key(text))
        return ("sid", sid) if sid else ("name", *_name_key(text))

    def observe(self, users: Iterable[str]) -> None:
        for user in users:
            if user and user != "-":
                forms = self._forms.setdefault(self.key(user), Counter())
                forms[user] += 1

    def display(self, user: str) -> str:
        forms = self._forms.get(self.key(user))
        if not forms:
            return user
        named = [(n, form) for form, n in forms.items() if not form.upper().startswith("S-1-")]
        return max(named)[1] if named else forms.most_common(1)[0][0]

    def is_null_session(self, user: str) -> bool:  # noqa: D102 - see is_anonymous
        return is_anonymous(user) or self.key(user) == ("sid", ANONYMOUS_SID)

    def actors(self, users: Iterable[str]) -> tuple[str, ...]:
        """Accounts in first-seen order, one entry each; null sessions and
        placeholders are left out: they are not actors."""
        out: dict[tuple, str] = {}
        for user in users:
            if user and user != "-" and not self.is_null_session(user):
                out.setdefault(self.key(user), self.display(user))
        return tuple(out.values())


_name_key = account_key


# --------------------------------------------------------------------------
# beats
# --------------------------------------------------------------------------


def _components(graph: AttackGraph) -> list[list[GraphNode]]:
    groups: dict[int, list[GraphNode]] = {}
    for node in graph.connected:
        groups.setdefault(node.component, []).append(node)
    return [groups[k] for k in sorted(groups)]


def _edge_beats(edge: GraphEdge, nodes: dict[str, GraphNode], accounts: _Accounts) -> list[Beat]:
    """One line per step: an edge's movements within VISIT_GAP of the first."""
    host = nodes[edge.dst].label
    visits: list[list[Movement]] = []
    for m in sorted(edge.movements, key=lambda m: (m.timestamp, m.kind)):
        if not _dated(m.timestamp):
            continue
        if visits and m.timestamp - visits[-1][0].timestamp <= VISIT_GAP:
            visits[-1].append(m)
        else:
            visits.append([m])
    # A logon a finding on this edge already tells (the 4624s of a pass-the-hash
    # burst, which can run past one visit) is not counted again in any visit.
    cited = frozenset().union(*(m.records for m in edge.movements if m.finding is not None))
    beats = []
    for visit in visits:
        found = [m.finding for m in visit if m.finding is not None]
        logons = [m for m in visit if m.finding is None and not (m.records and m.records <= cited)]
        segments = _logon_segments(logons, accounts) + _action_segments(found)
        if not segments:  # only logons a finding in an earlier visit tells
            continue
        segments.sort(key=lambda s: s[0])
        times = [m.timestamp for m in visit] + [e.timestamp for f in found for e in f.evidence]
        beats.append(Beat(
            when=visit[0].timestamp, host=host, source=_source_label(nodes[edge.src], visit),
            text=", then ".join(text for _, text in segments),
            users=accounts.actors(m.user for m in visit), until=_until(visit[0].timestamp, times),
            **_rating(found),
        ))
    return beats


def _host_beats(host: str, findings: list[Finding], accounts: _Accounts) -> list[Beat]:
    """One line per burst: a rule's findings on a host within SAME_MOMENT of
    the burst's first. A repeat later on is its own line, at its own time."""
    groups: list[list[Finding]] = []
    for f in sorted(findings, key=lambda f: (f.timestamp, f.rule_id)):
        for group in reversed(groups):
            if group[0].rule_id == f.rule_id and f.timestamp - group[0].timestamp <= SAME_MOMENT:
                group.append(f)
                break
        else:
            groups.append([f])
    beats = []
    for group in groups:
        times = [f.timestamp for f in group] + [e.timestamp for f in group for e in f.evidence]
        beats.append(Beat(
            when=group[0].timestamp, host=host,
            text=", then ".join(text for _, text in _action_segments(group)),
            users=accounts.actors(f.user for f in group), until=_until(group[0].timestamp, times),
            unsourced=any(_unsourced(f) for f in group),
            **_rating(group),
        ))
    return beats


def _logon_segments(logons: list[Movement], accounts: _Accounts) -> list[tuple[datetime, str]]:
    kinds: dict[str, list[Movement]] = {}
    for m in logons:
        kind = "null-session" if accounts.is_null_session(m.user) else m.kind
        kinds.setdefault(kind, []).append(m)
    segments = []
    for kind, items in kinds.items():
        one, several = LOGON_WORDS.get(kind, (f"a {kind} logon", f"{{n}} {kind} logons"))
        n, admin = len(items), sum(m.privileged for m in items)
        text = one if n == 1 else several.format(n=n)
        if admin:
            text += " with admin rights" if admin == n else f" ({admin} with admin rights)"
        segments.append((items[0].timestamp, text))
    return segments


def _action_segments(found: list[Finding]) -> list[tuple[datetime, str]]:
    """One segment per rule: its phrases with repeats counted in words, and
    more than PHRASES_PER_RULE + 1 different ones shortened to the first few
    and a count. One rule's burst never hides another rule's action."""
    by_rule: dict[str, list[Finding]] = {}
    for f in sorted(found, key=lambda f: (f.timestamp, f.rule_id)):
        by_rule.setdefault(f.rule_id, []).append(f)
    segments = []
    for items in by_rule.values():
        counts: Counter[str] = Counter()
        for f in items:
            counts[_phrase(f)] += f.count
        distinct = list(dict.fromkeys(_phrase(f) for f in items))
        if len(distinct) > PHRASES_PER_RULE + 1:
            shown = [_times(p, counts[p]) for p in distinct[:PHRASES_PER_RULE]]
            text = f"{', '.join(shown)} and {len(distinct) - PHRASES_PER_RULE} more like them"
        else:
            text = _and([_times(p, counts[p]) for p in distinct])
        segments.append((items[0].timestamp, text))
    return segments


def _unsourced(finding: Finding) -> bool:
    """Remote activity (a Remote Services technique) whose records name no
    source: not a client on this host (a 5145 from ::1 is local), just one
    the logs do not identify."""
    if finding.src_ip or finding.src_host or not any(t.startswith("T1021") for t in finding.techniques):
        return False
    addresses = [clean_ip(e.get("IpAddress")) for e in finding.evidence if e.get("IpAddress")]
    return not any(ip and is_local_address(ip) for ip in addresses)


def _phrase(finding: Finding) -> str:
    return finding.action or finding.title[:1].lower() + finding.title[1:]


def _times(phrase: str, n: int) -> str:
    """'x twice', 'x 3 times'; a trailing '(aside)' stays last."""
    if n == 1:
        return phrase
    count = "twice" if n == 2 else f"{n} times"
    if phrase.endswith(")") and " (" in phrase:
        head, aside = phrase.rsplit(" (", 1)
        return f"{head} {count} ({aside}"
    return f"{phrase} {count}"


def _rating(found: list[Finding]) -> dict[str, Any]:
    if not found:
        return {}
    return {
        "severity": _worst(found),
        "rules": tuple(sorted({f.rule_id for f in found})),
        "techniques": tuple(sorted({t for f in found for t in f.techniques})),
    }


def _worst(found: list[Finding]) -> str:
    return max((f.severity for f in found), key=lambda s: SEVERITY_RANK.get(s, 0))


def _until(start: datetime, times: list[datetime]) -> datetime | None:
    last = max((t for t in times if _dated(t)), default=start)
    return last if last - start > SAME_MOMENT else None


def _source_label(node: GraphNode, visit: list[Movement]) -> str:
    """The step's source as its own records give it. A host name the step's
    records do not carry (learned from other records) is said to be."""
    ips = sorted({ip for ip in (clean_ip(m.src_ip) for m in visit) if ip})
    named = any(short_host(m.src_host) for m in visit)
    external = node.address_class == "external" or any(classify_ip(ip) == "external" for ip in ips)
    tail = " (external address)" if external else ""
    if node.key.startswith("ip:"):
        return node.label + tail
    shown = ", ".join(ips[:2]) + (f" +{len(ips) - 2}" if len(ips) > 2 else "")
    if named or not ips:
        return f"{node.label} ({shown})" + tail if ips else node.label + tail
    return f"{shown}{tail} (named {node.label} elsewhere in the logs)"


def _mark_gaps(beats: list[Beat]) -> None:
    for prev, beat in zip(beats, beats[1:]):
        if beat.when - prev.when > NOTE_GAP:
            beat.after = beat.when - prev.when


def _dated(when: datetime) -> bool:
    """A FILETIME-null record time (1601) cannot be placed in a story."""
    return when.year >= MIN_YEAR


# --------------------------------------------------------------------------
# chapters and headline
# --------------------------------------------------------------------------


def _chapter(graph: AttackGraph, members: list[GraphNode], beats: list[Beat]) -> Chapter:
    chain = _time_ordered_chain(graph, members)
    in_chain = {n.key for n in chain}
    also = [n.label for n in sorted(members, key=lambda n: (n.first_seen or datetime.max, n.key))
            if n.key not in in_chain]
    first, last = beats[0].when, max(b.until or b.when for b in beats)
    origins = [n.label + (" (external address)" if n.address_class == "external" else "")
               for n in members if n.origin]
    started = (f"started from {_and(origins)}" if origins
               else "no single origin (the hosts reached each other)")
    rated = [b.severity for b in beats if b.severity]
    worst = (f"worst finding: {max(rated, key=lambda s: SEVERITY_RANK.get(s, 0))}" if rated
             else "logons only, no finding")
    lead = f"{len(members)} hosts · {_span_dates(first, last)} · {started} · {worst}"
    notes = []
    gaps = [b.after for b in beats if b.after]
    if any(g > CAVEAT_GAP for g in gaps):
        listed = (f"gaps of {_and([_span(g) for g in gaps])}" if len(gaps) <= 5
                  else f"{len(gaps)} gaps of up to {_span(max(gaps))}")
        notes.append(
            f"this path has {listed}. crabwalk links these hosts only because they share "
            "host names and addresses; it has no case or incident ID, so confirm that the steps "
            "belong to one intrusion before reporting them as one.")
    return Chapter([n.label for n in chain], also, lead, beats, notes)


def _time_ordered_chain(graph: AttackGraph, members: list[GraphNode]) -> list[GraphNode]:
    """The longest chain of hops in which each hop starts no earlier than the
    one before it (the title must not contradict the dated lines below it),
    never visiting a host twice. Ties go to the chain that starts first."""
    keys = {n.key for n in members}
    edges = sorted((e for e in graph.edges if e.src in keys and e.dst in keys),
                   key=lambda e: (e.first, e.src, e.dst))
    chains: list[list[str]] = []
    for i, edge in enumerate(edges):
        best = [edge.src, edge.dst]
        for j in range(i):
            prev = edges[j]
            if prev.dst == edge.src and prev.first <= edge.first and edge.dst not in chains[j]:
                if len(chains[j]) + 1 > len(best):
                    best = chains[j] + [edge.dst]
        chains.append(best)
    longest = max(chains, key=len)  # first of the longest, edges being time-ordered
    return [graph.nodes[k] for k in longest]


def _headline(findings: list[Finding], chapters: list[Chapter], other: list[HostActivity],
              undated: tuple[int, int]) -> str:
    left = []
    if undated[1]:
        left.append(f"{undated[1]} logon{'s' * (undated[1] > 1)}")
    if undated[0]:
        left.append(f"{undated[0]} finding{'s' * (undated[0] > 1)}")
    left_out = (f" {_and(left)} without a usable timestamp {'are' if sum(undated) > 1 else 'is'} "
                "left out of the story; see the findings list." if left else "")
    if not chapters and not other:
        return ("Nothing to tell: no findings and no host-to-host movement." if not findings and not left
                else f"Nothing to tell in order.{left_out}")
    times = [b.when for c in chapters for b in c.beats] + [b.when for a in other for b in a.beats]
    ends = [b.until or b.when for c in chapters for b in c.beats] + [b.until or b.when for a in other
                                                                    for b in a.beats]
    span = _span_dates(min(times), max(ends))
    hosts = sum(c.hosts for c in chapters)
    if chapters:
        head = (f"{len(chapters)} attack path{'s' * (len(chapters) > 1)} across {hosts} hosts"
                + (f", and findings on {len(other)} more host{'s' * (len(other) > 1)}" if other else ""))
    else:
        head = (f"No host-to-host movement was reconstructed; findings on {len(other)} "
                f"host{'s' * (len(other) > 1)}")
    counts = Counter(f.severity for f in findings)
    rated = ", ".join(f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low") if counts[s])
    tail = f" {len(findings)} finding{'s' * (len(findings) != 1)}" + (f": {rated}." if rated else ".")
    return f"{head}, {span}.{tail}{left_out}"


# --------------------------------------------------------------------------
# rendering helpers
# --------------------------------------------------------------------------


def _when(b: Beat) -> str:
    start = f"{b.when:%Y-%m-%d %H:%M:%S}Z"
    if not b.until:
        return start
    end = f"{b.until:%H:%M:%S}Z" if b.until.date() == b.when.date() else f"{b.until:%Y-%m-%d %H:%M:%S}Z"
    return f"{start}–{end}"


def _line(b: Beat, arrow: str = "→") -> str:
    gap = f"({_span(b.after)} later) " if b.after else ""
    who = f" as {_and(list(b.users))}" if b.users else ""
    where = f"{b.source} {arrow} {b.host}" if b.source else f"on {b.host}"
    unnamed = ", from a host the logs do not name" if b.unsourced and not b.source else ""
    return f"{gap}{where}{who}{unnamed}: {b.text}"


def _tag(b: Beat) -> str:
    return f"  [{b.severity} {', '.join(b.rules)}]" if b.severity else ""


def _md_tag(b: Beat) -> str:
    if not b.severity:
        return ""
    return f" *({b.severity} · {', '.join(b.rules)} · {', '.join(b.techniques)})*"


def _html_beats(beats: list[Beat]) -> str:
    items = []
    for b in beats:
        if b.severity:
            badge = (f'<span class="badge" style="background:{SEVERITY_COLOR.get(b.severity, "#888")};'
                     f'color:{SEVERITY_TEXT.get(b.severity, "#fff")}">{_esc(b.severity.upper())}</span>')
        else:
            badge = '<span class="b-logon">logon</span>'
        chips = "".join(
            f'<a class="chip" href="https://attack.mitre.org/techniques/{t.replace(".", "/")}/">{_esc(t)}</a>'
            for t in b.techniques)
        rules = f' <span class="rule">{_esc(", ".join(b.rules))}</span>' if b.rules else ""
        until = (f'<br><span class="b-until">–{_esc(_when(b).split("–", 1)[1])}</span>'
                 if b.until else "")  # the end on its own line: the column is narrow
        items.append(
            f'<li><span class="b-time mono">{b.when:%Y-%m-%d %H:%M:%S}Z{until}</span>{badge}'
            f'<span class="b-text">{_esc(_line(b))}{rules}{chips}</span></li>')
    return f'<ol class="beats">{"".join(items)}</ol>'


def _span(delta: timedelta) -> str:
    days = delta.days
    if days >= 2:
        return f"{days} days"
    hours = int(delta.total_seconds() // 3600)
    return f"{hours} hours" if hours >= 2 else f"{int(delta.total_seconds() // 60)} minutes"


def _span_dates(first: datetime, last: datetime) -> str:
    return f"{first:%Y-%m-%d}" + (f" to {last:%Y-%m-%d}" if last.date() != first.date() else "")


def _and(items: list[str]) -> str:
    if len(items) <= 2:
        return " and ".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


def _esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


_MD_SPECIAL = str.maketrans({c: "\\" + c for c in "\\`*_[]<>|#&~"})


def _md(text: str) -> str:
    return text.translate(_MD_SPECIAL)
