"""Named-pipe remote execution (CW-012).

PsExec and its clones, impacket psexec/smbexec, Metasploit psexec, atexec and
SMB C2 implants all drive the target through named pipes on IPC$. Two logs see
those pipes, so the rule works on Sysmon-only and Security-only exports alike:

* Sysmon 17/18 — ``PipeName`` (``\\PSEXESVC``). An 18 (connect) whose Image is
  ``System`` came in over SMB, i.e. from another machine.
* Security 5145 on ``\\\\*\\IPC$`` — ``RelativeTargetName`` (``svcctl``) plus the
  client ``IpAddress`` and account.

Signatures, strongest first:

tool     default pipes of remote-exec tools (PsExec, RemCom/impacket, PAExec,
         CSExec, Cobalt Strike), and PsExec-style stdio pipes
         ``<service>-<SOURCEHOST>-<pid>-stdin|stdout|stderr``. Those survive
         service renaming (``psexec -r``) and name the machine PsExec ran on —
         a cross-host edge recovered from the target's logs alone.
control  remote access to the service-control (svcctl/ntsvcs) or scheduler
         (atsvc) RPC pipes. Escalated when the same host then shows a service
         install or task, or an executable was just dropped on ADMIN$/C$.
random   a remote connection to a pipe with a long random hex name: the shape
         of named-pipe remote shells and SMB C2.

Activity is clustered per (host, client address), so two clients working the
same host at once stay apart. Sysmon hits carry no address: each borrows the
client of the 5145 record of the same pipe open, and only unmatched ones fall
back to joining the single address cluster they overlap. An install or task is
credited to the cluster with corroborating context (a binary dropped by the
same client, a tool pipe), then to the most recent activity strictly before
it. A client touching many distinct pipes is enumeration, not execution: its
uncorroborated hits are dropped. A tool pipe used by a client process on the
host itself is local execution; a cluster is only called local when none of
its signature pipes was driven from another machine.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from ..catalog import SECURITY, SYSMON
from ..hosts import clean_ip, is_local_address, short_host
from ..models import NormalizedEvent
from ..sessions import display_user
from .base import Finding, HuntContext, Rule, ServiceInstall, basename
from .lateral import KNOWN_REMOTE_EXEC_SERVICES, credible_installs, looks_like_remote_exec

TOOL_PIPES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^psexesvc$", re.I), "PsExec"),
    (re.compile(r"^remcom", re.I), "RemCom / impacket psexec"),
    (re.compile(r"^paexec", re.I), "PAExec"),
    (re.compile(r"^csexecsvc", re.I), "CSExec"),
    (re.compile(r"^msse-\d+-server$", re.I), "Cobalt Strike"),
    (re.compile(r"^(?:msagent|postex|postex_ssh|status)_[0-9a-f]+$", re.I), "Cobalt Strike"),
)
# "<service>-<SOURCEHOST>-<pid>-<stream>"; service and host may contain dashes.
STDIO_PIPE = re.compile(r"^(?P<base>[^-]+-.+)-(?P<pid>\d+)-(?P<stream>stdin|stdout|stderr)$", re.I)
CONTROL_PIPES = {"svcctl": "service-control", "ntsvcs": "service-control", "atsvc": "task-scheduler"}
RANDOM_PIPE = re.compile(r"^[0-9a-f]{16,}$", re.I)
EXECUTABLE = (".exe", ".dll", ".bat", ".ps1", ".cmd", ".scr")

_KIND_RANK = {"tool": 2, "control": 1, "random": 0}


@dataclass(frozen=True)
class PipeWindows:
    """The time windows and thresholds CW-012 correlates with (all tunable)."""

    cluster_gap: timedelta = timedelta(seconds=120)  # hits further apart start a new cluster
    follow_window: timedelta = timedelta(seconds=120)  # install/task after the pipe activity
    drop_window: timedelta = timedelta(seconds=300)  # binary copied to ADMIN$ before it
    skew: timedelta = timedelta(seconds=5)  # tolerance between channels of one host
    enum_window: timedelta = timedelta(seconds=30)  # a sweep's span around a cluster
    enum_distinct_pipes: int = 5  # distinct pipes that make a client's activity a sweep


DEFAULT_WINDOWS = PipeWindows()


@dataclass(slots=True)
class PipeHit:
    timestamp: datetime
    computer: str
    pipe: str  # without leading backslashes, original case
    remote: bool  # arrived over SMB from another machine
    src_ip: str | None  # client address as logged (5145 only)
    user: str
    event: NormalizedEvent
    peer: str | None = None  # remote client this activity belongs to, if known

    @property
    def is_local_connect(self) -> bool:
        """A Sysmon 18 by a process on this host: the client runs here."""
        return self.event.channel == SYSMON and self.event.event_id == 18 and not self.remote


@dataclass
class _Cluster:
    computer: str
    client: str | None  # remote client address, None for address-less hits
    hits: list[PipeHit] = field(default_factory=list)
    kinds: set[str] = field(default_factory=set)  # tool / control / random
    labels: list[str] = field(default_factory=list)  # tool names, in first-seen order
    control: set[str] = field(default_factory=set)  # service-control / task-scheduler
    installs: list[ServiceInstall] = field(default_factory=list)
    tasks: list[NormalizedEvent] = field(default_factory=list)
    drops: list[NormalizedEvent] = field(default_factory=list)

    @property
    def start(self) -> datetime:
        return self.hits[0].timestamp

    @property
    def end(self) -> datetime:
        return self.hits[-1].timestamp

    def add(self, hit: PipeHit, kind: str, label: str) -> None:
        self.hits.append(hit)
        self.kinds.add(kind)
        if kind == "tool" and label not in self.labels:
            self.labels.append(label)
        if kind == "control":
            self.control.add(label)

    def absorb(self, other: _Cluster) -> None:
        self.hits = sorted(self.hits + other.hits, key=lambda h: (h.timestamp, h.pipe))
        self.kinds |= other.kinds
        self.labels += [label for label in other.labels if label not in self.labels]
        self.control |= other.control


def pipe_name(value: object) -> str:
    return str(value or "").strip().lstrip("\\").strip()


def pipe_hits(ctx: HuntContext, w: PipeWindows = DEFAULT_WINDOWS) -> list[PipeHit]:
    """Every named-pipe open/create from Sysmon 17/18 and Security 5145 on IPC$."""
    hits: list[PipeHit] = []
    for event in ctx.events_for(SYSMON, 17, 18):
        name = pipe_name(event.get("PipeName"))
        if not name or name.startswith("<"):  # "<Anonymous Pipe>"
            continue
        remote = event.event_id == 18 and basename(event.get("Image")) == "system"
        hits.append(PipeHit(event.timestamp, event.computer, name, remote, None, "-", event))
    for event in ctx.events_for(SECURITY, 5145):
        if not str(event.get("ShareName") or "").upper().endswith("IPC$"):
            continue
        name = pipe_name(event.get("RelativeTargetName"))
        if not name or name.lower() == "none":
            continue
        ip = clean_ip(event.get("IpAddress"))
        remote = ip is not None and not is_local_address(ip)
        user = display_user(event.get("SubjectDomainName"), event.get("SubjectUserName"))
        hits.append(PipeHit(event.timestamp, event.computer, name, remote, ip, user, event,
                            peer=ip if remote else None))
    hits.sort(key=lambda h: (h.timestamp, h.computer, h.pipe))
    _attribute_sysmon_hits(hits, w)
    return hits


def _attribute_sysmon_hits(hits: list[PipeHit], w: PipeWindows) -> None:
    """Give address-less Sysmon hits the client of the matching 5145 record.

    On a host that logs both, every remote pipe open appears twice: as a
    Sysmon 18 (Image "System", no address) and as a 5145 with IpAddress. Take
    the nearest same-pipe 5145 open within the skew; for a pipe creation (17,
    logged by the service side shortly before its client connects), accept the
    one client that opened that pipe within the cluster gap if it is unambiguous.
    """
    opens: dict[tuple[str, str], list[PipeHit]] = {}
    for hit in hits:
        if hit.peer is not None:
            opens.setdefault((hit.computer, hit.pipe.lower()), []).append(hit)
    for hit in hits:
        if hit.peer is not None or hit.event.channel != SYSMON or hit.is_local_connect:
            continue
        candidates = opens.get((hit.computer, hit.pipe.lower()), [])
        close = [c for c in candidates if abs(c.timestamp - hit.timestamp) <= w.skew]
        if close:
            hit.peer = min(close, key=lambda c: (abs(c.timestamp - hit.timestamp), c.peer or "")).peer
            continue
        nearby = {c.peer for c in candidates if abs(c.timestamp - hit.timestamp) <= w.cluster_gap}
        if len(nearby) == 1:
            hit.peer = nearby.pop()


def classify(hit: PipeHit) -> tuple[str, str] | None:
    """(kind, label) for a signature hit, or None for an ordinary pipe."""
    for pattern, label in TOOL_PIPES:
        if pattern.search(hit.pipe):
            return "tool", label
    if STDIO_PIPE.match(hit.pipe):
        return "tool", "PsExec-style stdio pipes"
    if hit.remote and hit.pipe.lower() in CONTROL_PIPES:
        return "control", CONTROL_PIPES[hit.pipe.lower()]
    if hit.remote and RANDOM_PIPE.match(hit.pipe):
        return "random", "random-named pipe"
    return None


def stdio_origin(pipe: str, known_pipes: set[str]) -> tuple[str, str, str] | None:
    """(service, source host, pid) from a PsExec stdio pipe name.

    The service name is taken from a main pipe seen on the same host when one
    prefixes the stdio name (resolving dashes in renamed services); otherwise
    the first dash-separated token.
    """
    match = STDIO_PIPE.match(pipe)
    if not match:
        return None
    base = match.group("base")
    prefixes = [p for p in known_pipes if base.lower().startswith(p.lower() + "-")]
    service = max(prefixes, key=len) if prefixes else base.split("-", 1)[0]
    source = base[len(service) + 1:]
    return service, source, match.group("pid")


def build_clusters(hits: list[PipeHit], w: PipeWindows = DEFAULT_WINDOWS) -> list[_Cluster]:
    """Signature hits grouped per (host, client), split on the cluster gap."""
    clusters: list[_Cluster] = []
    open_clusters: dict[tuple[str, str | None], _Cluster] = {}
    for hit in hits:
        verdict = classify(hit)
        if verdict is None:
            continue
        key = (hit.computer, hit.peer)
        cluster = open_clusters.get(key)
        if cluster is None or hit.timestamp - cluster.end > w.cluster_gap:
            cluster = _Cluster(hit.computer, hit.peer)
            open_clusters[key] = cluster
            clusters.append(cluster)
        cluster.add(hit, *verdict)

    # An address-less (Sysmon) cluster is the same activity as the one address
    # cluster it overlaps on that host; with zero or several, keep it apart.
    absorbed: set[int] = set()
    for cluster in clusters:
        if cluster.client is not None:
            continue
        partners = [
            c for c in clusters
            if c.client is not None and c.computer == cluster.computer
            and c.start - w.cluster_gap <= cluster.end and cluster.start <= c.end + w.cluster_gap
        ]
        if len(partners) == 1:
            partners[0].absorb(cluster)
            absorbed.add(id(cluster))
    return [c for c in clusters if id(c) not in absorbed]


def _credit(clusters: list[_Cluster], installs: list[ServiceInstall],
            tasks: list[NormalizedEvent], drops: list[NormalizedEvent], w: PipeWindows) -> None:
    """Attach drops, installs and tasks to the activity that most plausibly
    caused them.

    A drop goes to the nearest cluster of the same client that it precedes
    (the binary is copied first) or falls inside. An install or task goes to
    the cluster with corroborating context first (a drop by the same client,
    a tool pipe), then to the most recent activity strictly before it, an
    address-known cluster winning ties; hits up to the skew *after* it are only
    considered when nothing precedes it. Recency alone would let a poller
    whose tick lands next to the install take credit for an attacker's burst.
    """
    for drop in drops:
        ip = clean_ip(drop.get("IpAddress"))
        candidates = [
            c for c in clusters
            if c.computer == drop.computer
            and (c.client is None or c.client == ip)
            and c.start - w.drop_window <= drop.timestamp <= c.end + w.skew
        ]
        if candidates:
            nearest = min(candidates, key=lambda c: (abs((c.start - drop.timestamp).total_seconds()),
                                                     c.client is None))
            nearest.drops.append(drop)

    def owner(when: datetime, computer: str, candidates: list[_Cluster]) -> _Cluster | None:
        for strict in (True, False):
            ranked = []
            for cluster in candidates:
                if cluster.computer != computer:
                    continue
                before = [h.timestamp for h in cluster.hits
                          if (h.timestamp < when if strict else h.timestamp <= when + w.skew)]
                if not before or when - max(before) > w.follow_window:
                    continue
                context = bool(cluster.drops) or "tool" in cluster.kinds
                burst = -(cluster.end - cluster.start).total_seconds()  # a burst beats a poller
                ranked.append(((context, max(before), cluster.client is not None, burst), cluster))
            if ranked:
                return max(ranked, key=lambda r: r[0])[1]
        return None

    for install in installs:
        cluster = owner(install.timestamp, install.computer, clusters)
        if cluster:
            cluster.installs.append(install)
    schedulers = [c for c in clusters if "task-scheduler" in c.control]
    for task in tasks:
        cluster = owner(task.timestamp, task.computer, schedulers)
        if cluster:
            cluster.tasks.append(task)


class NamedPipeExecution(Rule):
    id = "CW-012"
    title = "Remote execution over named pipes"
    severity = "high"
    techniques = ("T1021.002", "T1569.002")
    local_title = "Local execution through a remote-exec tool's pipes"
    cluster_gap = DEFAULT_WINDOWS.cluster_gap
    follow_window = DEFAULT_WINDOWS.follow_window
    drop_window = DEFAULT_WINDOWS.drop_window
    skew = DEFAULT_WINDOWS.skew
    enum_window = DEFAULT_WINDOWS.enum_window
    enum_distinct_pipes = DEFAULT_WINDOWS.enum_distinct_pipes
    tunables = ("cluster_gap", "follow_window", "drop_window", "skew", "enum_window",
                "enum_distinct_pipes")
    zero_ok_tunables = ("skew",)

    def windows(self) -> PipeWindows:
        return PipeWindows(self.cluster_gap, self.follow_window, self.drop_window, self.skew,
                           self.enum_window, self.enum_distinct_pipes)

    def evaluate(self, ctx: HuntContext) -> Iterator[Finding]:
        w = self.windows()
        hits = pipe_hits(ctx, w)
        if not hits:
            return
        clusters = build_clusters(hits, w)
        drops = [
            e for e in ctx.events_for(SECURITY, 5145)
            if str(e.get("ShareName") or "").upper().endswith(("ADMIN$", "C$"))
            and str(e.get("RelativeTargetName") or "").lower().endswith(EXECUTABLE)
        ]
        _credit(clusters, credible_installs(ctx), ctx.events_for(SECURITY, 4698, 4702), drops, w)
        for cluster in sorted(clusters, key=lambda c: (c.start, c.computer)):
            finding = self._judge(cluster, hits, w)
            if finding is not None:
                yield finding

    def _judge(self, cluster: _Cluster, all_hits: list[PipeHit], w: PipeWindows) -> Finding | None:
        host = cluster.computer
        corroborated = bool(cluster.installs or cluster.drops or cluster.tasks)
        if "tool" not in cluster.kinds and not corroborated and _is_enumeration(cluster, all_hits, w):
            return None

        known_pipes = {h.pipe for h in all_hits if h.computer == host}
        origin = None
        for hit in cluster.hits:
            origin = stdio_origin(hit.pipe, known_pipes)
            if origin:
                break
        local_client = _local_client(cluster)
        local_evidence = bool(
            local_client
            or (origin and short_host(origin[1]) == short_host(host))
            or (not any(h.remote for h in cluster.hits)
                and any(h.src_ip and is_local_address(h.src_ip) for h in cluster.hits))
        )
        local = local_evidence and not _driven_remotely(cluster)

        strongest = max(cluster.kinds, key=_KIND_RANK.__getitem__)
        severity = {"tool": "high", "control": "medium", "random": "medium"}[strongest]
        if "control" in cluster.kinds and corroborated:
            severity = "high"
        known_tool = any(KNOWN_REMOTE_EXEC_SERVICES.search(str(d.get("RelativeTargetName")))
                         for d in cluster.drops)
        if (("tool" in cluster.kinds and corroborated) or known_tool
                or any(looks_like_remote_exec(i) for i in cluster.installs)):
            severity = "critical"
        if local:
            severity = "medium"

        techniques = [] if local else ["T1021.002"]
        if "tool" in cluster.kinds or "service-control" in cluster.control or cluster.installs:
            techniques.append("T1569.002")
        if cluster.installs:
            techniques.append("T1543.003")
        if cluster.tasks:
            techniques.append("T1053.005")
        if cluster.drops:
            techniques.append("T1570")

        users = [h.user for h in cluster.hits if h.user != "-"]
        evidence = [h.event for h in cluster.hits] + [i.event for i in cluster.installs]
        evidence += cluster.tasks + cluster.drops
        evidence.sort(key=lambda e: (e.timestamp, e.record_id))

        summary = _summary(cluster, origin)
        if local:
            client = f" by {local_client}" if local_client else ""
            summary = f"local use, client ran on this host{client}: {summary}"
        return self.finding(
            title=self.local_title if local else self.title,
            severity=severity,
            techniques=tuple(techniques),
            timestamp=cluster.start,
            host=host,
            user=Counter(users).most_common(1)[0][0] if users else "-",
            summary=summary,
            evidence=evidence,
            src_ip=None if local else cluster.client,
            src_host=None if local or not origin else origin[1],
        )


def _local_client(cluster: _Cluster) -> str | None:
    """Image of a local process connecting to the tool's pipes, if any.

    The tool's service side creates its pipes (Sysmon 17); the client connects
    (18). A remote client shows up as "System"; anything else is a process on
    this very host.
    """
    for hit in cluster.hits:
        if hit.is_local_connect:
            verdict = classify(hit)
            if verdict and verdict[0] == "tool":
                return basename(hit.event.get("Image")) or "?"
    return None


def _driven_remotely(cluster: _Cluster) -> bool:
    """Was any signature pipe of the cluster used from another machine?

    Control and random-pipe hits only count when remote. A tool pipe counts
    when a remote client opened it and no local client did: a pipe that a
    local process also drives (a PsExec client on the box, a squatter waiting
    for one) is local, while e.g. a Cobalt Strike SMB beacon linked from
    another host stays lateral even if local post-ex pipes follow.
    """
    if cluster.kinds & {"control", "random"}:
        return True
    locally_driven = {h.pipe.lower() for h in cluster.hits if h.is_local_connect}
    return any(h.remote and h.pipe.lower() not in locally_driven for h in cluster.hits)


def _is_enumeration(cluster: _Cluster, all_hits: list[PipeHit], w: PipeWindows) -> bool:
    """Did this cluster's own client sweep many distinct pipes around it?"""
    lo, hi = cluster.start - w.enum_window, cluster.end + w.enum_window
    users = {h.user for h in cluster.hits if h.user != "-"}

    def same_actor(hit: PipeHit) -> bool:
        if cluster.client is not None:
            return hit.peer == cluster.client
        if users:
            return hit.user in users
        return True  # address- and account-less (Sysmon): only the host is known

    distinct = {
        h.pipe.lower() for h in all_hits
        if h.computer == cluster.computer and h.remote and lo <= h.timestamp <= hi and same_actor(h)
    }
    return len(distinct) >= w.enum_distinct_pipes


def _summary(cluster: _Cluster, origin: tuple[str, str, str] | None) -> str:
    if cluster.labels:
        head = " + ".join(cluster.labels)
    elif cluster.control:
        head = "remote " + " + ".join(sorted(cluster.control)) + " pipe access"
    else:
        head = "remote connection to a random-named pipe"
    pipes = sorted({"\\" + h.pipe for h in cluster.hits}, key=str.lower)
    shown = ", ".join(pipes[:4]) + (f" (+{len(pipes) - 4} more)" if len(pipes) > 4 else "")
    parts = [f"{head}: {shown}"]
    if cluster.client:
        parts.append(f"from {cluster.client}")
    if origin:
        service, source, pid = origin
        renamed = "" if service.lower() == "psexesvc" else " (renamed)"
        parts.append(f"service '{service}'{renamed} launched from host {source} (pid {pid})")
    if cluster.installs:
        parts.append(f"then {cluster.installs[0].describe()}")
    if cluster.tasks:
        parts.append(f"then task '{cluster.tasks[0].get('TaskName') or '?'}' registered")
    if cluster.drops:
        drop = cluster.drops[0]
        parts.append(f"after '{drop.get('RelativeTargetName')}' was written to {drop.get('ShareName')}")
    return "; ".join(parts)
