"""Analyst configuration: which rules run, how wide their windows are, and
which known-good activity is suppressed.

Detection that cannot be tuned drowns a SOC: every environment has backup
agents, deployment tools and admins whose normal work looks like lateral
movement. A TOML file (``crabwalk hunt --config crabwalk.toml``) handles that
without touching code::

    [rules]
    disable = ["CW-003"]          # or: only = ["CW-012", "CW-001"]
    min_severity = "medium"

    [rules.CW-001]
    window = "15m"                # any tunable listed by `crabwalk config --example`

    [[allow]]
    reason = "SCCM client push"   # required: every suppression says why
    rules = ["CW-001"]            # optional, default all rules
    users = ["CORP\\\\svc_sccm"]     # globs; a bare name matches any domain
    sources = ["10.0.5.0/24"]     # client IP/CIDR, or source host glob
    expires = 2026-12-31          # optional: allowlists rot
    [[allow.fields]]              # optional: one table per kind of evidence record
    ServiceName = "^ccmsetup$"    #   the install: its name AND its binary
    ImagePath = '^"?C:\\\\Windows\\\\ccmsetup\\\\ccmsetup\\.exe"?( |$)'

Within an [[allow]] entry every given criterion must match; within a list any
item may. An entry needs at least one criterion — a blanket suppression is
what ``disable`` is for. With fields, EVERY evidence event of a finding must
match one of the entry's field tables: carry all of that table's fields, each
matching its regex. One benign event cannot excuse the rest of a finding, an
entry cannot excuse evidence it says nothing about (the service install that
escalated a pipe finding), and a misspelled or misplaced field name makes its
table match nothing, so the entry fails closed. `hunt` warns about both near
misses. A domain-qualified user pattern only matches records that show that
domain.

Unknown keys, rule ids, CIDRs and regexes are errors, not silently ignored: a
typo in a suppression list must never pass quietly, and a CIDR is never
widened (10.0.5.0/2 is refused, not read as 0.0.0.0/2). Suppressed findings
are kept and reported with their reason.
"""

from __future__ import annotations

import codecs
import fnmatch
import ipaddress
import math
import re
import sys
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised on the 3.10 CI leg
    import tomli as tomllib

from .hosts import clean_ip, short_host
from .models import NormalizedEvent
from .rules import ALL_RULES
from .rules.base import SEVERITY_RANK, Finding, Rule

RULES_BY_ID: dict[str, type[Rule]] = {cls.id: cls for cls in ALL_RULES}
SEVERITIES = ("low", "medium", "high", "critical")

_DURATION = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*(ms|s|m|h|d)?\s*$", re.IGNORECASE)
_UNIT_SECONDS = {"ms": 0.001, "s": 1, "m": 60, "h": 3600, "d": 86400}
_RULES_KEYS = {"only", "disable", "min_severity"}
_ALLOW_KEYS = {"reason", "rules", "users", "hosts", "sources", "fields", "expires"}


class ConfigError(ValueError):
    """A configuration problem, phrased for the analyst who wrote the file."""


# --------------------------------------------------------------------------
# allowlist
# --------------------------------------------------------------------------

Network = ipaddress.IPv4Network | ipaddress.IPv6Network
#: One [allow.fields] table: (field name as written, regex) pairs that a single
#: evidence event must all satisfy. Names compare case-insensitively.
FieldTable = tuple[tuple[str, re.Pattern[str]], ...]
VOUCHED, CONTRADICTED, SILENT = "vouched", "contradicted", "silent"

#: Fields that say what a record is: the service and its binary, the share
#: object or pipe, the registry value, the task and what it runs, the process
#: and its command line, the script, the directory object, the cleared log.
#: Every [allow.fields] table must name at least one. Everything else (who,
#: where, process context, per-type constants such as ObjectType or
#: AccountName=LocalSystem) appears on many kinds of record, so a table of
#: those alone would vouch for records it never meant, such as the install
#: that escalated a finding. An allowlist rather than a denylist, so a field
#: nobody thought about fails closed. `users`, `hosts` and `sources` cover
#: who and where.
IDENTIFYING_FIELDS = (
    "ServiceName", "ImagePath", "ServiceFileName",          # 7045, 4697 (and 4769)
    "RelativeTargetName", "PipeName",                       # 5145, Sysmon 17/18
    "TargetObject", "Details",                              # Sysmon 13
    "TaskName", "TaskContent", "TaskContentNew",            # 4698, 4702
    "CommandLine", "NewProcessName", "Hashes", "OriginalFileName",  # Sysmon 1, 4688
    "TargetFilename",                                       # Sysmon 11
    "ScriptBlockText",                                      # 4104
    "Properties", "ObjectName",                             # 4662
    "Channel", "BackupPath",                                # System 104
)
_IDENTIFYING = frozenset(name.lower() for name in IDENTIFYING_FIELDS)
#: A regex that matches all of these constrains nothing a real record would show.
_PROBES = ("x", "0", "-", "C:\\Windows\\Temp\\x.exe", "%COMSPEC% /Q /c whoami", "\\svcctl",
           "PSEXESVC-WKS66-4242-stdin", "crabwalk probe 7f3a9c \u2603", "A" * 300)


@dataclass(frozen=True)
class AllowEntry:
    reason: str
    index: int  # 1-based position among [[allow]] entries, for messages
    rules: frozenset[str] | None = None  # None: any rule
    users: tuple[str, ...] = ()
    hosts: tuple[str, ...] = ()
    networks: tuple[Network, ...] = ()
    source_hosts: tuple[str, ...] = ()
    fields: tuple[FieldTable, ...] = ()  # each table describes one kind of evidence event
    expires: date | None = None

    @property
    def label(self) -> str:
        return f"allow[{self.index}] {self.reason!r}"

    def expired(self, today: date) -> bool:
        return self.expires is not None and today > self.expires

    def matches(self, finding: Finding) -> bool:
        return self.matches_scope(finding) and self.matches_fields(finding)

    def matches_scope(self, finding: Finding) -> bool:
        """Every criterion except the evidence fields."""
        if self.rules is not None and finding.rule_id not in self.rules:
            return False
        if self.users and not any(_user_matches(p, finding.user) for p in self.users):
            return False
        if self.hosts and not any(_host_matches(p, finding.host) for p in self.hosts):
            return False
        if (self.networks or self.source_hosts) and not self._source_matches(finding):
            return False
        return True

    def matches_fields(self, finding: Finding) -> bool:
        """The entry has to vouch for every evidence event, one by one: each
        must match one of the field tables (carry all of its fields, each
        matching its regex).

        * One benign event (an svcctl open) cannot excuse a finding whose
          other evidence is a PsExec run: those opens match no table.
        * An entry written for svcctl polling cannot excuse the service
          install that escalated the same cluster: no table describes it.
        * A misspelled field, or one that belongs to another event type,
          makes its table match nothing, so the entry fails closed.
        * Generic fields (SubjectUserName, User, AccountName) only narrow a
          table that also names one of IDENTIFYING_FIELDS; a table without
          one is refused when the config is read.

        Separate tables describe separate kinds of evidence, so one entry
        can cover a tool's 5145 opens, Sysmon pipe events and install across
        rules. A finding without evidence never matches a fields entry.
        """
        if not self.fields:
            return True
        return bool(finding.evidence) and all(
            self.event_status(event) == VOUCHED for event in finding.evidence)

    def event_status(self, event: NormalizedEvent) -> str:
        """VOUCHED: a table matches the event. CONTRADICTED: the event carries
        every field of some table, but a regex fails, so the entry describes
        something else. SILENT: no table names only fields the event carries;
        the entry says nothing about it.

        A field the record leaves null counts as absent, and when a record
        repeats a name in another case every copy must match."""
        values = _field_values(event)
        status = SILENT
        for table in self.fields:
            if all(name.lower() in values for name, _ in table):
                if all(pattern.search(value) for name, pattern in table
                       for value in values[name.lower()]):
                    return VOUCHED
                status = CONTRADICTED
        return status

    def unseen_tables(self, shapes: set[frozenset[str]]) -> list[FieldTable]:
        """Tables whose fields no record of these shapes carries together and
        that look like a mistake. A lone identifying field that no record
        carries is just a log source the data lacks (a misspelled one would
        have been refused at load, since its table then names no identifying
        field); a misspelled narrowing field, or fields of different records
        put in one table, is the mistake worth a warning."""
        return [table for table in self.fields
                if not (len(table) == 1 and table[0][0].lower() in _IDENTIFYING)
                and not any(all(name.lower() in shape for name, _ in table) for shape in shapes)]

    def _source_matches(self, finding: Finding) -> bool:
        ip = clean_ip(finding.src_ip)  # session-layer addresses may be ::ffff:-mapped
        if ip is not None:
            address = ipaddress.ip_address(ip)
            if any(address in network for network in self.networks):
                return True
        for pattern in self.source_hosts:  # host globs; '10.0.5.*' globs the address
            if finding.src_host and _host_matches(pattern, finding.src_host):
                return True
            if ip is not None and fnmatch.fnmatchcase(ip, pattern.lower()):
                return True
        return False


@dataclass(frozen=True)
class _Account:
    """An account as logged: 'CORP\\\\svc', 'CORP.LOCAL\\\\svc', 'svc@corp.local' or 'svc'.

    ``realm`` is the DNS form when the record shows one (dotted), ``label``
    the NetBIOS-style short domain (the realm's first label, or the domain as
    written when it has no dot).
    """

    name: str
    label: str | None = None
    realm: str | None = None


def _split_account(account: str) -> _Account:
    account = account.strip().lower()
    if "\\" in account:
        domain, _, name = account.rpartition("\\")
    elif "@" in account:
        name, _, domain = account.partition("@")
    else:
        return _Account(account)
    if "." in domain:
        return _Account(name, domain.split(".", 1)[0], domain)
    return _Account(name, domain or None)


def _user_matches(pattern: str, user: str) -> bool:
    """A bare 'svc*' matches the account under any domain. A domain-qualified
    pattern also requires the record to show that domain, never matching
    more than written:

    * a DNS realm in the pattern ('svc@corp.contoso.com', 'CORP.CONTOSO.COM\\\\svc')
      is compared whole against a record's realm (globs allowed), and only
      against a NetBIOS-only record through its first label when written
      without globs ('CORP');
    * a NetBIOS domain ('CORP\\\\svc') matches a record's NetBIOS domain or its
      realm's first label, so 'CORP.LOCAL\\\\svc' and 'svc@corp.local' qualify.

    A record that logged only a bare name, or a SID, cannot prove its domain
    and never matches a qualified pattern. When a domain's NetBIOS name is not
    the first label of its DNS name, list both forms.
    """
    want, have = _split_account(pattern), _split_account(str(user or ""))
    if not fnmatch.fnmatchcase(have.name, want.name):
        return False
    if want.label is None:
        return True
    if want.realm is not None:
        if have.realm is not None:
            return fnmatch.fnmatchcase(have.realm, want.realm)
        literal = not _GLOB_CHARS & set(want.realm)
        return literal and have.label is not None and have.label == want.label
    return have.label is not None and fnmatch.fnmatchcase(have.label, want.label)


def _host_matches(pattern: str, host: str) -> bool:
    """A glob against the logged name or its short form ('SRV*' matches
    'SRV01.corp.local'; '*.corp.local' matches the FQDN). A plain FQDN also
    matches the bare NetBIOS name most logs record ('SCCM01.corp.local'
    matches 'SCCM01')."""
    pattern, name = pattern.lower(), str(host or "").lower()
    short = short_host(name) or ""
    if fnmatch.fnmatchcase(name, pattern) or fnmatch.fnmatchcase(short, pattern):
        return True
    if not _GLOB_CHARS & set(pattern) and "." in pattern and "." not in name:
        return short_host(pattern) == short
    return False


# --------------------------------------------------------------------------
# the configuration
# --------------------------------------------------------------------------


@dataclass
class Screened:
    """Findings after the allowlist and the severity floor."""

    kept: list[Finding]
    suppressed: list[tuple[Finding, AllowEntry]]
    below_min_severity: int
    expired: list[AllowEntry]
    warnings: list[str] = field(default_factory=list)


@dataclass
class Config:
    source: str | None = None
    only: frozenset[str] | None = None
    disable: frozenset[str] = frozenset()
    min_severity: str | None = None
    tunables: dict[str, dict[str, Any]] = field(default_factory=dict)
    allow: list[AllowEntry] = field(default_factory=list)

    def with_overrides(
        self, *, only: list[str] | None = None, disable: list[str] | None = None,
        min_severity: str | None = None,
    ) -> Config:
        """Command-line flags layered over the file: --rule replaces `only`,
        --disable adds to `disable`, --min-severity replaces the floor."""
        where = "command line"
        return Config(
            source=self.source,
            only=frozenset(_rule_ids(only, where)) if only else self.only,
            disable=self.disable | frozenset(_rule_ids(disable or [], where)),
            min_severity=_severity(min_severity, where) if min_severity else self.min_severity,
            tunables=self.tunables,
            allow=self.allow,
        )

    def rule_ids(self) -> list[str]:
        return [
            cls.id for cls in ALL_RULES
            if (self.only is None or cls.id in self.only) and cls.id not in self.disable
        ]

    def build_rules(self) -> list[Rule]:
        selected = self.rule_ids()
        if not selected:
            raise ConfigError("no rules left to run (check `only` and `disable`)")
        rules = []
        for rule_id in selected:
            rule = RULES_BY_ID[rule_id]()
            for name, value in self.tunables.get(rule_id, {}).items():
                setattr(rule, name, value)
            rules.append(rule)
        return rules

    def screen(
        self, findings: list[Finding], today: date | None = None,
        events: list[NormalizedEvent] | None = None,
    ) -> Screened:
        """Apply the allowlist and the severity floor. ``events`` (every
        parsed record) lets the typo check tell a field no record carries
        from one this rule's evidence just does not; without it, only the
        findings' evidence is consulted."""
        today = today or date.today()
        active = [entry for entry in self.allow if not entry.expired(today)]
        kept: list[Finding] = []
        suppressed: list[tuple[Finding, AllowEntry]] = []
        below = 0
        for finding in findings:
            # an entry has to cover what was merged into a finding too (its
            # rule is in the entry's scope only if the entry says so)
            entry = next((e for e in active if e.matches(finding)
                          and all(e.matches(m) for m in finding.merged)), None)
            if entry is not None:
                suppressed.append((finding, entry))
            elif self.min_severity and SEVERITY_RANK[finding.severity] < SEVERITY_RANK[self.min_severity]:
                below += 1
            else:
                kept.append(finding)
        expired = [entry for entry in self.allow if entry.expired(today)]
        done = {id(finding) for finding, _ in suppressed}
        records = events if events is not None else [e for f in findings for e in f.evidence]
        shapes = {frozenset(_field_values(event)) for event in records}
        warnings = (_unseen_table_warnings(active, findings, done, shapes)
                    + _near_miss_warnings(active, kept, shapes)
                    + _merged_miss_warnings(active, kept))
        return Screened(kept, suppressed, below, expired, warnings)

    def describe(self) -> dict[str, Any]:
        """Effective settings, recorded next to the findings they produced."""
        return {
            "config": self.source,
            "rules": self.rule_ids(),
            "min_severity": self.min_severity,
            "tunables": {
                rule_id: {name: _format_value(value) for name, value in values.items()}
                for rule_id, values in sorted(self.tunables.items())
            },
            "allow_entries": len(self.allow),
        }


def _unseen_table_warnings(
    entries: list[AllowEntry], findings: list[Finding], suppressed: set[int],
    shapes: set[frozenset[str]],
) -> list[str]:
    """Flag the likely typo behind an entry that passed a finding by without
    a word: its other criteria hold, yet its tables say nothing about any of
    the finding's evidence, and one of them names fields that no record in
    the data carries together. An entry that vouched for part of the
    evidence, or contradicted it, evidently applies; a table for another
    rule or log source is not flagged then."""
    warnings = []
    for entry in entries:
        if not entry.fields:
            continue
        in_scope = [f for f in findings if entry.matches_scope(f)]
        ignored = [f for f in in_scope if id(f) not in suppressed and f.evidence
                   and all(entry.event_status(e) == SILENT for e in f.evidence)]
        if not ignored:
            continue
        for table in entry.unseen_tables(shapes):
            names = ", ".join(repr(name) for name, _ in table)
            if len(table) == 1:
                what, hint = f"field {names} occurs in no record", "check the name"
            else:
                what = f"fields {names} never occur together in one record"
                hint = ("check the names, and give fields of different records "
                        "separate [[allow.fields]] tables")
            warnings.append(f"{entry.label}: {what} of this data, and the entry said nothing about "
                            f"{len(ignored)} finding(s) it otherwise matches; {hint} "
                            "(or the data lacks that log source)")
    return warnings


def _near_miss_warnings(
    entries: list[AllowEntry], kept: list[Finding], shapes: set[frozenset[str]]
) -> list[str]:
    """Explain a near miss: an entry's criteria held and its tables vouched
    for part of a finding's evidence without contradicting any of it, but
    said nothing about the rest, so the finding was kept. Usually that rest
    is what escalated it; sometimes the table meant for it has a typo, so a
    table whose fields no record carries together is named as well. One line
    per entry, rule and kind of evidence."""
    groups: dict[tuple[int, str, str], list[Finding]] = {}
    by_index = {entry.index: entry for entry in entries}
    for finding in kept:
        for entry in entries:
            if not entry.fields or not entry.matches_scope(finding):
                continue
            status = [(event, entry.event_status(event)) for event in finding.evidence]
            silent = [event for event, s in status if s == SILENT]
            if not silent or len(silent) == len(status) or any(s == CONTRADICTED for _, s in status):
                continue
            kinds = ", ".join(sorted({f"{_channel_label(e.channel)} {e.event_id}" for e in silent}))
            groups.setdefault((entry.index, finding.rule_id, kinds), []).append(finding)
    warnings = []
    for (index, rule_id, kinds), found in groups.items():
        entry = by_index[index]
        first = min(found, key=lambda f: f.timestamp)
        message = (
            f"{entry.label}: kept {len(found)} {rule_id} finding(s) (first on {first.host} at "
            f"{first.timestamp:%Y-%m-%d %H:%M:%S}Z): no fields table describes their {kinds} "
            "evidence; if that is expected too, add a table that pins what it is (name and path)")
        for table in entry.unseen_tables(shapes):
            names = ", ".join(repr(name) for name, _ in table)
            message += (f"; note that no record of this data carries {names} together "
                        "(a typo, fields of different records in one table, or a log source "
                        "the data lacks?)")
        warnings.append(message)
    return warnings


def _merged_miss_warnings(entries: list[AllowEntry], kept: list[Finding]) -> list[str]:
    """An entry matched a finding but not a finding merged into it (usually:
    the merged one's rule is not in the entry's `rules`), so it was kept."""
    warnings = []
    for finding in kept:
        for entry in entries:
            if not finding.merged or not entry.matches(finding):
                continue
            missed = sorted({m.rule_id for m in finding.merged if not entry.matches(m)})
            if missed:
                warnings.append(
                    f"{entry.label}: kept {finding.rule_id} on {finding.host} at "
                    f"{finding.timestamp:%Y-%m-%d %H:%M:%S}Z; it also tells {', '.join(missed)}, which "
                    "the entry does not cover (add it to the entry's rules if that is expected too)")
    return warnings


def _field_values(event: NormalizedEvent) -> dict[str, list[str]]:
    """Lower-cased field name -> every non-null value the record has for it."""
    values: dict[str, list[str]] = {}
    for key, value in event.data.items():
        if value is not None:
            values.setdefault(str(key).lower(), []).append(str(value))
    return values


def _channel_label(channel: str) -> str:
    """'Microsoft-Windows-Sysmon/Operational' -> 'Sysmon'."""
    return channel.split("/", 1)[0].removeprefix("Microsoft-Windows-")


def load_config(path: str | Path) -> Config:
    """Read a TOML config, whatever encoding a Windows shell saved it in.

    PowerShell 5.1 writes `>` redirections as UTF-16 and `Out-File -Encoding
    utf8` with a BOM; both are accepted, as is plain UTF-8.
    """
    path = Path(path)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc.strerror or exc}") from None
    try:
        if raw.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
            text = raw.decode("utf-16")
        else:
            text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ConfigError(f"{path}: not UTF-8 or UTF-16 text") from None
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: not valid TOML: {exc}") from None
    return parse_config(data, source=str(path))


def parse_config(data: dict[str, Any], *, source: str | None = None) -> Config:
    unknown = set(data) - {"rules", "allow"}
    if unknown:
        raise ConfigError(f"unknown top-level key(s): {', '.join(sorted(unknown))} "
                          "(expected [rules] and [[allow]])")
    config = Config(source=source)
    rules = data.get("rules", {})
    if not isinstance(rules, dict):
        raise ConfigError("[rules] must be a table")
    for key, value in rules.items():
        where = f"rules.{key}"
        if key == "only":
            config.only = frozenset(_rule_ids(_str_list(value, where), where))
        elif key == "disable":
            config.disable = frozenset(_rule_ids(_str_list(value, where, allow_empty=True), where))
        elif key == "min_severity":
            config.min_severity = _severity(value, where)
        elif key in RULES_BY_ID:
            if not isinstance(value, dict):
                raise ConfigError(f"[{where}] must be a table of settings")
            config.tunables[key] = _tunables(RULES_BY_ID[key], value, where)
        else:
            raise ConfigError(f"unknown key {where!r}: expected only/disable/min_severity "
                              f"or a rule id ({', '.join(RULES_BY_ID)})")
    allow = data.get("allow", [])
    if not isinstance(allow, list):
        raise ConfigError("allow entries must be written as [[allow]] tables")
    config.allow = [_allow_entry(entry, i) for i, entry in enumerate(allow, 1)]
    return config


# --------------------------------------------------------------------------
# value parsing
# --------------------------------------------------------------------------


#: Longest correlation window accepted. Beyond a year a window is a typo, and
#: timestamps shifted by it overflow datetime arithmetic inside the rules.
MAX_DURATION = timedelta(days=366)
MIN_WINDOW = timedelta(seconds=1)


def parse_duration(value: Any, where: str) -> timedelta:
    """'90s', '10m', '6h', '1d', '250ms', or a number of seconds."""
    if isinstance(value, bool):
        raise ConfigError(f"{where}: expected a duration like '10m', got {value!r}")
    if isinstance(value, (int, float)):
        seconds = float(value)
    elif isinstance(value, str) and (match := _DURATION.match(value)):
        unit = (match.group(2) or "s").lower()
        seconds = float(match.group(1)) * _UNIT_SECONDS[unit]
    else:
        raise ConfigError(f"{where}: expected a duration like '90s', '10m' or '6h', got {value!r}")
    if not math.isfinite(seconds) or seconds < 0:
        raise ConfigError(f"{where}: a duration must be a finite, non-negative number")
    if seconds > MAX_DURATION.total_seconds():
        raise ConfigError(f"{where}: {value!r} is longer than {MAX_DURATION.days} days")
    return timedelta(seconds=seconds)


def _tunables(cls: type[Rule], values: dict[str, Any], where: str) -> dict[str, Any]:
    if not cls.tunables:
        raise ConfigError(f"[{where}]: {cls.id} has no tunable settings")
    parsed: dict[str, Any] = {}
    for name, raw in values.items():
        key = f"{where}.{name}"
        if name not in cls.tunables:
            raise ConfigError(f"unknown setting {key!r}; {cls.id} accepts: {', '.join(cls.tunables)}")
        default = getattr(cls, name)
        if isinstance(default, bool):
            if not isinstance(raw, bool):
                raise ConfigError(f"{key}: expected true or false, got {raw!r}")
            parsed[name] = raw
        elif isinstance(default, timedelta):
            parsed[name] = parse_duration(raw, key)
            # A zero window cannot correlate anything: it would switch the rule
            # off without saying so. Only tolerances (CW-012 skew) may be zero.
            if parsed[name] < MIN_WINDOW and name not in cls.zero_ok_tunables:
                raise ConfigError(f"{key}: must be at least {format_duration(MIN_WINDOW)}; "
                                  f"use rules.disable to turn {cls.id} off")
        elif isinstance(default, int):
            if isinstance(raw, bool) or not isinstance(raw, int) or raw < 1:
                raise ConfigError(f"{key}: expected a whole number >= 1, got {raw!r}")
            parsed[name] = raw
        elif isinstance(default, tuple):
            if raw == []:
                raise ConfigError(f"{key}: must not be empty; use rules.disable to turn {cls.id} off")
            parsed[name] = tuple(_str_list(raw, key))
        else:  # pragma: no cover - a new tunable type needs a parser here
            raise ConfigError(f"{key}: unsupported setting type {type(default).__name__}")
        try:
            parsed[name] = cls.check_tunable(name, parsed[name])
        except ValueError as exc:
            raise ConfigError(f"{key}: {exc}") from None
    return parsed


def _allow_entry(raw: Any, index: int) -> AllowEntry:
    where = f"allow[{index}]"
    if not isinstance(raw, dict):
        raise ConfigError(f"{where}: must be a table")
    unknown = set(raw) - _ALLOW_KEYS
    if unknown:
        raise ConfigError(f"{where}: unknown key(s) {', '.join(sorted(unknown))}; "
                          f"allowed: {', '.join(sorted(_ALLOW_KEYS))}")
    reason = raw.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        raise ConfigError(f"{where}: 'reason' is required — say why this activity is benign")
    rules = raw.get("rules")
    if rules is not None and _str_list(rules, f"{where}.rules", allow_empty=True) == []:
        raise ConfigError(f"{where}.rules: must name at least one rule; "
                          "omit the key to apply the entry to all rules")
    networks: list[Network] = []
    source_hosts: list[str] = []
    for i, item in enumerate(_optional_list(raw, "sources", where)):
        networks_or_host = _source(item, f"{where}.sources[{i}]")
        if isinstance(networks_or_host, str):
            source_hosts.append(networks_or_host)
        else:
            networks.append(networks_or_host)
    fields = _field_tables(raw["fields"], f"{where}.fields") if "fields" in raw else ()
    entry = AllowEntry(
        reason=reason.strip(),
        index=index,
        rules=frozenset(_rule_ids(_str_list(rules, f"{where}.rules"), f"{where}.rules"))
        if rules is not None else None,
        users=tuple(_optional_list(raw, "users", where)),
        hosts=tuple(_host_pattern(h, f"{where}.hosts[{i}]")
                    for i, h in enumerate(_optional_list(raw, "hosts", where))),
        networks=tuple(networks),
        source_hosts=tuple(source_hosts),
        fields=fields,
        expires=_date(raw.get("expires"), f"{where}.expires"),
    )
    if not (entry.users or entry.hosts or entry.networks or entry.source_hosts or entry.fields):
        raise ConfigError(f"{where}: needs at least one of users, hosts, sources or fields; "
                          "to silence a rule entirely use rules.disable")
    return entry


def _field_tables(raw: Any, where: str) -> tuple[FieldTable, ...]:
    """`[allow.fields]` (one table) or `[[allow.fields]]` (one per kind of evidence).

    A table must be able to say what a record is: one that is empty, that
    names none of IDENTIFYING_FIELDS, or whose regex accepts any value would
    vouch for records it never meant (the install that escalated a finding),
    so it is refused here rather than discovered in an incident. A regex
    that is merely broad cannot be detected; anchor whole values.
    """
    single = isinstance(raw, dict)
    tables = [raw] if single else raw
    usage = ('must be a table of field = "regex" ([allow.fields]), '
             "or several such tables ([[allow.fields]])")
    if not isinstance(tables, list) or not tables:
        raise ConfigError(f"{where}: {usage}")
    parsed: list[FieldTable] = []
    for i, table in enumerate(tables):
        at = where if single else f"{where}[{i}]"
        if not isinstance(table, dict):
            raise ConfigError(f"{at}: {usage}, got {table!r}")
        if not table:
            raise ConfigError(f"{at}: empty; an empty table would vouch for any record")
        pairs = []
        for name, pattern in table.items():
            name = str(name).strip()
            if not name:
                raise ConfigError(f"{at}: empty field name")
            if not isinstance(pattern, str):
                raise ConfigError(f"{at}.{name}: expected a regex string, got {pattern!r}")
            try:
                # names compare case-insensitively: 'servicename' must not quietly miss 'ServiceName'
                compiled = re.compile(pattern, re.IGNORECASE)
            except re.error as exc:
                raise ConfigError(f"{at}.{name}: invalid regex {pattern!r}: {exc}") from None
            if all(compiled.search(probe) for probe in _PROBES):
                raise ConfigError(f"{at}.{name}: regex {pattern!r} accepts any value; "
                                  "pin what the field must be (anchor it with ^...$)")
            pairs.append((name, compiled))
        if not any(name.lower() in _IDENTIFYING for name, _ in pairs):
            listed = ", ".join(name for name, _ in pairs)
            raise ConfigError(
                f"{at}: names no field that says what a record is ({listed}); fields like these "
                "appear on many kinds of record, so the table would vouch for any of them, "
                "including an install that escalated the finding. Name one of "
                f"{', '.join(IDENTIFYING_FIELDS)} (check the spelling), and use users, hosts or "
                "sources for who and where")
        key = tuple(sorted((name.lower(), compiled.pattern) for name, compiled in pairs))
        if key not in {tuple(sorted((n.lower(), p.pattern) for n, p in t)) for t in parsed}:
            parsed.append(tuple(pairs))
    return tuple(parsed)


_GLOB_CHARS = set("*?[")
# Unicode word characters: Windows allows localized computer names (ÇAĞRI-PC).
_HOST_GLOB = re.compile(r"[\w.\-*?\[\]!]+")
_IPV6_GLOB = re.compile(r"[0-9a-fA-F:*?\[\]!]+")


def _source(item: str, where: str) -> Network | str:
    """An exact IP/CIDR, or a host (or address) glob.

    A CIDR must be written exactly: '10.0.5.0/2' is rejected, not widened to
    0.0.0.0/2 — a suppression must never silently cover more than written.
    Something shaped like an address that does not parse ('10.0.5.300',
    '10.0.5', a range) is an error too, not a host glob that never matches.
    An IPv4-mapped IPv6 address or network is stored as the IPv4 network it
    denotes, since findings carry the unwrapped IPv4 form.
    """
    try:
        network = ipaddress.ip_network(item, strict=True)
    except ValueError:
        network = None
    if network is not None:
        mapped = getattr(network.network_address, "ipv4_mapped", None)
        if mapped is not None:
            if network.prefixlen < 96:
                raise ConfigError(f"{where}: {item!r} is wider than the IPv4-mapped range")
            return ipaddress.ip_network(f"{mapped}/{network.prefixlen - 96}")
        return network
    if "/" in item:
        try:
            widened = ipaddress.ip_network(item, strict=False)
        except ValueError:
            raise ConfigError(f"{where}: {item!r} is not a valid CIDR") from None
        raise ConfigError(f"{where}: {item!r} has host bits set; write the network itself, "
                          f"e.g. {widened}") from None
    if ":" in item:
        if _GLOB_CHARS & set(item) and _IPV6_GLOB.fullmatch(item):
            return item.lower()  # an IPv6 address glob such as 2001:db8::*
        raise ConfigError(f"{where}: {item!r} looks like an address but is not a valid IP or CIDR")
    return _host_pattern(item, where)


def _host_pattern(item: str, where: str) -> str:
    """A host name or glob for `hosts` and `sources`.

    The FQDN root dot and a machine-account '$' are dropped (they are not part
    of what logs compare), and an address-shaped string that is neither a
    valid IP nor a glob is refused rather than kept as a pattern that can
    never match.
    """
    pattern = item.strip().rstrip("$").rstrip(".")
    is_glob = bool(_GLOB_CHARS & set(pattern))
    if not is_glob and re.fullmatch(r"[0-9.\-]+", pattern):
        raise ConfigError(f"{where}: {item!r} looks like an address but is not a valid IP or CIDR "
                          "(use a CIDR, or a glob such as 10.0.5.*)")
    if not pattern or not _HOST_GLOB.fullmatch(pattern):
        raise ConfigError(f"{where}: {item!r} is not an IP, CIDR or host name glob")
    return pattern


def _str_list(value: Any, where: str, *, allow_empty: bool = False) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
        raise ConfigError(f"{where}: expected a list of non-empty strings, got {value!r}")
    if not value and not allow_empty:
        raise ConfigError(f"{where}: must not be an empty list")
    return [v.strip() for v in value]


def _optional_list(raw: dict[str, Any], key: str, where: str) -> list[str]:
    """An allow criterion: absent means 'not used'; present must be non-empty."""
    return _str_list(raw[key], f"{where}.{key}") if key in raw else []


def _rule_ids(values: list[str], where: str) -> list[str]:
    ids = [v.upper() for v in values]
    unknown = [v for v in ids if v not in RULES_BY_ID]
    if unknown:
        raise ConfigError(f"{where}: unknown rule id(s) {', '.join(unknown)}; "
                          f"known: {', '.join(RULES_BY_ID)}")
    return ids


def _severity(value: Any, where: str) -> str:
    if not isinstance(value, str) or value.lower() not in SEVERITIES:
        raise ConfigError(f"{where}: expected one of {', '.join(SEVERITIES)}, got {value!r}")
    return value.lower()


def _date(value: Any, where: str) -> date | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        try:
            return date.fromisoformat(value.strip())
        except ValueError:
            pass
    raise ConfigError(f"{where}: expected a date like 2026-12-31, got {value!r}")


def _format_value(value: Any) -> Any:
    if isinstance(value, timedelta):
        return format_duration(value)
    if isinstance(value, tuple):
        return list(value)
    return value


def format_duration(value: timedelta) -> str:
    seconds = value.total_seconds()
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60), ("s", 1)):
        if seconds >= size and seconds % size == 0:
            return f"{int(seconds // size)}{unit}"
    return f"{seconds:g}s"


# --------------------------------------------------------------------------
# the example file
# --------------------------------------------------------------------------


def example_config() -> str:
    """A complete, commented config that changes nothing until edited.

    Generated from the rules themselves, so every tunable and its default is
    always listed. ASCII only: it is printed to whatever console code page.
    """
    lines = [
        "# crabwalk configuration - use with: crabwalk hunt <logs> --config crabwalk.toml",
        "# Everything below is commented out: this file changes nothing until you edit it.",
        "",
        "[rules]",
        '# only = ["CW-012", "CW-001"]    # run just these rules',
        '# disable = ["CW-003"]           # never run these',
        '# min_severity = "medium"        # hide findings below: low, medium, high, critical',
    ]
    for cls in ALL_RULES:
        if not cls.tunables:
            continue
        lines += ["", f"# [rules.{cls.id}]    # {cls.title}"]
        for name in cls.tunables:
            lines.append(f"# {name} = {_toml_value(getattr(cls, name))}")
    lines += [
        "",
        "# Suppress known-good activity. Every given criterion must match; at least one",
        "# of users/hosts/sources/fields is required. Suppressed findings are still",
        "# counted and listed (crabwalk hunt --show-suppressed, JSON, HTML report).",
        "#",
        "# [[allow]]",
        '# reason = "SCCM client push installs ccmsetup"   # required',
        '# rules = ["CW-001", "CW-005", "CW-012"]          # optional, default: all',
        '# users = ["CORP\\\\svc_sccm"]                     # globs; bare name = any domain',
        '# hosts = ["WKS*"]                                # target host globs',
        '# sources = ["10.0.5.0/24", "SCCM01"]             # client IP/CIDR or host glob',
        "# expires = 2026-12-31                            # optional; ignored after this date",
        "# # Every evidence record must match one [[allow.fields]] table: all of its",
        "# # fields, each regex anchored. Pin what the record is (binary, share, pipe),",
        "# # not only names an attacker can reuse.",
        "# [[allow.fields]]                                # the install (System 7045)",
        '# ServiceName = "^ccmsetup$"',
        "# ImagePath = '^\"?C:\\\\Windows\\\\ccmsetup\\\\ccmsetup\\.exe\"?( |$)'",
        "# [[allow.fields]]                                # the binary copied to ADMIN$",
        "# ShareName = '\\\\ADMIN\\$$'",
        "# RelativeTargetName = '^ccmsetup\\\\ccmsetup\\.exe$'",
        "# [[allow.fields]]                                # the SCM pipe, opened on IPC$",
        "# ShareName = '\\\\IPC\\$$'",
        "# RelativeTargetName = '^svcctl$'",
    ]
    return "\n".join(lines) + "\n"


def _toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, timedelta):
        return f'"{format_duration(value)}"'
    if isinstance(value, tuple):
        return "[" + ", ".join(f'"{v}"' for v in value) + "]"
    return str(value)
