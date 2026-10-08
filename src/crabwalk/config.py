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
    rules = ["CW-001", "CW-012"]  # optional, default all rules
    users = ["CORP\\\\svc_sccm"]     # globs; a bare name matches any domain
    sources = ["10.0.5.0/24"]     # client IP/CIDR, or source host glob
    expires = 2026-12-31          # optional: allowlists rot
    [allow.fields]                # optional regexes on the evidence events
    ServiceName = "^ccmsetup$"

Within an [[allow]] entry every given criterion must match; within a list any
item may. An entry needs at least one criterion — a blanket suppression is
what ``disable`` is for. A field regex must hold for every evidence event that
carries the field, so one benign event cannot excuse the rest of a finding.
A domain-qualified user pattern only matches records that show that domain.

Unknown keys, rule ids, CIDRs and regexes are errors, not silently ignored: a
typo in a suppression list must never pass quietly, and a CIDR is never
widened (10.0.5.0/2 is refused, not read as 0.0.0.0/2). Suppressed findings
are kept and reported with their reason; field names that never occur in the
evidence they are meant to match are reported as likely typos.
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


@dataclass(frozen=True)
class AllowEntry:
    reason: str
    index: int  # 1-based position among [[allow]] entries, for messages
    rules: frozenset[str] | None = None  # None: any rule
    users: tuple[str, ...] = ()
    hosts: tuple[str, ...] = ()
    networks: tuple[Network, ...] = ()
    source_hosts: tuple[str, ...] = ()
    fields: tuple[tuple[str, re.Pattern[str]], ...] = ()
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
        """Each field regex must hold for EVERY evidence event that carries the
        field, and at least one must carry it. One benign event (an svcctl
        open) must not excuse a finding whose other evidence is a PsExec run."""
        for name, pattern in self.fields:
            values = [value for event in finding.evidence
                      for key, value in event.data.items() if key.lower() == name]
            if not values or not all(pattern.search(str(value)) for value in values):
                return False
        return True

    def missing_fields(self, finding: Finding) -> set[str]:
        """Field names no evidence event of the finding carries at all."""
        present = {key.lower() for event in finding.evidence for key in event.data}
        return {name for name, _ in self.fields} - present

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

    def screen(self, findings: list[Finding], today: date | None = None) -> Screened:
        today = today or date.today()
        active = [entry for entry in self.allow if not entry.expired(today)]
        kept: list[Finding] = []
        suppressed: list[tuple[Finding, AllowEntry]] = []
        below = 0
        for finding in findings:
            entry = next((e for e in active if e.matches(finding)), None)
            if entry is not None:
                suppressed.append((finding, entry))
            elif self.min_severity and SEVERITY_RANK[finding.severity] < SEVERITY_RANK[self.min_severity]:
                below += 1
            else:
                kept.append(finding)
        expired = [entry for entry in self.allow if entry.expired(today)]
        return Screened(kept, suppressed, below, expired, _field_warnings(active, findings))

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


def _field_warnings(entries: list[AllowEntry], findings: list[Finding]) -> list[str]:
    """Flag field names that are probably typos: the entry's other criteria
    match some findings, yet none of their evidence carries the field."""
    warnings = []
    for entry in entries:
        if not entry.fields:
            continue
        in_scope = [f for f in findings if entry.matches_scope(f)]
        if not in_scope:
            continue
        never = set.intersection(*(entry.missing_fields(f) for f in in_scope))
        for name in sorted(never):
            warnings.append(f"{entry.label}: field {name!r} appears in no evidence of the "
                            f"{len(in_scope)} finding(s) it otherwise matches; check the name")
    return warnings


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
    fields = []
    raw_fields = raw.get("fields", {})
    if not isinstance(raw_fields, dict):
        raise ConfigError(f"{where}.fields: must be a table of field = \"regex\"")
    for name, pattern in raw_fields.items():
        if not isinstance(pattern, str):
            raise ConfigError(f"{where}.fields.{name}: expected a regex string, got {pattern!r}")
        try:
            # names compare case-insensitively: 'servicename' must not quietly miss 'ServiceName'
            fields.append((str(name).lower(), re.compile(pattern, re.IGNORECASE)))
        except re.error as exc:
            raise ConfigError(f"{where}.fields.{name}: invalid regex {pattern!r}: {exc}") from None
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
        fields=tuple(fields),
        expires=_date(raw.get("expires"), f"{where}.expires"),
    )
    if not (entry.users or entry.hosts or entry.networks or entry.source_hosts or entry.fields):
        raise ConfigError(f"{where}: needs at least one of users, hosts, sources or fields; "
                          "to silence a rule entirely use rules.disable")
    return entry


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
        '# rules = ["CW-001", "CW-012"]                    # optional, default: all',
        '# users = ["CORP\\\\svc_sccm"]                     # globs; bare name = any domain',
        '# hosts = ["WKS*"]                                # target host globs',
        '# sources = ["10.0.5.0/24", "SCCM01"]             # client IP/CIDR or host glob',
        "# expires = 2026-12-31                            # optional; ignored after this date",
        "# [allow.fields]                                  # regex on evidence event fields",
        '# ServiceName = "^ccmsetup$"',
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
