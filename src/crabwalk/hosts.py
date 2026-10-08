"""Host identity: normalizing the many ways Windows logs name a machine.

The same box shows up as ``WIN-77LTAPHIQ1R.example.corp`` (Computer),
``WIN-77LTAPHIQ1R`` (WorkstationName), ``10.0.2.17`` or
``::ffff:10.0.2.17`` (IpAddress), ``\\\\PC01`` (UNC) or ``PC01$`` (machine
account). Cross-host correlation only works once those collapse to one key.
"""

from __future__ import annotations

import ipaddress
from collections import Counter, defaultdict

#: Values logs use to mean "no address / no name".
PLACEHOLDERS = {"", "-", "?", "null", "none", "localhost", "local", "127.0.0.1", "::1"}


def clean_ip(value: object) -> str | None:
    """Canonical IP string, or None when the value is not an IP address.

    Unwraps IPv4-mapped IPv6 (``::ffff:10.0.2.17``), brackets and zone ids.
    """
    text = str(value or "").strip().strip("[]")
    if not text:
        return None
    text = text.split("%", 1)[0]
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return str(address)


def is_local_address(value: object) -> bool:
    """True for placeholders and loopback: activity that did not cross hosts."""
    text = str(value or "").strip().lower()
    if text in PLACEHOLDERS:
        return True
    ip = clean_ip(text)
    return ip is not None and ipaddress.ip_address(ip).is_loopback


def remote_ip(value: object) -> str | None:
    """Canonical IP if the value is an address of another machine, else None."""
    ip = clean_ip(value)
    return None if ip is None or is_local_address(ip) else ip


def remote_name(value: object) -> str | None:
    """The host name as logged, unless it is a placeholder or an address."""
    return str(value).strip() if short_host(value) else None


def classify_ip(ip: str) -> str:
    """'loopback', 'internal' (private/link-local) or 'external'."""
    address = ipaddress.ip_address(ip)
    if address.is_loopback:
        return "loopback"
    if address.is_private or address.is_link_local:
        return "internal"
    return "external"


def account_name(account: object) -> str:
    """'CORP\\user', 'user@CORP.LOCAL' or 'user' -> 'user'."""
    return str(account or "").strip().split("@", 1)[0].rsplit("\\", 1)[-1]


def is_machine_account(account: object) -> bool:
    """Computer accounts end in '$' whatever form the log uses
    ('CORP\\PC01$', 'PC01$@CORP.LOCAL', 'PC01$')."""
    return account_name(account).endswith("$")


def short_host(name: object) -> str | None:
    """'\\\\WIN-1.corp.local$' -> 'win-1'; IPs and placeholders -> None."""
    text = str(name or "").strip().lstrip("\\").rstrip("$").strip().lower()
    if text in PLACEHOLDERS or clean_ip(text) is not None:
        return None
    return text.split(".", 1)[0] or None


class HostResolver:
    """Collapse names and addresses to one node key per machine.

    Learns IP -> hostname from evidence that carries both (a 4624 has
    IpAddress and WorkstationName; a PsExec stdio pipe names its source). When
    an address was seen with several names (DHCP churn) the most frequent wins.
    """

    def __init__(self) -> None:
        self._ip_names: dict[str, Counter[str]] = defaultdict(Counter)
        self._display: dict[str, Counter[str]] = defaultdict(Counter)

    def learn(self, ip: object = None, name: object = None) -> None:
        short = short_host(name)
        if short:
            self._display[short][str(name).strip().lstrip("\\").rstrip("$")] += 1
        address = clean_ip(ip)
        if address and short and not is_local_address(address):
            self._ip_names[address][short] += 1

    def key(self, ip: object = None, name: object = None) -> str | None:
        """Node key for a (possibly partial) host reference; None when empty or
        local (loopback is this machine, never a separate source)."""
        short = short_host(name)
        if short:
            return short
        address = clean_ip(ip) or clean_ip(name)
        if address is None or is_local_address(address):
            return None
        names = self._ip_names.get(address)
        if names:
            return min(names.items(), key=lambda kv: (-kv[1], kv[0]))[0]
        return f"ip:{address}"

    def display(self, key: str) -> str:
        """Most specific observed name for a key (prefers the FQDN)."""
        if key.startswith("ip:"):
            return key[3:]
        names = self._display.get(key)
        if not names:
            return key
        return min(names.items(), key=lambda kv: (-len(kv[0]), -kv[1], kv[0]))[0]

    def addresses(self, key: str) -> list[str]:
        if key.startswith("ip:"):
            return [key[3:]]
        return sorted(ip for ip, names in self._ip_names.items() if key in names)
