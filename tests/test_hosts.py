import pytest

from crabwalk.hosts import (
    HostResolver,
    classify_ip,
    clean_ip,
    is_local_address,
    remote_ip,
    remote_name,
    short_host,
)


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("::ffff:10.0.2.17", "10.0.2.17"),
        ("[::1]", "::1"),
        ("fe80::1%12", "fe80::1"),
        (" 172.16.66.25 ", "172.16.66.25"),
        ("PC01", None),
        ("-", None),
        (None, None),
    ],
)
def test_clean_ip(raw, expected):
    assert clean_ip(raw) == expected


@pytest.mark.parametrize("raw", ["-", "", "::1", "127.0.0.1", "LOCAL", "localhost", "::ffff:127.0.0.1"])
def test_local_addresses(raw):
    assert is_local_address(raw)
    assert remote_ip(raw) is None


def test_remote_ip_and_name():
    assert remote_ip("::ffff:10.0.0.5") == "10.0.0.5"
    assert remote_name("PC02") == "PC02"
    assert remote_name("NULL") is None
    assert remote_name("10.0.0.5") is None


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("\\\\WIN-1.corp.local$", "win-1"),
        ("PC01.example.corp", "pc01"),
        ("PC01$", "pc01"),
        ("10.0.2.17", None),  # never truncate an address to its first octet
        ("NULL", None),
        ("", None),
    ],
)
def test_short_host(raw, expected):
    assert short_host(raw) == expected


@pytest.mark.parametrize("account, machine", [
    ("CORP\\PC01$", True),
    ("PC01$@CORP.LOCAL", True),  # Kerberos UPN form
    ("PC01$", True),
    ("CORP\\admin", False),
    ("admin@CORP.LOCAL", False),
    ("", False),
])
def test_is_machine_account(account, machine):
    from crabwalk.hosts import is_machine_account

    assert is_machine_account(account) is machine


def test_classify_ip():
    assert classify_ip("10.0.0.5") == "internal"
    assert classify_ip("8.8.8.8") == "external"
    assert classify_ip("127.0.0.1") == "loopback"


def test_resolver_learns_address_to_name_and_prefers_fqdn():
    hosts = HostResolver()
    hosts.learn("10.0.2.17", "PC01")
    hosts.learn(name="PC01.example.corp")
    assert hosts.key("10.0.2.17") == "pc01"
    assert hosts.key(name="::ffff:10.0.2.17") == "pc01"
    assert hosts.key(name="pc01.example.corp") == "pc01"
    assert hosts.display("pc01") == "PC01.example.corp"
    assert hosts.addresses("pc01") == ["10.0.2.17"]


def test_resolver_most_frequent_name_wins_and_placeholders_are_ignored():
    hosts = HostResolver()
    hosts.learn("10.0.0.9", "OLDNAME")
    hosts.learn("10.0.0.9", "NEWNAME")
    hosts.learn("10.0.0.9", "NEWNAME")
    hosts.learn("10.0.0.9", "NULL")  # anonymous logons log WorkstationName NULL
    assert hosts.key("10.0.0.9") == "newname"


def test_resolver_unknown_address_is_its_own_node():
    hosts = HostResolver()
    assert hosts.key("192.0.2.10") == "ip:192.0.2.10"
    assert hosts.display("ip:192.0.2.10") == "192.0.2.10"
    assert hosts.key("-", "") is None
