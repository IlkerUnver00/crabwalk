from datetime import datetime, timedelta, timezone

from crabwalk.catalog import SECURITY, TS_LSM
from crabwalk.models import NormalizedEvent
from crabwalk.sessions import build_sessions, norm_logon_id

T0 = datetime(2026, 8, 1, 12, 0, 0, tzinfo=timezone.utc)


def ev(event_id, *, minutes=0, computer="WS01", channel=SECURITY, **data):
    return NormalizedEvent(
        timestamp=T0 + timedelta(minutes=minutes),
        channel=channel,
        provider="test",
        event_id=event_id,
        record_id=1,
        computer=computer,
        data=data,
        source_file="test.evtx",
    )


def remote_logon(logon_id="0x3E7A", minutes=0, computer="SRV01", user="admin", **extra):
    data = {
        "TargetLogonId": logon_id,
        "TargetUserName": user,
        "TargetDomainName": "CORP",
        "LogonType": "3",
        "IpAddress": "10.0.0.5",
        "WorkstationName": "WS01",
        "AuthenticationPackageName": "NTLM",
    }
    data.update(extra)
    return ev(4624, minutes=minutes, computer=computer, **data)


def test_remote_logon_creates_session_and_edge():
    result = build_sessions([remote_logon()])
    session = result.sessions[("SRV01", "0x3e7a")]
    assert session.user == "CORP\\admin"
    assert session.logon_type == 3
    assert session.is_remote
    assert not session.privileged
    (edge,) = result.edges
    assert edge.src == "10.0.0.5 (WS01)"
    assert edge.dst == "SRV01"
    assert edge.kind == "network"


def test_local_logon_creates_no_edge():
    event = remote_logon(IpAddress="-", WorkstationName="-")
    result = build_sessions([event])
    assert result.edges == []
    assert not result.sessions[("SRV01", "0x3e7a")].is_remote


def test_privilege_backfill_marks_session_and_edge():
    events = [
        remote_logon(),
        ev(4672, minutes=0, computer="SRV01", SubjectLogonId="0x3E7A"),
    ]
    result = build_sessions(events)
    assert result.sessions[("SRV01", "0x3e7a")].privileged
    assert result.edges[0].privileged
    assert result.privileged_remote_sessions()


def test_out_of_order_privileges_before_logon():
    events = [
        ev(4672, computer="SRV01", SubjectLogonId="0x3E7A", SubjectUserName="admin"),
        remote_logon(),
    ]
    result = build_sessions(events)
    session = result.sessions[("SRV01", "0x3e7a")]
    assert session.privileged
    assert session.user == "CORP\\admin"  # 4624 overwrites the 4672 fallback


def test_logoff_closes_session():
    events = [
        remote_logon(),
        ev(4634, minutes=30, computer="SRV01", TargetLogonId="0x3E7A"),
    ]
    session = build_sessions(events).sessions[("SRV01", "0x3e7a")]
    assert session.duration_seconds == 30 * 60


def test_sessions_are_scoped_per_host():
    events = [remote_logon(computer="SRV01"), remote_logon(computer="SRV02")]
    result = build_sessions(events)
    assert len(result.sessions) == 2


def test_machine_account_flagged():
    result = build_sessions([remote_logon(user="WS01$")])
    assert result.sessions[("SRV01", "0x3e7a")].is_machine_account
    assert result.edges[0].is_machine_account


def test_rdp_session_event_creates_edge():
    event = ev(
        21, channel=TS_LSM, computer="SRV01", User="CORP\\admin", Address="10.0.0.5"
    )
    (edge,) = build_sessions([event]).edges
    assert edge.kind == "rdp-session"
    assert edge.logon_type == 10
    assert edge.dst == "SRV01"


def test_rdp_session_from_local_address_ignored():
    event = ev(21, channel=TS_LSM, computer="SRV01", User="CORP\\admin", Address="LOCAL")
    assert build_sessions([event]).edges == []


def test_explicit_credentials_outbound_edge():
    event = ev(
        4648,
        computer="WS01",
        SubjectLogonId="0x111",
        TargetUserName="admin",
        TargetDomainName="CORP",
        TargetServerName="SRV01.corp.local",
    )
    (edge,) = build_sessions([event]).edges
    assert edge.kind == "explicit-credentials"
    assert edge.src_host == "WS01"
    assert edge.dst == "SRV01.corp.local"


def test_explicit_credentials_to_localhost_ignored():
    event = ev(4648, computer="WS01", TargetServerName="localhost", TargetUserName="x")
    assert build_sessions([event]).edges == []


def test_norm_logon_id_variants():
    assert norm_logon_id("0x3E7") == "0x3e7"
    assert norm_logon_id("999") == "0x3e7"
    assert norm_logon_id(999) == "0x3e7"
    assert norm_logon_id("-") is None
    assert norm_logon_id(None) is None
