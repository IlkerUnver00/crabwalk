import json
from datetime import datetime, timezone

import pytest

from crabwalk.parser import flatten_payload, parse_record, parse_timestamp, scalar


def make_record(event: dict) -> dict:
    return {
        "event_record_id": 42,
        "timestamp": "2026-08-01 10:20:30.123456 UTC",
        "data": json.dumps({"Event": event}),
    }


SYSTEM = {
    # Real pyevtx-rs shape: XML attributes nested under "#attributes".
    "Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing"}},
    "EventID": 4624,
    "TimeCreated": {"#attributes": {"SystemTime": "2026-08-01T10:20:30.123456Z"}},
    "EventRecordID": 42,
    "Channel": "Security",
    "Computer": "WS01.corp.local",
    "Security": {"#attributes": {"UserID": "S-1-5-18"}},
}


def test_parse_record_maps_system_fields():
    event = parse_record(
        make_record(
            {"System": SYSTEM, "EventData": {"TargetUserName": "alice", "LogonType": "3"}}
        ),
        source_file="Security.evtx",
    )
    assert event.event_id == 4624
    assert event.channel == "Security"
    assert event.provider == "Microsoft-Windows-Security-Auditing"
    assert event.computer == "WS01.corp.local"
    assert event.record_id == 42
    assert event.user_sid == "S-1-5-18"
    # SystemTime wins over the record-level timestamp.
    assert event.timestamp == datetime(2026, 8, 1, 10, 20, 30, 123456, tzinfo=timezone.utc)
    assert event.data["TargetUserName"] == "alice"
    assert event.get("LogonType") == "3"


def test_record_id_is_the_event_record_id_not_the_position_in_the_file():
    # A filtered export renumbers its records; EventRecordID is what Event Viewer shows.
    record = make_record({"System": dict(SYSTEM, EventRecordID=84050)})
    record["event_record_id"] = 20
    event = parse_record(record, source_file="Security.evtx")
    assert (event.record_id, event.record_number) == (84050, 20)
    assert json.loads(event.to_json())["record_number"] == 20


def test_record_id_falls_back_to_the_position_without_an_event_record_id():
    system = {k: v for k, v in SYSTEM.items() if k != "EventRecordID"}
    event = parse_record(make_record({"System": system}), source_file="Security.evtx")
    assert (event.record_id, event.record_number) == (42, 42)


def test_copies_in_differently_filtered_exports_collapse():
    from crabwalk.parser import dedup_events

    copies = []
    for position in (14, 1):  # the same 4698 as record 14 of one export, record 1 of another
        record = make_record({"System": dict(SYSTEM, EventID=4698, EventRecordID=566836)})
        record["event_record_id"] = position
        copies.append(parse_record(record, source_file=f"export{position}.evtx"))
    assert len(dedup_events(copies)) == 1


def test_timestamp_falls_back_to_record_when_systemtime_null():
    system = dict(SYSTEM)
    system.pop("TimeCreated")
    record = make_record({"System": system})
    record["timestamp"] = "2026-08-01 10:20:30.123456 UTC"
    event = parse_record(record, source_file="Security.evtx")
    assert event.timestamp == datetime(2026, 8, 1, 10, 20, 30, 123456, tzinfo=timezone.utc)


def test_systemtime_preferred_over_null_record_timestamp():
    # The real-world bug: record ts is FILETIME-null but SystemTime is valid.
    record = make_record({"System": SYSTEM})
    record["timestamp"] = "1601-01-01T00:00:00Z UTC"
    event = parse_record(record, source_file="Security.evtx")
    assert event.timestamp.year == 2026


def test_attributes_accepts_legacy_at_prefixed_form():
    from crabwalk.parser import attributes

    assert attributes({"#attributes": {"Name": "x"}}) == {"Name": "x"}
    assert attributes({"@Name": "x"}) == {"Name": "x"}
    assert attributes(None) == {}


def test_event_id_with_qualifiers_wrapper():
    system = dict(SYSTEM, EventID={"#text": 7045, "@Qualifiers": 16384}, Channel="System")
    event = parse_record(make_record({"System": system}), source_file="System.evtx")
    assert event.event_id == 7045
    assert event.data == {}


def test_flatten_unwraps_userdata_wrapper():
    payload = flatten_payload(
        {"UserData": {"EventXML": {"Param1": "svc", "@xmlns": "ignored"}}}
    )
    assert payload == {"Param1": "svc"}


def test_flatten_merges_eventdata_text_nodes():
    payload = flatten_payload(
        {"EventData": {"ServiceName": {"#text": "evil"}, "StartType": "auto"}}
    )
    assert payload == {"ServiceName": "evil", "StartType": "auto"}


def test_parse_timestamp_iso_with_100ns_precision():
    # pyevtx-rs >= 0.8 emits ISO timestamps with 7 fractional digits
    assert parse_timestamp("2026-08-07T19:00:02.0206079Z UTC") == datetime(
        2026, 8, 7, 19, 0, 2, 20607, tzinfo=timezone.utc
    )


def test_parse_timestamp_without_fraction():
    assert parse_timestamp("2026-08-01 10:20:30 UTC") == datetime(
        2026, 8, 1, 10, 20, 30, tzinfo=timezone.utc
    )


def test_parse_timestamp_rejects_garbage():
    with pytest.raises(ValueError):
        parse_timestamp("yesterday")


def test_dedup_events_drops_same_record_from_overlapping_exports():
    from crabwalk.models import NormalizedEvent
    from crabwalk.parser import dedup_events

    def rec(record_id, source):
        return NormalizedEvent(
            timestamp=datetime(2026, 8, 1, tzinfo=timezone.utc),
            channel="Security", provider="p", event_id=4624, record_id=record_id,
            computer="WS01", data={}, source_file=source,
        )

    # same (computer, channel, record_id, ts) from two files -> one
    events = [rec(5, "a.evtx"), rec(5, "b.evtx"), rec(6, "a.evtx")]
    out = dedup_events(events)
    assert len(out) == 2
    assert {e.record_id for e in out} == {5, 6}


@pytest.mark.parametrize(
    "target, kept",
    [
        (r"HKLM\System\CurrentControlSet\services\hello\ImagePath", True),
        (r"HKLM\SYSTEM\ControlSet001\Services\PSEXESVC\ImagePath", True),
        (r"HKLM\System\CurrentControlSet\services\hello\Start", False),
        (r"HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run\x", False),
    ],
)
def test_sysmon_13_kept_only_for_service_image_path(target, kept):
    from crabwalk.catalog import SYSMON, keep_event
    from crabwalk.models import NormalizedEvent

    event = NormalizedEvent(
        timestamp=datetime(2026, 8, 1, tzinfo=timezone.utc), channel=SYSMON,
        provider="p", event_id=13, record_id=1, computer="WS01",
        data={"TargetObject": target}, source_file="s.evtx",
    )
    assert keep_event(event) is kept


def test_scalar_unwraps_text_nodes():
    assert scalar({"#text": 5}) == 5
    assert scalar("plain") == "plain"
