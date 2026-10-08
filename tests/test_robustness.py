"""Damaged inputs must never abort a run: a triage image routinely contains
zero-byte, locked, truncated or non-EVTX files next to good ones."""

import json
import os

import pytest

import crabwalk.parser as parser_mod
from crabwalk.cli import main
from crabwalk.parser import EVTX_CHUNK, EVTX_HEADER, ParseStats, iter_events, read_error_budget

REAL_PARSER = parser_mod.PyEvtxParser
FOREVER = object()  # script marker: the reader raises on every call, never advancing


def record(record_id: int) -> dict:
    event = {
        "System": {
            "EventID": 4624,
            "Channel": "Security",
            "Computer": "WS01",
            "TimeCreated": {"#attributes": {"SystemTime": "2026-08-01T10:00:00Z"}},
        },
        "EventData": {"TargetLogonId": hex(record_id), "LogonType": "3"},
    }
    return {
        "event_record_id": record_id,
        "timestamp": "2026-08-01 10:00:00 UTC",
        "data": json.dumps({"Event": event}),
    }


class _ScriptedRecords:
    """Iterator that replays a script of records and exceptions."""

    def __init__(self, script: list) -> None:
        self._script = list(script)

    def __iter__(self):
        return self

    def __next__(self):
        if not self._script:
            raise StopIteration
        if self._script[0] is FOREVER:
            raise RuntimeError("damaged chunk")
        item = self._script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


@pytest.fixture
def scripted(monkeypatch):
    """Route files named in the returned dict to a scripted reader; all other
    files still go through the real pyevtx-rs parser."""
    scripts: dict[str, list] = {}

    class _Parser:
        def __init__(self, path: str) -> None:
            self._script = scripts[os.path.basename(path)]

        def records_json(self):
            return _ScriptedRecords(self._script)

    def factory(path: str):
        if os.path.basename(path) in scripts:
            return _Parser(path)
        return REAL_PARSER(path)

    monkeypatch.setattr(parser_mod, "PyEvtxParser", factory)
    return scripts


def touch(directory, name: str, content: bytes = b"") -> None:
    (directory / name).write_bytes(content)


def test_non_evtx_file_is_reported_and_the_run_continues(tmp_path, scripted):
    touch(tmp_path, "garbage.evtx", os.urandom(4096))  # real parser: bad header magic
    touch(tmp_path, "good.evtx")
    scripted["good.evtx"] = [record(1), record(2)]

    stats = ParseStats()
    events = list(iter_events([tmp_path], stats=stats))

    assert len(events) == 2
    assert stats.files == 2
    assert stats.file_errors == 1
    assert "garbage.evtx: cannot open" in stats.file_problems[0]


def test_zero_byte_file_is_reported_not_raised(tmp_path):
    touch(tmp_path, "empty.evtx")  # real parser: OSError reading the header
    stats = ParseStats()
    assert list(iter_events([tmp_path], stats=stats)) == []
    assert stats.file_errors == 1


def sized(directory, name: str, chunks: int) -> None:
    """A file as large as an EVTX with that many chunks (content is irrelevant
    to scripted readers; only the size drives the read-error budget)."""
    with open(directory / name, "wb") as fh:
        fh.seek(EVTX_HEADER + chunks * EVTX_CHUNK - 1)
        fh.write(b"\0")


def test_unreadable_chunk_is_counted_apart_and_reading_continues(tmp_path, scripted):
    touch(tmp_path, "partly-damaged.evtx")
    scripted["partly-damaged.evtx"] = [record(1), RuntimeError("bad chunk"), record(3)]

    stats = ParseStats()
    events = list(iter_events([tmp_path], stats=stats))

    assert [e.record_id for e in events] == [1, 3]
    assert stats.records == 2  # only what the reader produced
    assert stats.read_errors == 1  # a chunk is not one record: never mixed in
    assert stats.skipped == 0
    assert (stats.file_errors, stats.damaged_files) == (0, 1)
    assert stats.file_problems == ["partly-damaged.evtx: partially read, 1 unreadable chunks/records"]


def test_long_damaged_span_does_not_hide_later_chunks(tmp_path, scripted):
    # pyevtx-rs raises once per bad chunk and moves on; 150 bad chunks in a
    # 200-chunk file must not cost the good records that follow them.
    sized(tmp_path, "carved.evtx", chunks=200)
    scripted["carved.evtx"] = [record(1)] + [RuntimeError("bad chunk")] * 150 + [record(2)]

    stats = ParseStats()
    events = list(iter_events([tmp_path], stats=stats))

    assert [e.record_id for e in events] == [1, 2]
    assert stats.read_errors == 150
    assert (stats.file_errors, stats.damaged_files) == (0, 1)


def test_reader_that_never_advances_is_abandoned(tmp_path, scripted):
    sized(tmp_path, "a-stuck.evtx", chunks=30)  # budget 47: overflows the 20-message cap
    touch(tmp_path, "b-good.evtx")
    scripted["a-stuck.evtx"] = [record(1), FOREVER]
    scripted["b-good.evtx"] = [record(7)]

    stats = ParseStats()
    events = list(iter_events([tmp_path], stats=stats))

    budget = read_error_budget(tmp_path / "a-stuck.evtx")
    assert [e.record_id for e in events] == [1, 7]  # keeps what it read, moves on
    assert stats.read_errors == budget + 1
    assert stats.damaged_files == 1
    # the file-level verdict survives even though read errors overflowed the cap
    assert len(stats.errors) == ParseStats._MAX_ERRORS
    assert stats.file_problems == [f"a-stuck.evtx: abandoned after {budget + 1} unreadable chunks/records"]


def test_file_that_opens_but_yields_nothing_is_unreadable(tmp_path, scripted):
    touch(tmp_path, "wrecked.evtx")
    scripted["wrecked.evtx"] = [RuntimeError("Failed to parse chunk header")] * 3

    stats = ParseStats()
    assert list(iter_events([tmp_path], stats=stats)) == []
    assert stats.file_errors == 1
    assert "no record could be read" in stats.file_problems[0]


def test_cli_partial_damage_still_succeeds(tmp_path, scripted, capsys):
    touch(tmp_path, "garbage.evtx", b"not an evtx file at all")
    touch(tmp_path, "good.evtx")
    scripted["good.evtx"] = [record(1)]

    assert main(["hunt", str(tmp_path)]) == 0
    out, err = capsys.readouterr()
    assert "unreadable: 1" in out
    assert "cannot open" in err


def test_cli_fails_when_nothing_could_be_read(tmp_path, capsys):
    touch(tmp_path, "garbage.evtx", b"not an evtx file at all")
    assert main(["parse", str(tmp_path)]) == 1
    assert "cannot open" in capsys.readouterr().err


@pytest.mark.parametrize("command", ["parse", "sessions", "hunt"])
def test_cli_fails_when_files_open_but_nothing_decodes(tmp_path, scripted, capsys, command):
    touch(tmp_path, "wrecked.evtx")
    scripted["wrecked.evtx"] = [RuntimeError("Failed to parse chunk header")] * 4
    assert main([command, str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "unreadable chunks: 4" in out


def test_cli_clean_empty_input_is_not_a_failure(tmp_path):
    assert main(["hunt", str(tmp_path)]) == 0  # no .evtx at all: nothing wrong, nothing found
