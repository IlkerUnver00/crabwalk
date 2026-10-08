"""Ground-truth corpus validation against sbousseaden/EVTX-ATTACK-SAMPLES.

Each entry is a sample whose *filename* documents the technique it demonstrates;
the test asserts crabwalk maps it to the expected ATT&CK technique. This is the
regression net: a rule change that stops detecting a known attack fails here.

The corpus is not vendored (it is gitignored). Point CRABWALK_SAMPLES at a clone
of EVTX-ATTACK-SAMPLES, or drop it under ``samples/EVTX-ATTACK-SAMPLES``; absent
that, these tests skip so the unit suite still runs anywhere.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from crabwalk.cli import main
from crabwalk.parser import EVTX_CHUNK, EVTX_HEADER, ParseStats, iter_events
from crabwalk.rules import hunt


def _corpus_root() -> Path | None:
    env = os.environ.get("CRABWALK_SAMPLES")
    candidates = [Path(env)] if env else []
    candidates.append(Path(__file__).resolve().parent.parent / "samples" / "EVTX-ATTACK-SAMPLES")
    for path in candidates:
        if path.is_dir():
            return path
    return None


CORPUS = _corpus_root()

# (relative path under the corpus, expected ATT&CK technique, expected rule)
GROUND_TRUTH: list[tuple[str, str, str]] = [
    ("Lateral Movement/LM_4624_mimikatz_sekurlsa_pth_source_machine.evtx", "T1550.002", "CW-003"),
    ("Lateral Movement/remote task update 4624 4702 same logonid.evtx", "T1053.005", "CW-004"),
    ("Lateral Movement/LM_renamed_psexecsvc_5145.evtx", "T1021.002", "CW-005"),
    ("Lateral Movement/LM_REMCOM_5145_TargetHost.evtx", "T1570", "CW-005"),
    ("Credential Access/sysmon_10_1_memdump_comsvcs_minidump.evtx", "T1047", "CW-006"),
    ("Lateral Movement/LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx", "T1021.006", "CW-007"),
    ("Other/emotet/exec_emotet_ps_4104.evtx", "T1059.001", "CW-008"),
    ("Defense Evasion/DE_1102_security_log_cleared.evtx", "T1070.001", "CW-009"),
    ("Defense Evasion/DE_104_system_log_cleared.evtx", "T1070.001", "CW-009"),
    ("Credential Access/CA_DCSync_4662.evtx", "T1003.006", "CW-011"),
    # CW-012 across both telemetry sources: Sysmon 17/18 and Security 5145 IPC$
    ("Defense Evasion/DE_renamed_psexec_service_sysmon_17_18.evtx", "T1569.002", "CW-012"),
    ("Lateral Movement/LM_renamed_psexecsvc_5145.evtx", "T1569.002", "CW-012"),
    ("Lateral Movement/LM_sysmon_psexec_smb_meterpreter.evtx", "T1543.003", "CW-012"),
    ("Lateral Movement/lm_sysmon_18_remshell_over_namedpipe.evtx", "T1021.002", "CW-012"),
    ("Lateral Movement/LM_ScheduledTask_ATSVC_target_host.evtx", "T1053.005", "CW-012"),
    ("Lateral Movement/LM_Remote_Service01_5145_svcctl.evtx", "T1021.002", "CW-012"),
]

# (relative path, rule that must stay quiet): attacker activity of a different
# kind that a sloppy rule would mislabel. This is the precision half of the net.
NEGATIVE_TRUTH: list[tuple[str, str]] = [
    ("Discovery/Discovery_Remote_System_NamedPipes_Sysmon_18.evtx", "CW-012"),  # pipe sweep
    ("Discovery/discovery_bloodhound.evtx", "CW-012"),  # samr/lsarpc/srvsvc over IPC$
    ("Discovery/discovery_psloggedon.evtx", "CW-012"),
    ("Credential Access/remote_sam_registry_access_via_backup_operator_priv.evtx", "CW-012"),
]

pytestmark = pytest.mark.skipif(
    CORPUS is None, reason="EVTX-ATTACK-SAMPLES not present (set CRABWALK_SAMPLES)"
)


@pytest.mark.parametrize("relpath,technique,rule_id", GROUND_TRUTH, ids=lambda v: v)
def test_known_sample_detected(relpath: str, technique: str, rule_id: str):
    assert CORPUS is not None
    sample = CORPUS / relpath
    if not sample.is_file():
        pytest.skip(f"missing sample: {relpath}")
    _, findings = hunt(iter_events([sample]))
    techniques = {t for f in findings for t in f.techniques}
    rules = {f.rule_id for f in findings}
    assert technique in techniques, f"{relpath}: expected {technique}, got {sorted(techniques)}"
    assert rule_id in rules, f"{relpath}: expected rule {rule_id}, got {sorted(rules)}"


@pytest.mark.parametrize("relpath,rule_id", NEGATIVE_TRUTH, ids=lambda v: v)
def test_known_sample_does_not_trigger(relpath: str, rule_id: str):
    assert CORPUS is not None
    sample = CORPUS / relpath
    if not sample.is_file():
        pytest.skip(f"missing sample: {relpath}")
    _, findings = hunt(iter_events([sample]))
    fired = [f.summary for f in findings if f.rule_id == rule_id]
    assert not fired, f"{relpath}: {rule_id} should stay quiet, fired: {fired}"


def test_psexec_pipe_names_reveal_the_source_host():
    """The target's own 5145 log names the machine PsExec ran on."""
    assert CORPUS is not None
    sample = CORPUS / "Lateral Movement/LM_renamed_psexecsvc_5145.evtx"
    if not sample.is_file():
        pytest.skip("missing sample")
    _, findings = hunt(iter_events([sample]))
    (finding,) = [f for f in findings if f.rule_id == "CW-012"]
    assert (finding.src_ip, finding.src_host) == ("10.0.2.16", "NLLT108334")
    assert finding.severity == "critical"
    assert "T1021.002" in finding.techniques


@pytest.mark.parametrize(
    "relpath",
    [
        "Defense Evasion/DE_renamed_psexec_service_sysmon_17_18.evtx",  # PsExec.exe on the box
        "Privilege Escalation/sysmon_privesc_psexec_dwell.evtx",  # local PSEXESVC pipe squat
    ],
)
def test_local_psexec_is_not_called_lateral_movement(relpath: str):
    assert CORPUS is not None
    sample = CORPUS / relpath
    if not sample.is_file():
        pytest.skip(f"missing sample: {relpath}")
    _, findings = hunt(iter_events([sample]))
    (finding,) = [f for f in findings if f.rule_id == "CW-012"]
    assert finding.title.startswith("Local execution")
    assert "T1021.002" not in finding.techniques
    assert finding.src_ip is None and finding.src_host is None


def _sample_bytes(relpath: str) -> bytes:
    assert CORPUS is not None
    sample = CORPUS / relpath
    if not sample.is_file():
        pytest.skip(f"missing sample: {relpath}")
    return sample.read_bytes()


def _decoded(path: Path) -> ParseStats:
    stats = ParseStats()
    for _ in iter_events([path], keep_all=True, stats=stats):
        pass
    return stats


def test_real_damaged_span_keeps_the_good_chunks_after_it(tmp_path):
    """Real pyevtx-rs behavior: one failure per bad chunk, then it moves on."""
    data = _sample_bytes("Lateral Movement/LM_5145_Remote_FileCopy.evtx")
    header, good = data[:EVTX_HEADER], data[EVTX_HEADER:EVTX_HEADER + 3 * EVTX_CHUNK]
    (tmp_path / "good.evtx").write_bytes(header + good)
    (tmp_path / "carved.evtx").write_bytes(header + good + b"Z" * (120 * EVTX_CHUNK) + good)

    baseline = _decoded(tmp_path / "good.evtx").decoded
    stats = _decoded(tmp_path / "carved.evtx")
    assert baseline > 0
    assert stats.decoded == 2 * baseline  # nothing after the damaged span is lost
    assert stats.read_errors >= 120
    assert (stats.file_errors, stats.damaged_files) == (0, 1)


def test_real_file_with_every_chunk_header_destroyed_fails_the_run(tmp_path, capsys):
    data = bytearray(_sample_bytes("Lateral Movement/LM_5145_Remote_FileCopy.evtx"))
    for offset in range(EVTX_HEADER, len(data), EVTX_CHUNK):
        data[offset:offset + 8] = b"XXXXXXXX"  # was b"ElfChnk\0"
    (tmp_path / "wrecked.evtx").write_bytes(bytes(data))

    assert main(["hunt", str(tmp_path)]) == 1
    assert "no record could be read" in capsys.readouterr().err


def test_corpus_parses_without_errors():
    """Every sample in the corpus must parse cleanly (no unparsable records)."""
    assert CORPUS is not None
    stats = ParseStats()
    # Consume a bounded slice so the smoke test stays fast but broad.
    count = 0
    for _ in iter_events([CORPUS], keep_all=True, stats=stats):
        count += 1
    assert stats.records > 0
    assert stats.file_errors == stats.damaged_files == 0, f"file problems: {stats.file_problems}"
    assert stats.read_errors == 0, f"{stats.read_errors} unreadable chunks: {stats.errors[:5]}"
    assert stats.skipped == 0, f"{stats.skipped} unparsable records: {stats.errors[:5]}"
