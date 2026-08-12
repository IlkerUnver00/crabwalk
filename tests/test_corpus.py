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

from crabwalk.parser import iter_events
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


def test_corpus_parses_without_errors():
    """Every sample in the corpus must parse cleanly (no unparsable records)."""
    assert CORPUS is not None
    from crabwalk.parser import ParseStats

    stats = ParseStats()
    # Consume a bounded slice so the smoke test stays fast but broad.
    count = 0
    for _ in iter_events([CORPUS], keep_all=True, stats=stats):
        count += 1
    assert stats.records > 0
    assert stats.skipped == 0, f"{stats.skipped} unparsable records: {stats.errors[:5]}"
