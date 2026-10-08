"""scripts/benchmark.py: the yardstick it applies to every tool's output.

Running the benchmark needs the Hayabusa and Chainsaw releases; these tests
only pin the criteria, so a change to them shows up here and in the docs.
"""

import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "benchmark", Path(__file__).resolve().parent.parent / "scripts" / "benchmark.py")
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


def test_levels_are_normalized_across_tools():
    assert bench.level("info") == bench.level("Informational") == "informational"
    assert bench.level("med") == "medium"
    assert bench.level("emergency") == bench.level("crit") == "critical"
    assert bench.level("whatever") == "informational"  # unknown never inflates a count


def test_lateral_means_the_tactic_or_one_of_its_techniques():
    assert bench.is_lateral(["Lateral Movement"], [])  # Hayabusa, abbreviations off
    assert bench.is_lateral(["LatMov"], [])  # Hayabusa, abbreviated
    assert bench.is_lateral(["lateral-movement"], [])  # Chainsaw / Sigma tag
    assert bench.is_lateral([], ["T1021.002"]) and bench.is_lateral([], ["T1570"])
    assert not bench.is_lateral(["Execution"], ["T1569.002", "T1047"])


def test_summary_counts_medium_and_above():
    alerts = [bench.alert("high", "a", [], ["T1021.002"]), bench.alert("medium", "b", [], []),
              bench.alert("low", "c", ["lateral-movement"], []), bench.alert("informational", "d", [], [])]
    s = bench.summarize(alerts)
    assert (s["alerts"], s["medium_plus"], s["lateral_medium_plus"]) == (4, 2, 1)
    assert s["by_level"] == {"informational": 1, "low": 1, "medium": 1, "high": 1}
    assert s["titles_medium_plus"] == [("a", 1), ("b", 1)]
    assert s["titles_lateral_medium_plus"] == [("a", 1)]  # the low lateral alert does not count


def test_files_are_grouped_by_their_top_subfolder():
    assert bench.group_of("TA0008-Lateral Movement/T1021.002-SMB/ID5145-x.evtx") == "TA0008-Lateral Movement"
    assert bench.group_of("LM_renamed_psexecsvc_5145.evtx") == "."  # a flat folder is one group


def test_engine_rows_are_reused_only_from_the_same_corpus_and_versions(tmp_path):
    import json

    import pytest

    versions = {"crabwalk": "0.1.0", "hayabusa": "Hayabusa v4.1.0", "chainsaw": "chainsaw 2.16.5"}
    row = {"alerts": 1}
    prior = tmp_path / "prior.json"
    prior.write_text(json.dumps({"meta": {"corpus_commit": "abc", "versions": versions}, "files": [
        {"file": "a.evtx", "tools": {"crabwalk": row, "hayabusa": row, "chainsaw": row}}]}))
    assert bench._reusable_rows(prior, "abc", versions) == {"a.evtx": {"hayabusa": row, "chainsaw": row}}
    assert bench._reusable_rows(prior, "abc", {**versions, "crabwalk": "0.2.0"})  # crabwalk may change
    with pytest.raises(SystemExit):
        bench._reusable_rows(prior, "def", versions)
    with pytest.raises(SystemExit):
        bench._reusable_rows(prior, "abc", {**versions, "hayabusa": "Hayabusa v4.2.0"})


def test_crabwalk_side_runs_in_process():
    demo = Path(__file__).resolve().parent.parent / "demo" / "evtx" / "LM_renamed_psexecsvc_5145.evtx"
    s = bench.summarize(bench.run_crabwalk(demo))
    assert (s["medium_plus"], s["lateral_medium_plus"]) == (1, 1)
