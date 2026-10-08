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


def test_crabwalk_side_runs_in_process():
    demo = Path(__file__).resolve().parent.parent / "demo" / "evtx" / "LM_renamed_psexecsvc_5145.evtx"
    s = bench.summarize(bench.run_crabwalk(demo))
    assert (s["medium_plus"], s["lateral_medium_plus"]) == (1, 1)
