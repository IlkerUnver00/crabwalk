"""Export findings as a MITRE ATT&CK Navigator layer.

The layer JSON opens directly in https://mitre-attack.github.io/attack-navigator/
as a heatmap over the ATT&CK matrix — a compact, recognisable way to show which
techniques an intrusion touched.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from typing import Any

from .attack import technique_name
from .rules.base import Finding

# Green -> red ramp; count is normalised onto this gradient by the Navigator.
_GRADIENT = ["#8ec843", "#eda100", "#e34948"]


def build_layer(
    findings: Iterable[Finding], *, name: str = "crabwalk lateral movement"
) -> dict[str, Any]:
    """Scores per technique, laid out so sub-techniques are visible.

    Most detections map to sub-techniques (T1021.002, T1003.006). The
    Navigator collapses those under their parent and leaves the parent
    uncoloured, so a layer of sub-technique scores looks almost empty. Each
    parent is therefore listed with its sub-techniques expanded, and parents
    show the highest score among their sub-techniques.
    """
    findings = list(findings)
    counts = Counter(t for f in findings for t in f.techniques)
    parents = sorted({t.split(".", 1)[0] for t in counts if "." in t})
    techniques = []
    for technique_id, count in sorted(counts.items()):
        rules = sorted({f.rule_id for f in findings if technique_id in f.techniques})
        techniques.append(
            {
                "techniqueID": technique_id,
                "score": count,
                "comment": f"{count} finding(s) via {', '.join(rules)}",
                "enabled": True,
                "showSubtechniques": technique_id in parents,
                "metadata": [{"name": "technique", "value": technique_name(technique_id)}],
            }
        )
    for parent in parents:
        if parent not in counts:
            subs = sorted(t for t in counts if t.startswith(parent + "."))
            techniques.append({
                "techniqueID": parent,
                "enabled": True,
                "showSubtechniques": True,
                "comment": f"detected sub-techniques: {', '.join(subs)}",
            })

    high = max(counts.values()) if counts else 1
    return {
        "name": name,
        "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": (
            f"crabwalk detections: {len(findings)} findings across "
            f"{len(counts)} techniques."
        ),
        "techniques": techniques,
        "gradient": {"colors": _GRADIENT, "minValue": 0, "maxValue": high},
        "legendItems": [],
        "sorting": 3,  # descending by score
        "layout": {
            "layout": "side",
            "showID": True,
            "showName": True,
            "showAggregateScores": True,  # parents take their sub-techniques' max
            "aggregateFunction": "max",
            "countUnscored": False,
            "expandedSubtechniques": "annotated",
        },
        "hideDisabled": False,
    }
