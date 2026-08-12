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
    findings = list(findings)
    counts = Counter(t for f in findings for t in f.techniques)
    techniques = []
    for technique_id, count in sorted(counts.items()):
        rules = sorted({f.rule_id for f in findings if technique_id in f.techniques})
        techniques.append(
            {
                "techniqueID": technique_id,
                "score": count,
                "comment": f"{count} finding(s) via {', '.join(rules)}",
                "enabled": True,
                "metadata": [{"name": "technique", "value": technique_name(technique_id)}],
            }
        )

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
        "layout": {"layout": "side", "showID": True, "showName": True},
        "hideDisabled": False,
    }
