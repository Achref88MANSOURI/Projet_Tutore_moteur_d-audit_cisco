#!/usr/bin/env python3
"""Validate catalogue structure and its 744-dependency bridge (stdlib only)."""
from __future__ import annotations
import sys
from pathlib import Path
from collections import Counter, defaultdict
import json


def validate(root: Path) -> None:
    directory = root / "audit" / "catalog"
    catalogue = json.loads((directory / "cis_ios15_v4_1_1.json").read_text(encoding="utf-8"))
    bridge = json.loads((directory / "cis_ios15_v4_1_1_dependency_bridge.json").read_text(encoding="utf-8"))
    manifest = json.loads((directory / "cis_ios15_rule_manifest.json").read_text(encoding="utf-8"))
    controls = catalogue["controls"]
    deps = bridge["dependencies"]
    assert len(controls) == 90, ("controls", len(controls))
    assert len(deps) == 744, ("dependencies", len(deps))
    assert len(manifest["rules"]) == 90
    ids = {x["id"] for x in controls}
    assert len(ids) == 90, "duplicate control ID"
    assert all(x["assessment"] in ("Automated", "Manual") for x in controls)
    assert Counter(x["assessment"] for x in controls) == {"Automated": 87, "Manual": 3}
    assert Counter(x["profile_level"] for x in controls) == {"Level 1": 53, "Level 2": 37}
    assert len({x["dependency_id"] for x in deps}) == 744, "duplicate dependency ID"
    assert all(x["control_id"] in ids for x in deps), "orphan dependency"
    linked = defaultdict(list)
    for dep in deps:
        linked[dep["control_id"]].append(dep["dependency_id"])
    for control in controls:
        assert len(linked[control["id"]]) == control["dependency_count"]
        assert set(linked[control["id"]]) == set(control["dependency_ids"])
        assert control["source"]["pdf_page_end"] >= control["source"]["pdf_page_start"]
        assert control["source"]["pdf_page_start"] >= 1
        assert control["audit"] and control["remediation"]
    print("OK: 90 controls, 87 automated/3 manual, 53 level 1/37 level 2, 744 unique mapped dependencies, 90 rule stubs.")
    byfamily = defaultdict(lambda: {"controls": 0, "dependencies": 0})
    for x in controls:
        byfamily[x["family"]]["controls"] += 1
        byfamily[x["family"]]["dependencies"] += x["dependency_count"]
    for f, counts in sorted(byfamily.items()):
        print(f"  {f}: {counts['controls']} controls, {counts['dependencies']} dependencies")


if __name__ == "__main__":
    base = Path(__file__).resolve().parents[1]
    validate(base)
