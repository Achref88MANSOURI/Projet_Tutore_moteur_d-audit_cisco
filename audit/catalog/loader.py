"""Read-only catalogue of CIS Cisco IOS 15 v4.1.1 recommendations.

This module only loads source-derived metadata and a frozen dependency bridge.
It does not evaluate compliance and does not execute remediation commands.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any
import json

_ROOT = Path(__file__).resolve().parent


class CISIOS15Catalog:
    def __init__(self, directory: str | Path | None = None):
        directory = Path(directory) if directory is not None else _ROOT
        catalog = json.loads((directory / "cis_ios15_v4_1_1.json").read_text(encoding="utf-8"))
        bridge = json.loads((directory / "cis_ios15_v4_1_1_dependency_bridge.json").read_text(encoding="utf-8"))
        self.metadata: dict[str, Any] = catalog["metadata"]
        self.controls: list[dict[str, Any]] = catalog["controls"]
        self.dependencies: list[dict[str, Any]] = bridge["dependencies"]
        self._control_lookup = {x["id"]: x for x in self.controls}
        self._dependency_lookup: dict[str, list[dict[str, Any]]] = {}
        for dependency in self.dependencies:
            self._dependency_lookup.setdefault(dependency["control_id"], []).append(dependency)

    def control(self, control_id: str) -> dict[str, Any]:
        """Get metadata for a benchmark control, e.g. '1.5.9'."""
        return self._control_lookup[control_id]

    def dependencies_for_control(self, control_id: str) -> list[dict[str, Any]]:
        """Get all mapped Fxx dependencies for a benchmark control."""
        return list(self._dependency_lookup.get(control_id, []))

    def controls_for_family(self, family: str) -> list[dict[str, Any]]:
        return [x for x in self.controls if x["family"] == family]

    def controls_for_profile(self, level: int, *, include_lower: bool = True) -> list[dict[str, Any]]:
        """Level 2 extends level 1 in the CIS benchmark.
        
        When include_lower=False, only controls exactly matching the requested level are returned.
        """
        if level not in (1, 2):
            raise ValueError("level must be 1 or 2")
        if include_lower:
            return [x for x in self.controls
                    if int(x["profile_level"].split()[-1]) <= level]
        else:
            return [x for x in self.controls
                    if int(x["profile_level"].split()[-1]) == level]

    def counts_by_family(self) -> dict[str, dict[str, int]]:
        counts = collections.defaultdict(lambda: {"controls": 0, "dependencies": 0})
        for item in self.controls:
            counts[item["family"]]["controls"] += 1
            counts[item["family"]]["dependencies"] += item["dependency_count"]
        return dict(sorted(counts.items()))


# Import only the modules used by the above functions.
import collections
