"""Check versioned data integrity offline, including a subset of JSON Schema 2020-12."""
import csv
import hashlib
import json
import re
import subprocess
from collections import Counter

from collect import CACHE, ROOT, dump


def check_schema(value, schema, path="$"):
    if "const" in schema:
        assert value == schema["const"], (path, "const")
    if "enum" in schema:
        assert value in schema["enum"], (path, "enum")
    kind = schema.get("type")
    types = {"object": dict, "array": list, "string": str, "null": type(None)}
    if kind:
        assert isinstance(value, types[kind]), (path, kind)
    if isinstance(value, dict):
        assert set(schema.get("required", [])) <= value.keys(), (path, "missing required keys")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            assert value.keys() <= properties.keys(), (path, "additionalProperties")
        for key, child in value.items():
            if key in properties:
                check_schema(child, properties[key], path + "." + key)
    if isinstance(value, list):
        assert len(value) >= schema.get("minItems", 0), (path, "minItems")
        if schema.get("uniqueItems"):
            assert len({json.dumps(v, sort_keys=True) for v in value}) == len(value), (path, "uniqueItems")
        for index, child in enumerate(value):
            check_schema(child, schema.get("items", {}), f"{path}[{index}]")
    if isinstance(value, str):
        assert len(value) >= schema.get("minLength", 0), (path, "minLength")
        if "pattern" in schema:
            assert re.search(schema["pattern"], value), (path, "pattern")
        if schema.get("format") == "date-time":
            from datetime import datetime
            datetime.fromisoformat(value.replace("Z", "+00:00"))


def read_rows(name):
    return [json.loads(line) for line in (ROOT / name).read_text(encoding="utf-8").splitlines() if line]


def run():
    schema = json.loads((ROOT / "schema.json").read_text(encoding="utf-8"))
    inventory = read_rows("inventory.jsonl")
    excluded, anomalies, reviewed = (read_rows(n) for n in ["excluded.jsonl", "anomalies.jsonl", "reviewed.jsonl"])
    summary = json.loads((ROOT / "summary.json").read_text(encoding="utf-8"))
    sources = json.loads((ROOT / "sources.json").read_text(encoding="utf-8"))
    source_map = {s["url"]: s for s in sources}
    ids = {r["id"] for r in inventory}
    assert len(ids) == len(inventory), "Duplicate occurrence IDs"
    assert inventory and reviewed, "An empty inventory is not a successful collection"
    for row in inventory:
        check_schema(row, schema)
        assert re.search(r"config", " ".join(row["modes"]), re.I), row["id"]
        assert not re.match(r"^(show|debug|clear|copy|write|reload|ping|traceroute|test)\b", row["command"], re.I), row["id"]
        page = row["source"]["url"].split("#")[0]
        assert page in source_map and source_map[page]["status"] == "ok", row["id"]
        assert row["source"]["sha256"] == source_map[page]["sha256"], row["id"]
        forms = sorted({"no" if re.match(r"^no\b", s) else "default" if re.match(r"^default\b", s) else "positive" for s in row["syntaxes"]})
        assert row["documented_forms"] == forms, row["id"]
    for row in reviewed:
        assert set(row["candidate_ids"]) <= ids, row["id"]
        source = source_map[row["source"]["url"]]
        assert source["sha256"] == row["source"]["sha256"], row["id"]
        assert row["full_grammar_verified"] is False
        assert row["confidence"]["universal_platform_release_support"] == "unknown"
    assert len({r["id"] for r in reviewed}) == len(reviewed), "Duplicate reviewed IDs"
    assert summary["candidate_records"] == len(inventory)
    assert summary["unique_command_titles"] == len({r["command"] for r in inventory})
    assert summary["excluded_records"] == len(excluded)
    assert summary["anomalies"] == len(anomalies)
    assert summary["reviewed_example_records"] == len(reviewed)
    assert summary["exhaustive"] is False
    groups = read_rows("syntax_groups.jsonl")
    grouped_ids = [rid for g in groups for rid in g["occurrence_ids"]]
    assert len(grouped_ids) == len(ids) and set(grouped_ids) == ids
    with (ROOT / "inventory.csv").open(encoding="utf-8-sig", newline="") as f:
        assert len(list(csv.DictReader(f))) == len(inventory)
    cached_verified = 0
    for source in sources:
        assert source["url"].startswith("https://www.cisco.com/")
        if source["status"] == "ok":
            assert re.fullmatch(r"[a-f0-9]{64}", source["sha256"])
            cache_path = CACHE / (hashlib.sha256(source["url"].encode()).hexdigest() + ".html")
            if cache_path.exists():
                assert hashlib.sha256(cache_path.read_bytes()).hexdigest() == source["sha256"], source["url"]
                cached_verified += 1
    # The research branch may only add/change this research directory against main.
    project = ROOT.parent.parent
    diff = subprocess.run(["git", "diff", "main...HEAD", "--name-only"], cwd=project, capture_output=True, text=True, check=True).stdout.splitlines()
    staged = subprocess.run(["git", "diff", "--cached", "--name-only"], cwd=project, capture_output=True, text=True, check=True).stdout.splitlines()
    assert all(p.startswith("docs/cisco-command-inventory/") for p in diff + staged), diff + staged
    working = subprocess.run(["git", "diff", "--name-only"], cwd=project, capture_output=True, text=True, check=True).stdout.splitlines()
    outside_research = [p for p in working if not p.startswith("docs/cisco-command-inventory/")]
    result = {"status": "passed", "inventory_rows_checked": len(inventory), "reviewed_rows_checked": len(reviewed),
              "cached_source_hashes_verified": cached_verified, "versioned_data_consistent": True,
              "runtime_files_changed_in_committed_or_staged_delivery": False,
              "uncommitted_files_outside_research_preserved_not_in_delivery": outside_research,
              "device_validation_performed": False,
              "schema_check": "standard-library checker for all keywords used by schema.json; not a general JSON Schema implementation"}
    dump(ROOT / "validation.json", result)
    print(json.dumps(result))


if __name__ == "__main__":
    run()
