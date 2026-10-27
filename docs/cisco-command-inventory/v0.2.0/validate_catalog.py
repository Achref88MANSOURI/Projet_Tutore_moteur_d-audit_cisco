"""Independent data/provenance checks and fixed stratified expectations, offline."""
import argparse
import collections
import csv
import hashlib
import json
import re
import subprocess

from common import ROOT, BASE, OLD_CACHE, CACHE, read, rows, dump, digest
from reports import select_sample


def validate(verify_cache=False):
    frozen = read("BASELINE_MANIFEST.json")
    for name, expected in frozen["files"].items():
        assert hashlib.sha256((BASE / name).read_bytes()).hexdigest() == expected, "Modified v0.1 file: " + name
    original = {r["id"]: r for r in rows("inventory.jsonl", BASE)}
    facts = {r["legacy_id"]: r for r in rows("ARTICLE_FACTS.jsonl")}
    assert facts.keys() == original.keys(), "Every original candidate must have a source re-examination result"
    catalogue = rows("router_config_commands.jsonl")
    assert len({r["id"] for r in catalogue}) == len(catalogue)
    links = rows("LEGACY_LINKS.jsonl")
    assert len(links) == len(original) == 7296
    assert {l["legacy_candidate_id"] for l in links} == original.keys()
    assert len({l["legacy_candidate_id"] for l in links}) == 7296
    by_id = {r["id"]: r for r in catalogue}
    proof = {p["id"]: p for p in rows("CONFIGURATION_PROOFS.jsonl")}
    registry = read("SOURCE_REGISTRY.json")["sources"]
    source_map = {s["url"]: s for s in registry}
    assert len(source_map) == len(registry), "Source registry URL duplicates"
    for row in catalogue:
        assert row["status"] in {"confirmed_config", "documented_config", "uncertain", "excluded"}
        assert row["syntaxes"] and all(isinstance(s, str) and s.strip() for s in row["syntaxes"])
        assert row["reason_codes"] and row["sources"]
        assert row["universal_applicability"] is False
        assert row["catalogue_version"] == "0.2.0"
        assert row["releases_confirmed"] == [], "No exact variant/release matrix has been demonstrated in this snapshot"
        for source in row["sources"]:
            url = source["url"].split("#")[0]
            assert url.startswith("https://www.cisco.com/") and url in source_map
            assert re.fullmatch(r"[0-9a-f]{64}", source["sha256"])
            assert any(v.get("sha256") == source["sha256"] for v in source_map[url]["versions"]), (row["id"], "unregistered source bytes")
        for legacy in row["legacy_candidate_ids"]:
            origin = original[legacy]
            assert row["syntaxes"] == origin["syntaxes"], (legacy, "inferred or lost syntax")
            assert row["modes"] == origin["modes"], (legacy, "lost mode distinction")
            assert origin["source"] in row["sources"], (legacy, "lost source")
            assert row["parameters"] == facts[legacy]["parameters"], (legacy, "lost parameter distinction")
            assert row["platform_mentions_unverified"] == origin["platform_mentions"], (legacy, "lost unverified platform metadata")
            assert row["status"] != "confirmed_config", "An observed literal must not certify a whole generic family"
        if row["status"] == "confirmed_config":
            assert row["record_kind"] == "observed_instance"
            assert row["syntax_scope"] == "literal_instance_only_no_optional_expansion"
            assert row["evidence_ids"] and row["platforms_confirmed"]
            for pid in row["evidence_ids"]:
                p = proof[pid]
                assert p["kind"] == "running_config_output", "CLI-only or anonymous-platform example promoted to confirmed"
                assert p["literal_form"] in row["syntaxes"]
                assert p["context_path"] == row["context"]["entry_path"]
                assert p["platforms"] == row["platforms_confirmed"]
                assert p["literal_form"] in p["configuration_excerpt"]
        if row["record_kind"] == "observed_instance":
            assert row["parameters"] == [], "Literal examples must not generate parameter grammar"
            for pid in row["evidence_ids"]:
                assert proof[pid]["literal_form"] in row["syntaxes"]
        if row["status"] in {"uncertain", "excluded"}:
            assert row["reason_codes"], row["id"]
    for link in links:
        r = by_id[link["catalogue_id"]]
        assert link["legacy_candidate_id"] in r["legacy_candidate_ids"]
        assert link["status"] == r["status"]
    anomalies = rows("ANOMALY_TRIAGE.jsonl")
    assert len(anomalies) == 261 and len({a["anomaly_id"] for a in anomalies}) == 261
    assert all(a["disposition"] and a["source_url"].startswith("https://www.cisco.com/") for a in anomalies)
    frontier = read("FRONTIER_RELEVANCE.json")
    assert frontier["input_document_count"] == 1142
    assert len(frontier["original_url_groups"]) == 1142
    assert all(r["url"] in source_map for r in frontier["original_url_groups"])
    expectations = []
    for selection in read("SAMPLE_EXPECTATIONS.json"):
        matches = select_sample(catalogue, selection)
        assert matches, "Missing sample stratum: " + selection["id"]
        assert all(r["status"] == selection["expected"] for r in matches), (selection["id"], [r["status"] for r in matches])
        expectations.append({"id": selection["id"], "stratum": selection["stratum"], "expected": selection["expected"], "catalogue_ids": [r["id"] for r in matches], "result": "passed"})
    assert {s["expected"] for s in read("SAMPLE_EXPECTATIONS.json")} == {"confirmed_config", "documented_config", "uncertain", "excluded"}
    with (ROOT / "EXCLUSIONS_AND_UNCERTAINTIES.csv").open(encoding="utf-8-sig", newline="") as f:
        csv_rows = list(csv.DictReader(f))
    assert {r["catalogue_id"] for r in csv_rows} == {r["id"] for r in catalogue if r["status"] != "confirmed_config"}
    summary = read("SUMMARY.json")
    assert summary["catalogue_records"] == len(catalogue)
    assert summary["catalogue_status_counts"] == dict(collections.Counter(r["status"] for r in catalogue))
    assert summary["exhaustive"] is False and summary["ttp_comparison_performed"] is False
    assert summary["confirmed_full_parameterized_grammars"] == 0
    cache_checks = 0
    if verify_cache:
        seen = set()
        for source in registry:
            for v in source["versions"]:
                expected = v.get("sha256")
                if not expected or (source["url"], expected) in seen:
                    continue
                seen.add((source["url"], expected))
                key = hashlib.sha256(source["url"].encode()).hexdigest()
                paths = [p / (key + ".html") for p in [OLD_CACHE, CACHE]]
                available = [p for p in paths if p.exists() and hashlib.sha256(p.read_bytes()).hexdigest() == expected]
                assert available, "Cached source bytes absent/changed: " + source["url"]
                cache_checks += 1
    # Only this subtree may enter the phase-2 commit; preserve external worktree edits.
    for command in [["git", "diff", "d6e9bb9...HEAD", "--name-only"], ["git", "diff", "--cached", "--name-only"]]:
        changed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=True).stdout.splitlines()
        assert all(p.startswith("docs/cisco-command-inventory/v0.2.0/") for p in changed), changed
    result = {"status": "passed", "baseline_files_unchanged": len(frozen["files"]), "legacy_candidates_accounted_for": len(links),
        "catalogue_records_checked": len(catalogue), "anomalies_accounted_for": len(anomalies), "frontier_documents_accounted_for": 1142,
        "fixed_stratified_expectations_checked": len(expectations), "sample_results": expectations,
        "confirmed_instances_require_running_config_proof": True, "parameterized_grammars_confirmed": 0,
        "cache_byte_hashes_checked": cache_checks, "cache_verification_requested": verify_cache,
        "runtime_or_templates_changed_in_delivery": False, "device_validation": False}
    dump("VALIDATION.json", result)
    print({k: v for k, v in result.items() if k != "sample_results"})
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-cache", action="store_true")
    validate(parser.parse_args().verify_cache)
