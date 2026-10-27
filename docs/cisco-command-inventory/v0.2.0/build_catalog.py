"""Rebuild the qualified catalogue offline from retained factual evidence."""
import collections
import csv
import re
import urllib.parse

from common import ROOT, BASE, read, rows, dump, jsonl, digest, contexts, cached, articles, clean

STATUSES = {"confirmed_config", "documented_config", "uncertain", "excluded"}


def technology(command, fallback="other"):
    s = command.lower()
    for label, pattern in [
        ("EEM", r"^(action |event |event manager|track stub)"),
        ("SNMP", r"snmp"), ("telemetry", r"telemetry|netconf|restconf|gnmi"),
        ("NetFlow", r"flow (?:record|monitor|exporter)|netflow|^(collect|match (?:flow|ipv4|ipv6|transport))"),
        ("multicast/PIM", r"pim|igmp|msdp|multicast"), ("MPLS/VPN", r"mpls|l2vpn|l2 vfi|vrf|route-target|^rd$"),
        ("QoS", r"class-map|policy-map|service-policy|^police|^shape|^priority|^bandwidth"),
        ("security/VPN", r"aaa|crypto|ipsec|isakmp|pki|password|^access-list|access-group|access-class"),
        ("routing", r"bgp|ospf|eigrp|rip|isis|^network|^neighbor|^router|^ip route|^ipv6 route|route-map|prefix-list"),
        ("interfaces", r"interface|encapsulation|shutdown|duplex|^speed|^ip address|^ipv6 address"),
        ("administration", r"hostname|logging|ntp|^line$|transport|^service |^ip http|banner|archive|^log config|hidekeys")]:
        if re.search(pattern, s):
            return label
    return fallback


def structure_kind(command):
    if re.search(r"banner|certificate chain|key-string|menu.*text|macro", command, re.I):
        return "may_contain_opaque_or_delimited_payload_not_independent_command_lines"
    if command.startswith(("exit-", "address-family", "interface", "router ", "line ", "vrf ")):
        return "context_sensitive_configuration"
    return "single_command_or_context_entry_not_fully_resolved"


def verify_scoped_claims(original):
    retained_path = ROOT / "SCOPED_EVIDENCE.json"
    if retained_path.exists():
        retained = read("SCOPED_EVIDENCE.json")
        assert retained["selection_digest"] == digest(read("SCOPED_CLAIMS.json"))
        return retained["claims_by_legacy_id"]
    result = {}
    for claim in read("SCOPED_CLAIMS.json"):
        for legacy_id in claim["legacy_ids"]:
            row = original[legacy_id]
            page, _, anchor = row["source"]["url"].partition("#")
            dom, _ = cached(page, row["source"]["sha256"])
            assert dom is not None
            node = next(n for name, a, n in articles(dom) if a == anchor and name == row["command"])
            assert clean(claim["required_marker"]) in node.text(), (legacy_id, claim["required_marker"])
            result[legacy_id] = {**claim, "source": row["source"], "evidence_marker_sha256": digest(clean(claim["required_marker"]))}
    dump("SCOPED_EVIDENCE.json", {"selection_digest": digest(read("SCOPED_CLAIMS.json")), "claims_by_legacy_id": result})
    return result


def classify(row, fact, scoped=None):
    # Classification is deliberately conservative. Keyword mentions and Command
    # History never automatically establish a platform/release support matrix.
    if fact.get("switch_only_facts"):
        return "excluded", ["explicit_supported_only_on_switch_in_this_reference_edition"]
    if row["command"] == "do":
        return "excluded", ["exec_wrapper_not_persistent_configuration_statement"]
    if scoped and scoped["overall_decision"] == "documented_config":
        return "documented_config", ["explicit_router_documentation_with_hardware_or_image_constraint", "serialization_not_observed"]
    reasons = ["router_platform_or_serialization_not_established_for_this_full_syntax"]
    if not row.get("modes"):
        reasons.append("configuration_mode_not_documented_in_extracted_article")
    if fact.get("status") == "article_not_located":
        reasons.append("source_article_not_located")
    if fact.get("router_support_facts"):
        reasons.append("router_mention_requires_subject_option_and_condition_review")
    if fact.get("source_quality_flags"):
        reasons += fact["source_quality_flags"]
    if structure_kind(row["command"]).startswith("may_contain"):
        reasons.append("opaque_payload_and_terminator_need_separate_source_block_validation")
    return "uncertain", reasons


def canonical_key(row, fact, status, claim):
    # Identical titles alone, unknown context alone and same leading keyword are
    # never sufficient. Exact article contents, variables, modes, edition scope
    # and history must agree before aliases can be merged.
    return digest([row["command"], row["syntaxes"], row.get("modes", []),
                   fact.get("article_text_sha256") or row["source"]["url"], fact.get("parameters", []),
                   row.get("release_scope"), row.get("release_history_labels", []), row.get("platform_mentions", []),
                   status, claim])


def make_record(row, fact, status, reasons, scoped=None, legacy=True):
    return {
        "id": "cmd-" + canonical_key(row, fact, status, scoped)[:20], "catalogue_version": "0.2.0",
        "record_kind": "documented_syntax_family", "command": row["command"],
        "legacy_candidate_ids": [row["id"]] if legacy else [],
        "new_candidate_ids": [] if legacy else [row["id"]],
        "status": status, "syntax_scope": "printed_syntax_not_a_verified_device_grammar",
        "syntaxes": row["syntaxes"], "parameters": fact.get("parameters", []),
        "parameter_evidence": fact.get("parameter_status", "not_established"),
        "parameter_constraints": {"status": "not_fully_transcribed", "note": "Do not infer types, ranges or options absent from the printed syntax."},
        "documented_forms": sorted({"no" if re.match(r"^no\b", s) else "default" if re.match(r"^default\b", s) else "positive" for s in row["syntaxes"]}),
        "modes": row.get("modes", []), "context": contexts(row.get("modes", [])),
        "structure_kind": structure_kind(row["command"]), "technologies": [technology(row["command"], row.get("technology", "other"))],
        "platforms_confirmed": scoped["platforms"] if scoped and status == "documented_config" else [],
        "platform_mentions_unverified": row.get("platform_mentions", []),
        "platform_conditions": scoped["constraints"] if scoped else [],
        "releases_confirmed": [], "release_history_not_support": row.get("release_history_labels", []),
        "document_release_scope_not_support": [row.get("release_scope", "unknown")],
        "scoped_applicability_claims": [scoped] if scoped else [],
        "unreviewed_router_statement_locators": fact.get("router_support_facts", []),
        "switch_only_statement_locators": fact.get("switch_only_facts", []),
        "sources": [row["source"]], "evidence_ids": [],
        "serialization": "not_confirmed_for_printed_variants", "reason_codes": reasons,
        "confidence": {"syntax": "medium_source_extraction", "router_applicability": "medium_conditional_documentary" if status == "documented_config" else "high_scope_exclusion" if status == "excluded" else "unknown",
                       "serialization": "unknown", "release_support": "unknown"},
        "review_method": "automatic_article_reexamination_with_explicit_conservative_rules",
        "universal_applicability": False,
    }


def source_registry(catalogue):
    registry = {}
    def put(url):
        url = urllib.parse.urldefrag(url)[0]
        if url not in registry:
            registry[url] = {"url": url, "origins": [], "access_status": "not_reviewed", "review_status": "not_reviewed", "versions": [], "titles": []}
        return registry[url]
    for source in read("sources.json", BASE):
        record = put(source["url"])
        if "v0.1_source_registry" not in record["origins"]:
            record["origins"].append("v0.1_source_registry")
        record["access_status"] = "accessible_cached_v01" if source["status"] == "ok" else "inaccessible"
        version = {k: source[k] for k in ["sha256", "retrieved_at", "resolved_url", "status", "error"] if k in source}
        if version not in record["versions"]:
            record["versions"].append(version)
        if source.get("title") and source["title"] not in record["titles"]:
            record["titles"].append(source["title"])
    frontier = read("frontier.json", BASE)
    for source in frontier:
        record = put(source["url"])
        record["origins"].append("v0.1_frontier")
        record["titles"].append(source.get("title", ""))
    for source in read("RESEARCH_FETCHES.json"):
        record = put(source["url"])
        record["origins"].append("phase_2_fetch")
        record["access_status"] = source["access_status"]
        record["versions"].append({k: source[k] for k in ["sha256", "retrieved_at", "resolved_url", "access_status", "access_detail", "attempted_at"] if k in source})
        record["phase_2_plan"] = source["plan"]
        for child in source.get("discovered_children", []):
            child_record = put(child["url"])
            child_record["origins"].append("phase_2_discovery")
            child_record["titles"].append(child["title"])
    reviewed = {s["url"].split("#")[0] for row in catalogue if row["record_kind"] == "observed_instance" or row["scoped_applicability_claims"] for s in row["sources"]}
    extracted = {r["url"] for r in read("PAGE_AUDIT.json") if r["status"] == "automatically_reexamined"}
    document_groups = collections.defaultdict(list)
    for url, r in registry.items():
        r["origins"] = sorted(set(r["origins"]))
        r["titles"] = sorted(set(r["titles"]))
        lower = (url + " " + " ".join(r["titles"])).lower()
        if any(s in lower for s in ["/iosxr/", "/nx-os/", "/nxos/", "/security/asa/"]):
            r["relevance"], r["priority"] = "outside_os_scope_by_locator", 4
        elif any(s in lower for s in ["debug command", "install", "hardware installation", "release-notes"]):
            r["relevance"], r["priority"] = "supporting_or_operational_reference_not_command_qualification", 3
        elif any(s in lower for s in ["ipmulti", "snmp", "fnetflow", "telemetry", "/eem/", "mpls", "qos", "security", "iproute"]):
            r["relevance"], r["priority"] = "priority_technology_reference_requires_content_review", 1
        else:
            r["relevance"], r["priority"] = "potentially_relevant_platform_or_general_reference", 2
        r["review_status"] = "partially_reviewed" if url in reviewed else "not_reviewed"
        r["automatic_article_extraction_performed"] = url in extracted
        r["review_limit"] = "Only selected evidence/sections were reviewed; whole-document review is not claimed."
        stem = re.sub(r"\.(html|pdf)$", "", url)
        r["document_group_id"] = digest(stem)[:16]
        r["grouping_rule"] = "same_locator_stem_html_pdf_only_no_cross_release_merge"
        document_groups[r["document_group_id"]].append(url)
    dump("FRONTIER_RELEVANCE.json", {"input_document_count": len(frontier), "input_unique_urls": len({s["url"] for s in frontier}),
        "original_url_groups": [{"url": s["url"], "document_group_id": put(s["url"])["document_group_id"], "priority": put(s["url"])["priority"], "review_status": put(s["url"])["review_status"]} for s in frontier],
        "alias_groups": [{"id": k, "urls": urls} for k, urls in document_groups.items() if len(urls) > 1]})
    result = sorted(registry.values(), key=lambda r: (r["priority"], r["url"]))
    dump("SOURCE_REGISTRY.json", {"schema_version": "1.0.0", "snapshot": "0.2.0", "sources": result})
    return result


def run():
    baseline = rows("inventory.jsonl", BASE)
    original = {r["id"]: r for r in baseline}
    facts = {r["legacy_id"]: r for r in rows("ARTICLE_FACTS.jsonl")}
    scoped = verify_scoped_claims(original)
    merged = {}
    for row in baseline:
        fact = facts[row["id"]]
        status, reasons = classify(row, fact, scoped.get(row["id"]))
        record = make_record(row, fact, status, reasons, scoped.get(row["id"]))
        if record["id"] in merged:
            existing = merged[record["id"]]
            existing["legacy_candidate_ids"].extend(record["legacy_candidate_ids"])
            existing["sources"].extend(s for s in record["sources"] if s not in existing["sources"])
            existing["technologies"] = sorted(set(existing["technologies"] + record["technologies"]))
        else:
            merged[record["id"]] = record
    for new in rows("NEW_CANDIDATES.jsonl"):
        status, reasons = classify(new, new["facts"])
        record = make_record(new, new["facts"], status, reasons, legacy=False)
        if record["id"] in merged:
            merged[record["id"]]["new_candidate_ids"].extend(record["new_candidate_ids"])
        else:
            merged[record["id"]] = record
    # A literal example is a separate record, never proof of its whole parent grammar.
    for proof in rows("CONFIGURATION_PROOFS.jsonl"):
        status = "confirmed_config" if proof["kind"] == "running_config_output" else "documented_config" if proof["kind"] == "cli_configuration_example" and proof["platforms"] else "uncertain"
        ident = "form-" + digest([proof["literal_form"], proof["mode"], proof["context_path"], proof["platforms"], proof["configuration_version_token"], status])[:20]
        if ident in merged:
            merged[ident]["evidence_ids"].append(proof["id"])
            if proof["source"] not in merged[ident]["sources"]:
                merged[ident]["sources"].append(proof["source"])
            continue
        merged[ident] = {"id": ident, "catalogue_version": "0.2.0", "record_kind": "observed_instance", "command": proof["command"],
            "legacy_candidate_ids": [], "related_legacy_candidate_ids": proof["related_legacy_ids"], "new_candidate_ids": [],
            "status": status, "syntax_scope": "literal_instance_only_no_optional_expansion", "syntaxes": [proof["literal_form"]],
            "parameters": [], "parameter_evidence": "literal_values_not_generalized_to_parameter_grammar", "parameter_constraints": {"status": "not_applicable_to_literal_instance"},
            "documented_forms": ["no" if proof["literal_form"].startswith("no ") else "default" if proof["literal_form"].startswith("default ") else "positive"],
            "modes": [proof["mode"]], "context": {"documented_mode_labels": [proof["mode"]], "entry_path": proof["context_path"], "resolution": "reviewed_example_context"},
            "structure_kind": structure_kind(proof["command"]), "technologies": [technology(proof["command"])],
            "platforms_confirmed": proof["platforms"], "platform_conditions": [proof.get("support_scope", "document_example_only_not_every_model")],
            "platform_mentions_unverified": [],
            "releases_confirmed": [], "configuration_version_token_not_os_release": proof["configuration_version_token"],
            "release_history_not_support": [], "document_release_scope_not_support": [], "scoped_applicability_claims": [],
            "sources": [proof["source"]], "evidence_ids": [proof["id"]],
            "serialization": "observed_in_official_router_running_config" if status == "confirmed_config" else "not_confirmed_for_target_platform",
            "reason_codes": ["official_router_configuration_output_exact_form" if status == "confirmed_config" else "router_guide_cli_example_not_a_saved_configuration" if status == "documented_config" else "native_example_without_verified_target_router_platform"],
            "confidence": {"syntax": "high_literal_transcription", "router_applicability": "medium_document_example_scope" if proof["platforms"] else "unknown", "serialization": "high_documentary_presence_not_device_round_trip" if status == "confirmed_config" else "unknown", "release_support": "unknown"},
            "review_method": "fixed_reviewed_selection_revalidated_against_source_bytes", "universal_applicability": False}
    catalogue = sorted(merged.values(), key=lambda r: (r["command"].lower(), r["id"]))
    jsonl("router_config_commands.jsonl", catalogue)
    ledger = [{"legacy_candidate_id": legacy, "catalogue_id": r["id"], "status": r["status"], "review_method": r["review_method"]} for r in catalogue for legacy in r["legacy_candidate_ids"]]
    jsonl("LEGACY_LINKS.jsonl", sorted(ledger, key=lambda r: r["legacy_candidate_id"]))
    registry = source_registry(catalogue)
    with (ROOT / "EXCLUSIONS_AND_UNCERTAINTIES.csv").open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["catalogue_id", "legacy_ids", "command", "status", "reason_codes", "sources", "scope"])
        for r in catalogue:
            if r["status"] != "confirmed_config":
                writer.writerow([r["id"], " | ".join(r["legacy_candidate_ids"]), r["command"], r["status"], " | ".join(r["reason_codes"]), " | ".join(s["url"] for s in r["sources"]), r["syntax_scope"]])
    counts = collections.Counter(r["status"] for r in catalogue)
    summary = {"version": "0.2.0", "exhaustive": False, "baseline_candidates_examined_automatically": len(baseline),
        "baseline_candidates_with_explicit_disposition": len(ledger), "baseline_status_counts_by_occurrence": dict(collections.Counter(r["status"] for r in ledger)),
        "baseline_documentary_entries_after_deduplication": sum(bool(r["legacy_candidate_ids"]) for r in catalogue),
        "baseline_alias_occurrences_merged": len(baseline) - sum(bool(r["legacy_candidate_ids"]) for r in catalogue),
        "new_or_recovered_candidate_occurrences": len(rows("NEW_CANDIDATES.jsonl")),
        "catalogue_records": len(catalogue), "catalogue_status_counts": dict(counts),
        "resolved_records_confirmed_documented_or_excluded": sum(counts[s] for s in ["confirmed_config", "documented_config", "excluded"]),
        "confirmed_literal_instances": counts["confirmed_config"], "confirmed_full_parameterized_grammars": 0,
        "sources_in_registry": len(registry), "source_review_counts": dict(collections.Counter(s["review_status"] for s in registry)),
        "phase_2_http_attempts": len(read("RESEARCH_FETCHES.json")),
        "anomalies_triaged": len(rows("ANOMALY_TRIAGE.jsonl")), "anomaly_dispositions": dict(collections.Counter(r["disposition"] for r in rows("ANOMALY_TRIAGE.jsonl"))),
        "sources_not_reviewed": sum(s["review_status"] == "not_reviewed" for s in registry),
        "inaccessible_sources": sum(s["access_status"] == "inaccessible" for s in registry),
        "ttp_comparison_performed": False, "device_validation_performed": False}
    dump("SUMMARY.json", summary)
    from reports import render
    render(catalogue, registry, summary)
    print(summary)


if __name__ == "__main__":
    run()
