"""Research data safety regressions; no imports of TTP or the application runtime."""
import copy
import hashlib
import unittest
from unittest.mock import patch

from common import BASE, read, rows, contexts
from build_catalog import classify, canonical_key, structure_kind


class QualificationTests(unittest.TestCase):
    def setUp(self):
        self.row = {"command": "network", "syntaxes": ["network prefix"], "modes": ["Router configuration"],
                    "source": {"url": "https://www.cisco.com/example.html#command"}, "release_scope": "17.12.x", "release_history_labels": []}
        self.fact = {"article_text_sha256": "same", "parameters": ["prefix"], "router_support_facts": [], "switch_only_facts": []}

    def test_homonyms_in_different_modes_cannot_merge(self):
        other = copy.deepcopy(self.row)
        other["modes"] = ["DHCP pool configuration"]
        self.assertNotEqual(canonical_key(self.row, self.fact, "uncertain", None), canonical_key(other, self.fact, "uncertain", None))

    def test_different_reference_editions_cannot_merge(self):
        other = {**self.row, "release_scope": "17.18.x"}
        self.assertNotEqual(canonical_key(self.row, self.fact, "uncertain", None), canonical_key(other, self.fact, "uncertain", None))

    def test_source_alias_can_merge_only_with_identical_article_evidence(self):
        other = copy.deepcopy(self.row)
        other["source"]["url"] = "https://www.cisco.com/alias.html#same-command"
        self.assertEqual(canonical_key(self.row, self.fact, "uncertain", None), canonical_key(other, self.fact, "uncertain", None))
        different_article = {**self.fact, "article_text_sha256": "different-usage-or-context"}
        self.assertNotEqual(canonical_key(self.row, self.fact, "uncertain", None), canonical_key(other, different_article, "uncertain", None))

    def test_router_mention_does_not_qualify_entire_syntax(self):
        self.fact["router_support_facts"] = [{"platform_literals": ["ASR 1000"]}]
        self.assertEqual(classify(self.row, self.fact)[0], "uncertain")

    def test_configure_prefix_is_not_an_operational_exclusion(self):
        self.row["command"] = "configure issu set rollback timer"
        self.assertEqual(classify(self.row, self.fact)[0], "uncertain")

    def test_partial_keyword_claim_does_not_qualify_all_options(self):
        claim = {"overall_decision": "uncertain", "scope": "strict_keyword_only"}
        self.assertEqual(classify(self.row, self.fact, claim)[0], "uncertain")

    def test_unknown_context_does_not_invent_parent_entry_commands(self):
        self.assertIsNone(contexts(["Router address-family configuration"])["entry_path"])
        self.assertEqual(contexts(["Global configuration (config)"])["entry_path"], [])

    def test_opaque_payload_is_flagged_without_treating_payload_as_cli(self):
        self.assertTrue(structure_kind("crypto pki certificate chain").startswith("may_contain"))
        self.assertTrue(structure_kind("banner motd").startswith("may_contain"))

    def test_no_cli_only_evidence_is_confirmed(self):
        proofs = {p["id"]: p for p in rows("CONFIGURATION_PROOFS.jsonl")}
        for record in rows("router_config_commands.jsonl"):
            if record["status"] == "confirmed_config":
                self.assertTrue(all(proofs[p]["kind"] == "running_config_output" for p in record["evidence_ids"]))

    def test_baseline_snapshot_is_unchanged(self):
        for name, expected in read("BASELINE_MANIFEST.json")["files"].items():
            self.assertEqual(hashlib.sha256((BASE / name).read_bytes()).hexdigest(), expected)

    def test_inherited_variants_are_not_auto_expanded(self):
        original = {r["id"]: r for r in rows("inventory.jsonl", BASE)}
        for record in rows("router_config_commands.jsonl"):
            for legacy in record["legacy_candidate_ids"]:
                self.assertEqual(record["syntaxes"], original[legacy]["syntaxes"])

    def test_portable_scoped_evidence_does_not_need_html_cache(self):
        from build_catalog import verify_scoped_claims
        original = {r["id"]: r for r in rows("inventory.jsonl", BASE)}
        with patch("build_catalog.cached", side_effect=AssertionError("HTML must not be read for an offline fact rebuild")):
            self.assertEqual(len(verify_scoped_claims(original)), 4)


if __name__ == "__main__":
    unittest.main()
