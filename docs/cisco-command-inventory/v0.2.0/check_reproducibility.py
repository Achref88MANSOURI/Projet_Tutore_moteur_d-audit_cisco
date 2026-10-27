"""Assert deterministic rebuilding from versioned facts, with HTTP/HTML-cache access forbidden."""
import hashlib
from unittest.mock import patch

import build_catalog
from common import ROOT, dump

OUTPUTS = ["router_config_commands.jsonl", "LEGACY_LINKS.jsonl", "EXCLUSIONS_AND_UNCERTAINTIES.csv",
           "SOURCE_REGISTRY.json", "FRONTIER_RELEVANCE.json", "SUMMARY.json",
           "QUALIFICATION_REPORT.md", "COVERAGE_V02.md", "VALIDATION_SAMPLES.md"]


def hashes():
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in OUTPUTS}


def run():
    before = hashes()
    with patch("build_catalog.cached", side_effect=AssertionError("HTML cache access forbidden during fact-only rebuild")), \
         patch("urllib.request.urlopen", side_effect=AssertionError("Network forbidden during fact-only rebuild")):
        build_catalog.run()
    after = hashes()
    assert before == after, "Non-deterministic outputs or stale generated artefacts"
    result = {"status": "passed", "outputs_byte_identical": len(OUTPUTS), "network_forbidden": True,
              "html_cache_access_forbidden": True, "source_facts_and_proofs_required": True, "output_sha256": after}
    dump("REPRODUCIBILITY.json", result)
    print("Fact-only deterministic rebuild passed:", len(OUTPUTS), "outputs")


if __name__ == "__main__":
    run()
