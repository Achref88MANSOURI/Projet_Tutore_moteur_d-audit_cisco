"""Check fixed, reviewed documentary selections; never abstract examples into grammar."""
import re
from common import BASE, read, rows, dump, jsonl, cached, clean, digest


def window(text, start, end, examples):
    text = clean(text)
    offset = 0
    while True:
        first = text.casefold().find(start.casefold(), offset)
        if first < 0:
            raise ValueError("Evidence window absent: " + start)
        last = text.casefold().find(end.casefold(), first + len(start))
        if last >= 0:
            block = text[first:last + len(end)]
            if all(clean(e) in block for e in examples):
                return block
        offset = first + 1


def run():
    fetches = {s["plan"]["id"]: s for s in read("RESEARCH_FETCHES.json")}
    original = {r["id"]: r for r in rows("inventory.jsonl", BASE)}
    proofs = []
    # Revalidate every selected v0.1 example against its exact source bytes.
    for old in rows("reviewed.jsonl", BASE):
        dom, meta = cached(old["source"]["url"], old["source"]["sha256"])
        if dom is None:
            raise ValueError("Missing v0.1 selected source: " + old["source"]["url"])
        markers = old["evidence_window"]
        block = window(dom.raw_text(), markers["start_marker"], markers["end_marker"], [old["observed_example"]])
        platforms = old["platform_scope"]
        source_id = old["source"].get("source_id")
        if source_id == "evidence-ios-g2":
            platforms = ["ISR G2 1900/2900/3900 shared guide example; exact model unresolved"]
        elif source_id == "evidence-c8200-c8300":
            platforms = ["Catalyst 8200/8300 shared guide example; exact model unresolved"]
        elif source_id == "evidence-isr1000":
            pid = re.search(r"license udi pid (\S+)", block)
            platforms = [pid.group(1)] if pid else ["ISR 1000 guide example; exact model unresolved"]
        # The config version token is not necessarily the IOS-XE release.
        proofs.append({"id": "proof-v01-" + old["id"], "command": old["command"], "literal_form": old["observed_example"],
            "kind": old["evidence_kind"], "mode": old["mode"], "context_path": old["context_path"],
            "platforms": platforms, "platform_scope_kind": "document_example_not_every_model",
            "configuration_version_token": old["example_release"].split(" (")[0] if old["example_release"] else None, "confirmed_os_releases": [],
            "source": old["source"], "window": {**markers, "sha256_v02": digest(block)},
            "configuration_excerpt": "\n".join(old["context_path"] + [old["observed_example"]]),
            "excerpt_kind": "selected_context_lines_not_necessarily_contiguous_in_original",
            "related_legacy_ids": [i for i in old["candidate_ids"] if i in original],
            "relationship": "related_title_only_not_form_equivalence", "origin": "v0.1_review_revalidated"})
    for selection in read("EVIDENCE_SELECTIONS.json"):
        source = fetches[selection["source_id"]]
        assert source["access_status"] == "accessible", selection["source_id"]
        dom, meta = cached(source["url"], source["sha256"])
        assert dom is not None
        text = dom.text()
        for marker in [selection["platform_marker"]] + selection.get("additional_markers", []):
            assert clean(marker).casefold() in text.casefold(), (selection["source_id"], marker)
        examples = [entry[1] for entry in selection["entries"]]
        block = window(text, selection["start"], selection["end"], examples) if "start" in selection else text
        for command, literal, mode, context in selection["entries"]:
            assert clean(literal) in block, (selection["source_id"], literal)
            for parent in context:
                assert parent in block, parent
            ident = "proof-" + digest([selection["source_id"], literal, context, selection["kind"]])[:20]
            related = [r["id"] for r in original.values() if r["command"] == command]
            proofs.append({"id": ident, "command": command, "literal_form": literal, "kind": selection["kind"],
                "mode": mode, "context_path": context, "platforms": selection["platforms"],
                "platform_scope_kind": "selected_platform_guide_or_feature_information" if selection["platforms"] else "target_router_platform_not_established",
                "configuration_version_token": selection.get("configuration_version"), "confirmed_os_releases": [],
                "source": {"url": source["url"], "sha256": source["sha256"], "retrieved_at": source["retrieved_at"]},
                "window": {"start_marker": selection.get("start"), "end_marker": selection.get("end"), "sha256_v02": digest(block),
                           "platform_marker": selection["platform_marker"], "additional_markers": selection.get("additional_markers", [])},
                "configuration_excerpt": "\n".join(context + [literal]),
                "excerpt_kind": "selected_context_lines_not_necessarily_contiguous_in_original",
                "related_legacy_ids": related, "relationship": "related_title_only_not_form_equivalence",
                "support_scope": selection.get("support_scope", "limited_to_published_example_or_guide_conditions"),
                "origin": "phase_2_fixed_selection"})
    jsonl("CONFIGURATION_PROOFS.jsonl", proofs)
    print("checked documentary selections", len(proofs))


if __name__ == "__main__":
    run()
