"""Re-examine baseline articles and anomalies, preserving factual evidence for offline builds."""
import collections
import re

from common import ROOT, BASE, read, rows, dump, jsonl, digest, cached, articles, parameters, section, section_text, TARGET, SWITCH, OPERATIONAL, v01, Node


def text_sections(node):
    usage = section_text(node, "usage", "Usage Guidelines")
    # Use only non-history content for router support. Related-command tables are not proofs.
    intro = ""
    body = next((n for n in node.children if isinstance(n, Node) and n.tag == "section"), None)
    if body:
        first = next((n for n in body.children if isinstance(n, Node) and n.tag == "section"), None)
        if first and not any(n.tag.startswith("h") and n.tag in {"h2", "h3", "h4"} for n in first.walk()):
            intro = first.text()
    return {"intro": intro, "usage": usage}


def facts(node):
    result = {"parameters": parameters(node), "article_text_sha256": digest(node.text()),
              "router_support_facts": [], "switch_only_facts": [], "source_quality_flags": []}
    for source_section, text in text_sections(node).items():
        for sentence in re.split(r"(?<=[.!?])\s+", text):
            if len(sentence) > 1400:
                continue
            negative = bool(re.search(r"\b(?:not supported|unsupported|not available|does not support|cannot)\b", sentence, re.I))
            names = list(dict.fromkeys(TARGET.findall(sentence)))
            explicit = re.search(r"\b(?:is|are)\s+(?:(?:also|only|currently)\s+)?(?:supported|available|used)\s+(?:(?:only|exclusively)\s+)?(?:on|for|in)\b", sentence, re.I)
            if names and explicit and not negative:
                result["router_support_facts"].append({"section": source_section, "platform_literals": names,
                    "statement_sha256": digest(sentence), "support_predicate": explicit.group(),
                    "scope": "command_applicability_only_options_and_releases_not_inferred"})
            only_switch = re.search(r"(?:supported|available)\s+(?:only|exclusively)\s+on\b", sentence, re.I)
            if only_switch and SWITCH.search(sentence) and not names and not re.search(r"router|not\s+supported", sentence, re.I):
                result["switch_only_facts"].append({"section": source_section,
                    "platform_literals": list(dict.fromkeys(SWITCH.findall(sentence))),
                    "statement_sha256": digest(sentence), "support_predicate": only_switch.group()})
    if "commanddistance" in node.text():
        result["source_quality_flags"].append("published_commanddistance_typo_not_silently_repaired")
    # Preserve names, not prose definitions or an inferred grammar.
    result["parameter_status"] = "explicit_html_variable_names" if result["parameters"] else "no_variable_markup_or_no_arguments_not_disambiguated"
    return result


def run():
    baseline = rows("inventory.jsonl", BASE)
    anomalies = rows("anomalies.jsonl", BASE)
    old_sources = read("sources.json", BASE)
    source_map = {s["url"]: s for s in old_sources}
    by_page = collections.defaultdict(list)
    for row in baseline:
        by_page[row["source"]["url"].split("#")[0]].append(row)
    for anomaly in anomalies:
        by_page[anomaly["source_url"].split("#")[0]]
    partial_pages = [s for s in old_sources if s.get("extraction_status") and "CLT_chapter" not in s["url"]]
    for s in partial_pages:
        by_page[s["url"]]
    fetches = read("RESEARCH_FETCHES.json")
    fresh = {s["url"]: s for s in fetches}
    for s in fetches:
        if s["plan"]["kind"] == "command_chapter" and s["access_status"] == "accessible":
            by_page[s["url"]]
    details, recovery, page_audits, node_index = {}, [], [], {}
    for index, (url, old_rows) in enumerate(sorted(by_page.items())):
        expected = source_map.get(url, {}).get("sha256")
        dom, meta = cached(url, expected)
        if not dom:
            page_audits.append({"url": url, "status": "inaccessible", "reason": meta["status"]})
            continue
        command_articles = articles(dom)
        lookup = collections.defaultdict(list)
        for title, anchor, node in command_articles:
            lookup[(anchor, title)].append(node)
            lookup[("", title)].append(node)
        node_index[url] = lookup
        for row in old_rows:
            anchor = row["source"]["url"].split("#", 1)[1] if "#" in row["source"]["url"] else ""
            matches = lookup.get((anchor, row["command"]), [])
            if not matches:
                details[row["id"]] = {"legacy_id": row["id"], "url": row["source"]["url"], "status": "article_not_located", "parameters": [], "router_support_facts": [], "switch_only_facts": [], "source_quality_flags": []}
            else:
                details[row["id"]] = {"legacy_id": row["id"], "url": row["source"]["url"], "status": "article_reexamined_automatically", **facts(matches[0])}
        # Newly discovered structured articles and old flat FrameMaker pages.
        old_keys = {(r["source"]["url"].split("#")[-1], r["command"]) for r in old_rows}
        for title, anchor, node in command_articles:
            if (anchor, title) in old_keys:
                continue
            # For flat FrameMaker, syntax/modes are sibling heading-delimited blocks.
            mode_section = section(node, "command_modes", "Command Modes")
            if mode_section is node or mode_section is None:
                mode_text = ""
                active = False
                syntax_parts = []
                in_syntax = False
                for child in node.children:
                    if not isinstance(child, Node):
                        continue
                    cls = child.attrs.get("class", "")
                    if "CmdRefCmdModes" in cls:
                        active, in_syntax = True, False
                        continue
                    if child.tag in {"h2", "h3"}:
                        active = False
                    if active:
                        mode_text += " " + child.text()
                    if "CmdRefCommand" in cls:
                        in_syntax = True
                        continue
                    if "CmdRefSynDesc" in cls:
                        in_syntax = False
                    if in_syntax and child.tag == "p" and ("Syntax" in cls or "pCE_CmdEnv" in cls):
                        syntax_parts.append(child.text())
                modes = [mode_text.strip()] if mode_text.strip() else []
                syntaxes = list(dict.fromkeys(syntax_parts))
            else:
                modes = v01.paragraphs(mode_section)
                if not modes:
                    modes = [mode_section.text().removeprefix("Command Modes").strip()]
                syn = section(node, "refsyn", "Command Syntax")
                syntaxes = v01.syntax_paragraphs(syn)
            modes = [m for m in modes if m.strip()]
            if not syntaxes or (modes and not any("config" in m.lower() for m in modes)) or OPERATIONAL.match(title):
                continue
            ident = "new-" + digest([url, anchor, title, syntaxes, modes])[:16]
            recovery.append({"id": ident, "command": title, "syntaxes": list(dict.fromkeys(syntaxes)), "modes": modes,
                "source": {"url": url + ("#" + anchor if anchor else ""), "sha256": meta["sha256"]},
                "technology": fresh.get(url, {}).get("plan", {}).get("technology") or source_map.get(url, {}).get("book_id", "legacy_flat_reference"),
                "facts": facts(node), "origin": "recovered_or_new_official_article"})
        page_audits.append({"url": url, "status": "automatically_reexamined", "command_articles_detected": len(command_articles),
                            "legacy_occurrences": len(old_rows), "sha256": meta["sha256"]})
        if index % 30 == 0:
            print("articles reexamined", index + 1, "/", len(by_page), flush=True)
    anomaly_results = []
    for i, anomaly in enumerate(anomalies, 1):
        url, _, anchor = anomaly["source_url"].partition("#")
        lookup = node_index.get(url, {})
        matches = lookup.get((anchor, anomaly["command"]), [])
        reason = anomaly["reason"]
        source_text = matches[0].text() if matches else ""
        recovered = [r["id"] for r in recovery if r["source"]["url"] == anomaly["source_url"] and r["command"] == anomaly["command"]]
        if "duplicate_identical" in reason:
            disposition = "resolved_duplicate_already_deduplicated"
        elif re.search(r"not CLI commands|cannot be removed or modified using the CLI", source_text, re.I):
            disposition = "non_cli_serialization_marker"
        elif re.search(r"no longer documented|incorporated into.*command documentation|has been replaced", source_text, re.I):
            disposition = "documentation_redirect_stub_retained_for_resolution"
        elif recovered:
            disposition = "recovered_candidate_needs_router_qualification"
        elif OPERATIONAL.match(anomaly["command"]):
            disposition = "excluded_operational_article"
        elif any(w in anomaly["command"].lower() for w in ["character set", "introduction", "command syntax", "command history", "frame relay", "finding", "references", "about this"]):
            disposition = "non_command_document_section"
        else:
            disposition = "uncertain_missing_structured_syntax_or_mode"
        anomaly_results.append({"anomaly_id": "v01-anomaly-" + str(i).zfill(3), **anomaly,
            "disposition": disposition, "article_located": bool(matches), "recovered_ids": recovered,
            "source_article_text_sha256": digest(source_text) if source_text else None,
            "replacement_links": [{"text": n.text(), "href": n.attrs.get("href")} for n in matches[0].walk() if n.tag == "a" and n.attrs.get("href")] if matches and "redirect_stub" in disposition else [],
            "review_method": "bounded_structural_triage_not_manual_syntax_reconstruction"})
    # Remove identical recovery entries without discarding context/release distinctions.
    unique_recovery = {r["id"]: r for r in recovery}
    jsonl("ARTICLE_FACTS.jsonl", [details[k] for k in sorted(details)])
    jsonl("NEW_CANDIDATES.jsonl", [unique_recovery[k] for k in sorted(unique_recovery)])
    jsonl("ANOMALY_TRIAGE.jsonl", anomaly_results)
    dump("PAGE_AUDIT.json", page_audits)
    print("facts", len(details), "new/recovered", len(unique_recovery), "anomalies", len(anomaly_results))


if __name__ == "__main__":
    run()
