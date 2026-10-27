"""Collect factual syntax/mode metadata from public Cisco HTML references.

Python 3.12 standard library only. Never imports or modifies the application.
Network collection is explicit; offline rebuilds use an untracked HTML cache.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import http.client
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CACHE = ROOT.parent.parent / "cache" / "cisco-command-inventory"
VOID = set("area base br col embed hr img input link meta param source track wbr".split())


def clean(value):
    return re.sub(r"\s+", " ", value).strip()


class Node:
    def __init__(self, tag="root", attrs=(), parent=None):
        self.tag, self.attrs, self.parent = tag, dict(attrs), parent
        self.children = []

    def walk(self):
        yield self
        for child in self.children:
            if isinstance(child, Node):
                yield from child.walk()

    def raw_text(self):
        return "".join(c.raw_text() if isinstance(c, Node) else c for c in self.children)

    def text(self):
        return clean(self.raw_text())

    def has(self, cls):
        return cls in self.attrs.get("class", "").split()


class DOM(HTMLParser):
    def __init__(self, data):
        super().__init__(convert_charrefs=True)
        self.root = Node()
        self.stack = [self.root]
        self.feed(data)

    def handle_starttag(self, tag, attrs):
        n = Node(tag, attrs, self.stack[-1])
        self.stack[-1].children.append(n)
        if tag not in VOID:
            self.stack.append(n)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in VOID:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, 0, -1):
            if self.stack[i].tag == tag:
                self.stack = self.stack[:i]
                return

    def handle_data(self, data):
        self.stack[-1].children.append(data)


def dump(path, obj):
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def jsonl(path, rows):
    path.write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def fetch(url, offline=False):
    key = hashlib.sha256(url.encode()).hexdigest()
    html_path, meta_path = CACHE / (key + ".html"), CACHE / (key + ".json")
    if html_path.exists() and meta_path.exists():
        raw = html_path.read_bytes()
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        if hashlib.sha256(raw).hexdigest() == meta["sha256"]:
            return DOM(raw.decode("utf-8", errors="replace")).root, meta
    if offline and meta_path.exists():
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        if meta.get("status") == "fetch_failed":
            return None, meta
    if offline:
        return None, {"url": url, "status": "offline_cache_miss"}
    CACHE.mkdir(parents=True, exist_ok=True)
    if urllib.parse.urlparse(url).hostname != "www.cisco.com":
        raise ValueError("Only www.cisco.com is allowed")
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=45) as response:
            raw, final = response.read(), response.url
            content = raw.decode("utf-8", errors="replace")
            status = "ok" if "/support/index.html" not in final else "redirected_to_support"
            meta = {"url": url, "resolved_url": final, "status": status,
                    "retrieved_at": datetime.now(timezone.utc).isoformat(),
                    "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
            html_path.write_bytes(raw)
            dump(meta_path, meta)
            return DOM(content).root, meta
    except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
        meta = {"url": url, "status": "fetch_failed", "error": str(exc),
                "last_attempt_at": datetime.now(timezone.utc).isoformat()}
        dump(meta_path, meta)
        return None, meta


def links(dom, base):
    if dom is None:
        return []
    result = {}
    for n in dom.walk():
        if n.tag == "a" and n.attrs.get("href"):
            url = urllib.parse.urljoin(base, n.attrs["href"]).split("#")[0]
            if url.startswith("https://www.cisco.com/c/en/us/td/docs/") and url.endswith((".html", ".pdf")):
                result[url] = n.text()
    return sorted(result.items())


def section(article, cls, heading):
    for n in article.walk():
        if n.has(cls):
            return n
    for n in article.walk():
        if n.tag in {"h2", "h3", "h4"} and n.text().lower() == heading.lower():
            return n.parent
    return None


def paragraphs(n):
    return [v.text() for v in n.walk() if v.tag == "p"] if n else []


def syntax_paragraphs(n):
    def marked_text(node):
        if node.tag == "br":
            return "\x1e"
        return "".join(marked_text(c) if isinstance(c, Node) else c for c in node.children)
    result = []
    if n:
        for paragraph in (v for v in n.walk() if v.tag == "p"):
            parts = [clean(part) for part in marked_text(paragraph).split("\x1e") if clean(part)]
            if not parts:
                continue
            current = parts[0]
            first_keyword = current.split()[0]
            for part in parts[1:]:
                if re.match(r"^(no|default)\s", part) or part.split()[0] == first_keyword:
                    result.append(current)
                    current = part
                else:
                    current += " " + part
            result.append(current)
    return result


def extract(dom, meta, book):
    included, excluded, anomalies = [], [], []
    if dom is None or meta["status"] != "ok":
        return included, excluded, anomalies
    title_nodes = [n for n in dom.walk() if n.tag == "title"]
    meta["title"] = title_nodes[0].text() if title_nodes else ""
    for article in dom.walk():
        if article.tag not in {"article", "div", "section"} or not (article.has("reference") or article.has("nested1") or article.has("nested2")):
            continue
        headings = [n for n in article.children if isinstance(n, Node) and n.tag in {"h1", "h2", "h3"}]
        if not headings:
            continue
        name = headings[0].text()
        mode_section = section(article, "command_modes", "Command Modes")
        modes = paragraphs(mode_section)
        if not modes and mode_section:
            modes = [mode_section.text().removeprefix("Command Modes").strip()]
        modes = [v for v in modes if v]
        syn_section = section(article, "refsyn", "Command Syntax")
        if syn_section is None:
            # Older Cisco HTML uses anonymous sections and section.nested1.
            # The syntax block is the sibling immediately before Syntax Description.
            description = section(article, "syntax", "Syntax Description")
            if description is not None and description.parent is not None:
                siblings = [v for v in description.parent.children if isinstance(v, Node)]
                position = siblings.index(description)
                if position and siblings[position - 1].tag == "section":
                    previous = siblings[position - 1]
                    if (not any(v.tag in {"h2", "h3", "h4"} for v in previous.walk())
                            and not re.match(r"^(To|The|This|Use)\b", previous.text())):
                        syn_section = previous
        syntaxes = syntax_paragraphs(syn_section)
        syntaxes = list(dict.fromkeys(v for v in syntaxes if v))
        anchor = article.attrs.get("id", headings[0].attrs.get("id", ""))
        evidence_url = meta["url"] + ("#" + anchor if anchor else "")
        short = {"command": name, "source_url": evidence_url, "modes": modes, "book_id": book["id"]}
        mode_text = " ".join(modes).lower()
        if not syntaxes or not modes:
            anomalies.append({**short, "reason": "missing_syntax" if not syntaxes else "missing_modes"})
            continue
        if not re.search(r"config|\(config", mode_text):
            excluded.append({**short, "reason": "no_configuration_mode_documented"})
            continue
        if re.match(r"^(show|debug|clear|copy|write|reload|ping|traceroute|test)\b", name, re.I):
            excluded.append({**short, "reason": "operational_command_even_if_config_mode_listed"})
            continue
        history = section(article, "command_history", "Command History")
        releases, release_history = [], []
        if history:
            for tr in history.walk():
                if tr.tag != "tr":
                    continue
                cells = [n.text() for n in tr.children if isinstance(n, Node) and n.tag == "td"]
                if cells:
                    releases.append(cells[0])
                    modification = " ".join(cells[1:]).lower()
                    kinds = [k for k in ["introduced", "modified", "removed", "replaced", "integrated", "deprecated"] if k in modification]
                    release_history.append({"release": cells[0], "change_kinds": kinds or ["unspecified"],
                                            "support_inference": "none_history_event_only"})
        # Exact names are evidence mentions, never an assertion of support.
        article_text = article.text()
        platforms = sorted(set(re.findall(r"(?:Cisco\s+)?(?:ASR\s*100[0-9A-Za-z-]*|ISR\s*(?:4[0-9]{3}|1[0-9]{3})|Catalyst\s+(?:8[0-9]{3}[A-Za-z]*))", article_text, re.I)))
        signatures = ["no" if re.match(r"^no\b", s) else "default" if re.match(r"^default\b", s) else "positive" for s in syntaxes]
        ident = hashlib.sha256((book["id"] + "|" + evidence_url + "|" + name).encode()).hexdigest()[:16]
        included.append({
            "id": ident, "command": name, "syntaxes": syntaxes, "documented_forms": sorted(set(signatures)),
            "modes": modes, "context_path": None, "technology": book["technology"],
            "scope_status": "router_applicability_unverified_shared_reference",
            "os_families_document_scope": book["os_families"],
            "platform_mentions": platforms, "platform_support": "unverified_per_command",
            "release_history_labels": list(dict.fromkeys(releases)),
            "release_history": release_history,
            "release_scope": book.get("release_scope", "multi_release_not_a_support_matrix"),
            "source": {"book_id": book["id"], "url": evidence_url, "sha256": meta["sha256"], "retrieved_at": meta["retrieved_at"]},
            "configuration_presence": "candidate_from_documented_configuration_mode",
            "serialization": "unverified_no_device_round_trip",
            "confidence": {"syntax": "medium_automatic_extraction", "configuration_mode": "medium_documented_mode", "platform_release_support": "unknown", "persistence": "unknown"},
            "review_status": "needs_review", "variants_policy": "Only printed syntax forms; no automatic no/default expansion",
        })
    unique = {}
    for row in included:
        if row["id"] not in unique:
            unique[row["id"]] = row
        elif unique[row["id"]] == row:
            anomalies.append({"command": row["command"], "source_url": row["source"]["url"],
                              "modes": row["modes"], "book_id": book["id"], "reason": "duplicate_identical_html_article_ignored"})
        else:
            # Retain conflicting occurrences; never merge different modes or syntax.
            row["id"] = hashlib.sha256(json.dumps(row, sort_keys=True).encode()).hexdigest()[:16]
            unique[row["id"]] = row
            anomalies.append({"command": row["command"], "source_url": row["source"]["url"],
                              "modes": row["modes"], "book_id": book["id"], "reason": "conflicting_duplicate_anchor_disambiguated"})
    return list(unique.values()), excluded, anomalies


def run(offline=False, limit=None):
    seeds = json.loads((ROOT / "seeds.json").read_text(encoding="utf-8"))
    all_sources, books, explicit_chapters = [], {}, []
    # Discovery is deliberately bounded and every unvisited link remains visible.
    for seed in seeds:
        dom, meta = fetch(seed["url"], offline)
        meta.update({"id": seed["id"], "kind": seed["kind"], "platform_scope": seed.get("platform_scope", [])})
        found = links(dom, seed["url"])
        meta["discovered_links"] = [{"url": u, "title": t} for u, t in found]
        all_sources.append(meta)
        if seed["kind"] == "platform_command_index":
            for u, t in found:
                if (u.endswith(".html") and "Command Reference" in t and "Debug" not in t and "SD-Routing" not in t
                        and ("Programmability" not in t or "17.12" in t or "17.18" in t)):
                    key = hashlib.sha256(u.encode()).hexdigest()[:12]
                    books[u] = {"id": key, "url": u, "title": t, "technology": t,
                                "os_families": ["IOS", "IOS-XE"], "discovery_seed_ids": []}
        if seed["kind"] == "command_book":
            books[seed["url"]] = seed.copy()
        if seed["kind"] == "command_chapter":
            explicit_chapters.append(seed)
    for u, book in books.items():
        book["discovery_seed_ids"] = [s["id"] for s in all_sources if any(v["url"] == u for v in s["discovered_links"])]
        if "Programmability" in book.get("title", ""):
            book["os_families"] = ["IOS-XE"]
            book["release_scope"] = "17.12.x" if "1712" in u else "17.18.x" if "1718" in u else "see_document_title"
    dump(ROOT / "books.json", sorted(books.values(), key=lambda x: x["url"]))
    by_book_id = {b["id"]: b for b in books.values()}
    chapters = {s["url"]: (by_book_id[s["book_id"]], s["title"]) for s in explicit_chapters}
    for u, book in sorted(books.items()):
        dom, meta = fetch(u, offline)
        meta.update({"id": book["id"], "kind": "command_book", "discovery_seed_ids": book["discovery_seed_ids"]})
        directory = u.rsplit("/", 1)[0] + "/"
        found = [(v, t) for v, t in links(dom, u) if v.endswith(".html") and v.startswith(directory) and v != u and not re.search(r"index|preface|about|readme", v.rsplit("/", 1)[-1], re.I)]
        meta["discovered_links"] = [{"url": v, "title": t} for v, t in found]
        all_sources.append(meta)
        for v, t in found:
            chapters[v] = (book, t)
    selected = sorted(chapters.items())[:limit] if limit else sorted(chapters.items())
    inventory, excluded, anomalies = [], [], []
    def process(item):
        u, (book, title) = item
        dom, meta = fetch(u, offline)
        meta.update({"kind": "command_chapter", "book_id": book["id"], "discovered_title": title})
        inc, exc, errs = extract(dom, meta, book)
        meta.update({"configuration_candidates": len(inc), "excluded_commands": len(exc), "extraction_anomalies": len(errs)})
        if meta["status"] == "ok" and not (inc or exc or errs):
            meta["extraction_status"] = "no_structured_command_articles_found"
        return meta, inc, exc, errs
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        for meta, inc, exc, errs in pool.map(process, selected):
            all_sources.append(meta)
            inventory.extend(inc)
            excluded.extend(exc)
            anomalies.extend(errs)
            print(f'{meta["status"]}: {meta["url"]} -> {len(inc)} candidates', flush=True)
    visited = {s["url"] for s in all_sources}
    chapter_frontier = [{"url": u, "book_id": b["id"], "title": title, "reason": "collection_limit"} for u, (b, title) in chapters.items() if u not in visited]
    other_frontier = {}
    for source in all_sources:
        for link in source.get("discovered_links", []):
            if link["url"] not in visited and link["url"] not in chapters:
                other_frontier[link["url"]] = {**link, "reason": "pdf_not_extracted" if link["url"].endswith(".pdf") else "discovered_not_selected_by_collection_policy"}
    frontier = chapter_frontier + list(other_frontier.values())
    inventory.sort(key=lambda r: (r["command"].lower(), r["source"]["url"]))
    jsonl(ROOT / "inventory.jsonl", inventory)
    jsonl(ROOT / "excluded.jsonl", sorted(excluded, key=lambda x: (x["command"], x["source_url"])))
    jsonl(ROOT / "anomalies.jsonl", sorted(anomalies, key=lambda x: (x["command"], x["source_url"])))
    dump(ROOT / "sources.json", all_sources)
    dump(ROOT / "frontier.json", sorted(frontier, key=lambda x: x["url"]))
    summary = {"schema_version": "1.0.0", "inventory_version": "0.1.0", "snapshot_date": "2026-10-27", "exhaustive": False,
               "candidate_records": len(inventory), "unique_command_titles": len({r["command"] for r in inventory}),
               "excluded_records": len(excluded), "anomalies": len(anomalies),
               "books_discovered": len(books), "chapters_discovered": len(chapters), "chapters_attempted": len(selected),
               "unvisited_chapters": len(chapter_frontier), "other_unvisited_documents": len(other_frontier), "source_statuses": dict(Counter(s["status"] for s in all_sources)),
               "unique_source_urls": len({s["url"] for s in all_sources}),
               "unique_successful_urls": len({s["url"] for s in all_sources if s["status"] == "ok"}),
               "by_book": dict(sorted(Counter(r["source"]["book_id"] for r in inventory).items())),
               "all_records_require_review": True}
    dump(ROOT / "summary.json", summary)
    print(json.dumps(summary, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--limit", type=int, help="Only attempt the first N discovered chapters; remaining URLs are recorded")
    args = parser.parse_args()
    run(args.offline, args.limit)
