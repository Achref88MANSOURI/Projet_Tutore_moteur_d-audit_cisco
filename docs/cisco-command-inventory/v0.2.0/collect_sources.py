"""Bounded Cisco research. Writes phase-2 cache/metadata only; never changes v0.1.0."""
import argparse
import concurrent.futures
import hashlib
import http.client
import json
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from common import ROOT, BASE, CACHE, DOM, dump, read, cached, v01


def fetch(plan):
    url = plan["url"]
    assert urllib.parse.urlparse(url).hostname == "www.cisco.com"
    key = hashlib.sha256(url.encode()).hexdigest()
    CACHE.mkdir(parents=True, exist_ok=True)
    meta_path = CACHE / (key + ".json")
    if meta_path.exists():
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        return {**meta, "plan": plan}
    try:
        with urllib.request.urlopen(url, timeout=40) as response:
            raw = response.read()
            status = "accessible" if "/support/index.html" not in response.url else "inaccessible"
            meta = {"url": url, "resolved_url": response.url, "access_status": status,
                    "access_detail": "generic_support_redirect" if status == "inaccessible" else "http_success",
                    "retrieved_at": datetime.now(timezone.utc).isoformat(), "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
            (CACHE / (key + ".html")).write_bytes(raw)
    except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
        meta = {"url": url, "access_status": "inaccessible", "access_detail": str(exc), "attempted_at": datetime.now(timezone.utc).isoformat()}
    meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {**meta, "plan": plan}


def run():
    plan = read("research_sources.json")
    # Revisit all five distinct failed/redirected v0.1 locators in a separate cache.
    seen = {x["url"] for x in plan}
    for old in read("sources.json", BASE):
        if old["status"] != "ok" and old["url"] not in seen:
            plan.append({"id": "retry-" + hashlib.sha256(old["url"].encode()).hexdigest()[:10], "kind": "retry_locator", "url": old["url"], "platform_scope": []})
            seen.add(old["url"])
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        fetched = list(pool.map(fetch, plan))
    child_plan = []
    for result in fetched:
        print(result["access_status"], result["url"], flush=True)
        if result["plan"]["kind"] not in {"command_book", "guide_book"} or result["access_status"] != "accessible":
            continue
        key = hashlib.sha256(result["url"].encode()).hexdigest()
        dom = DOM((CACHE / (key + ".html")).read_bytes().decode("utf-8", errors="replace")).root
        directory = result["url"].rsplit("/", 1)[0] + "/"
        children = [(u, t) for u, t in v01.links(dom, result["url"]) if u.startswith(directory) and u.endswith(".html") and u != result["url"] and not any(w in u.rsplit("/", 1)[-1].lower() for w in ["preface", "index", "about", "clt_chapter"])]
        # All EEM command chapters; at most 3 chapters per configuration guide book.
        chosen = children if result["plan"]["kind"] == "command_book" else children[:3]
        result["discovered_children"] = [{"url": u, "title": t, "selected": (u, t) in chosen} for u, t in children]
        for u, title in chosen:
            if u not in seen:
                seen.add(u)
                child_plan.append({"id": result["plan"]["id"] + "-" + hashlib.sha256(u.encode()).hexdigest()[:8], "kind": "command_chapter" if result["plan"]["kind"] == "command_book" else "technology_guide", "url": u, "title": title, "parent_id": result["plan"]["id"], "technology": result["plan"].get("technology"), "platform_scope": result["plan"].get("platform_scope", [])})
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        for result in pool.map(fetch, child_plan):
            fetched.append(result)
            print(result["access_status"], result["url"], flush=True)
    dump("RESEARCH_FETCHES.json", fetched)
    print("phase-2 source attempts:", len(fetched))


if __name__ == "__main__":
    run()
