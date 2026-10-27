"""Research-only helpers. The v0.1.0 snapshot and runtime are read-only inputs."""
import hashlib
import importlib.util
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BASE = ROOT.parent
PROJECT = BASE.parent.parent
OLD_CACHE = PROJECT / "cache" / "cisco-command-inventory"
CACHE = PROJECT / "cache" / "cisco-qualification-v02"
spec = importlib.util.spec_from_file_location("cisco_inventory_v01_readonly", BASE / "collect.py")
v01 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v01)
DOM, Node, clean = v01.DOM, v01.Node, v01.clean


def read(name, base=ROOT):
    return json.loads((base / name).read_text(encoding="utf-8"))


def rows(name, base=ROOT):
    return [json.loads(s) for s in (base / name).read_text(encoding="utf-8").splitlines() if s]


def dump(name, value):
    (ROOT / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def jsonl(name, values):
    (ROOT / name).write_text("".join(json.dumps(v, ensure_ascii=False, sort_keys=True) + "\n" for v in values), encoding="utf-8")


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else json.dumps(value, ensure_ascii=False, sort_keys=True).encode()).hexdigest()


def cached(url, expected=None):
    key = hashlib.sha256(url.encode()).hexdigest()
    # A baseline source must use its original bytes, even if a fresh URL was fetched.
    places = [OLD_CACHE, CACHE] if expected else [CACHE, OLD_CACHE]
    for folder in places:
        html, meta = folder / (key + ".html"), folder / (key + ".json")
        if html.exists() and meta.exists():
            raw = html.read_bytes()
            metadata = json.loads(meta.read_text(encoding="utf-8"))
            if hashlib.sha256(raw).hexdigest() == metadata.get("sha256") and (not expected or expected == metadata["sha256"]):
                return DOM(raw.decode("utf-8", errors="replace")).root, metadata
    return None, {"url": url, "status": "cache_missing_or_hash_mismatch"}


def articles(dom):
    if not dom:
        return []
    found = []
    for node in dom.walk():
        if node.tag in {"article", "div", "section"} and any(node.has(c) for c in ["reference", "nested1", "nested2"]):
            heads = [v for v in node.children if isinstance(v, Node) and v.tag in {"h1", "h2", "h3"}]
            if heads:
                found.append((heads[0].text(), node.attrs.get("id", heads[0].attrs.get("id", "")), node))
    # Older FrameMaker exports have flat command headings within chapterContent.
    for parent in dom.walk():
        if parent.attrs.get("id") != "chapterContent":
            continue
        current, title, anchor = None, None, None
        for child in parent.children:
            if isinstance(child, Node) and "CmdRefCommand" in child.attrs.get("class", ""):
                if current is not None:
                    found.append((title, anchor, current))
                title = child.text()
                anchor = child.attrs.get("id", "")
                if not anchor:
                    anchor = next((n.attrs.get("name") or n.attrs.get("id") for n in child.walk() if n.tag == "a" and (n.attrs.get("name") or n.attrs.get("id"))), "")
                current = Node("article", [("id", anchor or "flat-" + digest(title)[:16])])
            if current is not None:
                current.children.append(child)
        if current is not None:
            found.append((title, anchor, current))
    return found


def section(node, cls, heading):
    value = v01.section(node, cls, heading)
    # Synthetic flat articles retain original parent pointers. Never read a whole
    # chapter as if it were a single command's Usage Guidelines or Command Modes.
    return value if value is not None and any(v is value for v in node.walk()) else None


def section_text(node, cls, heading):
    value = section(node, cls, heading)
    return value.text() if value else ""


TARGET = re.compile(r"(?:Cisco\s+)?(?:ASR\s*100[0-9A-Za-z-]*|ISR\s*(?:1000|4000|1900|2900|3900)|Catalyst\s+(?:8200|8300|8500|8000V)[A-Za-z0-9-]*|Cisco\s+(?:8[0-9]{2}|1900|2900|3900|4000)\s+(?:Series\s+)?(?:ISR|router))", re.I)
SWITCH = re.compile(r"(?:Catalyst\s*(?:[236][0-9]{3}|9[0-9]{3})|Cisco\s+ME\s*(?:[0-9]+))", re.I)
OPERATIONAL = re.compile(r"^(?:show|debug|clear|copy|write|reload|ping|traceroute|test|do)(?:\s|$)", re.I)


def parameters(node):
    syntax = section(node, "refsyn", "Command Syntax")
    if syntax is None:
        desc = section(node, "syntax", "Syntax Description")
        if desc and desc.parent:
            siblings = [n for n in desc.parent.children if isinstance(n, Node)]
            index = siblings.index(desc)
            if index and siblings[index - 1].tag == "section":
                syntax = siblings[index - 1]
    names = []
    if syntax:
        names = [n.text() for n in syntax.walk() if n.tag in {"var", "i"} and n.text()]
    else:
        for paragraph in node.children:
            if isinstance(paragraph, Node) and paragraph.tag == "p" and paragraph.has("pCE_CmdEnv"):
                names += [n.text() for n in paragraph.walk() if n.tag in {"var", "i"} and n.text()]
    return list(dict.fromkeys(names))


def contexts(modes):
    """Return documented mode labels; do not invent entry commands or parent paths."""
    if len(modes) == 1 and modes[0].lower() in {"global configuration", "global configuration (config)"}:
        return {"documented_mode_labels": modes, "entry_path": [], "resolution": "documented_global_mode"}
    return {"documented_mode_labels": modes, "entry_path": None,
            "resolution": "not_established_from_mode_name_alone"}
