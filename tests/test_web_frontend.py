"""Regression checks for the existing vanilla-JS dashboard."""
from pathlib import Path
import re
import shutil
import subprocess
import pytest

ROOT = Path(__file__).resolve().parents[1]
HTML = ROOT / "web" / "index.html"


def inline_script():
    match = re.search(r"<script>(.*?)</script>", HTML.read_text(encoding="utf-8"), re.S)
    assert match
    return match.group(1)


def test_inline_javascript_parses_with_node(tmp_path):
    node = shutil.which("node") or r"C:\Program Files\nodejs\node.exe"
    if not Path(node).is_file() and not shutil.which("node"):
        pytest.skip("Node.js is unavailable")
    script = tmp_path / "dashboard.js"
    script.write_text(inline_script(), encoding="utf-8")
    result = subprocess.run([node, "--check", str(script)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_untrusted_cisco_source_is_rendered_as_text():
    script = inline_script()
    assert "source.textContent" in script or "source.value" in script
    assert "createTextNode(text.slice(last, match.index))" in script
    assert "escapeHtml(s)" in script and "&#39;" in script
    assert "generateCorrectionDiff" in script
    assert "Aucun diff contextuel disponible" in script
    assert "transport input ssh telnet" not in script


def test_catalog_and_audit_check_http_errors():
    script = inline_script()
    assert "if (!response.ok) throw new Error" in script
    assert "fetchJson('/api/catalog')" in script
    assert "fetchJson('/api/audit'" in script
