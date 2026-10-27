"""One-time import of immutable project references; runtime needs no parent files."""
import hashlib
import json
from pathlib import Path
import shutil

PROJECT = Path(__file__).resolve().parents[1]
PARENT = PROJECT.parent
CONTRACT = PARENT / 'NormalizedConfig_v0.1_OpenConfig' / 'normalizedconfig_v0_1'

manifest = json.loads((PARENT / 'outputs/selected_20/selection_manifest.json').read_text(encoding='utf-8'))
for record in manifest:
    source = PARENT / 'selected' / record['relative_path']
    data = source.read_bytes()
    assert hashlib.sha256(data).hexdigest() == record['description_sha256']
    name = Path(record['relative_path']).name
    target = PROJECT / 'configs' / name
    target.write_bytes(data)
    record['config_file'] = 'configs/' + name
(PROJECT / 'configs/manifest.json').write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
for name in ('normalizedconfig.py', 'normalizedconfig_v0_1.schema.json', 'field_mapping_openconfig.csv', 'README.md',
             'sample_cisco_ios.conf', 'sample_cisco_ios.normalized.json', 'sample_junos_set.conf', 'sample_junos_set.normalized.json'):
    shutil.copy2(CONTRACT / name, PROJECT / 'schemas' / name)
shutil.copy2(PARENT / 'outputs/selected_20/report.json', PROJECT / 'baseline/report.json')
shutil.copy2(PARENT / 'selected/CATALOGUE_60_CONFIGURATIONS.txt', PROJECT / 'docs/CATALOGUE_REFERENCE.txt')
shutil.copy2(Path('C:/Users/achre/.codex/attachments/d8f03779-6605-480b-811c-c01836574f74/Texte collé.txt'), PROJECT / 'docs/APPROCHE_DEMANDEE.txt')
baseline_lines = []
for row in json.loads((PROJECT / 'baseline/report.json').read_text(encoding='utf-8'))['results']:
    folder = PARENT / 'outputs/selected_20' / row['artifacts_directory']
    native = json.loads((folder / 'cisco_parser.json').read_text(encoding='utf-8'))
    unknown = {r['line_start'] for r in json.loads((folder / 'unconverted_commands.json').read_text(encoding='utf-8'))}
    text = (PARENT / 'selected' / row['relative_path']).read_text(encoding='utf-8-sig').splitlines()
    cursor = 0
    def visit(node, ancestors):
        global cursor
        # Previously redacted nodes are opaque to exact matching; their source
        # lines are recovered in order with the same redaction rule as the export.
        import re
        while cursor < len(text):
            raw = text[cursor].strip()
            masked = bool(re.search(r'(?i)(?:\b(?:secret|password|key-string|pre-shared-key|server-key|key|community)\b|^snmp-server (?:host|user)\b)', raw))
            expected = '[REDACTED credential-bearing command]' if masked else raw
            if expected == node['line'].strip():
                break
            cursor += 1
        assert cursor < len(text), (row['id'], node['line'])
        number = cursor + 1
        cursor += 1
        baseline_lines.append({'file_id': row['id'], 'line': number,
                               'old_recognized': number not in unknown})
        for child in node.get('children', []):
            visit(child, ancestors + [node['line']])
    for root in native['config_tree']:
        visit(root, [])
assert len(baseline_lines) == 3051
assert sum(x['old_recognized'] for x in baseline_lines) == 1224
(PROJECT / 'baseline/legacy_line_inventory.json').write_text(json.dumps(baseline_lines, indent=2) + '\n', encoding='utf-8')
print(f'Copied {len(manifest)} configs; 3,051 baseline nodes; unchanged contract.')
