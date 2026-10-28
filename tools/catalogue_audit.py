"""Read-only corpus discovery and source-led before/after audit; no raw corpus commits."""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from parser.inventory import redacted
from parser.run_ttp import extract
from parser.coverage_v02 import build_coverage
from normalizer.v02 import SemanticMapper

OUT=ROOT/'outputs/catalogue_ttp_completion'
CORPUS=ROOT.parent/'catalogue'


def write(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')


def discover():
    result=[]
    for path in sorted(CORPUS.rglob('*')):
        if not path.is_file():continue
        raw=path.read_bytes();text=raw.decode('utf-8-sig',errors='replace')
        lines=text.splitlines();status='ambiguous';reason='No convincing complete IOS router configuration signature.'
        if path.name.lower() in ('description.txt','lire_moi.txt'):status='excluded_document';reason='Catalogue documentation, not a configuration.'
        elif re.search(r'!!\s*IOS XR|IOS XR Configuration|^!! Last configuration|^interface (?:MgmtEth|HundredGigE)\d+/\d+/\d+/\d+|^vrf (?!definition\b)\S+|^router static\s*$|^ssh server v2\s*$|^ +ipv4 (?:address|unnumbered|point-to-point)\b',text,re.M|re.I):status='excluded_iosxr';reason='IOS XR header, interface namespace or XR-specific native configuration syntax.'
        elif re.search(r'^ASA Version|^!Command:|^feature \S+|NX-OS|boot nxos',text,re.M):status='excluded_other_os';reason='ASA/NX-OS signature.'
        elif re.search(r'^(?:license udi pid (?:WS-C\S+|C9[0-9]{3}\S*)|boot system .*?(?:vios_l2|cat[239][0-9]{3})|!.*\bIOSvL2\b)',text,re.I|re.M):status='excluded_switch';reason='Explicit switch-only platform identifier on a metadata/boot line (never certificate hex).'
        elif re.search(r'^hostname \S+',text,re.M) and re.search(r'^interface \S+|^router (?:bgp|ospf|isis|eigrp|rip)',text,re.M):status='included';reason='IOS-style full router configuration; no contrary OS/platform signature found.'
        family='iosxe' if re.search(r'CSR1000|C8000|C8[235]00|ISR4|isr4|^version 1[67]\.',text,re.M|re.I) else 'ios'
        result.append(dict(id=f'C{len(result)+1:04d}',file=str(path.relative_to(CORPUS)),sha256=hashlib.sha256(raw).hexdigest(),bytes=len(raw),physical_lines=len(lines),status=status,reason=reason,os_family=family,
            version_token=next((x.split(maxsplit=1)[1] for x in lines if x.startswith('version ')),None)))
    return result


def pattern_matches(pattern,text):
    """Independent source-token accounting: TTP output alone is not whole-line credit."""
    pattern=re.sub(r'{{\s*\w+\s*\|\s*set\(.*?\)\s*}}','',pattern).strip()
    pieces=[];start=0
    for match in re.finditer(r'{{(.*?)}}',pattern):
        literal=pattern[start:match.start()]
        pieces.append(re.escape(literal))
        expr=match[1]
        if '| set(' in expr:
            pass
        else:
            pieces.append('.+?' if 'ORPHRASE' in expr or 're(' in expr else r'\S+')
        start=match.end()
    pieces.append(re.escape(pattern[start:]))
    expression=''.join(pieces)
    expression=re.sub(r'(?:\\ )+',r'\\s+',expression)
    return bool(re.fullmatch(expression,text))


def category(row,record,rules):
    state=row['status']
    if state in ('opaque_preserved','export_wrapper','structure_or_metadata'):return 'opaque_or_structural'
    if not record:return 'unrecognized'
    if state=='invalid_or_ambiguous':return 'incorrectly_normalized'
    if state=='fully_normalized':return 'correctly_normalized' if pattern_matches(rules[record['rule']]['pattern'],row['_source']) else 'partially_normalized'
    if state=='partially_normalized':return 'partially_normalized'
    return 'captured_unmapped'


def run(phase):
    OUT.mkdir(parents=True,exist_ok=True)
    manifest=discover()
    if phase=='baseline':
        if (OUT/'BASELINE_COVERAGE.json').exists():raise RuntimeError('Baseline already exists; never overwrite it')
        write(OUT/'CORPUS_MANIFEST.json',manifest)
        write(OUT/'BASELINE_CODE_HASHES.json',{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for folder in ['parser','normalizer','templates','schemas','tests'] for p in (ROOT/folder).rglob('*') if p.is_file() and '__pycache__' not in str(p)})
    else:
        before=json.loads((OUT/'CORPUS_MANIFEST.json').read_text(encoding='utf-8'))
        assert [(r['file'],r['sha256']) for r in manifest]==[(r['file'],r['sha256']) for r in before], 'Original catalogue changed'
    rules={r['id']:r for r in json.loads((ROOT/'templates/rules.json').read_text(encoding='utf-8'))}
    total=Counter();families=Counter();missing=Counter();rows=[];failures=[];file_reports=[];official_errors=[]
    for item in manifest:
        if item['status']!='included':continue
        raw=(CORPUS/item['file']).read_bytes();text=raw.decode('utf-8-sig')
        try:
            x=extract(text,official=phase=='final');m=SemanticMapper(x,text,item['file'],item['os_family'],item['sha256']);n=m.run();coverage=build_coverage(x,m)
            official_errors.extend(dict(file=item['file'],**e) for e in x['official_errors'])
            from jsonschema import Draft202012Validator
            Draft202012Validator(n.model_json_schema()).validate(n.model_dump(mode='json'))
        except Exception as exc:
            failures.append(dict(file=item['file'],error=type(exc).__name__))
            print(item['id'],type(exc).__name__,flush=True);continue
        counts=Counter()
        for row in coverage['commands']:
            node=x['nodes'][row['line']];record=x['records'].get(row['line'])
            row['_source']=node.text
            status=category(row,record,rules);counts[status]+=1;total[status]+=1;families[node.family]+=1
            public=dict(file=item['file'],line=row['line'],line_end=row['line_end'],kind=node.kind,context=[redacted(a.text) for a in __import__('parser.inventory',fromlist=['ancestors']).ancestors(node,x['nodes'])],
                command=redacted(node.text),family=node.family,category=status,engine_status=row['status'],rule=row['template_rule'],fields=[f['name'] for f in row['fields']],
                values_sha256=hashlib.sha256(json.dumps(record['values'] if record else {},sort_keys=True).encode()).hexdigest(),normalized_paths=row['normalized_paths'])
            rows.append(public)
            if status!='correctly_normalized' and status!='opaque_or_structural':missing[(node.family,redacted(node.text))]+=1
        file_reports.append(dict(file=item['file'],id=item['id'],counts=dict(counts),commands=len(coverage['commands'])))
        # Private local outputs retain ordinary masked model conventions; not committed.
        write(OUT/phase/item['id']/'normalized_config.json',n.model_dump(mode='json'))
        print(item['id'],'OK',sum(counts.values()),flush=True)
    summary=dict(phase=phase,all_files=len(manifest),file_statuses=dict(Counter(r['status'] for r in manifest)),included=sum(r['status']=='included' for r in manifest),physical_lines_included=sum(r['physical_lines'] for r in manifest if r['status']=='included'),node_occurrences=sum(total.values()),counts=dict(total),families=dict(families),failures=failures,official_templates_enabled=phase=='final',official_template_errors=official_errors,files=file_reports)
    write(OUT/('BASELINE_COVERAGE.json' if phase=='baseline' else 'FINAL_COVERAGE.json'),summary)
    write(OUT/(phase.upper()+'_OCCURRENCES.json'),rows)
    write(OUT/(phase.upper()+'_MISSING_GROUPS.json'),[dict(family=k[0],command=k[1],count=v) for k,v in missing.most_common()])
    print(json.dumps({k:v for k,v in summary.items() if k not in ('files',)},ensure_ascii=False),flush=True)


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('phase',choices=['baseline','final']);run(p.parse_args().phase)
