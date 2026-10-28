"""Immutable before/after corpus audit, independent source facts, no raw commits."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from cli import convert_file
from parser.run_ttp import extract
from parser.coverage_v02 import build_coverage
from normalizer.v02 import SemanticMapper
from tools.catalogue_audit import category,write
from tools.catalogue_verify import leaves,value_at
from tests.source_oracle import expected
from tests.p1_source_oracle import check as source_check
from jsonschema import Draft202012Validator

OUT=ROOT/'outputs/cisco_normalization_p1';PREVIOUS=ROOT/'outputs/catalogue_ttp_completion'


def main():
    reference=OUT/'BEFORE_REFERENCE.json'
    if not reference.exists():
        # Copy pinned hashes, never recompute a baseline from current output.
        write(reference,json.loads((ROOT/'docs/cisco-normalization-p1/reference_hashes.json').read_text()))
    refs=json.loads(reference.read_text())
    for p,h in refs['immutable_reference_hashes'].items():assert hashlib.sha256((ROOT/p).read_bytes()).hexdigest()==h,'Reference changed'
    manifest=json.loads((PREVIOUS/'CORPUS_MANIFEST.json').read_text());oldrows=json.loads((PREVIOUS/'FINAL_OCCURRENCES.json').read_text())
    old={(r['file'],r['line']):r for r in oldrows}
    decisions={r['family_id']:r for r in json.loads((ROOT/'docs/cisco-normalization-p1/decisions.json').read_text())}
    rules={r['id']:r for r in json.loads((ROOT/'templates/rules.json').read_text())}
    validator=Draft202012Validator(json.loads((ROOT/'schemas/normalizedconfig_v0_2_1.schema.json').read_text()))
    counts=Counter();checks=Counter();promoted=Counter();rows=[];failures=[];files=0
    def check(ok,kind,file,line=None):
        checks[kind]+=1
        if not ok:failures.append(dict(check=kind,file=file,line=line))
    for item in manifest:
        path=ROOT.parent/'catalogue'/item['file'];raw=path.read_bytes()
        check(hashlib.sha256(raw).hexdigest()==item['sha256'],'original_hash',item['id'])
        if item['status']!='included':continue
        text=raw.decode('utf-8-sig');x=extract(text,official=True)
        mapper=SemanticMapper(x,text,item['file'],item['os_family'],item['sha256']);n=mapper.run();doc=n.model_dump(mode='json');coverage=build_coverage(x,mapper)
        check(not list(validator.iter_errors(doc)),'versioned_schema',item['id'])
        check(not x['official_errors'],'official_templates',item['id'])
        truth=expected(text);c=n.configuration
        check(c.system.hostname==truth['hostname'],'source_hostname',item['id'])
        check({i.name:i.admin_enabled for i in c.interfaces}==truth['interfaces'],'source_interfaces_admin',item['id'])
        check(sorted((i.name,str(a.address),a.prefix_length,bool(a.secondary)) for i in c.interfaces for a in i.ipv4_addresses)==truth['ipv4'],'source_ipv4',item['id'])
        check(sorted((i.name,str(a.address),a.prefix_length) for i in c.interfaces for a in i.ipv6_addresses)==truth['ipv6'],'source_ipv6',item['id'])
        before_doc=json.loads((PREVIOUS/'final'/item['id']/'normalized_config.json').read_text())
        for row in coverage['commands']:
            line=row['line'];record=x['records'].get(line);row['_source']=x['nodes'][line].text
            state=category(row,record,rules);counts[state]+=1;before=old[(item['file'],line)]
            check(before['values_sha256']==hashlib.sha256(json.dumps(record['values'] if record else {},sort_keys=True).encode()).hexdigest(),'unchanged_native_values',item['id'],line)
            current_context=[x['nodes'][l].text for l in record['context_lines']] if record else before['context']
            # Before contexts are redacted; these families contain no credentials.
            if before['category']=='captured_unmapped':check(current_context==before['context'],'unchanged_parent',item['id'],line)
            if before['category']=='correctly_normalized':
                check(state=='correctly_normalized','baseline_correct_status',item['id'],line)
                for pointer in before['normalized_paths']:
                    for subpath,value in leaves(value_at(before_doc,pointer)):
                        try:matches=value_at(doc,pointer+subpath)==value
                        except (KeyError,IndexError,TypeError):matches=False
                        check(matches,'baseline_semantic_value',item['id'],line)
            if before['category'] in ('partially_normalized','unrecognized'):
                check(state==before['category'],'partial_unknown_unchanged',item['id'],line)
            if before['category']=='captured_unmapped':
                d=decisions[before['rule']]
                if d['decision'] in ('KEEP_NATIVE','NEEDS_REVIEW') or d['priority']!='P1':check(state=='captured_unmapped','deferred_scope_unchanged',item['id'],line)
                if state=='correctly_normalized':
                    try:source_check(text,before,doc);ok=True
                    except (AssertionError,ValueError,KeyError,IndexError,StopIteration,TypeError):ok=False
                    check(ok,'independent_promoted_source',item['id'],line);promoted[before['rule']]+=1
            rows.append(dict(file=item['file'],id=item['id'],line=line,rule=row['template_rule'],category=state,before_category=before['category'],reason=mapper.partial_notes.get(line) or row.get('reason'),normalized_paths=row['normalized_paths']))
        write(OUT/'after'/item['id']/'normalized_config.json',doc)
        write(OUT/'after'/item['id']/'coverage_report.json',{k:v for k,v in coverage.items() if k!='commands'})
        files+=1;print(item['id'],'checked',flush=True)
    for item in json.loads((ROOT/'configs/manifest.json').read_text()):
        n,coverage=convert_file(ROOT/item['config_file'],OUT/'historical_20'/item['id'],os_family=item['os_family'],official=True)
        check(not coverage['official_template_errors'],'historical_official',item['id'])
        check(not list(validator.iter_errors(n.model_dump(mode='json'))),'historical_schema',item['id'])
        checks['historical_files']+=1
    result=dict(files=files,counts=counts,checks=checks,promoted_rules=promoted,promoted_occurrences=sum(promoted.values()),failures=failures)
    write(OUT/'AFTER_COVERAGE.json',result);write(OUT/'AFTER_OCCURRENCES.json',rows)
    print(json.dumps({**result,'failures':len(failures)}),flush=True)
    return bool(failures)


if __name__=='__main__':raise SystemExit(main())
