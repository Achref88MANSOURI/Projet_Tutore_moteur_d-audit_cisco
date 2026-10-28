"""Independent reviewed-source checks on all retained files and historical 20.

Never emits source values on failure. Requires the private local catalogue and
historical fixtures; neither is committed. Run after catalogue_audit.py final.
"""
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tools.catalogue_audit import CORPUS,OUT,discover,write
from tests.test_catalogue_completion import CASES
from tests.source_oracle import expected
from parser.run_ttp import extract
from normalizer.v02 import SemanticMapper
from cli import convert_file
from jsonschema import Draft202012Validator


def literal_oracle(command,values):
    """Compile handwritten examples, not production templates, to source facts.

    Locate reviewed scalar spellings as complete tokens. Boolean/implicit values
    remain constants. Variable fields retain their exact source spelling/type.
    """
    spans=[];constants={}
    for key,value in values.items():
        match=None if isinstance(value,bool) else re.search(r'(?<!\S)'+re.escape(str(value))+r'(?!\S)',command)
        if match:spans.append((match.start(),match.end(),key,type(value)))
        else:constants[key]=value
    spans.sort();start=0;parts=[];types={}
    for left,right,key,kind in spans:
        assert left>=start
        parts.append(re.escape(command[start:left]))
        parts.append('(?P<'+key+'>'+('.+?' if key in ('options','transports','expression','expansion') or ' ' in command[left:right] else r'\S+')+')')
        start=right;types[key]=kind
    parts.append(re.escape(command[start:]))
    return re.compile(''.join(parts)),types,constants


def value_at(doc,path):
    for key in path.strip('/').split('/') if path else []:
        doc=doc[int(key)] if isinstance(doc,list) else doc[key]
    return doc


def leaves(value,path=''):
    if isinstance(value,dict):
        for k,v in value.items():yield from leaves(v,path+'/'+k)
    elif isinstance(value,list):
        for i,v in enumerate(value):yield from leaves(v,path+'/'+str(i))
    elif value is not None:yield path,value


def main():
    manifest=discover();baseline_manifest=json.loads((OUT/'CORPUS_MANIFEST.json').read_text())
    assert [(r['file'],r['sha256']) for r in manifest]==[(r['file'],r['sha256']) for r in baseline_manifest]
    baseline=json.loads((OUT/'BASELINE_OCCURRENCES.json').read_text())
    final={(r['file'],r['line']):r for r in json.loads((OUT/'FINAL_OCCURRENCES.json').read_text())}
    examples={rule:literal_oracle(command,values) for rule,_,command,values in CASES}
    schema=json.loads((ROOT/'schemas/normalizedconfig_v0_2.schema.json').read_text())
    validator=Draft202012Validator(schema);counts=Counter();failures=[];rule_counts=Counter()
    def check(ok,kind,file,line=None):
        counts[kind+'_checked']+=1
        if not ok:failures.append(dict(check=kind,file=file,line=line))
    for item in manifest:
        if item['status']!='included':continue
        text=(CORPUS/item['file']).read_text(encoding='utf-8-sig');lines=text.splitlines()
        x=extract(text,official=False)
        m=SemanticMapper(x,text,item['file'],item['os_family'],item['sha256']);result=m.run();doc=result.model_dump(mode='json')
        check(not list(validator.iter_errors(doc)),'static_json_schema',item['file'])
        truth=expected(text);c=result.configuration
        check(c.system.hostname==truth['hostname'],'hostname',item['file'])
        check({i.name:i.admin_enabled for i in c.interfaces}==truth['interfaces'],'interfaces_and_admin_state',item['file'])
        check(sorted((i.name,str(a.address),a.prefix_length,bool(a.secondary)) for i in c.interfaces for a in i.ipv4_addresses)==truth['ipv4'],'static_ipv4',item['file'])
        check(sorted((i.name,str(a.address),a.prefix_length) for i in c.interfaces for a in i.ipv6_addresses)==truth['ipv6'],'static_ipv6',item['file'])
        check(sorted({p.local_as for p in c.routing.bgp})==truth['asns'],'bgp_asn',item['file'])
        accounted=set()
        for node in x['nodes'].values():
            span=set(range(node.line,(node.end_line or node.line)+1))
            check(not span&accounted,'nonoverlapping_node_spans',item['file'],node.line);accounted|=span
        for i,line in enumerate(lines,1):
            check(i in accounted or not line.strip() or line.lstrip().startswith('!'),'physical_line_accounting',item['file'],i)
        for line,record in x['records'].items():
            if record['rule'] not in examples:continue
            regex,types,constants=examples[record['rule']];match=regex.fullmatch(lines[line-1].strip())
            wanted=dict(constants)
            if match:wanted.update({k:types[k](v) for k,v in match.groupdict().items()})
            check(bool(match) and wanted==record['values'] and {k:type(v) for k,v in wanted.items()}=={k:type(v) for k,v in record['values'].items()},'reviewed_source_all_parameters',item['file'],line)
            # Check actual ancestors against source indentation without using the
            # normalizer's scope/path construction.
            chain=[];depth=len(lines[line-1])-len(lines[line-1].lstrip())
            for j in range(line-2,-1,-1):
                raw=lines[j];s=raw.strip()
                if not s or s.startswith('!') or s in ('exit','exit-address-family','quit'):continue
                indent=len(raw)-len(raw.lstrip())
                if indent<depth:chain.append(j+1);depth=indent
                if depth==0:break
            check(record['context_lines']==list(reversed(chain)),'reviewed_source_parent_chain',item['file'],line)
            rule_counts[record['rule']]+=1
        old=json.loads((OUT/'baseline'/item['id']/'normalized_config.json').read_text())
        for row in baseline:
            if row['file']!=item['file'] or row['category']!='correctly_normalized':continue
            new=final[(row['file'],row['line'])]
            check(row['values_sha256']==new['values_sha256'] and new['category']=='correctly_normalized','baseline_correct_capture',item['file'],row['line'])
            for pointer in row['normalized_paths']:
                for subpath,old_value in leaves(value_at(old,pointer)):
                    try:present=value_at(doc,pointer+subpath)==old_value
                    except (KeyError,IndexError,TypeError):present=False
                    check(present,'baseline_semantic_leaf',item['file'],row['line'])
        counts['catalogue_files']+=1
        print(item['id'],'verified',flush=True)
    # Actual CLI path with all upstream templates on the historical 20.
    historical=json.loads((ROOT/'configs/manifest.json').read_text())
    for item in historical:
        raw=(ROOT/item['config_file']).read_bytes();text=raw.decode('utf-8-sig')
        result,coverage=convert_file(ROOT/item['config_file'],OUT/'historical_20'/item['id'],os_family=item['os_family'],official=True)
        check(hashlib.sha256(raw).hexdigest()==item['description_sha256'],'historical_source_hash',item['id'])
        check(not coverage['official_template_errors'],'historical_upstream_execution',item['id'])
        check(not list(validator.iter_errors(result.model_dump(mode='json'))),'historical_static_schema',item['id'])
        truth=expected(text)
        check(result.configuration.system.hostname==truth['hostname'],'historical_hostname',item['id'])
        check({i.name:i.admin_enabled for i in result.configuration.interfaces}==truth['interfaces'],'historical_interfaces',item['id'])
        counts['historical_files']+=1
    write(OUT/'INDEPENDENT_VERIFICATION.json',dict(counts=counts,reviewed_rule_occurrences=rule_counts,failures=failures,corpus_hashes_unchanged=True))
    print(json.dumps(dict(counts=counts,failures=len(failures))),flush=True)
    return bool(failures)


if __name__=='__main__':raise SystemExit(main())
