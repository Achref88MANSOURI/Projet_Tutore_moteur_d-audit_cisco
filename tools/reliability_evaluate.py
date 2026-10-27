"""Versioned corpus evaluation: never overwrite the original corpus outputs."""
from pathlib import Path
import argparse
import hashlib
import json
from collections import Counter
import sys
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from cli import convert_file,write_json


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--phase',required=True);args=parser.parse_args()
    out=ROOT/'outputs/reliability'/('phase'+args.phase);out.mkdir(parents=True,exist_ok=True)
    rules={r['id']:r for r in json.loads((ROOT/'templates/rules.json').read_text())}
    old=json.loads((ROOT/'baseline/legacy_line_inventory.json').read_text())
    rows=[];deltas=[];constants=0;missing=[];statuses=Counter()
    for item in json.loads((ROOT/'configs/manifest.json').read_text(encoding='utf-8')):
        source=ROOT/item['config_file'];raw=source.read_bytes()
        assert hashlib.sha256(raw).hexdigest()==item['description_sha256']
        result,coverage=convert_file(source,out/item['id'],os_family=item['os_family'],legacy_lines=[r for r in old if r['file_id']==item['id']],schema_version='0.1.0' if args.phase in ('1','2') else '0.2.0')
        native=json.loads((out/item['id']/'parsed_native.json').read_text(encoding='utf-8'))
        original=json.loads((ROOT/'baseline/fiabilisation_v01/outputs/corpus_20'/item['id']/'parsed_native.json').read_text(encoding='utf-8'))
        prior={r['source_line']:r for r in original['records']}
        for r in native['records']:
            for field,expected in rules[r['rule']].get('constants',{}).items():
                constants+=1
                if r['values'].get(field)!=expected or type(r['values'].get(field)) is not type(expected):missing.append([item['id'],r['source_line'],field])
            if prior.get(r['source_line'])!=r:deltas.append(dict(file_id=item['id'],line=r['source_line'],before=prior.get(r['source_line']),after=r))
        statuses.update(coverage['legacy_comparison_status_counts'])
        rows.append(dict(file_id=item['id'],input_unchanged=True,statuses=coverage['legacy_comparison_status_counts']))
        print(item['id'],'PASS',flush=True)
    assert not missing
    write_json(out/'native_diff.json',deltas)
    write_json(out/'report.json',dict(files=rows,summary=dict(phase=args.phase,files=len(rows),legacy_positions=sum(statuses.values()),
        statuses=dict(statuses),expected_constants=constants,missing_constants=missing,changed_native_records=len(deltas))))
    print(json.dumps(dict(statuses=statuses,constants=constants,missing=missing),indent=2))


if __name__=='__main__':main()
