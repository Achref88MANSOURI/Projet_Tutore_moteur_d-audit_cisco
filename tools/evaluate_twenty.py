"""Reproduce official-template pilot and complete frozen-corpus evaluation."""
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from cli import convert_file, write_json
from tests.source_oracle import check_result


def main():
    import argparse
    args=argparse.ArgumentParser(description=__doc__)
    args.add_argument('--pilot',action='store_true',help='Run the five representative configurations first')
    options=args.parse_args()
    manifest=json.loads((ROOT/'configs/manifest.json').read_text(encoding='utf-8'))
    if options.pilot: manifest=[m for m in manifest if m['id'] in ('F0456','F0004','F0057','F0371','F0291')]
    old=json.loads((ROOT/'baseline/legacy_line_inventory.json').read_text(encoding='utf-8'))
    out=ROOT/'outputs'/('pilot_5' if options.pilot else 'corpus_20');out.mkdir(parents=True,exist_ok=True)
    rows=[]
    for entry in manifest:
        source=ROOT/entry['config_file'];raw=source.read_bytes()
        row={'id':entry['id'],'file':entry['config_file'],'hostname':entry['hostname_description'],'os':entry['os_family']}
        try:
            result,coverage=convert_file(source,out/entry['id'],os_family=entry['os_family'],
                legacy_lines=[x for x in old if x['file_id']==entry['id']])
            checks=check_result(result,raw.decode('utf-8-sig'),entry)
            checks.update(original_contract_pydantic_and_jsonschema=True,
                original_source_hash=hashlib.sha256(raw).hexdigest()==entry['description_sha256'],
                source_unchanged_after_run=source.read_bytes()==raw,
                official_templates_execute=not coverage['official_template_errors'])
            comparable=coverage['legacy_comparison']
            checks['legacy_nonopaque_recognition_preserved']=not any(
                x['old_recognized'] and not x['ttp_taken_into_account'] and x['ttp_status']!='preserved_opaque' for x in comparable)
            row.update(passed=all(checks.values()),checks=checks,
                legacy_nodes=len(comparable),old_recognized=sum(x['old_recognized'] for x in comparable),
                ttp_captured_legacy_nodes=sum(x['ttp_extracted'] for x in comparable),
                ttp_normalized_value_nodes=sum(x['ttp_has_normalized_values'] for x in comparable),
                ttp_taken_into_account=sum(x['ttp_taken_into_account'] for x in comparable),
                statuses=coverage['legacy_comparison_status_counts'],
                meaningful_command_count=coverage['command_count'],
                official_fields_consumed=len(coverage['official_fields_consumed']),
                error_diagnostics=sum(d.severity=='error' for d in result.parsing.diagnostics),
                warning_diagnostics=sum(d.severity=='warning' for d in result.parsing.diagnostics))
        except Exception as exc:
            row.update(passed=False,error_type=type(exc).__name__)
            # Frame coordinates without exception payloads, which can contain secrets.
            import traceback
            row['error_frames']=[f'{Path(f.filename).name}:{f.lineno}' for f in traceback.extract_tb(exc.__traceback__)]
        rows.append(row)
        print(f'{row["id"]}: {"PASS" if row["passed"] else "FAIL"} '+str([k for k,v in row.get('checks',{}).items() if not v] or row.get('error_type','')),flush=True)
    statuses=Counter()
    for row in rows:statuses.update(row.get('statuses',{}))
    summary={'files':len(manifest),'passed':sum(r['passed'] for r in rows),
        'checks':sum(len(r.get('checks',{})) for r in rows),
        'checks_passed':sum(sum(r.get('checks',{}).values()) for r in rows),
        'legacy_nodes':sum(r.get('legacy_nodes',0) for r in rows),
        'old_recognized':sum(r.get('old_recognized',0) for r in rows),
        'ttp_captured_legacy_nodes':sum(r.get('ttp_captured_legacy_nodes',0) for r in rows),
        'ttp_normalized_value_nodes':sum(r.get('ttp_normalized_value_nodes',0) for r in rows),
        'ttp_taken_into_account':sum(r.get('ttp_taken_into_account',0) for r in rows),
        'official_fields_consumed':sum(r.get('official_fields_consumed',0) for r in rows),
        'statuses':dict(statuses)}
    write_json(out/'report.json',{'summary':summary,'files':rows})
    with (out/'comparison.csv').open('w',encoding='utf-8-sig',newline='') as h:
        keys=['id','file','os','passed','legacy_nodes','old_recognized','ttp_captured_legacy_nodes','ttp_normalized_value_nodes','ttp_taken_into_account','official_fields_consumed']
        writer=csv.DictWriter(h,fieldnames=keys,extrasaction='ignore');writer.writeheader();writer.writerows(rows)
    print(json.dumps(summary,indent=2))
    return 0 if summary['passed']==len(manifest) else 1


if __name__=='__main__': raise SystemExit(main())
