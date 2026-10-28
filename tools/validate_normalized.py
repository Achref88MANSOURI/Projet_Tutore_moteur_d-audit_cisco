"""Validate ten representative exports by default, using read-only inputs.

Optional before/after snapshots compare business data, never parser reports.
Failure details contain identifiers and check names only, no configuration data.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from cli import convert_file,write_json
from schemas.normalized_config import business_schema
from jsonschema import Draft202012Validator,FormatChecker

FORBIDDEN={'evidence','diagnostics','parsing','observations','unknown_commands',
    'feature_coverage','opaque_blocks','source_file','source_line','line_start',
    'line_end','source_sha256','raw_command','parser_rule','confidence','basis'}

REPRESENTATIVE_IDS = ('C0017','F0049','F0456','C0043','C0075',
    'C0020','C0004','C0016','C0148','C0103')


def read(path):return json.loads(path.read_text(encoding='utf-8'))


def entries():
    catalogue=read(ROOT/'tests/fixtures/corpus_manifest.json')
    result=[(r['id'],ROOT.parent/'catalogue'/r['file'],r['os_family'],r['sha256'])
        for r in catalogue if r['status']=='included']
    result.extend((r['id'],ROOT/r['config_file'],r['os_family'],r['description_sha256'])
        for r in read(ROOT/'configs/manifest.json'))
    return result


def business_only(value):
    if isinstance(value,dict):
        return not FORBIDDEN.intersection(value) and all(business_only(v) for v in value.values())
    if isinstance(value,list):return all(business_only(v) for v in value)
    return value is not None


def run(output,baseline=None,identifiers=None):
    before=read(baseline) if baseline else {}
    by_id={key.split('_')[0]:key for key in before}
    validator=Draft202012Validator(business_schema(),format_checker=FormatChecker())
    results=[]
    for identifier,source,family,expected_hash in entries():
        if identifiers and identifier not in identifiers:continue
        name=by_id.get(identifier,identifier+'_'+source.stem)
        destination=output/name
        raw=source.read_bytes()
        checks={'source_hash':hashlib.sha256(raw).hexdigest()==expected_hash}
        try:
            config=convert_file(source,destination,os_family=family)
            checks.update(schema=not list(validator.iter_errors(config)),
                business_only=bool(business_only(config)),
                one_output={p.name for p in destination.iterdir()}=={'normalized.json'},
                api_matches_file=read(destination/'normalized.json')==config,
                input_unchanged=source.read_bytes()==raw)
            if baseline:checks['business_unchanged']=name in before and config==before[name]
        except Exception as exc:
            checks['conversion']=False
            results.append(dict(equipment=name,checks=checks,error_type=type(exc).__name__))
            continue
        results.append(dict(equipment=name,checks=checks))
    return dict(passed=all(all(r['checks'].values()) for r in results),
        configurations=len(results),baseline_comparison=bool(baseline),results=results)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=ROOT/'outputs/normalized_only_validation/exports')
    parser.add_argument('--baseline',type=Path)
    selection=parser.add_mutually_exclusive_group()
    selection.add_argument('--ids',nargs='+',help='Choose equipment identifiers instead of the representative sample')
    selection.add_argument('--all',action='store_true',help='Explicitly request the complete corpus')
    parser.add_argument('--summary',type=Path,default=ROOT/'outputs/normalized_only_validation/validation.json')
    args=parser.parse_args(argv)
    identifiers=None if args.all else args.ids or REPRESENTATIVE_IDS
    result=run(args.output,args.baseline,identifiers)
    write_json(args.summary,result)
    print(f"{result['configurations']} configurations; passed={result['passed']}")
    return 0 if result['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
