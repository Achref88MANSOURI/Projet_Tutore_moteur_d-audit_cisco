"""Single-file CLI, using only files/dependencies inside this project."""
import argparse
import hashlib
import json
from pathlib import Path

from parser.run_ttp import extract, public_native
from parser.coverage import build_coverage
from normalizer.mapping import Mapper
from normalizer.validation import validate


def write_json(path, value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')


def convert_file(source, output, *, os_family='ios', legacy_lines=None, official=True,schema_version='0.2.0'):
    source,output=Path(source),Path(output)
    if output.resolve()==source.resolve() or output.resolve() in source.resolve().parents:
        raise ValueError('Output must not replace an input file or its parent')
    raw=source.read_bytes();text=raw.decode('utf-8-sig')
    if any(line.startswith(('!! IOS XR','!Command:','feature ')) for line in text.splitlines()):
        raise ValueError('Unsupported non-IOS platform signature')
    extracted=extract(text,official=official)
    if schema_version=='0.2.0':
        from normalizer.v02 import SemanticMapper
        mapper=SemanticMapper(extracted,text,str(source.resolve()),os_family,hashlib.sha256(raw).hexdigest())
    else:mapper=Mapper(extracted,text,str(source.resolve()),os_family,hashlib.sha256(raw).hexdigest())
    normalized=mapper.run()
    normalized.parsing.native_tree_file=str((output/'parsed_native.json').resolve())
    document=normalized.model_dump(mode='json')
    if schema_version=='0.2.0':
        from jsonschema import Draft202012Validator
        from parser.coverage_v02 import build_coverage as coverage2
        from schemas.normalizedconfig_v02 import NormalizedConfig
        NormalizedConfig.model_validate(document)
        Draft202012Validator(NormalizedConfig.model_json_schema()).validate(document)
        coverage=coverage2(extracted,mapper,legacy_lines)
    else:
        validate(document);coverage=build_coverage(extracted,mapper,legacy_lines)
    native=public_native(extracted)
    if schema_version=='0.2.0':native['validation_by_source_line']=mapper.validation
    write_json(output/'parsed_native.json',native)
    write_json(output/'normalized_config.json',document)
    write_json(output/'coverage_report.json',coverage)
    assert hashlib.sha256(source.read_bytes()).hexdigest()==normalized.metadata.source_sha256
    return normalized,coverage


def main(argv=None):
    p=argparse.ArgumentParser(description='TTP Cisco IOS/IOS-XE → NormalizedConfig v0.1.0')
    p.add_argument('input',type=Path);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--os-family',choices=('ios','iosxe'),default='ios')
    p.add_argument('--strict',action='store_true')
    p.add_argument('--schema-version',choices=('0.1.0','0.2.0'),default='0.2.0')
    args=p.parse_args(argv)
    result,coverage=convert_file(args.input,args.output,os_family=args.os_family,schema_version=args.schema_version)
    remaining=[row for row in coverage['commands'] if row['status'] in ('extracted_unmapped','preserved_uninterpreted','invalid_value','partially_normalized','uninterpreted','invalid_or_ambiguous')]
    print(f'{args.output}: {len(result.configuration.interfaces)} interfaces, {len(remaining)} commands without full mapping.')
    return 2 if args.strict and remaining else 0


if __name__=='__main__': raise SystemExit(main())
