"""Cisco IOS/IOS-XE normalization: one parse, one business JSON output."""
import argparse
import json
from pathlib import Path
from parser.run_ttp import extract
from parser.platform import unsupported_platform
from normalizer.engine import normalize_captures
from normalizer.serialization import to_dict, to_json


def write_json(path, value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')


def _normalize_model(text, *, os_family='ios', official=True):
    if unsupported_platform(text):raise ValueError('Unsupported non-IOS platform signature')
    extracted=extract(text,official=official)
    return normalize_captures(extracted,os_family=os_family)


def normalize(text, *, os_family='ios', official=True):
    """Return configured business facts. Parsing state is local to this call."""
    return to_dict(_normalize_model(text,os_family=os_family,official=official))


def convert_file(source, output, *, os_family='ios', official=True):
    """Normalize a Cisco file, write normalized.json, return its business dict."""
    source,output=Path(source),Path(output)
    if output.resolve()==source.resolve() or output.resolve() in source.resolve().parents:
        raise ValueError('Output must not replace an input file or its parent')
    model=_normalize_model(source.read_text(encoding='utf-8-sig'),os_family=os_family,official=official)
    output.mkdir(parents=True,exist_ok=True)
    (output/'normalized.json').write_text(to_json(model),encoding='utf-8')
    return to_dict(model)


export_file=convert_file


def main(argv=None):
    p=argparse.ArgumentParser(description='Cisco IOS/IOS-XE → normalized.json')
    p.add_argument('input',type=Path);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--os-family',choices=('ios','iosxe'),default='ios')
    args=p.parse_args(argv)
    convert_file(args.input,args.output,os_family=args.os_family)
    print(args.output/'normalized.json')
    return 0


if __name__=='__main__':raise SystemExit(main())
