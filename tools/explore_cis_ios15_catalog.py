#!/usr/bin/env python3
"""Inspect a control or family without importing the audit engine."""
from pathlib import Path
import argparse
import json
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from audit.catalog.loader import CISIOS15Catalog


def main():
    parser = argparse.ArgumentParser()
    select = parser.add_mutually_exclusive_group(required=True)
    select.add_argument('--control', help='Example: 1.5.9')
    select.add_argument('--family', help='Example: F05')
    parser.add_argument('--deps', action='store_true', help='Show linked Fxx dependencies for --control')
    parser.add_argument('--json', action='store_true', help='Print JSON rather than compact text')
    args = parser.parse_args()
    c = CISIOS15Catalog()
    if args.control:
        try: x = c.control(args.control)
        except KeyError: parser.error(f'Unknown control: {args.control}')
        result = {'control': x, 'dependencies': c.dependencies_for_control(args.control)} if args.deps else x
    else:
        xs = c.controls_for_family(args.family.upper())
        if not xs: parser.error(f'Unknown family: {args.family}')
        result = xs
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        for x in result if isinstance(result,list) else ([result.get('control',result)]):
            print(f"{x['id']} [{x['family']}] {x['title']} — {x['profile_level']} / {x['assessment']}")
            print(f"  source PDF pages: {x['source']['pdf_page_start']}-{x['source']['pdf_page_end']}  | dependencies: {x['dependency_count']}")
            for cmd in x.get('audit_command_templates',[]):print('  AUDIT SOURCE: '+cmd)
            if args.deps and isinstance(result,dict):
                for d in result['dependencies']:print('  DEP:', d['dependency_id'], d['syntax'])

if __name__ == '__main__':main()
