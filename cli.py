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


def normalize_with_provenance(text, *, os_family='ios', official=True, limits=None, on_provenance_error='raise', _evidence_sink=None):
    """Opt-in Python result: unchanged normalized dict and a sealed SourceMap.

    No sidecar is written, no HTTP/CLI response format is changed. Credentials
    and unknown source lines are never copied into the provenance result.
    """
    from normalizer.engine import NormalizationEngine
    from normalizer.provenance import Collector, Limits, NormalizationResult, ProvenanceError, check_input
    try:
        limits = Limits() if limits is None else limits
        if not isinstance(limits, Limits):
            raise ProvenanceError('Invalid provenance limits')
        if on_provenance_error not in ('raise', 'unavailable'):
            raise ProvenanceError('Invalid provenance error policy')
        limits.check()
        unavailable = False
        try:
            check_input(text, limits)
        except Exception:
            if on_provenance_error == 'raise':
                raise
            unavailable = True
        if unsupported_platform(text):
            raise ProvenanceError('Unsupported non-IOS platform signature')
        categories = {} if _evidence_sink is not None else None
        extracted = extract(text, official=official, **({'community_categories': categories} if categories is not None else {}))
        collector = None
        if not unavailable:
            try:
                collector = Collector(text, extracted, limits=limits)
            except Exception:
                if on_provenance_error == 'raise':
                    raise
                unavailable = True
        engine = NormalizationEngine(extracted, os_family=os_family, provenance=collector,
                                     provenance_errors=on_provenance_error)
        normalized = to_dict(engine.run())
        if _evidence_sink is not None:
            from normalizer.common.sensitive import community_facts
            _evidence_sink.update(community_facts(engine, categories))
        if unavailable or engine.provenance_error or collector is None or collector.sidecar is None:
            return NormalizationResult(normalized=normalized, source_map=None,
                                       provenance_error='PROVENANCE_UNAVAILABLE')
        return NormalizationResult(normalized=normalized, source_map=collector.sidecar)
    except ProvenanceError:
        raise
    except Exception:
        raise ProvenanceError('Normalization with provenance failed') from None


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


def analyze_with_evidence(text, *, os_family='ios', official=True, profile_level=2, include_lower=True):
    """Configuration-only Python transaction, including safe pre-redaction facts.

    Supplementary SHOW artifacts are not accepted. Historical profile arguments
    are retained, while the application transaction is always cumulative.
    """
    from cis_operation import analyze
    return analyze(text, os_family=os_family, official=official,
                   profile_level=profile_level, include_lower=include_lower)


def main(argv=None):
    p=argparse.ArgumentParser(description='Cisco IOS/IOS-XE → normalized.json')
    p.add_argument('input',type=Path);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--os-family',choices=('ios','iosxe'),default='ios')
    args=p.parse_args(argv)
    convert_file(args.input,args.output,os_family=args.os_family)
    print(args.output/'normalized.json')
    return 0


if __name__=='__main__':raise SystemExit(main())
