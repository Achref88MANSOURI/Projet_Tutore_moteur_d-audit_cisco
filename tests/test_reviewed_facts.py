"""Expected facts transcribed from source lines, not generated from parser output."""
import json
from pathlib import Path
import pytest
from parser.run_ttp import extract
from normalizer.engine import NormalizationEngine
from normalizer.common.validation import validate

ROOT=Path(__file__).resolve().parents[1]
FACTS=[fact for fact in json.loads((ROOT/'tests/reviewed_source_facts.json').read_text()) if fact['kind'] != 'native_evpn_instance']


@pytest.fixture(scope='module')
def parsed():
    manifest=json.loads((ROOT/'configs/manifest.json').read_text(encoding='utf-8'))
    results={}
    for record in manifest:
        if record['id'] not in {x['file_id'] for x in FACTS}:continue
        text=(ROOT/record['config_file']).read_text(encoding='utf-8-sig')
        x=extract(text,official=False)
        result=NormalizationEngine(x,os_family=record['os_family']).run()
        validate(result.model_dump(mode='json'))
        results[record['id']]=(result,x)
    return results


@pytest.mark.parametrize('fact',FACTS,ids=lambda f:f'{f["file_id"]}-L{f["line"]}-{f["kind"]}')
def test_reviewed_source_fact(parsed,fact):
    result,x=parsed[fact['file_id']];c=result
    kind,expected=fact['kind'],fact['expected']
    if kind=='hostname':assert c.system.identity.hostname==expected
    elif kind=='ipv4':
        interface=next(i for i in c.interfaces if i.name==fact['interface'])
        assert expected in [f'{a.address}/{a.prefix_length}' for a in interface.ipv4.addresses]
    elif kind=='asn':assert expected in [p.local_as for p in c.routing.bgp]
    elif kind=='rd':assert next(v for v in c.network_instances if v.name==fact['vrf']).route_distinguisher==expected
    elif kind=='as_path':
        policy=next(p for p in c.routing_policies.route_maps if p.name==fact['policy'])
        statement=next(s for s in policy.statements if s.identifier==fact['statement'])
        assert any(a.kind=='as_path_prepend' and a.as_numbers==[int(v) for v in expected.split()] for a in statement.actions)
    elif kind=='qos':assert any(a.interface_name==fact['interface'] and a.policy_name==expected and a.direction=='ingress' for a in c.qos.attachments)
    else:raise AssertionError('Unknown reviewed fact type')
