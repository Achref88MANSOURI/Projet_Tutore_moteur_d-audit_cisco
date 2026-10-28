import hashlib,json
from pathlib import Path
import pytest
from pydantic import ValidationError
from schemas import normalized_config as s
from parser.run_ttp import extract
from normalizer.engine import NormalizationEngine
from .oracle_v02 import FACTS
ROOT=Path(__file__).resolve().parents[1]


def parse(text):
    x=extract(text,official=False);m=NormalizationEngine(x,os_family='ios');n=m.run()
    return x,n,m


@pytest.fixture(scope='module')
def corpus():
    result={}
    for item in json.loads((ROOT/'configs/manifest.json').read_text(encoding='utf-8')):
        source=ROOT/item['config_file'];raw=source.read_bytes();text=raw.decode('utf-8-sig')
        assert hashlib.sha256(raw).hexdigest()==item['description_sha256']
        x=extract(text,official=False);m=NormalizationEngine(x,os_family=item['os_family']);n=m.run()
        result[item['id']]=(text,x,n.model_dump(mode='json'))
    return result


def pointer(value,path):
    for key in path.strip('/').split('/') if path else []:value=value[int(key)] if isinstance(value,list) else value[key]
    return value


@pytest.mark.parametrize('fact',FACTS,ids=lambda f:f'{f["file_id"]}-L{f["line"]}-{f["field"]}')
def test_independent_original_line_native_and_semantic_value(corpus,fact):
    text,x,doc=corpus[fact['file_id']]
    assert text.splitlines()[fact['line']-1].strip()==fact['source']
    record=x['records'][fact['line']]
    for key,expected in fact['native'].items():
        assert record['values'][key]==expected and type(record['values'][key]) is type(expected)
    target=doc
    for collection,identity in fact['selectors']:
        matches=[o for o in pointer(target,collection) if all(o[k]==v for k,v in identity.items())]
        assert len(matches)==1;target=matches[0]
    assert pointer(target,fact['field'])==fact['expected']


@pytest.mark.parametrize('command',[
 'speed potato','speed 0','duplex banana','negotiation off','media-type unknown-medium','encapsulation dot1Q 4095','ip tcp adjust-mss 70000',
])
def test_invalid_interface_domains_are_never_normalized(command):
    x,n,c=parse('interface E1\n '+command+'\n')
    assert not c.is_complete(2)
    assert not c.consumed[2]


def test_invalid_protocol_and_direction_not_given_full_credit():
    for text in ('ip access-list extended A\n permit imaginary-protocol any any\n','router bgp 65000\n neighbor 192.0.2.1 route-map X sideways\n'):
        x,n,c=parse(text);assert not c.is_complete(max(c.nodes))


def test_ospf_versions_do_not_merge():
    x,n,c=parse('router ospf 1\n router-id 192.0.2.1\nipv6 router ospf 1\n router-id 192.0.2.2\n')
    assert {(p.version,str(p.router_id)) for p in n.routing.ospf}=={(2,'192.0.2.1'),(3,'192.0.2.2')}


def test_prefix_constraints_and_duplicate_order():
    with pytest.raises(ValidationError):s.PrefixListEntry(action='permit',prefix='192.0.2.0/24',ge=16)
    with pytest.raises(ValidationError):s.PrefixListEntry(action='permit',prefix='::/0',le=129)
    x,n,c=parse('ip prefix-list X seq 10 permit 192.0.2.0/24\nip prefix-list X seq 10 deny 198.51.100.0/24\n')
    assert not c.is_complete(max(c.nodes))
    assert len(c.c.routing.prefix_lists[0].entries)==1
    assert not n.routing.prefix_lists  # A rejected duplicate must not publish a partial ordered list.


def test_native_only_observation_does_not_become_fully_normalized():
    x,n,c=parse('interface E1\n ip nat inside\n')
    assert not c.is_complete(max(c.nodes))


def test_context_guard_not_global_vty_or_physical_service():
    assert 1 not in extract('logging synchronous\n',official=False)['records']
    x,n,c=parse('interface E1\n service instance 100 ethernet\n  encapsulation dot1q 10\n  bridge-domain 100\n')
    assert n.interfaces[0].encapsulation is None
    service,=n.cisco.ethernet_services
    assert (service.interface,service.instance,service.encapsulation.kind,service.encapsulation.outer_vlan,service.bridge_domain)==('E1',100,'dot1q',10,100)
    assert all(c.is_complete(line) for line in c.nodes)






def test_schema_types_and_missing_ospf_version():
    with pytest.raises(ValidationError):s.Ethernet(speed_mode='auto',speed_bps=1000000000)
    with pytest.raises(ValidationError):s.OSPFProcess(identifier='1')


def test_af_options_are_not_widened_to_process():
    x,n,c=parse('router bgp 65000\n address-family ipv4\n  bgp dampening\n  maximum-paths eibgp 5\n exit-address-family\n')
    proc=n.routing.bgp[0]
    assert proc.dampening is None and proc.maximum_paths==[]
    assert proc.address_families[0].dampening is True and proc.address_families[0].maximum_paths[0].count==5


def test_classful_network_has_documented_natural_mask_and_derivation_proof():
    x,n,c=parse('router bgp 65000\n network 10.0.0.0\n')
    assert str(n.routing.bgp[0].networks[0].prefix)=='10.0.0.0/8'
    assert c.is_complete(max(c.nodes))


def test_nonmatching_global_context_is_not_adopted():
    assert 2 not in extract('line vty 0 4\n login on-success log\n',official=False)['records']


def test_duplicate_interface_does_not_create_guessed_second_object():
    x,n,c=parse('interface E1\n description FIRST\ninterface E1\n description SECOND\n')
    assert len(n.interfaces)==1 and n.interfaces[0].description=='FIRST'
    assert not c.is_complete(max(c.nodes))
