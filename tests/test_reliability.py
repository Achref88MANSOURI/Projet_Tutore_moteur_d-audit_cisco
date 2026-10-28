"""Independent literals and source coordinates for the reliability corrections."""
from pathlib import Path
import hashlib
import json
import pytest
from parser.run_ttp import extract
from normalizer.engine import NormalizationEngine

ROOT=Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('text,line,field,expected',[
    ('interface E1\n shutdown\n',2,'enabled',False),
    ('interface E1\n no shutdown\n',2,'enabled',True),
    ('interface E1\n no ip proxy-arp\n',2,'enabled',False),
    ('interface E1\n no ip redirects\n',2,'enabled',False),
    ('interface E1\n no ip address\n',2,'empty',True),
    ('interface E1\n no switchport\n',2,'mode','routed'),
    ('router bgp 65000\n address-family ipv4\n  neighbor 192.0.2.1 activate\n',3,'enabled',True),
    ('router bgp 65000\n address-family ipv6\n  no neighbor 192.0.2.1 activate\n',3,'enabled',False),
    ('router bgp 65000\n bgp log-neighbor-changes\n',2,'enabled',True),
    ('router bgp 65000\n neighbor 192.0.2.1 send-community\n',2,'option','unspecified'),
])
def test_constant_literals(text,line,field,expected):
    actual=extract(text,official=False)['records'][line]['values'][field]
    assert actual==expected and type(actual) is type(expected)


@pytest.mark.parametrize('command',['shutdown EXTRA','no shutdown EXTRA','no ip address EXTRA','no ip proxy-arp EXTRA','no ip redirects EXTRA'])
def test_no_constants_on_nonmatching_interface_variants(command):
    assert 2 not in extract('interface E1\n '+command+'\n',official=False)['records']


def test_login_logging_is_global_not_authentication():
    x=extract('login on-success log\nline vty 0 4\n login local\n',official=False)
    assert x['records'][1]['rule']=='services_login_logging'
    assert x['records'][1]['values']=={'enabled':True}
    assert x['records'][3]['rule']=='services_login'


def test_redaction_preserves_credential_type_not_credential():
    text='username reader privilege 15 secret 9 CANARY_SECRET_123\n'
    doc=normalize(text).model_dump(mode='json')
    assert doc['system']['aaa']['local_users'][0]['credential_type']=='secret:9'
    assert 'CANARY_SECRET_123' not in json.dumps(doc)


@pytest.fixture(scope='module')
def corpus_native():
    result={}
    for item in json.loads((ROOT/'configs/manifest.json').read_text(encoding='utf-8')):
        path=ROOT/item['config_file'];raw=path.read_bytes()
        assert hashlib.sha256(raw).hexdigest()==item['description_sha256']
        result[item['id']]=extract(raw.decode('utf-8-sig'),official=False)
    return result


def test_all_359_previous_constant_losses_recovered(corpus_native):
    expected=json.loads((ROOT/'tests/fixtures/constant_fields.json').read_text())
    assert len(expected)==359
    for fact in expected:
        actual=corpus_native[fact['file_id']]['records'][fact['line']]['values'][fact['field']]
        assert actual==fact['expected'] and type(actual) is type(fact['expected'])


def test_all_six_real_login_logging_lines_reclassified(corpus_native):
    count=0
    for x in corpus_native.values():
        for r in x['records'].values():
            if r['rule']=='services_login_logging':
                assert r['values']=={'enabled':True};count+=1
    assert count==6


def normalize(text):
    x=extract(text,official=False)
    return NormalizationEngine(x,os_family='ios').run()


def test_explicit_no_ip_address_is_not_ipv4_disabled():
    result=normalize('interface E1\n no ip address\n ip unnumbered Loopback0\n')
    assert result.interfaces[0].ipv4_addresses==[]
    assert result.interfaces[0].admin_enabled is None


def test_no_address_after_positive_address_has_no_dangling_evidence():
    r=normalize('interface E1\n ip address 192.0.2.1 255.255.255.0\n no ip address\n')
    assert not r.interfaces[0].ipv4_addresses


def test_tunnel_unknown_technology_and_dual_source_evidence():
    r=normalize('interface Loopback0\n ip address 192.0.2.1 255.255.255.255\ninterface Tunnel0\n tunnel source Loopback0\n tunnel destination 198.51.100.1\n')
    t=r.vpn_tunnels[0]
    assert (t.technology,t.local_endpoint,t.remote_endpoint)==('unknown','192.0.2.1','198.51.100.1')


def test_ambiguous_tunnel_source_is_not_resolved():
    r=normalize('interface Loopback0\n ip address 192.0.2.1 255.255.255.255\n ip address 192.0.2.2 255.255.255.255 secondary\ninterface Tunnel0\n tunnel source Loopback0\n tunnel destination 198.51.100.1\n')
    assert r.vpn_tunnels[0].local_endpoint is None


def test_transport_all_is_literal_wildcard_not_enumerated_protocols():
    r=normalize('line vty 0 4\n transport input all\n')
    assert r.system.management.lines[0].allowed_transports==['all']


def test_invalid_bgp_direction_has_no_partial_peer_credit():
    text='router bgp 65000\n neighbor 192.0.2.1 route-map P sideways\n'
    x=extract(text,official=False)
    m=NormalizationEngine(x,os_family='ios');r=m.run()
    assert not m.validation[2]['valid'] and 2 not in m.mapped


def test_29_real_empty_address_declarations_and_real_tunnel():
    count=0
    for entry in json.loads((ROOT/'configs/manifest.json').read_text(encoding='utf-8')):
        text=(ROOT/entry['config_file']).read_text(encoding='utf-8-sig');x=extract(text,official=False)
        m=NormalizationEngine(x,os_family=entry['os_family']);r=m.run()
        for rec in x['records'].values():
            if rec['rule']=='if_no_ipv4':
                assert rec['source_line'] in m.mapped;count+=1
        if entry['id']=='F0456':
            t=r.vpn_tunnels[0]
            assert (t.tunnel_interface,t.local_endpoint,t.remote_endpoint,t.technology)==('Tunnel0','94.45.227.2','195.177.253.41','unknown')
    assert count==29
