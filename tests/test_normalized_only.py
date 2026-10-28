"""Single-output API and semantic safeguards, with literal source expectations."""
from dataclasses import fields
import json
import pytest
import cli
from normalizer.common.configured import Binding,validate_targets
from normalizer.engine import NormalizationEngine
from normalizer.serialization import to_dict
from parser.run_ttp import extract
from schemas.normalized_config import NormalizedConfig


def test_no_provenance_or_report_buffers_are_built():
    x=extract('interface E1\n ip address 192.0.2.1 255.255.255.0\n',official=False)
    m=NormalizationEngine(x);model=m.run()
    assert {'interfaces','routing','system'} <= set(type(model).model_fields)
    assert 'configuration' not in type(model).model_fields
    for owner in (m,):
        assert not {'evidence','diagnostics','metadata','partial_notes','extra_invalid'}.intersection(vars(owner))
    assert {f.name for f in fields(Binding)}=={'path','record'}
    assert not {'official_errors','official_template_hashes','versions','selection'}.intersection(x)
    assert set(to_dict(model))=={'interfaces'}


def test_field_integrity_remains_enforced():
    model=NormalizedConfig(interfaces=[{'name':'E1'}])
    validate_targets(model,[Binding('/interfaces/0/name',1)])
    with pytest.raises(ValueError):validate_targets(model,[Binding('/interfaces/1/name',1)])
    with pytest.raises(ValueError):validate_targets(model,[Binding('/interfaces/0/mtu',1)])


def test_conflicting_capture_is_not_adopted():
    x=extract('interface E1\n mtu 1500\n',official=False)
    x['ambiguous_lines'].add(2)
    m=NormalizationEngine(x);model=m.run()
    assert not m.is_complete(2)
    assert to_dict(model)=={'interfaces':[{'name':'E1','kind':'physical'}]}


@pytest.mark.parametrize('command',[
    'mtu invalid','mtu -1','ip address 192.0.2.1 255.0.255.0',
    'ip address 999.0.0.1 255.255.255.0','speed potato',
])
def test_invalid_parameter_does_not_leak_a_guessed_fact(command):
    result=cli.normalize('interface E1\n '+command+'\n',official=False)
    assert result=={'interfaces':[{'name':'E1','kind':'physical'}]}


def test_incomplete_acl_blocks_its_route_map_dependency():
    result=cli.normalize('ip access-list extended A\n permit ip any any\n permit ip any any UNKNOWN\n'
        'route-map P permit 10\n match ip address A\n set metric 0\n',official=False)
    assert not result.get('security',{}).get('acl_sets')
    assert not result.get('routing',{}).get('routing_policies')


def test_partial_qos_policy_does_not_become_executable():
    result=cli.normalize('class-map match-any C\n match protocol http\n'
        'policy-map P\n class C\n  future-action 7\n',official=False)
    assert not result.get('qos',{}).get('policy_maps')


def test_python_text_api_has_no_file_side_effects(tmp_path,monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert cli.normalize('hostname R\n',official=False)=={'system':{'hostname':'R'}}
    assert list(tmp_path.iterdir())==[]


@pytest.mark.parametrize('option',['--legacy','--strict','--output-format','--schema-version'])
def test_removed_cli_options_are_rejected(option):
    with pytest.raises(SystemExit) as exc:cli.main(['router.cfg','--output','out',option])
    assert exc.value.code==2


def test_opaque_and_credentials_are_not_business_data():
    secret='CANARY_PRIVATE_6384'
    text=(f'username reader privilege 15 secret 9 {secret}\n'
        f'snmp-server community {secret} RO A\nlicense udi pid CSR1000V sn {secret}\n'
        f'banner motd #\nhostname {secret}\n#\nhostname REAL\n'
        f'crypto pki certificate chain TP\n certificate ca 01\n  0123456789ABCDEF\n quit\n')
    result=cli.normalize(text,official=False)
    assert secret not in json.dumps(result)
    assert '0123456789ABCDEF' not in json.dumps(result)
    assert result['system']['hostname']=='REAL'
    assert result['system']['aaa']['local_users'][0]['credential_configured'] is True


def test_unknown_mode_does_not_change_ospf_or_bgp_context():
    text=('router bgp 65000\n address-family ipv4 vrf A\n  unknown-mode\n'
        '   neighbor UNDECLARED allowas-in\nrouter ospf 1\n router-id 192.0.2.1\n')
    result=cli.normalize(text,official=False)
    assert not any(af.get('peers') for p in result['routing']['bgp'] for af in p.get('address_families',[]))
    assert result['routing']['ospf'][0]['router_id']=='192.0.2.1'
