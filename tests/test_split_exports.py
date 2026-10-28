"""Literal Cisco expectations; no generated mappings/templates used as truth."""
import json
from pathlib import Path
import pytest
import cli
from normalizer.common.contexts import at
from normalizer.domains.acl import acl_operand
from schemas.normalized_config import business_schema
from jsonschema import Draft202012Validator

def exported(tmp_path,text,**kwargs):
    source=tmp_path/'source.cfg';source.write_text(text,encoding='utf-8')
    return cli.export_file(source,tmp_path/'out',official=False,**kwargs)

def test_one_file_one_parse_no_defaults_false_zero_empty(tmp_path,monkeypatch):
    calls=[];real=cli.extract
    def counted(*a,**kw):calls.append(1);return real(*a,**kw)
    monkeypatch.setattr(cli,'extract',counted)
    n=exported(tmp_path,'hostname R\ninterface E1\n no ip address\n shutdown\nline vty 0 4\n exec-timeout 0 0\n transport input none\nno ip http server\n')
    assert len(calls)==1
    assert {p.name for p in (tmp_path/'out').iterdir()}=={'normalized.json'}
    assert n['interfaces'][0]['ipv4_addresses']==[]
    assert n['interfaces'][0]['admin_enabled'] is False
    assert n['system']['management']['lines'][0]['idle_timeout_seconds']==0
    assert n['system']['management']['lines'][0]['allowed_transports']==[]
    assert n['system']['management']['http_enabled'] is False
    assert 'https_enabled' not in n['system']['management']
    assert 'mtu' not in n['interfaces'][0]

def test_acl_host_that_looks_like_mask_is_literal(tmp_path):
    n=exported(tmp_path,'access-list 101 permit ip host 1.0.1.0 host 255.255.255.0\n')
    acl=n['security']['acl_sets'][0];assert acl['name']=='101'
    entry=acl['entries'][0]
    assert entry['source']=={'kind':'host','address':'1.0.1.0'}
    assert entry['destination']=={'kind':'host','address':'255.255.255.0'}

@pytest.mark.parametrize('source,expected',[
    ('any',{'kind':'any'}),
    ('host 255.255.255.0',{'kind':'host','address':'255.255.255.0'}),
    ('10.0.0.0 0.0.0.255',{'kind':'wildcard','address':'10.0.0.0','wildcard_mask':'0.0.0.255'}),
    ('10.0.0.0 0.255.0.255',{'kind':'wildcard','address':'10.0.0.0','wildcard_mask':'0.255.0.255'}),
    ('10.0.0.0 255.255.255.0',{'kind':'wildcard','address':'10.0.0.0','wildcard_mask':'255.255.255.0'}),
])
def test_acl_match_modes_do_not_confuse_wildcard_and_subnet(tmp_path,source,expected):
    n=exported(tmp_path,f'ip access-list extended A\n 10 permit ip {source} any\n')
    entry=n['security']['acl_sets'][0]['entries'][0]
    assert entry['sequence']==10 and entry['source']==expected and entry['destination']=={'kind':'any'}

def test_bgp_one_identity_inheritance_af_and_vrf(tmp_path):
    text=('router bgp 65000\n neighbor G peer-group\n neighbor G remote-as 65001\n neighbor G update-source Loopback0\n'
          ' neighbor 192.0.2.1 peer-group G\n address-family ipv4\n  no neighbor 192.0.2.1 activate\n exit-address-family\n'
          ' address-family ipv4 vrf BLUE\n  neighbor 192.0.2.1 remote-as 65002\n exit-address-family\n')
    n=exported(tmp_path,text)
    global_process=next(p for p in n['routing']['bgp'] if 'network_instance' not in p)
    group=global_process['peer_groups'][0]
    assert group=={'name':'G','remote_as':65001,'update_source':'Loopback0'}
    assert len(global_process['neighbors'])==1
    assert global_process['neighbors'][0]['inherited_group']=='G'
    assert 'remote_as' not in global_process['neighbors'][0]
    assert 'peer_options' not in global_process and 'family_options' not in global_process
    assert global_process['address_families'][0]['peers'][0]['active'] is False
    vrf=next(p for p in n['routing']['bgp'] if p.get('network_instance')=='BLUE')
    assert vrf['address_families'][0]['peers'][0]['remote_as']==65002

def test_qualified_policy_is_business_typed_not_cli_expression(tmp_path):
    n=exported(tmp_path,'route-map P permit 10\n set community 65000:1 65000:2 additive\n set as-path prepend 1.10 65000\n set local-preference 0\n')
    actions=n['routing']['routing_policies'][0]['statements'][0]['actions']
    assert {'kind':'community','communities':['65000:1','65000:2'],'additive':True} in actions
    assert {'kind':'as_path_prepend','as_numbers':[65546,65000]} in actions
    assert {'kind':'local_preference','value':0} in actions

def test_unqualified_policy_is_not_an_unconditional_permit(tmp_path):
    n=exported(tmp_path,'route-map UNSAFE permit 10\n match community UNKNOWN\n set metric 0\n')
    assert not n.get('routing',{}).get('routing_policies')

def test_partial_acl_is_not_exported_as_complete_acl(tmp_path):
    n=exported(tmp_path,'ip access-list extended A\n permit ip any any\n permit udp any any UNKNOWN-QUALIFIER\n')
    assert not n.get('security',{}).get('acl_sets')

def test_latest_speed_assignment_overrides_old_value(tmp_path):
    n=exported(tmp_path,'interface E1\n speed 100\n speed 1000\n')
    assert n['interfaces'][0]['ethernet']['speed_bps']==1000000000

def test_secrets_absent_from_output(tmp_path):
    secret='CANARY_NEVER_EXPORT_7a4a'
    n=exported(tmp_path,f'username reader privilege 15 secret 9 {secret}\nsnmp-server community {secret} RO A\nline vty 0 4\n password 0 {secret}\n login\n')
    assert secret not in json.dumps(n)
    assert n['system']['aaa']['local_users'][0]['credential_configured'] is True

def test_single_output_schema_without_second_parse(tmp_path,monkeypatch):
    calls=[];real=cli.extract
    monkeypatch.setattr(cli,'extract',lambda *a,**k:(calls.append(1),real(*a,**k))[1])
    doc=exported(tmp_path,'hostname R\n')
    assert len(calls)==1
    Draft202012Validator(business_schema()).validate(doc)
    assert 'schema_version' not in doc
    assert {p.name for p in (tmp_path/'out').iterdir()}=={'normalized.json'}

def test_no_technical_metadata_raw_commands_or_unproven_empty_collections(tmp_path):
    n=exported(tmp_path,'hostname R\ninterface E1\n description CUSTOMER LINK\n')
    forbidden={'evidence','parsing','diagnostics','unknown_commands','feature_coverage','observations','opaque_blocks','source_line','source_file','source_sha256','parser_rule','delimiter'}
    def visit(v):
        if isinstance(v,dict):
            assert not forbidden.intersection(v)
            for item in v.values():visit(item)
        elif isinstance(v,list):
            for item in v:visit(item)
    visit(n)
    assert n['interfaces'][0]['description']=='CUSTOMER LINK'
    assert 'ipv4_addresses' not in n['interfaces'][0]
    assert 'qos' not in n and 'cisco' not in n

@pytest.mark.parametrize('operand,expected',[
    ('any4',{'kind':'any','address_family':'ipv4'}),
    ('any6',{'kind':'any','address_family':'ipv6'}),
    ('2001:DB8::/32',{'kind':'prefix','prefix':'2001:db8::/32'}),
    ('object-group CLIENTS',{'kind':'object_group','name':'CLIENTS'}),
])
def test_other_captured_acl_operand_modes(operand,expected):
    assert acl_operand(operand)==expected

def test_same_mask_string_has_distinct_interface_and_acl_meanings(tmp_path):
    n=exported(tmp_path,'interface E1\n ip address 192.0.2.1 255.255.255.0\naccess-list 101 permit ip any host 255.255.255.0\n')
    assert n['interfaces'][0]['ipv4_addresses'][0]['prefix_length']==24
    assert n['security']['acl_sets'][0]['entries'][0]['destination']=={'kind':'host','address':'255.255.255.0'}

def test_ipv6_area_and_ipv4_network_mask_hierarchies_survive_projection(tmp_path):
    text=('interface E1\n ipv6 address 2001:DB8::1/64\n ipv6 ospf 1 area 0\n'
          'router bgp 65000\n address-family ipv4\n  network 192.0.2.0 mask 255.255.255.0\n exit-address-family\n'
          'ip route 198.51.100.0 255.255.255.0 192.0.2.2\n')
    n=exported(tmp_path,text)
    assert n['interfaces'][0]['ospf_bindings']==[{'version':3,'process':'1','area':'0'}]
    assert n['interfaces'][0]['ipv6_addresses'][0]['address']=='2001:db8::1'
    assert n['routing']['bgp'][0]['networks'][0]['prefix']=='192.0.2.0/24'
    assert n['routing']['static_routes'][0]['destination']=='198.51.100.0/24'

def test_unknown_child_does_not_invent_a_business_property(tmp_path):
    n=exported(tmp_path,'interface E1\n future-unsupported-command 7\n')
    assert n=={'interfaces':[{'name':'E1','kind':'physical'}]}

def test_cli_and_python_api_only_write_normalized(tmp_path):
    source=tmp_path/'input.cfg';source.write_text('hostname R\n')
    assert cli.main([str(source),'--output',str(tmp_path/'new')])==0
    assert {p.name for p in (tmp_path/'new').iterdir()}=={'normalized.json'}
    assert cli.convert_file(source,tmp_path/'api',official=False)=={'system':{'hostname':'R'}}
    assert {p.name for p in (tmp_path/'api').iterdir()}=={'normalized.json'}

def test_literal_unknown_is_not_an_unknown_value_marker(tmp_path):
    n=exported(tmp_path,'hostname unknown\ninterface E1\n description unknown\n')
    assert n['system']['hostname']=='unknown'
    assert n['interfaces'][0]['description']=='unknown'

def test_interface_only_ospfv2_has_versioned_business_process(tmp_path):
    n=exported(tmp_path,'interface E1\n ip ospf 1 area 0\n')
    assert n['routing']['ospf'][0]['identifier']=='1'
    assert n['routing']['ospf'][0]['version']==2
    assert n['routing']['ospf'][0]['areas'][0]['interfaces']==['E1']

def test_published_schema_is_the_actual_export_schema():
    root=Path(__file__).resolve().parents[1]
    assert json.loads((root/'schemas/normalized_export_v1.schema.json').read_text(encoding='utf-8'))==business_schema()

def test_collection_values_belong_to_the_correct_members(tmp_path):
    text=('interface E1\n ip ospf 1 area 0\ninterface E2\n ip ospf 1 area 0\nrouter ospf 1\n'
          'ip pim rp-address 192.0.2.1\nip pim rp-address 192.0.2.2\n'
          'service timestamps debug datetime msec localtime\nservice timestamps log datetime msec\n')
    n=exported(tmp_path,text)
    assert n['routing']['ospf'][0]['areas'][0]['interfaces']==['E1','E2']
    assert n['cisco']['multicast']['rendezvous_points']==['192.0.2.1','192.0.2.2']
    assert n['system']['timestamps']==[
        {'category':'debug','format':'datetime','options':['msec','localtime']},
        {'category':'log','format':'datetime','options':['msec']}]


def test_nat_does_not_export_an_identifier_generated_from_a_source_line(tmp_path):
    n=exported(tmp_path,'ip nat inside source static 192.0.2.10 198.51.100.10\n')
    assert n['nat']==[{'type':'static','source_match':'192.0.2.10','translated_source':'198.51.100.10'}]
