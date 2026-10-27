import hashlib
import importlib.util
import json
from pathlib import Path
import pytest

from parser.run_ttp import extract, public_native
from parser.inventory import inventory
from normalizer.mapping import Mapper
from normalizer.validation import validate

ROOT=Path(__file__).resolve().parents[1]


def convert(text,official=False):
    captured=extract(text,official=official)
    mapper=Mapper(captured,text,'test.cfg','ios')
    result=mapper.run()
    validate(result.model_dump(mode='json'))
    return result,captured,mapper


def test_runtime_does_not_import_previous_cisco_parser():
    assert importlib.util.find_spec('cisco_config_parser') is None


def test_ttp_values_actually_drive_mapping():
    x=extract('hostname SOURCE\n',official=False)
    x['records'][1]['values']['hostname']='CAPTURED'
    result=Mapper(x,'hostname SOURCE\n','test.cfg','ios').run()
    assert result.configuration.system.hostname=='CAPTURED'


def test_official_template_is_executed_and_its_address_record_consumed():
    result,x,mapper=convert('interface Ethernet1\n ip address 192.0.2.1 255.255.255.0\n!\n',official=True)
    assert not x['official_errors']
    assert x['official']['interfaces']
    assert mapper.official_usage==[{'line':2,'template':'interfaces','field':'ipv4_addresses.ip'}]
    assert result.configuration.interfaces[0].admin_enabled is None


@pytest.mark.parametrize('command,state',[('shutdown',False),('no shutdown',True)])
def test_explicit_admin_state(command,state):
    result,_,_=convert('interface Ethernet1\n '+command+'\n')
    assert result.configuration.interfaces[0].admin_enabled is state


def test_multiple_ipv4_ipv6_and_native_interface_name():
    result,_,_=convert('interface GigabitEthernet0/0.100\n ip address 10.0.0.1 255.255.255.0\n ip address 10.1.0.1 255.255.255.0 secondary\n ipv6 address 2001:db8::1/64\n')
    item=result.configuration.interfaces[0]
    assert item.name=='GigabitEthernet0/0.100' and item.parent_interface=='GigabitEthernet0/0'
    assert item.subinterface_index==100 and len(item.ipv4_addresses)==2
    assert item.ipv4_addresses[1].secondary is True and str(item.ipv6_addresses[0].address)=='2001:db8::1'


@pytest.mark.parametrize('mask',['255.0.255.0','0.0.0.255','255.255.255.1'])
def test_bad_netmask_does_not_produce_address(mask):
    result,_,mapper=convert('interface Ethernet1\n ip address 10.0.0.1 '+mask+'\n')
    assert not result.configuration.interfaces[0].ipv4_addresses
    assert 2 in mapper.failed


@pytest.mark.parametrize('indent',['',' ','  '])
def test_certificate_quit_is_attached_to_certificate_not_hex(indent):
    text='crypto pki certificate chain TP\n certificate ca 01\n  0123456789ABCDEF\n  ABCDEF0123456789\n'+indent+'quit\nhostname AFTER\n'
    nodes=inventory(text)
    blob=next(n for n in nodes.values() if n.kind=='opaque_pki')
    assert (blob.line,blob.end_line)==(3,4)
    assert nodes[5].parent==2 and nodes[5].root==1
    assert nodes[6].parent is None


def test_banner_body_cannot_create_configuration_objects():
    result,x,_=convert('banner motd ^C\nhostname EVIL\ninterface Ethernet99\n^C\nhostname REAL\n')
    assert result.configuration.system.hostname=='REAL'
    assert not result.configuration.interfaces
    assert any(n.kind=='opaque_banner' for n in x['nodes'].values())


def test_advanced_properties_extracted_but_not_credited_as_normalized():
    result,x,m=convert('interface Ethernet1\n ip pim sparse-mode\n mpls ip\n speed auto\n duplex full\n')
    assert {x['records'][i]['rule'] for i in (2,3,4,5)}=={'if_pim','if_mpls','if_speed','if_duplex'}
    assert not ({2,3,4,5} & m.mapped)
    assert len(result.parsing.unknown_commands)==4


def test_nested_service_instance_does_not_overwrite_physical_description():
    result,_,_=convert('interface Ethernet1\n description PHYSICAL\n service instance 10 ethernet\n  description SERVICE\n  service-policy input CHILD\n')
    assert result.configuration.interfaces[0].description=='PHYSICAL'
    assert not result.configuration.qos.attachments


def test_bgp_group_inheritance_and_explicit_neighbor_override():
    text='router bgp 1.10\n neighbor GROUP peer-group\n neighbor GROUP remote-as 65010\n neighbor 192.0.2.1 peer-group GROUP\n neighbor 192.0.2.2 peer-group GROUP\n neighbor 192.0.2.2 remote-as 65020\n'
    result,_,_=convert(text)
    process=result.configuration.routing.bgp[0]
    assert process.local_as==65546
    assert {n.peer:n.remote_as for n in process.neighbors}=={'192.0.2.1':65010,'192.0.2.2':65020}


def test_bgp_activation_af_and_policy_scope_not_widened():
    result,x,m=convert('router bgp 65000\n neighbor 192.0.2.1 remote-as 65001\n address-family ipv4\n  neighbor 192.0.2.1 activate\n  neighbor 192.0.2.1 route-map ONLY-IPV4 in\n exit-address-family\n')
    neighbor=result.configuration.routing.bgp[0].neighbors[0]
    assert neighbor.enabled is None and neighbor.import_policies==[]
    assert x['records'][4]['rule']=='bgp_activate' and 4 not in m.mapped and 5 not in m.mapped


def test_ospfv3_is_captured_without_masquerading_as_ospfv2():
    result,x,m=convert('ipv6 router ospf 1\n router-id 192.0.2.1\ninterface Ethernet1\n ipv6 ospf 1 area 0\n')
    assert not result.configuration.routing.ospf
    assert x['records'][1]['rule']=='ospf3_header' and 4 not in m.mapped


def test_prefix_deny_and_length_conditions_not_weakened():
    result,x,m=convert('ip prefix-list FILTER seq 10 permit 10.0.0.0/8\nip prefix-list FILTER seq 20 deny 10.1.0.0/16\nip prefix-list OTHER permit 192.0.2.0/24 le 32\n')
    assert not result.configuration.routing.prefix_sets
    assert len(x['records'])==3
    assert not m.mapped


def test_exact_permit_prefix_set_can_be_normalized():
    result,_,_=convert('ip prefix-list FILTER seq 10 permit 192.0.2.0/24\n')
    assert result.configuration.routing.prefix_sets[0].prefixes==['192.0.2.0/24']


def test_route_map_as_path_and_ipv6_prefix_match_are_mapped():
    result,_,_=convert('route-map PREPEND permit 10\n match ipv6 address prefix-list V6\n set as-path prepend 65101 65101\n')
    clause=result.configuration.routing.routing_policies[0].statements[0]
    assert clause.matches[0].kind=='prefix_set_ipv6'
    assert clause.actions[0].kind=='as_path_prepend' and clause.actions[0].value=='65101 65101'


@pytest.mark.parametrize('entry,source_kind,dest_port',[
    ('10 permit tcp any host 192.0.2.1 eq ssh log','any',22),
    ('10 deny tcp 10.0.0.0 0.255.0.255 any eq 443','wildcard',443),
])
def test_acl_addresses_ports_and_order(entry,source_kind,dest_port):
    result,_,_=convert('ip access-list extended FILTER\n '+entry+'\n 20 deny ip any any\n')
    first,second=result.configuration.security.acl_sets[0].entries
    assert first.source.kind==source_kind and first.destination_port.start==dest_port
    assert [first.sequence,second.sequence]==[10,20]


@pytest.mark.parametrize('qualifier',['established','time-range NIGHT','fragments','eq unknownservice'])
def test_unsupported_acl_qualifier_never_becomes_broader_permit(qualifier):
    result,_,_=convert('ip access-list extended FILTER\n permit tcp any any '+qualifier+'\n deny ip any any\n')
    assert [e.action for e in result.configuration.security.acl_sets[0].entries]==['deny']
    assert any(d.code=='PARTIAL_POLICY_DOMAIN' for d in result.parsing.diagnostics)


@pytest.mark.parametrize('command,hop,interface',[
    ('ip route 0.0.0.0 0.0.0.0 192.0.2.1','192.0.2.1',None),
    ('ip route 10.0.0.0 255.255.255.0 Null0',None,'Null0'),
    ('ipv6 route ::/0 Ethernet1 fe80::1','fe80::1','Ethernet1'),
])
def test_routes(command,hop,interface):
    result,_,_=convert(command+'\n');route=result.configuration.routing.static_routes[0]
    assert (str(route.next_hop) if route.next_hop else None)==hop and route.outgoing_interface==interface


def test_no_silent_static_route_track_qualifier_loss():
    result,_,_=convert('ip route 10.0.0.0 255.255.255.0 192.0.2.1 track 5\n')
    assert not result.configuration.routing.static_routes


def test_nat_static_basic_and_transports_are_not_guessed():
    result,_,_=convert('ip nat inside source static 10.0.0.1 192.0.2.1\nline vty 0 4\n transport input ssh\n login\n')
    assert result.configuration.nat[0].translated_source=='192.0.2.1'
    assert result.configuration.system.management.ssh_enabled is None
    assert result.configuration.system.management.lines[0].authentication=='login'


def test_official_nat_template_on_synthetic_input():
    result,x,mapper=convert('ip nat inside source static 10.0.0.1 192.0.2.1\nip nat inside source static 10.0.0.2 192.0.2.2 extendable\n',official=True)
    assert not x['official_errors']
    native=json.dumps(x['official']['nat_static'])
    assert '10.0.0.2' in native and '10.0.0.1' not in native
    assert result.configuration.nat[0].source_match=='10.0.0.1'
    assert len(result.configuration.nat)==1
    assert x['records'][2]['rule']=='services_nat_static_extendable' and 2 not in mapper.mapped


def test_ntp_source_and_logging_severity_are_applied_with_evidence():
    result,_,_=convert('ntp server 192.0.2.10\nntp source Loopback0\nlogging 192.0.2.20\nlogging trap informational\n')
    assert result.configuration.system.ntp_servers[0].source_interface=='Loopback0'
    assert result.configuration.system.syslog_destinations[0].severity=='informational'


@pytest.mark.parametrize('text',[
    'username admin privilege 15 secret 9 TESTSECRET\n',
    'snmp-server community TESTSECRET RO ACL\n',
    'enable secret 5 TESTSECRET\n',
    'radius server R\n key 7 TESTSECRET\n',
])
def test_secrets_absent_from_native_normalized_and_inventory_exports(text):
    result,x,_=convert(text)
    assert 'TESTSECRET' not in result.model_dump_json()
    assert 'TESTSECRET' not in json.dumps(public_native(x))


def test_exact_original_contract_and_schema_are_frozen():
    assert hashlib.sha256((ROOT/'schemas/normalizedconfig.py').read_bytes()).hexdigest()=='438edb9bf58f0143491c6ddc18c5500bddfa552cc8a12898dcd970e79ffd58e4'
    assert hashlib.sha256((ROOT/'schemas/normalizedconfig_v0_1.schema.json').read_bytes()).hexdigest()=='c56f5734071230e1a1eb0b75f718b3e573717dbe2e7bb900efc3e11f870199ba'


def test_upstream_snapshot_byte_hashes_match_catalogue():
    for entry in json.loads((ROOT/'templates/catalogue_upstream.json').read_text()):
        assert hashlib.sha256((ROOT/entry['path']).read_bytes()).hexdigest()==entry['sha256']
