import hashlib
import importlib.util
import json
import logging
from pathlib import Path
import pytest

import cli
import parser.run_ttp as parsing
from parser.run_ttp import extract
from parser.inventory import inventory
from normalizer.engine import NormalizationEngine
from normalizer.common.validation import validate

ROOT=Path(__file__).resolve().parents[1]


def convert(text,official=False):
    captured=extract(text,official=official)
    mapper=NormalizationEngine(captured,os_family='ios')
    result=mapper.run()
    validate(result.model_dump(mode='json'))
    return result,captured,mapper


def test_runtime_does_not_import_previous_cisco_parser():
    assert importlib.util.find_spec('cisco_config_parser') is None


def test_ttp_values_actually_drive_mapping():
    x=extract('hostname SOURCE\n',official=False)
    x['records'][1]['values']['hostname']='CAPTURED'
    result=NormalizationEngine(x,os_family='ios').run()
    assert result.system.hostname=='CAPTURED'


def test_official_template_is_executed_and_its_address_record_consumed():
    result,x,mapper=convert('interface Ethernet1\n ip address 192.0.2.1 255.255.255.0\n!\n',official=True)
    assert x['official']['interfaces']
    assert result.interfaces[0].admin_enabled is None


@pytest.mark.parametrize('name', list(parsing.OFFICIAL))
def test_all_official_templates_load_and_execute_successfully(name):
    result = parsing.run_official_template(name, parsing.OFFICIAL[name], 'hostname READY\n')
    assert result is not None


@pytest.mark.parametrize('name', ['interfaces', 'vrfs'])
def test_required_official_template_missing_stops_normalization(monkeypatch, tmp_path, name):
    real_get = parsing.get_template

    def missing(*, path):
        if path.endswith(parsing.OFFICIAL[name]):
            raise FileNotFoundError('SECRET_CONFIGURATION')
        return real_get(path=path)

    monkeypatch.setattr(parsing, 'get_template', missing)
    source = tmp_path / 'input.cfg'
    source.write_text('hostname READY\n', encoding='utf-8')
    destination = tmp_path / 'export'
    with pytest.raises(parsing.OfficialTemplateError) as caught:
        cli.convert_file(source, destination)
    error = caught.value
    assert (error.template_id, error.code, error.stage, error.cause_type) == (
        name, 'unavailable', 'load', 'FileNotFoundError')
    assert 'SECRET_CONFIGURATION' not in str(error)
    assert not destination.exists()


def test_optional_official_template_failure_is_logged_without_sensitive_text(monkeypatch, caplog):
    real_get = parsing.get_template

    def missing(*, path):
        if path.endswith(parsing.OFFICIAL['nat_static']):
            raise FileNotFoundError('SECRET_CONFIGURATION')
        return real_get(path=path)

    monkeypatch.setattr(parsing, 'get_template', missing)
    with caplog.at_level(logging.WARNING, logger=parsing.__name__):
        result = parsing.extract('hostname READY\n', official=True)
    assert result['official']['nat_static'] is None
    assert result['official']['interfaces'] is not None
    assert result['official']['vrfs'] is not None
    assert 'nat_static: unavailable at load (FileNotFoundError)' in caplog.text
    assert 'SECRET_CONFIGURATION' not in caplog.text


def test_official_snapshot_divergence_is_not_silent(monkeypatch):
    real_get = parsing.get_template
    filename = parsing.OFFICIAL['interfaces']
    monkeypatch.setattr(parsing, 'get_template', lambda *, path: (
        real_get(path=path) + '\nchanged' if path.endswith(filename) else real_get(path=path)))
    with pytest.raises(parsing.OfficialTemplateError) as caught:
        parsing.extract('hostname READY\n', official=True)
    assert (caught.value.template_id, caught.value.code, caught.value.stage) == (
        'interfaces', 'version_mismatch', 'snapshot')


def test_missing_frozen_snapshot_is_not_skipped(monkeypatch):
    original = Path.read_text
    frozen = parsing.ROOT / 'templates/upstream' / parsing.OFFICIAL['interfaces']

    def missing(path, *args, **kwargs):
        if path == frozen:
            raise FileNotFoundError('SECRET_CONFIGURATION')
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, 'read_text', missing)
    with pytest.raises(parsing.OfficialTemplateError) as caught:
        parsing.run_official_template('interfaces', parsing.OFFICIAL['interfaces'], 'hostname READY\n')
    assert (caught.value.code, caught.value.stage) == ('snapshot_missing', 'snapshot')
    assert 'SECRET_CONFIGURATION' not in str(caught.value)


@pytest.mark.parametrize('failing_stage', ['parse', 'result'])
def test_official_ttp_execution_failure_is_identifiable_and_sanitized(monkeypatch, failing_stage):
    class BrokenEngine:
        def parse(self, *, one):
            if failing_stage == 'parse':
                raise RuntimeError('SECRET_CONFIGURATION')

        def result(self):
            if failing_stage == 'result':
                raise RuntimeError('SECRET_CONFIGURATION')

    monkeypatch.setattr(parsing, 'ttp', lambda **kwargs: BrokenEngine())
    with pytest.raises(parsing.OfficialTemplateError) as caught:
        parsing.run_official_template('interfaces', parsing.OFFICIAL['interfaces'], 'hostname READY\n')
    assert (caught.value.code, caught.value.stage, caught.value.cause_type) == (
        'execution_error', failing_stage, 'RuntimeError')
    assert 'SECRET_CONFIGURATION' not in str(caught.value)


def test_empty_official_result_is_valid(monkeypatch):
    class EmptyEngine:
        def parse(self, *, one):
            pass

        def result(self):
            return [[]]

    monkeypatch.setattr(parsing, 'ttp', lambda **kwargs: EmptyEngine())
    assert parsing.run_official_template('interfaces', parsing.OFFICIAL['interfaces'], 'hostname READY\n') == [[]]


@pytest.mark.parametrize('command,state',[('shutdown',False),('no shutdown',True)])
def test_explicit_admin_state(command,state):
    result,_,_=convert('interface Ethernet1\n '+command+'\n')
    assert result.interfaces[0].admin_enabled is state


def test_multiple_ipv4_ipv6_and_native_interface_name():
    result,_,_=convert('interface GigabitEthernet0/0.100\n ip address 10.0.0.1 255.255.255.0\n ip address 10.1.0.1 255.255.255.0 secondary\n ipv6 address 2001:db8::1/64\n')
    item=result.interfaces[0]
    assert item.name=='GigabitEthernet0/0.100' and item.parent_interface=='GigabitEthernet0/0'
    assert item.subinterface_index==100 and len(item.ipv4_addresses)==2
    assert item.ipv4_addresses[1].secondary is True and str(item.ipv6_addresses[0].address)=='2001:db8::1'


@pytest.mark.parametrize('mask',['255.0.255.0','0.0.0.255','255.255.255.1'])
def test_bad_netmask_does_not_produce_address(mask):
    result,_,mapper=convert('interface Ethernet1\n ip address 10.0.0.1 '+mask+'\n')
    assert not result.interfaces[0].ipv4_addresses
    assert not mapper.validation[2]['valid']


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
    assert result.system.hostname=='REAL'
    assert not result.interfaces
    assert any(n.kind=='opaque_banner' for n in x['nodes'].values())


def test_advanced_properties_are_normalized_by_the_unified_domain():
    result,x,m=convert('interface Ethernet1\n ip pim sparse-mode\n mpls ip\n speed auto\n duplex full\n')
    assert {x['records'][i]['rule'] for i in (2,3,4,5)}=={'if_pim','if_mpls','if_speed','if_duplex'}
    assert all(m.is_complete(line) for line in (2,3,4,5))
    interface=result.interfaces[0]
    assert interface.ethernet.speed_mode=='auto' and interface.ethernet.duplex=='full'
    assert interface.pim_mode=='sparse-mode' and interface.mpls_enabled is True


def test_nested_service_instance_does_not_overwrite_physical_description():
    result,_,_=convert('interface Ethernet1\n description PHYSICAL\n service instance 10 ethernet\n  description SERVICE\n  service-policy input CHILD\n')
    assert result.interfaces[0].description=='PHYSICAL'
    assert not result.qos.attachments


def test_bgp_group_inheritance_and_explicit_neighbor_override():
    text='router bgp 1.10\n neighbor GROUP peer-group\n neighbor GROUP remote-as 65010\n neighbor 192.0.2.1 peer-group GROUP\n neighbor 192.0.2.2 peer-group GROUP\n neighbor 192.0.2.2 remote-as 65020\n'
    result,_,_=convert(text)
    process=result.routing.bgp[0]
    assert process.local_as==65546
    assert {n.peer:n.remote_as for n in process.neighbors}=={'192.0.2.1':None,'192.0.2.2':65020}
    assert process.neighbors[0].inherited_group=='GROUP'
    assert process.peer_groups[0].remote_as==65010


def test_bgp_activation_af_and_policy_scope_not_widened():
    result,x,m=convert('router bgp 65000\n neighbor 192.0.2.1 remote-as 65001\n address-family ipv4\n  neighbor 192.0.2.1 activate\n  neighbor 192.0.2.1 route-map ONLY-IPV4 in\n exit-address-family\n')
    neighbor=result.routing.bgp[0].neighbors[0]
    assert neighbor.enabled is None and neighbor.import_policies==[]
    assert x['records'][4]['rule']=='bgp_activate'
    family=process.address_families[0] if (process:=result.routing.bgp[0]) else None
    assert family.peers[0].active is True and family.peers[0].import_policies==['ONLY-IPV4']


def test_ospfv3_is_captured_without_masquerading_as_ospfv2():
    result,x,m=convert('ipv6 router ospf 1\n router-id 192.0.2.1\ninterface Ethernet1\n ipv6 ospf 1 area 0\n')
    assert result.routing.ospf[0].version==3
    assert result.interfaces[0].ospf_bindings[0].version==3
    assert x['records'][1]['rule']=='ospf3_header'


def test_prefix_deny_and_length_conditions_not_weakened():
    result,x,m=convert('ip prefix-list FILTER seq 10 permit 10.0.0.0/8\nip prefix-list FILTER seq 20 deny 10.1.0.0/16\nip prefix-list OTHER permit 192.0.2.0/24 le 32\n')
    assert [(e.action,e.le) for e in result.routing.prefix_lists[0].entries]==[('permit',None),('deny',None)]
    assert result.routing.prefix_lists[1].entries[0].le==32
    assert len(x['records'])==3


def test_exact_permit_prefix_set_can_be_normalized():
    result,_,_=convert('ip prefix-list FILTER seq 10 permit 192.0.2.0/24\n')
    assert [str(e.prefix) for e in result.routing.prefix_lists[0].entries]==['192.0.2.0/24']


def test_route_map_as_path_and_ipv6_prefix_match_are_mapped():
    result,_,_=convert('ipv6 prefix-list V6 permit 2001:db8::/32\nroute-map PREPEND permit 10\n match ipv6 address prefix-list V6\n set as-path prepend 65101 65101\n')
    clause=result.routing.routing_policies[0].statements[0]
    assert clause.matches[0].kind=='prefix_set_ipv6'
    assert clause.actions[0].kind=='as_path_prepend' and clause.actions[0].as_numbers==[65101,65101]


@pytest.mark.parametrize('entry,source_kind,dest_port',[
    ('10 permit tcp any host 192.0.2.1 eq ssh log','any',22),
    ('10 deny tcp 10.0.0.0 0.255.0.255 any eq 443','wildcard',443),
])
def test_acl_addresses_ports_and_order(entry,source_kind,dest_port):
    result,_,_=convert('ip access-list extended FILTER\n '+entry+'\n 20 deny ip any any\n')
    first,second=result.security.acl_sets[0].entries
    assert first.source.kind==source_kind and first.destination_port.start==dest_port
    assert [first.sequence,second.sequence]==[10,20]


@pytest.mark.parametrize('qualifier',['established','time-range NIGHT','fragments','eq unknownservice'])
def test_unsupported_acl_qualifier_never_becomes_broader_permit(qualifier):
    result,_,_=convert('ip access-list extended FILTER\n permit tcp any any '+qualifier+'\n deny ip any any\n')
    assert not result.security.acl_sets  # Do not publish a partial policy as a complete ACL.


@pytest.mark.parametrize('command,hop,interface',[
    ('ip route 0.0.0.0 0.0.0.0 192.0.2.1','192.0.2.1',None),
    ('ip route 10.0.0.0 255.255.255.0 Null0',None,'Null0'),
    ('ipv6 route ::/0 Ethernet1 fe80::1','fe80::1','Ethernet1'),
])
def test_routes(command,hop,interface):
    result,_,_=convert(command+'\n');route=result.routing.static_routes[0]
    assert (str(route.next_hop) if route.next_hop else None)==hop and route.outgoing_interface==interface


def test_no_silent_static_route_track_qualifier_loss():
    result,_,_=convert('ip route 10.0.0.0 255.255.255.0 192.0.2.1 track 5\n')
    assert not result.routing.static_routes


def test_nat_static_basic_and_transports_are_not_guessed():
    result,_,_=convert('ip nat inside source static 10.0.0.1 192.0.2.1\nline vty 0 4\n transport input ssh\n login\n')
    assert result.nat[0].translated_source=='192.0.2.1'
    assert result.system.management.ssh_enabled is None
    assert result.system.management.lines[0].authentication.method=='line_password'


def test_official_nat_template_on_synthetic_input():
    result,x,mapper=convert('ip nat inside source static 10.0.0.1 192.0.2.1\nip nat inside source static 10.0.0.2 192.0.2.2 extendable\n',official=True)
    native=json.dumps(x['official']['nat_static'])
    assert '10.0.0.2' in native and '10.0.0.1' not in native
    assert result.nat[0].source_match=='10.0.0.1'
    assert len(result.nat)==1
    assert x['records'][2]['rule']=='services_nat_static_extendable' and 2 not in mapper.mapped


def test_ntp_source_and_logging_severity_are_applied_with_evidence():
    result,_,_=convert('ntp server 192.0.2.10\nntp source Loopback0\nlogging 192.0.2.20\nlogging trap informational\n')
    assert result.system.ntp_servers[0].source_interface=='Loopback0'
    assert result.system.syslog_destinations[0].severity=='informational'


@pytest.mark.parametrize('text',[
    'username admin privilege 15 secret 9 TESTSECRET\n',
    'snmp-server community TESTSECRET RO ACL\n',
    'enable secret 5 TESTSECRET\n',
    'radius server R\n key 7 TESTSECRET\n',
])
def test_secrets_absent_from_native_normalized_and_inventory_exports(text):
    result,x,_=convert(text)
    assert 'TESTSECRET' not in result.model_dump_json()




def test_upstream_snapshot_byte_hashes_match_catalogue():
    for entry in json.loads((ROOT/'templates/catalogue_upstream.json').read_text()):
        assert hashlib.sha256((ROOT/entry['path']).read_bytes()).hexdigest()==entry['sha256']
