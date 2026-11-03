"""Literal source/contract facts for every implemented P1 family."""
import json
from pathlib import Path
import pytest
from jsonschema import Draft202012Validator
from .test_v02 import parse,pointer
from .test_catalogue_completion import CASES,source
from schemas.router_contract_v1 import RouterContractV1
from cli import convert_file

ROOT=Path(__file__).resolve().parents[1]
# All values and paths are reviewed independently of mapper evidence.
TARGETS={
 'catalogue_password_minimum':('system/aaa/password_policy/minimum_length',1),
 'bgp_no_auto_summary':('routing/bgp/0/address_families/0/auto_summary',False),
 'bgp_no_sync':('routing/bgp/0/address_families/0/synchronization',False),
 'catalogue_allowas':('routing/bgp/0/address_families/0/peers/0/allowas_in/configured_max_occurrences',None),
 'catalogue_config_register':('system/boot/configuration_register','0x2102'),
 'catalogue_dns_view':('system/dns/views/0/network_instance','MGMT'),
 'catalogue_domain_source':('system/dns/lookup_source_interface','Loopback0'),
 'catalogue_dhcp4':('interfaces/0/ipv4/assignment_method','dhcp'),
 'catalogue_msdp_peer':('multicast/msdp/peers/0/address','192.0.2.2'),
 'catalogue_pim_autorp':('multicast/auto_rp/listener_configured',True),
 'catalogue_pim_bsr':('multicast/bsr_candidates/0/hash_mask_length',0),
 'catalogue_pim_discovery':('multicast/auto_rp/discovery_scope',10),
 'catalogue_pim_rp_candidate':('multicast/rp_candidates/0/source_interface','Loopback0'),
 'catalogue_pim_ssm':('multicast/ssm/range_selector','default'),
 'catalogue_sap':('interfaces/0/sap_listen_enabled',True),
 'catalogue_icmp_no_limit':('system/ip_services/icmp_unreachable_rate_limit_enabled',False),
 'catalogue_synwait':('system/ip_services/tcp_synwait_seconds',5),
 'catalogue_forward_protocol':('system/ip_services/broadcast_forwarding_protocols/0/protocol','nd'),
 'catalogue_rip':('routing/rip/0/declared',True),
 'catalogue_rip_family':('routing/rip/0/address_families/0/network_instance','CLIENT'),
 'catalogue_rip_network':('routing/rip/0/network_statements/0','192.0.2.0'),
 'catalogue_rip_no_summary':('routing/rip/0/address_families/0/auto_summary',False),
 'catalogue_rip_redistribute':('routing/rip/0/address_families/0/redistributions/0/source_bgp_as',65000),
 'catalogue_archive':('system/config_archive/declared',True),
 'catalogue_archive_hide':('system/config_archive/config_logging/hidekeys',True),
 'catalogue_archive_log':('system/config_archive/config_logging/declared',True),
 'catalogue_call_home':('system/call_home/declared',True),
 'catalogue_call_home_active':('system/call_home/profiles/0/active',True),
 'catalogue_call_home_destination':('system/call_home/profiles/0/transport_methods',['http']),
 'catalogue_call_home_on':('system/call_home/enabled',True),
 'catalogue_call_home_profile':('system/call_home/profiles/0/name','CiscoTAC-1'),
 'catalogue_virtual_service':('extensions/cisco/virtual_services/0/name','csr_mgmt'),
 'catalogue_cache_export':('system/flow_monitoring/aggregation_caches/0/destinations/0/port',9000),
 'catalogue_tftp_source':('system/file_transfer/tftp/source_interface','Loopback7'),
 'catalogue_cef':('system/ip_services/cef_ipv4_enabled',True),
 'catalogue_cef6':('system/ip_services/cef_ipv6_enabled',True),
 'catalogue_no_cef6':('system/ip_services/cef_ipv6_enabled',False),
}


@pytest.mark.parametrize('case',[r for r in CASES if r[0] in TARGETS],ids=lambda r:r[0])
def test_literal_p1_values_and_status(case):
    rule,parents,command,expected=case
    x,n,c=parse(source(parents,command));path,value=TARGETS[rule]
    actual=pointer(n.model_dump(mode='json'),path)
    assert actual==value and type(actual) is type(value)
    assert c.is_complete(max(c.nodes))


def test_other_router_p1_families_context_and_relation():
    x,n,c=parse('router bgp 65000\n neighbor G peer-group\n address-family ipv4\n  neighbor G advertise additional-paths all\n')
    assert n.routing.bgp[0].address_families[0].peers[0].additional_paths_advertise_selection=='all'
    assert c.is_complete(max(c.nodes))
    x,n,c=parse('interface E1\n ip pim sparse-mode\n ip pim bsr-border\n')
    assert n.interfaces[0].pim_mode=='sparse-mode'
    assert n.interfaces[0].pim_bsr_border is True
    assert c.is_complete(max(c.nodes))



@pytest.mark.parametrize('cmd,prefix,kind,value',[
 ('match ip address 101','ip access-list standard 101\n permit any\n','acl','101'),
 ('match ip address prefix-list F','ip prefix-list F seq 10 deny 192.0.2.0/24 le 32\n','prefix_set_ipv4','F'),
 ('match ipv6 address prefix-list F','ipv6 prefix-list F seq 10 permit 2001:db8::/32 le 64\n','prefix_set_ipv6','F'),
 ('set as-path prepend 65000 65000 1.10','','as_path_prepend','65000 65000 1.10'),
 ('set community 65000:1 additive','','community','65000:1 additive'),
 ('set community 65000:1','','community','65000:1'),
])
def test_existing_policy_no_duplicate_or_semantic_parameter_loss(cmd,prefix,kind,value):
    x,n,c=parse(prefix+'route-map P permit 10\n '+cmd+'\n')
    statement=n.routing_policies.route_maps[0].statements[0]
    objects=statement.matches if cmd.startswith('match ') else statement.actions
    assert len(objects)==1 and objects[0].kind==kind
    if cmd.startswith('match '):assert objects[0].name==value
    elif kind=='as_path_prepend':assert objects[0].as_numbers==[65000,65000,65546]
    else:
        assert objects[0].communities==['65000:1']
        assert objects[0].additive is value.endswith(' additive')
    assert c.is_complete(max(c.nodes))


@pytest.mark.parametrize('cmd',[
 'set community 65536:1 additive','set community 65000:1 unsupported','set as-path prepend 4294967296',
 'match community C',
])
def test_unvalidated_policy_not_promoted(cmd):
    x,n,c=parse('ip community-list expanded C permit _1:\nroute-map P permit 10\n '+cmd+'\n')
    assert not c.is_complete(max(c.nodes))


@pytest.mark.parametrize('number,prefix',[('10.0.0.0','10.0.0.0/8'),('172.16.0.0','172.16.0.0/16'),('192.168.10.0','192.168.10.0/24')])
def test_documented_classful_syntax(number,prefix):
    x,n,c=parse('router bgp 65000\n network '+number+'\n')
    assert str(n.routing.bgp[0].networks[0].prefix)==prefix
    assert c.is_complete(max(c.nodes))


@pytest.mark.parametrize('number',['10.1.0.0','172.16.1.0','127.0.0.0','224.0.0.0','0.0.0.0'])
def test_non_classful_or_special_form_is_not_invented(number):
    x,n,c=parse('router bgp 65000\n network '+number+'\n')
    assert n.routing.bgp[0].networks is None
    assert not c.is_complete(max(c.nodes))


def test_rip_scope_and_omitted_operational_properties():
    x,n,c=parse('router rip\n network 192.0.2.0\n address-family ipv4 vrf A\n  network 198.51.100.0\n  redistribute bgp 1.10 metric 1\n  no auto-summary\n exit-address-family\n address-family ipv4 vrf B\n  network 203.0.113.0\n')
    p=n.routing.rip[0]
    assert list(map(str,p.network_statements))==['192.0.2.0'] and p.auto_summary is None
    assert [(a.network_instance,list(map(str,a.network_statements))) for a in p.address_families]==[('A',['198.51.100.0']),('B',['203.0.113.0'])]
    assert p.address_families[0].redistributions[0].source_bgp_as==65546
    assert p.address_families[0].redistributions[0].metric==1
    assert p.address_families[1].auto_summary is None
    assert n.routing.bgp is None


def test_bgp_af_and_vrf_no_widening_and_unspecified_allowas_count():
    x,n,c=parse('router bgp 65000\n address-family ipv4 vrf A\n  no synchronization\n  no auto-summary\n  neighbor 192.0.2.1 allowas-in\n exit-address-family\n address-family ipv4 vrf B\n  neighbor 192.0.2.1 allowas-in\n')
    process,=n.routing.bgp
    a,b=process.address_families
    assert process.synchronization is None and process.auto_summary is None
    assert a.synchronization is False and a.auto_summary is False
    assert b.synchronization is None
    assert a.peers[0].allowas_in.configured_max_occurrences is None
    assert all(c.is_complete(line) for line in (3,4,5,8))


def test_p2_review_native_and_unknown_statuses_unchanged():
    x,n,c=parse('call-home\n contact-email-addr example@example.invalid\n profile P\n  active\n  destination transport-method http\ninterface E1\n ip address dhcp\nlogging synchronous\nmmi polling-interval 60\n')
    assert not c.is_complete(2)
    assert not c.is_complete(9) and 8 not in x['records']
    assert not hasattr(n.system.call_home.profiles[0],'tls')
    assert n.interfaces[0].ipv4.addresses is None
    assert n.system.call_home.enabled is None


@pytest.mark.parametrize('text',[
 'router rip\n unknown-mode\n  network 192.0.2.0\n',
 'router bgp 65000\n address-family ipv4\n  unknown-mode\n   no synchronization\n',
 'router bgp 65000\n address-family ipv4\n  unknown-mode\n   neighbor 192.0.2.1 allowas-in\n',
 'call-home\n unknown-mode\n  profile P\n',
 'call-home\n profile P\n  unknown-mode\n   active\n',
])
def test_unknown_intermediate_modes_never_widen_new_mappings(text):
    x,n,c=parse(text)
    assert not c.is_complete(max(c.nodes))
    assert not c.consumed[max(c.nodes)]


def test_all_approved_p1_extension_families_have_literal_tests():
    decisions=json.loads((ROOT/'tests/fixtures/approved_extensions.json').read_text())
    required={r['family_id'] for r in decisions if r['decision']=='EXTEND_MODEL' and r['priority']=='P1'}
    assert required - {'advanced_l2_bridge'} == set(TARGETS)|{'bgp_advertise_additional','if_pim'}


@pytest.mark.parametrize('text',[
 'interface E1\n ip address 192.0.2.1 255.255.255.0\n ip address dhcp\n',
 'ip tcp synwait-time 4\n','ip pim bsr-candidate Loopback0 33\n',
 'ip pim ssm SOMETHING\n','ip flow-aggregation cache as\n export destination 192.0.2.1 65536\n',
])
def test_invalid_new_properties_not_fully_normalized(text):
    x,n,c=parse(text)
    assert not c.is_complete(max(c.nodes))


@pytest.mark.parametrize('command,kind', [
    ('match ip address MISSING', 'acl'),
    ('match ip address prefix-list MISSING', 'prefix_set_ipv4'),
])
def test_unresolved_policy_reference_remains_literal(command, kind):
    x, model, engine = parse('route-map P permit 10\n ' + command + '\n')
    match, = model.routing_policies.route_maps[0].statements[0].matches
    assert (match.kind, match.name) == (kind, 'MISSING')
    assert engine.is_complete(2)
