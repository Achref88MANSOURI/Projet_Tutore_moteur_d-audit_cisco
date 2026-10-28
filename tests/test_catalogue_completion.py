"""Reviewed synthetic source facts, independent of templates/normalizer output.

Every added rule has a literal source example and all expected scalar values.
Rule coverage is checked against the directly maintained TTP groups.
"""
import json
from pathlib import Path
import pytest
from parser.run_ttp import extract, load_templates
from parser.inventory import inventory
from parser.platform import unsupported_platform
from .test_v02 import parse

ROOT=Path(__file__).resolve().parents[1]

# (rule suffix, literal command, independently reviewed expected capture)
GLOBAL=[
 ('multilink','multilink bundle-name authenticated',{'naming':'authenticated'}),
 ('control_plane','control-plane',{'declared':True}),
 ('forward_protocol','ip forward-protocol nd',{'protocol':'nd'}),
 ('redundancy','redundancy',{'declared':True}),
 ('cef','ip cef',{'enabled':True}),('cef6','ipv6 cef',{'enabled':True}),
 ('no_cef6','no ipv6 cef',{'enabled':False}),
 ('mmi_poll','mmi polling-interval 60',{'interval':60}),
 ('mmi_no_auto','no mmi auto-configure',{'enabled':False}),
 ('mmi_no_pvc','no mmi pvc',{'enabled':False}),
 ('mmi_timeout','mmi snmp-timeout 180',{'timeout':180}),
 ('ioam','ipv6 ioam timestamp',{'enabled':True}),
 ('scheduler_none','no scheduler allocate',{'configured':False}),
 ('scheduler','scheduler allocate 20000 1000',{'interrupt':20000,'process':1000}),
 ('subscriber','subscriber templating',{'enabled':True}),
 ('diagnostic','diagnostic bootup level minimal',{'level':'minimal'}),
 ('spanning_system_id','spanning-tree extend system-id',{'enabled':True}),
 ('console','platform console serial',{'transport':'serial'}),
 ('icmp_no_limit','no ip icmp rate-limit unreachable',{'limited':False}),
 ('synwait','ip tcp synwait-time 5',{'seconds':5}),
 ('memory_low','memory free low-watermark processor 71464',{'threshold':71464}),
 ('call_home','call-home',{'declared':True}),
 ('call_home_on','service call-home',{'enabled':True}),
 ('qfp','platform qfp utilization monitor load 80',{'percent':80}),
 ('punt','platform punt-keepalive disable-kernel-core',{'disabled':True}),
 ('no_punt','no platform punt-keepalive disable-kernel-core',{'disabled':False}),
 ('tftp_source','ip tftp source-interface Loopback7',{'interface':'Loopback7'}),
 ('dns_view','ip dns view vrf MGMT default',{'vrf':'MGMT','name':'default'}),
 ('no_cdp_log','no cdp log mismatch duplex',{'enabled':False}),
 ('bgp_community_format','ip bgp-community new-format',{'enabled':True}),
 ('upgrade','upgrade fpd auto',{'mode':'auto'}),
 ('mgcp','mgcp profile default',{'name':'default'}),
 ('gatekeeper','gatekeeper',{'declared':True}),
 ('virtual_service','virtual-service csr_mgmt',{'name':'csr_mgmt'}),
 ('config_register','config-register 0x2102',{'register':'0x2102'}),
 ('boot_system','boot system disk2:image.bin',{'image':'disk2:image.bin'}),
 ('password_minimum','security passwords min-length 1',{'length':1}),
 ('flow_aggregation','ip flow-aggregation cache as',{'aggregation':'as'}),
 ('ifindex','snmp ifmib ifindex persist',{'enabled':True}),
 ('domain_source','ip domain lookup source-interface Loopback0',{'interface':'Loopback0'}),
 ('license','license udi pid CSR1000V sn SYNTHETIC-SERIAL',{'pid':'CSR1000V','serial':'SYNTHETIC-SERIAL'}),
 ('alias','alias exec bgp4 show bgp ipv4 unicast summary',{'name':'bgp4','expansion':'show bgp ipv4 unicast summary'}),
 ('archive','archive',{'declared':True}),('rip','router rip',{'declared':True}),
 ('msdp_peer','ip msdp peer 192.0.2.2 connect-source Loopback0',{'address':'192.0.2.2','interface':'Loopback0'}),
 ('msdp_cache','ip msdp cache-sa-state',{'enabled':True}),
 ('pim_autorp','ip pim autorp listener',{'enabled':True}),
 ('pim_discovery','ip pim send-rp-discovery scope 10',{'scope':10}),
 ('pim_ssm','ip pim ssm default',{'range':'default'}),
 ('pim_bsr','ip pim bsr-candidate Loopback0 0',{'interface':'Loopback0','hash_mask':0}),
 ('pim_rp_candidate','ip pim rp-candidate Loopback0',{'interface':'Loopback0'}),
]
CASES=[('catalogue_'+r,[],text,values) for r,text,values in GLOBAL]
CASES += [('catalogue_'+r,parents,text,values) for r,parents,text,values in [
 ('call_home_contact',['call-home'],'contact-email-addr example@example.invalid',{'email':'example@example.invalid'}),
 ('call_home_profile',['call-home'],'profile "CiscoTAC-1"',{'name':'"CiscoTAC-1"'}),
 ('call_home_active',['call-home','profile "CiscoTAC-1"'],'active',{'enabled':True}),
 ('call_home_destination',['call-home','profile "CiscoTAC-1"'],'destination transport-method http',{'transport':'http'}),
 ('gatekeeper_shutdown',['gatekeeper'],'shutdown',{'enabled':False}),
 ('archive_log',['archive'],'log config',{'declared':True}),
 ('archive_hide',['archive','log config'],'hidekeys',{'enabled':True}),
 ('cache_entries',['ip flow-aggregation cache as'],'cache entries 16384',{'entries':16384}),
 ('cache_timeout',['ip flow-aggregation cache as'],'cache timeout active 5',{'type':'active','timeout':5}),
 ('cache_export',['ip flow-aggregation cache as'],'export destination 192.0.2.9 9000',{'address':'192.0.2.9','port':9000}),
 ('cache_enable',['ip flow-aggregation cache as'],'enabled',{'enabled':True}),
 ('rip_network',['router rip'],'network 192.0.2.0',{'network':'192.0.2.0'}),
 ('rip_family',['router rip'],'address-family ipv4 vrf CLIENT',{'afi':'ipv4','vrf':'CLIENT'}),
 ('rip_redistribute',['router rip','address-family ipv4 vrf CLIENT'],'redistribute bgp 65000 metric 1',{'local_as':'65000','metric':1}),
 ('rip_no_summary',['router rip','address-family ipv4 vrf CLIENT'],'no auto-summary',{'enabled':False}),
 ('dhcp4',['interface Ethernet1'],'ip address dhcp',{'method':'dhcp'}),
 ('sap',['interface Ethernet1'],'ip sap listen',{'enabled':True}),
 ('allowas',['router bgp 65000','address-family ipv4 vrf CLIENT'],'neighbor 192.0.2.1 allowas-in',{'peer':'192.0.2.1','count_unspecified':True}),
 ('soft',['router bgp 65000','address-family ipv4 vrf CLIENT'],'neighbor 192.0.2.1 soft-reconfiguration inbound',{'peer':'192.0.2.1','inbound':True}),
]]
CASES += [
 ('if_cdp_off',['interface Ethernet1'],'no cdp enable',{'enabled':False}),
 ('if_mop_off',['interface Ethernet1'],'no mop enabled',{'feature':'enabled','enabled':False}),
 ('if_service_instance',['interface Ethernet1'],'service instance 100 ethernet',{'instance':100}),
 ('if_bridge_domain',['interface Ethernet1','service instance 100 ethernet'],'bridge-domain 100',{'domain':100}),
 ('if_encap_untagged',['interface Ethernet1','service instance 100 ethernet'],'encapsulation untagged',{'kind':'untagged'}),
 ('advanced_mpls_ldp_no_option',[],'mpls ldp router-id Loopback0',{'interface':'Loopback0'}),
 ('services_timestamp',[],'service timestamps debug datetime msec',{'category':'debug','format':'datetime','options':'msec'}),
 ('services_timestamp_plain',[],'service timestamps log uptime',{'category':'log','format':'uptime'}),
 ('services_line_synchronous',['line con 0'],'logging synchronous',{'enabled':True}),
 ('services_line_privilege',['line con 0'],'privilege level 15',{'level':15}),
 ('services_line_stopbits',['line con 0'],'stopbits 1',{'bits':1}),
 ('services_line_length',['line vty 0 4'],'length 0',{'length':0}),
 ('services_line_preferred',['line vty 0 4'],'transport preferred none',{'transports':'none'}),
 ('services_console_off',[],'no logging console',{'enabled':False}),
 ('services_source_route_off',[],'no ip source-route',{'enabled':False}),
 ('services_lookup_off',[],'no ip domain lookup',{'enabled':False}),
 ('services_password_encryption_off',[],'no service password-encryption',{'enabled':False}),
 ('services_ipv6_routing',[],'ipv6 unicast-routing',{'enabled':True}),
 ('services_http_auth',[],'ip http authentication local',{'method':'local'}),
 ('services_community_expanded',[],'ip community-list expanded FILTER permit _65000:',{'name':'FILTER','action':'permit','expression':'_65000:'}),
 ('services_flow_source',[],'ip flow-export source Loopback0',{'interface':'Loopback0'}),
 ('services_flow_version',[],'ip flow-export version 5 origin-as',{'version':5,'as_mode':'origin-as'}),
 ('services_flow_timeout',[],'ip flow-cache timeout inactive 60',{'type':'inactive','timeout':60}),
 ('bgp_compare_med',['router bgp 65000'],'bgp always-compare-med',{'enabled':True}),
 ('bgp_deterministic_med',['router bgp 65000'],'bgp deterministic-med',{'enabled':True}),
 ('bgp_no_default_ipv4',['router bgp 65000'],'no bgp default ipv4-unicast',{'enabled':False}),
 ('bgp_no_sync',['router bgp 65000','address-family ipv4'],'no synchronization',{'enabled':False}),
 ('bgp_no_auto_summary',['router bgp 65000','address-family ipv4'],'no auto-summary',{'enabled':False}),
 ('bgp_no_enforce_first_as',['router bgp 65000'],'no bgp enforce-first-as',{'enabled':False}),
 ('bgp_advertise_additional',['router bgp 65000','address-family ipv4'],'neighbor GROUP advertise additional-paths all',{'peer':'GROUP','selection':'all'}),
 ('services_user_no_format',[],'username admin secret SYNTHETIC-CREDENTIAL',{'username':'admin','credential_type':'secret','credential':'SYNTHETIC-CREDENTIAL','credential_format':'not_specified'}),
]


def source(parents,command):
    return '\n'.join(' '*i+line for i,line in enumerate(parents+[command]))+'\n'


@pytest.mark.parametrize('rule,parents,command,expected',CASES,ids=[r[0] for r in CASES])
def test_reviewed_rule_values_context_and_preservation(rule,parents,command,expected):
    x,n,coverage=parse(source(parents,command));line=len(parents)+1
    record=x['records'][line]
    assert record['rule']==rule and record['values']==expected
    assert {k:type(v) for k,v in record['values'].items()}=={k:type(v) for k,v in expected.items()}
    assert record['context_lines']==list(range(1,line))
    assert coverage.validation[line]['valid']



@pytest.mark.parametrize('rule,parents,command,expected',CASES,ids=[r[0] for r in CASES])
def test_no_silent_trailing_parameter_loss(rule,parents,command,expected):
    x=extract(source(parents,command+' UNEXPECTED'),official=False)
    record=x['records'].get(len(parents)+1)
    # Free text may validly capture a suffix; a successful prefix cannot drop it.
    assert record is None or record['values']!=expected


def test_all_added_rule_ids_have_reviewed_examples():
    definitions,_=load_templates()
    reliability_ids=set(json.loads((ROOT/'tests/fixtures/reliability_rule_ids.json').read_text(encoding='utf-8')))
    assert len(reliability_ids)==30
    assert reliability_ids<=set(definitions)
    added={identifier for identifier in definitions if identifier.startswith('catalogue_')
        or identifier in reliability_ids or identifier=='services_user_no_format'}
    reviewed={case[0] for case in CASES}
    assert added<=reviewed
    assert reviewed<=set(definitions)


# Literal semantic expectations supplement native captures. Paths are independent
# contract coordinates, never taken from mapper evidence.
TYPED={
 'if_cdp_off':('interfaces/0/cdp_enabled',False),
 'if_mop_off':('interfaces/0/mop_enabled',False),
 'if_service_instance':('cisco/ethernet_services/0/instance',100),
 'if_bridge_domain':('cisco/ethernet_services/0/bridge_domain',100),
 'if_encap_untagged':('cisco/ethernet_services/0/encapsulation/kind','untagged'),
 'advanced_mpls_ldp_no_option':('cisco/mpls/ldp/router_id_interface','Loopback0'),
 'services_timestamp':('system/timestamps/0/options',['msec']),
 'services_timestamp_plain':('system/timestamps/0/format','uptime'),
 'services_line_synchronous':('system/management/lines/0/logging_synchronous',True),
 'services_line_privilege':('system/management/lines/0/privilege_level',15),
 'services_line_stopbits':('system/management/lines/0/stopbits',1),
 'services_line_length':('system/management/lines/0/screen_length',0),
 'services_line_preferred':('system/management/lines/0/preferred_transports',['none']),
 'services_console_off':('system/console_logging',False),
 'services_source_route_off':('system/source_routing',False),
 'services_lookup_off':('system/dns_lookup_enabled',False),
 'services_password_encryption_off':('system/password_encryption_service',False),
 'services_ipv6_routing':('system/ipv6_unicast_routing',True),
 'services_http_auth':('system/http_authentication','local'),
 'services_community_expanded':('cisco/community_lists/0/entries/0/expression','_65000:'),
 'services_flow_source':('system/flow_export/source_interface','Loopback0'),
 'services_flow_version':('system/flow_export/as_mode','origin-as'),
 'services_flow_timeout':('system/flow_export/cache_timeout_inactive_seconds',60),
 'bgp_compare_med':('routing/bgp/0/compare_med',True),
 'bgp_deterministic_med':('routing/bgp/0/deterministic_med',True),
 'bgp_no_default_ipv4':('routing/bgp/0/default_ipv4_unicast',False),
 'bgp_no_enforce_first_as':('routing/bgp/0/enforce_first_as',False),
 'services_user_no_format':('system/aaa/local_users/0/username','admin'),
}


@pytest.mark.parametrize('case',[r for r in CASES if r[0] in TYPED],ids=lambda r:r[0])
def test_literal_semantic_contract_values(case):
    rule,parents,command,_=case
    x,n,c=parse(source(parents,command));target=n.model_dump(mode='json')
    path,expected=TYPED[rule]
    for key in path.split('/'):target=target[int(key)] if isinstance(target,list) else target[key]
    assert target==expected and type(target) is type(expected)


@pytest.mark.parametrize('rule,parents,command,expected',CASES[:len(GLOBAL)],ids=[r[0] for r in CASES[:len(GLOBAL)]])
def test_global_rules_rejected_in_terminal_mode(rule,parents,command,expected):
    assert 2 not in extract('line vty 0 4\n '+command+'\n',official=False)['records']


def test_bgp_af_flags_and_vrf_native_properties_never_widen():
    x,n,c=parse('router bgp 65000\n address-family ipv4 vrf A\n  no synchronization\n  no auto-summary\n  neighbor 192.0.2.1 allowas-in\n exit-address-family\n address-family ipv4 vrf B\n  neighbor 192.0.2.1 soft-reconfiguration inbound\n')
    assert all(p.synchronization is None and p.auto_summary is None for p in n.routing.bgp)
    a=next(p for p in n.routing.bgp if p.network_instance=='A').address_families[0]
    assert a.synchronization is False and a.auto_summary is False
    assert a.peers[0].allowas_in.enabled is True and a.peers[0].allowas_in.configured_max_occurrences is None
    assert all(c.is_complete(line) for line in (3,4,5))
    assert not c.is_complete(8)


def test_one_line_banner_and_export_markers_are_not_commands():
    x,n,c=parse('boot-start-marker\nboot-end-marker\nbanner motd #hostname PRIVATE-TEXT#\nhostname REAL\n')
    assert not {1,2,3}&x['records'].keys()
    assert n.system.hostname=='REAL'
    assert 'PRIVATE-TEXT' not in n.model_dump_json()


def test_privacy_on_new_native_credential_and_serial_paths():
    text='username admin secret SYNTHETIC-CREDENTIAL\nlicense udi pid CSR1000V sn SYNTHETIC-SERIAL\n'
    x,n,c=parse(text)
    output=n.model_dump_json()
    assert 'SYNTHETIC-CREDENTIAL' not in output and 'SYNTHETIC-SERIAL' not in output
    assert x['records'][1]['values']['credential_format']=='not_specified'


@pytest.mark.parametrize('text,expected',[
 ('hostname XR\nvrf CLIENT\n rd 65000:1\n','iosxr'),
 ('hostname XR\ninterface GigabitEthernet0/0/0/0\n ipv4 address 192.0.2.1 255.255.255.0\n','iosxr'),
 ('hostname IOS\ncrypto pki certificate chain TP\n certificate ca 01\n  C9924FAA\n quit\n',None),
 ('hostname EDGE\nlicense udi pid C8300-1N1S-4T2X sn SYNTHETIC\n',None),
 ('hostname SW\nlicense udi pid C9300-24T sn SYNTHETIC\n','switch_platform'),
])
def test_platform_signatures_use_syntax_or_metadata_not_certificate_hex(text,expected):
    assert unsupported_platform(text)==expected


def test_choice_constraints_and_homonyms():
    assert 2 not in extract('interface E1\n no mop nonsense\n',official=False)['records']
    assert 1 not in extract('ip community-list expanded F maybe _1:\n',official=False)['records']
    assert 1 not in extract('logging synchronous\n',official=False)['records']
    assert 2 not in extract('interface E1\n bridge-domain 100\n',official=False)['records']
