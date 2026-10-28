"""Service domain ownership and existing context boundaries after file splitting."""
import pytest

import parser.run_ttp as parsing


DOMAIN_IDS = {
    'system': '''services_hostname services_version catalogue_redundancy catalogue_scheduler_none catalogue_scheduler catalogue_diagnostic catalogue_memory_low catalogue_qfp catalogue_punt catalogue_no_punt catalogue_upgrade catalogue_virtual_service catalogue_config_register catalogue_boot_system catalogue_license catalogue_tftp_source catalogue_archive catalogue_archive_log catalogue_archive_hide'''.split(),
    'administration': '''services_ssh_version services_http_on services_http_off services_https_on services_https_off services_http_auth services_line services_transport services_timeout services_timeout_minutes services_access_class services_login services_login_plain services_banner services_line_synchronous services_line_privilege services_line_stopbits services_line_length services_line_preferred catalogue_console catalogue_alias'''.split(),
    'aaa': '''services_aaa_on services_aaa_off services_aaa_method services_user services_user_simple services_user_no_format services_tacacs services_radius services_auth_address services_auth_ports services_password_encryption_off catalogue_password_minimum'''.split(),
    'dns': '''services_domain services_domain_alt services_dns services_lookup_off catalogue_dns_view catalogue_domain_source'''.split(),
    'ntp': '''services_ntp_prefer services_ntp services_ntp_vrf_prefer services_ntp_vrf services_ntp_source'''.split(),
    'logging': '''services_logging services_logging_legacy services_logging_trap services_logging_source services_login_logging services_timestamp services_timestamp_plain services_console_off catalogue_no_cdp_log'''.split(),
    'snmp': '''services_snmp_community services_snmp_community_simple services_snmp_location services_snmp_contact catalogue_ifindex'''.split(),
    'flow_telemetry': '''services_flow_source services_flow_version services_flow_timeout catalogue_flow_aggregation catalogue_cache_entries catalogue_cache_timeout catalogue_cache_export catalogue_cache_enable catalogue_ioam'''.split(),
    'network': '''services_nat_static services_nat_static_extendable services_source_route_off services_ipv6_routing services_community_expanded catalogue_control_plane catalogue_forward_protocol catalogue_cef catalogue_cef6 catalogue_no_cef6 catalogue_spanning_system_id catalogue_icmp_no_limit catalogue_synwait catalogue_bgp_community_format catalogue_msdp_peer catalogue_msdp_cache'''.split(),
    'call_home': '''catalogue_call_home catalogue_call_home_on catalogue_call_home_contact catalogue_call_home_profile catalogue_call_home_active catalogue_call_home_destination'''.split(),
    'wan_access': '''catalogue_multilink catalogue_mmi_poll catalogue_mmi_no_auto catalogue_mmi_no_pvc catalogue_mmi_timeout catalogue_subscriber'''.split(),
    'voice': '''catalogue_mgcp catalogue_gatekeeper catalogue_gatekeeper_shutdown'''.split(),
}

GLOBAL_CASES = [
    ('login on-success log', 'services_login_logging'),
    ('service timestamps log datetime msec', 'services_timestamp'),
    ('service timestamps debug uptime', 'services_timestamp_plain'),
    ('no logging console', 'services_console_off'),
    ('no ip source-route', 'services_source_route_off'),
    ('no ip domain lookup', 'services_lookup_off'),
    ('no service password-encryption', 'services_password_encryption_off'),
    ('ipv6 unicast-routing', 'services_ipv6_routing'),
    ('ip http authentication local', 'services_http_auth'),
    ('ip community-list expanded PUBLIC permit .*', 'services_community_expanded'),
    ('ip flow-export source Loopback0', 'services_flow_source'),
    ('ip flow-export version 9 origin-as', 'services_flow_version'),
    ('ip flow-cache timeout active 60', 'services_flow_timeout'),
]
ROOT_CASES = [
    ('call-home', ' contact-email-addr ops@example.test', 'catalogue_call_home_contact'),
    ('call-home', ' profile SUPPORT', 'catalogue_call_home_profile'),
    ('call-home\n profile SUPPORT', '  active', 'catalogue_call_home_active'),
    ('call-home\n profile SUPPORT', '  destination transport-method http', 'catalogue_call_home_destination'),
    ('gatekeeper', ' shutdown', 'catalogue_gatekeeper_shutdown'),
    ('archive', ' log config', 'catalogue_archive_log'),
    ('archive\n log config', '  hidekeys', 'catalogue_archive_hide'),
    ('ip flow-aggregation cache prefix', ' cache entries 100', 'catalogue_cache_entries'),
    ('ip flow-aggregation cache prefix', ' cache timeout active 60', 'catalogue_cache_timeout'),
    ('ip flow-aggregation cache prefix', ' export destination 192.0.2.1 2055', 'catalogue_cache_export'),
    ('ip flow-aggregation cache prefix', ' enabled', 'catalogue_cache_enable'),
]
LINE_CASES = [
    ('login local', 'services_login'), ('login authentication AUTH', 'services_login'),
    ('login', 'services_login_plain'), ('logging synchronous', 'services_line_synchronous'),
    ('privilege level 15', 'services_line_privilege'), ('stopbits 1', 'services_line_stopbits'),
    ('length 0', 'services_line_length'), ('transport preferred ssh', 'services_line_preferred'),
]
UNSCOPED_CASES = [
    ('transport input ssh', 'services_transport'),
    ('exec-timeout 10 30', 'services_timeout'), ('exec-timeout 10', 'services_timeout_minutes'),
    ('access-class MGMT in', 'services_access_class'),
    ('address ipv4 192.0.2.10', 'services_auth_address'),
    ('address ipv4 192.0.2.10 auth-port 1812 acct-port 1813', 'services_auth_ports'),
]
BANNER = 'banner motd ^C\nlogin on-success log\nhostname HIDDEN\n^C\nhostname VISIBLE\n'


def test_service_domains_have_exact_ownership_and_metadata():
    definitions, families = parsing.load_templates()
    sources = {source.path: source for source in families['services']}
    assert set(sources) == {'routing/rip.ttp'} | {'services/' + name + '.ttp' for name in DOMAIN_IDS}
    assert not (parsing.ROOT / 'templates/cisco_ios/services.ttp').exists()
    owned = []
    for domain, identifiers in DOMAIN_IDS.items():
        actual = sources['services/' + domain + '.ttp'].rule_ids
        assert set(actual) == set(identifiers)
        owned.extend(actual)
    assert len(owned) == len(set(owned)) == 117
    assert sum('scope' in definitions[i] for i in owned) == 57
    assert sum('choices' in definitions[i] for i in owned) == 2
    assert sources['services/network.ttp'].rule_ids[-2:] == ('catalogue_msdp_peer', 'catalogue_msdp_cache')


@pytest.mark.parametrize('command,rule', GLOBAL_CASES)
def test_service_global_guards_remain_global(command, rule):
    assert parsing.extract(command + '\n', official=False)['records'][1]['rule'] == rule
    assert 2 not in parsing.extract('archive\n ' + command + '\n', official=False)['records']


@pytest.mark.parametrize('parent,command,rule', ROOT_CASES)
def test_service_root_scopes_and_full_context_are_preserved(parent, command, rule):
    text = parent + '\n' + command + '\n'
    line = len(text.splitlines())
    record = parsing.extract(text, official=False)['records'][line]
    assert (record['rule'], record['family'], record['root_line'], record['context_lines']) == (
        rule, 'services', 1, list(range(1, line)))
    assert 2 not in parsing.extract('line vty 0 4\n' + command + '\n', official=False)['records']


@pytest.mark.parametrize('command,rule', LINE_CASES)
def test_service_line_guards_remain_in_line_context(command, rule):
    record = parsing.extract('line vty 0 4\n ' + command + '\n', official=False)['records'][2]
    assert (record['rule'], record['context_lines']) == (rule, [1])
    assert 2 not in parsing.extract('archive\n ' + command + '\n', official=False)['records']


@pytest.mark.parametrize('command,rule', UNSCOPED_CASES)
def test_generic_service_commands_do_not_gain_new_context_restrictions(command, rule):
    for parent in ('line vty 0 4', 'tacacs server AUTH', 'radius server AUTH', 'archive'):
        record = parsing.extract(parent + '\n ' + command + '\n', official=False)['records'][2]
        assert (record['rule'], record['root_line'], record['context_lines']) == (rule, 1, [1])


def test_service_login_choices_full_lines_and_banner_remain_filtered():
    for text in ('line vty 0 4\n login unsupported\n',
        'line vty 0 4\n login authentication AUTH EXTRA\n',
        'ip community-list expanded PUBLIC reject .*\n',
        'username TEST invalid VALUE\n', 'ntp server 192.0.2.1 unsupported\n'):
        result = parsing.extract(text, official=False)
        assert len(text.splitlines()) not in result['records']
    result = parsing.extract(BANNER, official=False)
    assert set(result['records']) == {1, 5}
    assert result['records'][5]['values'] == {'hostname': 'VISIBLE'}
    assert result['nodes'][2].kind == 'opaque_banner'
    assert result['nodes'][2].end_line == 4


def test_service_split_selection_is_independent_of_file_order(monkeypatch):
    definitions, families = parsing.load_templates()
    text = '\n'.join(command for command, _ in GLOBAL_CASES) + '\n'
    text += ''.join(parent + '\n' + command + '\n' for parent, command, _ in ROOT_CASES)
    text += 'line vty 0 4\n login local\nlogin on-success log\n' + BANNER
    before = parsing.extract(text, official=False)
    monkeypatch.setattr(parsing, 'load_templates', lambda: (
        definitions, {family: tuple(reversed(sources)) for family, sources in families.items()}))
    assert parsing.extract(text, official=False) == before
