"""Build reviewed TTP rule groups; one record per matched source command.

Project extensions use numbered, de-indented inventory lines. Context is kept
outside TTP, while TTP itself extracts the command values. Official templates
also run separately on the unmodified complete input.
"""
import json
import ast
import re
from pathlib import Path
from xml.sax.saxutils import escape, quoteattr

ROOT = Path(__file__).resolve().parents[1]
rules = []


def add(family, identifier, pattern, note=''):
    rules.append({'family': family, 'id': identifier, 'pattern': pattern, 'note': note})


def v(name, expr=None):
    return '{{ ' + name + (' | ' + expr if expr else '') + ' }}'


for identifier, pattern in {
    'if_header':'interface {{ name }}', 'if_description':'description {{ value | ORPHRASE }}',
    'if_shutdown':'shutdown {{ enabled | set(False) }}', 'if_no_shutdown':'no shutdown {{ enabled | set(True) }}',
    'if_mtu':'mtu {{ mtu | DIGIT | to_int }}', 'if_vrf':'vrf forwarding {{ vrf }}',
    'if_legacy_vrf':'ip vrf forwarding {{ vrf }}',
    'if_ipv4':'ip address {{ address | IP }} {{ mask | IP }}',
    'if_ipv4_secondary':'ip address {{ address | IP }} {{ mask | IP }} secondary',
    'if_ipv6':'ipv6 address {{ address | IPV6 }}/{{ prefix_length | DIGIT | to_int }}',
    'if_ipv6_qualified':'ipv6 address {{ address | IPV6 }}/{{ prefix_length | DIGIT | to_int }} {{ qualifier }}',
    'if_no_ipv4':'no ip address {{ empty | set(True) }}',
    'if_unnumbered':'ip unnumbered {{ interface }}',
    'if_acl4':'ip access-group {{ acl }} {{ direction }}',
    'if_acl6':'ipv6 traffic-filter {{ acl }} {{ direction }}',
    'if_ospf2':'ip ospf {{ process }} area {{ area }}',
    'if_ospf3':'ipv6 ospf {{ process }} area {{ area }}',
    'if_ospf_network':'ip ospf network {{ network_type }}',
    'if_pim':'ip pim {{ mode }}', 'if_pim_option':'ip pim {{ option }} {{ value | ORPHRASE }}',
    'if_service_policy':'service-policy {{ direction }} {{ policy }}',
    'if_nat_role':'ip nat {{ role }}', 'if_mpls':'mpls ip {{ enabled | set(True) }}',
    'if_isis':'ip router isis {{ process }}', 'if_isis_network':'isis network {{ network_type }}',
    'if_switchport':'switchport mode {{ mode }}', 'if_routed':'no switchport {{ mode | set("routed") }}',
    'if_access_vlan':'switchport access vlan {{ vlan | DIGIT | to_int }}',
    'if_native_vlan':'switchport trunk native vlan {{ vlan | DIGIT | to_int }}',
    'if_trunk_vlans':'switchport trunk allowed vlan {{ vlans }}',
    'if_trunk_modify':'switchport trunk allowed vlan {{ operation }} {{ vlans }}',
    'if_lag':'channel-group {{ lag_id | DIGIT | to_int }} mode {{ mode }}',
    'if_dot1q':'encapsulation dot1Q {{ vlan | DIGIT | to_int }}',
    'if_dot1q_lower':'encapsulation dot1q {{ vlan | DIGIT | to_int }}',
    'if_qinq':'encapsulation dot1Q {{ vlan | DIGIT | to_int }} second-dot1q {{ inner_vlan | DIGIT | to_int }}',
    'if_speed':'speed {{ speed }}', 'if_duplex':'duplex {{ duplex }}', 'if_negotiation':'negotiation {{ negotiation }}',
    'if_media':'media-type {{ media }}', 'if_proxyarp':'no ip proxy-arp {{ enabled | set(False) }}',
    'if_redirects':'no ip redirects {{ enabled | set(False) }}',
    'if_mss':'ip tcp adjust-mss {{ mss | DIGIT | to_int }}',
    'if_tunnel_source':'tunnel source {{ source }}', 'if_tunnel_destination':'tunnel destination {{ destination }}',
    'if_keepalive_off':'no keepalive {{ enabled | set(False) }}',
    'if_flow':'ip flow {{ direction }}', 'if_ipv6_enable':'ipv6 enable {{ enabled | set(True) }}',
}.items(): add('interfaces', identifier, pattern)

for identifier, pattern in {
    'bgp_header':'router bgp {{ local_as }}', 'bgp_router_id':'bgp router-id {{ router_id | IP }}',
    'bgp_af_vrf':'address-family {{ afi }} vrf {{ vrf }}',
    'bgp_af_two':'address-family {{ afi }} {{ safi }}', 'bgp_af':'address-family {{ afi }}',
    'bgp_af_exit':'exit-address-family {{ boundary | set(True) }}',
    'bgp_remote_as':'neighbor {{ peer }} remote-as {{ remote_as }}',
    'bgp_description':'neighbor {{ peer }} description {{ description | ORPHRASE }}',
    'bgp_group_definition':'neighbor {{ peer }} peer-group',
    'bgp_group_member':'neighbor {{ peer }} peer-group {{ group }}',
    'bgp_update_source':'neighbor {{ peer }} update-source {{ source }}',
    'bgp_route_map':'neighbor {{ peer }} route-map {{ policy }} {{ direction }}',
    'bgp_activate':'neighbor {{ peer }} activate {{ enabled | set(True) }}',
    'bgp_deactivate':'no neighbor {{ peer }} activate {{ enabled | set(False) }}',
    'bgp_shutdown':'neighbor {{ peer }} shutdown {{ enabled | set(False) }}',
    'bgp_no_shutdown':'no neighbor {{ peer }} shutdown {{ enabled | set(True) }}',
    'bgp_send_community':'neighbor {{ peer }} send-community {{ option | set("unspecified") }}',
    'bgp_send_community_option':'neighbor {{ peer }} send-community {{ option }}',
    'bgp_reflector':'neighbor {{ peer }} route-reflector-client {{ enabled | set(True) }}',
    'bgp_next_hop':'neighbor {{ peer }} next-hop-self {{ enabled | set(True) }}',
    'bgp_network4':'network {{ prefix | IP }} mask {{ mask | IP }}',
    'bgp_network':'network {{ prefix }}',
    'bgp_aggregate':'aggregate-address {{ prefix | IP }} {{ mask | IP }} {{ option | ORPHRASE }}',
    'bgp_redistribute_map':'redistribute {{ protocol }} route-map {{ policy }}',
    'bgp_redistribute':'redistribute {{ protocol }}',
    'bgp_redistribute_process':'redistribute {{ protocol }} {{ process }}',
    'bgp_maximum_paths':'maximum-paths {{ type }} {{ count | DIGIT | to_int }}',
    'bgp_log_changes':'bgp log-neighbor-changes {{ enabled | set(True) }}',
    'bgp_dampening':'bgp dampening {{ enabled | set(True) }}',
    'bgp_additional_select':'bgp additional-paths select {{ selection }}',
    'bgp_additional_send':'bgp additional-paths {{ send }} {{ receive }}',
}.items(): add('bgp', identifier, pattern)

for identifier, pattern in {
    'ospf_header_vrf':'router ospf {{ process }} vrf {{ vrf }}', 'ospf_header':'router ospf {{ process }}',
    'ospf3_header':'ipv6 router ospf {{ process }}', 'ospf_router_id':'router-id {{ router_id | IP }}',
    'ospf_network':'network {{ address | IP }} {{ wildcard | IP }} area {{ area }}',
    'ospf_passive':'passive-interface {{ interface }}', 'ospf_no_passive':'no passive-interface {{ interface }}',
    'ospf_cost':'auto-cost reference-bandwidth {{ bandwidth | DIGIT | to_int }}',
    'ospf_area':'area {{ area }} {{ type }}', 'ospf_virtual_link':'area {{ area }} virtual-link {{ peer | IP }}',
    'ospf_redistribute':'redistribute {{ protocol }} {{ options | ORPHRASE }}',
    'ospf_redistribute_simple':'redistribute {{ protocol }}',
    'ospf_default':'default-information originate {{ options | ORPHRASE }}',
    'ospf_log':'log-adjacency-changes {{ enabled | set(True) }}',
}.items(): add('ospf', identifier, pattern)

for identifier, pattern in {
    'vrf_header':'vrf definition {{ name }}', 'vrf_legacy_header':'ip vrf {{ name }}',
    'vrf_description':'description {{ description | ORPHRASE }}', 'vrf_rd':'rd {{ rd }}',
    'vrf_target':'route-target {{ direction }} {{ target }}', 'vrf_af':'address-family {{ afi }}',
    'vrf_af_exit':'exit-address-family {{ boundary | set(True) }}',
}.items(): add('vrf', identifier, pattern)

for identifier, pattern in {
    'policy_header':'route-map {{ name }} {{ action }} {{ sequence | DIGIT | to_int }}',
    'policy_match_prefix4':'match ip address prefix-list {{ value | ORPHRASE }}',
    'policy_match_prefix6':'match ipv6 address prefix-list {{ value | ORPHRASE }}',
    'policy_match_acl':'match ip address {{ value | ORPHRASE }}',
    'policy_match_interface':'match interface {{ value | ORPHRASE }}',
    'policy_match_community':'match community {{ value | ORPHRASE }}',
    'policy_match_aspath':'match as-path {{ value | ORPHRASE }}',
    'policy_match_tag':'match tag {{ value | ORPHRASE }}',
    'policy_set_aspath':'set as-path prepend {{ value | ORPHRASE }}',
    'policy_set_localpref':'set local-preference {{ value | DIGIT | to_int }}',
    'policy_set_metric':'set metric {{ value | DIGIT | to_int }}',
    'policy_set_weight':'set weight {{ value | DIGIT | to_int }}',
    'policy_set_community':'set community {{ value | ORPHRASE }}',
    'policy_description':'description {{ value | ORPHRASE }}',
}.items(): add('policies', identifier, pattern)

for afi in ('ip', 'ipv6'):
    for sequence in (False, True):
        for modifier in ('', ' ge {{ ge | DIGIT | to_int }}', ' le {{ le | DIGIT | to_int }}', ' ge {{ ge | DIGIT | to_int }} le {{ le | DIGIT | to_int }}'):
            identifier = f'prefix_{afi}_{int(sequence)}_{len(rules)}'
            add('prefix', identifier, f'{afi} prefix-list {{{{ name }}}} ' + ('seq {{ sequence | DIGIT | to_int }} ' if sequence else '')
                + '{{ action }} {{ prefix }}' + modifier)

for identifier, pattern in {
    'services_hostname':'hostname {{ hostname }}', 'services_version':'version {{ version | ORPHRASE }}',
    'services_domain':'ip domain-name {{ domain }}', 'services_domain_alt':'ip domain name {{ domain }}',
    'services_dns':'ip name-server {{ addresses | ORPHRASE }}',
    'services_ntp_prefer':'ntp server {{ address }} prefer {{ prefer | set(True) }}',
    'services_ntp':'ntp server {{ address }}',
    'services_ntp_vrf_prefer':'ntp server vrf {{ vrf }} {{ address }} prefer {{ prefer | set(True) }}',
    'services_ntp_vrf':'ntp server vrf {{ vrf }} {{ address }}', 'services_ntp_source':'ntp source {{ source }}',
    'services_logging':'logging host {{ address }}', 'services_logging_legacy':'logging {{ address | IP }}',
    'services_logging_trap':'logging trap {{ severity }}', 'services_logging_source':'logging source-interface {{ interface }}',
    'services_aaa_on':'aaa new-model {{ enabled | set(True) }}', 'services_aaa_off':'no aaa new-model {{ enabled | set(False) }}',
    'services_aaa_method':'aaa {{ category }} {{ method | ORPHRASE }}',
    'services_user':'username {{ username }} privilege {{ privilege | DIGIT | to_int }} {{ credential_type }} {{ credential_format | DIGIT }} {{ _ignore_ }}',
    'services_user_simple':'username {{ username }} {{ credential_type }} {{ credential_format | DIGIT }} {{ _ignore_ }}',
    'services_snmp_community':'snmp-server community {{ _ignore_ }} {{ access }} {{ acl }}',
    'services_snmp_community_simple':'snmp-server community {{ _ignore_ }} {{ access }}',
    'services_snmp_location':'snmp-server location {{ value | ORPHRASE }}',
    'services_snmp_contact':'snmp-server contact {{ value | ORPHRASE }}',
    'services_ssh_version':'ip ssh version {{ version }}',
    'services_http_on':'ip http server {{ enabled | set(True) }}', 'services_http_off':'no ip http server {{ enabled | set(False) }}',
    'services_https_on':'ip http secure-server {{ enabled | set(True) }}', 'services_https_off':'no ip http secure-server {{ enabled | set(False) }}',
    'services_line':'line {{ name | ORPHRASE }}', 'services_transport':'transport input {{ transports | ORPHRASE }}',
    'services_timeout':'exec-timeout {{ minutes | DIGIT | to_int }} {{ seconds | DIGIT | to_int }}',
    'services_timeout_minutes':'exec-timeout {{ minutes | DIGIT | to_int }}',
    'services_access_class':'access-class {{ acl }} {{ direction }}', 'services_login':'login {{ method | ORPHRASE }}',
    'services_login_plain':'login {{ enabled | set(True) }}',
    'services_banner':'banner {{ type }} {{ delimiter }}',
    'services_tacacs':'tacacs server {{ name }}', 'services_radius':'radius server {{ name }}',
    'services_auth_address':'address ipv4 {{ address | IP }}',
    'services_auth_ports':'address ipv4 {{ address | IP }} auth-port {{ auth_port | DIGIT | to_int }} acct-port {{ acct_port | DIGIT | to_int }}',
    'services_nat_static':'ip nat inside source static {{ inside | IP }} {{ outside | IP }}',
    'services_nat_static_extendable':'ip nat inside source static {{ inside | IP }} {{ outside | IP }} extendable {{ extendable | set(True) }}',
}.items(): add('services', identifier, pattern)

add('services', 'services_login_logging', 'login on-success log {{ enabled | set(True) }}')

for version in ('ip', 'ipv6'):
    for vrf in (False, True):
        prefix = version + ' route ' + ('vrf {{ vrf }} ' if vrf else '')
        prefix += '{{ destination }} ' + ('{{ mask | IP }} ' if version == 'ip' else '')
        for tail, label in [('{{ hop }}', 'hop'), ('{{ interface }} {{ hop }}', 'interface_hop')]:
            for extra, suffix in [('', ''), (' {{ distance | DIGIT | to_int }}', '_distance'),
                                  (' name {{ name }}', '_name'), (' {{ distance | DIGIT | to_int }} name {{ name }}', '_distance_name')]:
                add('routes', f'route_{version}_{int(vrf)}_{label}{suffix}', prefix + tail + extra)

for identifier, pattern in {
    'advanced_isis':'router isis {{ process }}', 'advanced_isis_net':'net {{ net }}',
    'advanced_isis_passive':'passive-interface {{ interface }}', 'advanced_mpls_ldp':'mpls ldp router-id {{ interface }} {{ option }}',
    'advanced_mpls_label':'mpls label protocol {{ protocol }}',
    'advanced_qos_classmap':'class-map {{ mode }} {{ name }}', 'advanced_qos_policymap':'policy-map {{ name }}',
    'advanced_qos_class':'class {{ name }}', 'advanced_qos_match_protocol':'match protocol {{ protocol }}',
    'advanced_qos_match_dscp':'match dscp {{ dscp }}', 'advanced_qos_match_precedence':'match ip precedence {{ precedence }}',
    'advanced_qos_match_acl':'match access-group name {{ acl }}', 'advanced_qos_set_dscp':'set dscp {{ dscp }}',
    'advanced_qos_set_precedence':'set ip precedence {{ precedence }}', 'advanced_qos_priority':'priority percent {{ percent | DIGIT | to_int }}',
    'advanced_qos_fair':'fair-queue {{ enabled | set(True) }}',
    'advanced_pim_rp':'ip pim rp-address {{ address | IP }}',
    'advanced_multicast':'ip multicast-routing {{ enabled | set(True) }}',
    'advanced_l2_evpn':'l2vpn evpn instance {{ instance | DIGIT | to_int }} {{ type }}',
    'advanced_l2_evpn_global':'l2vpn evpn {{ declaration | set(True) }}',
    'advanced_l2_replication':'replication-type {{ type }}', 'advanced_l2_rid':'router-id {{ interface }}',
    'advanced_l2_bridge':'bridge-domain {{ domain | DIGIT | to_int }}',
    'advanced_l2_member':'member {{ member | ORPHRASE }}', 'advanced_l2_vfi':'l2 vfi {{ vfi | DIGIT | to_int }} {{ mode }}',
    'advanced_l2_vpnid':'vpn id {{ vpn_id | DIGIT | to_int }}',
    'advanced_l2_neighbor':'neighbor {{ address | IP }} encapsulation {{ encapsulation }}',
    'advanced_pki_chain':'crypto pki certificate chain {{ name }}', 'advanced_pki_trust':'crypto pki trustpoint {{ name }}',
    'advanced_pki_certificate':'certificate {{ type }} {{ identifier }}',
    'advanced_pki_enrollment':'enrollment {{ method }}', 'advanced_pki_revocation':'revocation-check {{ method }}',
    'advanced_pki_subject':'subject-name {{ subject | ORPHRASE }}', 'advanced_pki_keypair':'rsakeypair {{ name }}',
    'advanced_vlan':'vlan {{ vlan }}', 'advanced_vlan_name':'name {{ name | ORPHRASE }}',
}.items(): add('advanced', identifier, pattern)

# ACL grammar is templated, not parsed by the previous Cisco parser. Variants
# are explicit, preserving any trailing options so unsupported qualifiers cannot
# silently produce a broader permit/deny rule.
address = r'any(?:4|6)?|host\s+\S+|object-group\s+\S+|\d+\.\d+\.\d+\.\d+(?:\s+\d+\.\d+\.\d+\.\d+)?|[0-9A-Fa-f:]+/\d+'
port = r'(?:eq|neq|lt|gt)\s+\S+|range\s+\S+\s+\S+'
for acl_type in ('extended', 'standard'):
    for numbered in (False, True):
        for seq in (False, True) if not numbered else (False,):
            for srcport in (False, True) if acl_type == 'extended' else (False,):
                for dstport in (False, True) if acl_type == 'extended' else (False,):
                    for options in (False, True):
                        pattern = ('access-list {{ acl_name }} ' if numbered else '') + ('{{ sequence | DIGIT | to_int }} ' if seq else '')
                        pattern += '{{ action | re("acl_action") }} '
                        if acl_type == 'extended': pattern += '{{ protocol }} '
                        pattern += v('source', 're("acl_address")')
                        if srcport: pattern += ' ' + v('source_port', 're("acl_port")')
                        if acl_type == 'extended': pattern += ' ' + v('destination', 're("acl_address")')
                        if dstport: pattern += ' ' + v('destination_port', 're("acl_port")')
                        if options: pattern += ' {{ options | ORPHRASE }}'
                        add('acl_' + acl_type, f'acl_{acl_type}_{int(numbered)}_{int(seq)}_{int(srcport)}_{int(dstport)}_{int(options)}', pattern)
add('acl_extended', 'acl_header_ext', 'ip access-list extended {{ name }}')
add('acl_standard', 'acl_header_std', 'ip access-list standard {{ name }}')
add('acl_extended', 'acl_header_ipv6', 'ipv6 access-list {{ name }}')

assert len({r['id'] for r in rules})==len(rules)
target = ROOT / 'templates/cisco_ios'
target.mkdir(parents=True, exist_ok=True)
for family in sorted({r['family'] for r in rules}):
    parts = ['<vars>\nacl_action = "permit|deny"\nacl_address = ' + repr(address) + '\nacl_port = ' + repr(port) + '\n</vars>'] if family.startswith('acl_') else []
    for r in rules:
        if r['family'] == family:
            constants = re.findall(r'{{\s*(\w+)\s*\|\s*set\((.*?)\)\s*}}', r['pattern'])
            r['constants'] = {key:ast.literal_eval(value) for key,value in constants}
            literal = re.sub(r'{{\s*\w+\s*\|\s*set\(.*?\)\s*}}', '', r['pattern']).rstrip()
            pattern = '{{ source_line | DIGIT | to_int }} ' + literal
            functions = ' | '.join(f'set({value!r}, {key})' for key,value in r['constants'].items())
            attrs = ' functions=' + quoteattr(functions) if functions else ''
            parts.append(f'<group name="{r["id"]}*" method="table"{attrs}>\n{escape(pattern)}\n</group>')
    (target / (family + '.ttp')).write_text('\n\n'.join(parts) + '\n', encoding='utf-8')
(ROOT / 'templates/rules.json').write_text(json.dumps(rules, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(f'{len(rules)} explicit TTP rules in {len({r["family"] for r in rules})} families')
