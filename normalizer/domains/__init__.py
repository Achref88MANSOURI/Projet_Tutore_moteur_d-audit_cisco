"""Capture ownership. A rule is dispatched to exactly one domain."""
from . import interfaces, acl, policies, services, nat, vpn, qos, pki, cisco_features, layer2
from .routing import bgp, ospf, rip, static_routes, vrf, prefix_lists

FEATURE_RULES = {
    'catalogue_password_minimum', 'catalogue_cef', 'catalogue_cef6', 'catalogue_no_cef6',
    'catalogue_icmp_no_limit', 'catalogue_synwait', 'catalogue_domain_source', 'catalogue_tftp_source',
    'catalogue_config_register', 'catalogue_dns_view', 'catalogue_forward_protocol', 'catalogue_virtual_service',
    'catalogue_archive', 'catalogue_archive_log', 'catalogue_archive_hide', 'catalogue_cache_export',
    'catalogue_call_home', 'catalogue_call_home_on', 'catalogue_call_home_profile', 'catalogue_call_home_active',
    'catalogue_call_home_destination', 'catalogue_pim_autorp', 'catalogue_pim_bsr', 'catalogue_pim_discovery',
    'catalogue_pim_rp_candidate', 'catalogue_pim_ssm', 'catalogue_msdp_peer',
}
FAMILIES = {'interfaces': interfaces, 'bgp': bgp, 'ospf': ospf, 'routes': static_routes,
    'vrf': vrf, 'prefix': prefix_lists, 'acl_standard': acl, 'acl_extended': acl,
    'policies': policies, 'services': services, 'advanced': cisco_features}
DECLARATIONS = {'if_header', 'bgp_header', 'ospf_header', 'ospf_header_vrf',
    'vrf_header', 'vrf_legacy_header', 'policy_header', 'services_line',
    'services_tacacs', 'services_radius', 'advanced_vlan'}


def handler_for(record):
    rule = record['rule']
    if rule.startswith('catalogue_rip'):
        return rip
    if rule in ('if_tunnel_source', 'if_tunnel_destination'):
        return vpn
    if rule.startswith('services_nat_static'):
        return nat
    if rule.startswith('advanced_qos') or rule == 'if_service_policy':
        return qos
    if rule.startswith('advanced_pki'):
        return pki
    if rule in ('advanced_vlan', 'advanced_vlan_name'):
        return layer2
    if rule in FEATURE_RULES:
        return cisco_features
    return FAMILIES[record['family']]
