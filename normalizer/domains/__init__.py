"""Capture ownership. A rule is dispatched to exactly one domain."""
from . import interfaces, acl, policies, services, nat, vpn, qos, pki, cisco_features
from .routing import bgp, ospf, rip, static_routes, vrf, prefix_lists, key_chains, eigrp

FEATURE_RULES = {
    'catalogue_password_minimum', 'catalogue_cef', 'catalogue_cef6', 'catalogue_no_cef6',
    'catalogue_icmp_no_limit', 'catalogue_synwait', 'catalogue_domain_source', 'catalogue_tftp_source',
    'catalogue_config_register', 'catalogue_dns_view', 'catalogue_forward_protocol', 'catalogue_virtual_service',
    'catalogue_archive', 'catalogue_archive_log', 'catalogue_archive_hide', 'catalogue_cache_export',
    'catalogue_call_home', 'catalogue_call_home_on', 'catalogue_call_home_profile', 'catalogue_call_home_active',
    'catalogue_call_home_destination', 'catalogue_pim_autorp', 'catalogue_pim_bsr', 'catalogue_pim_discovery',
    'catalogue_pim_rp_candidate', 'catalogue_pim_ssm', 'catalogue_msdp_peer',
    'catalogue_cache_entries', 'catalogue_cache_timeout', 'catalogue_cache_enable',
    'catalogue_flow_aggregation', 'catalogue_boot_system', 'catalogue_license',
    'catalogue_ifindex', 'catalogue_scheduler', 'catalogue_scheduler_none',
    'catalogue_no_cdp_log', 'catalogue_upgrade', 'catalogue_ioam',
    'catalogue_bgp_community_format', 'catalogue_call_home_contact',
    'catalogue_qfp', 'catalogue_punt',
}
FAMILIES = {'interfaces': interfaces, 'bgp': bgp, 'ospf': ospf, 'eigrp': eigrp, 'routes': static_routes,
    'vrf': vrf, 'prefix': prefix_lists, 'acl_standard': acl, 'acl_extended': acl,
    'policies': policies, 'services': services, 'advanced': cisco_features}
DECLARATIONS = {'if_header', 'bgp_header', 'ospf_header', 'ospf_header_vrf',
    'vrf_header', 'vrf_legacy_header', 'policy_header', 'services_line', 'eigrp_header', 'eigrp_header6',
    }


def handler_for(record):
    rule = record['rule']
    if rule == 'if_header':
        return interfaces
    if rule.startswith('lifecycle_'):
        from normalizer import lifecycle
        return lifecycle
    if rule.startswith('services_acl_'):
        return acl
    if rule.startswith('eigrp_'):
        return eigrp
    if rule.startswith('auth_key_'):
        return key_chains
    if rule.startswith('catalogue_rip'):
        return rip
    if rule.startswith(('auth_if_rip_', 'rip_if_')):
        return rip
    if rule in ('if_tunnel_source', 'if_tunnel_destination'):
        return vpn
    if rule.startswith('services_nat_static'):
        return nat
    if rule.startswith('advanced_qos') or rule == 'if_service_policy':
        return qos
    if rule.startswith('advanced_pki'):
        return pki
    if rule in FEATURE_RULES:
        return cisco_features
    return FAMILIES[record['family']]
