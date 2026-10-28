"""Explicit observed IOS/IOS-XE syntax additions; no generic whole-line fallback."""
import json
from pathlib import Path


def add_catalogue_rules(rules):
    root=Path(__file__).resolve().parents[1]
    for r in json.loads((root/'docs/deferred/reliability_rules.json').read_text(encoding='utf-8')):
        r=dict(r);r['note']='Activated for catalogue completion; native-only fields never earn semantic credit.'
        rules.append(r)
    def add(family,name,pattern,scope='global',domain='services'):
        rules.append(dict(family=family,id='catalogue_'+name,pattern=pattern,scope=scope,native_domain=domain,
                          note='Observed corpus syntax; explicitly scoped TTP capture with native preservation when no typed model exists.'))
    for name,pattern in {
        'multilink':'multilink bundle-name {{ naming }}',
        'control_plane':'control-plane {{ declared | set(True) }}',
        'forward_protocol':'ip forward-protocol {{ protocol }}',
        'redundancy':'redundancy {{ declared | set(True) }}',
        'cef':'ip cef {{ enabled | set(True) }}', 'cef6':'ipv6 cef {{ enabled | set(True) }}',
        'no_cef6':'no ipv6 cef {{ enabled | set(False) }}',
        'mmi_poll':'mmi polling-interval {{ interval | DIGIT | to_int }}',
        'mmi_no_auto':'no mmi auto-configure {{ enabled | set(False) }}',
        'mmi_no_pvc':'no mmi pvc {{ enabled | set(False) }}',
        'mmi_timeout':'mmi snmp-timeout {{ timeout | DIGIT | to_int }}',
        'ioam':'ipv6 ioam timestamp {{ enabled | set(True) }}',
        'scheduler_none':'no scheduler allocate {{ configured | set(False) }}',
        'scheduler':'scheduler allocate {{ interrupt | DIGIT | to_int }} {{ process | DIGIT | to_int }}',
        'subscriber':'subscriber templating {{ enabled | set(True) }}',
        'diagnostic':'diagnostic bootup level {{ level }}',
        'spanning_system_id':'spanning-tree extend system-id {{ enabled | set(True) }}',
        'console':'platform console {{ transport }}',
        'icmp_no_limit':'no ip icmp rate-limit unreachable {{ limited | set(False) }}',
        'synwait':'ip tcp synwait-time {{ seconds | DIGIT | to_int }}',
        'memory_low':'memory free low-watermark processor {{ threshold | DIGIT | to_int }}',
        'call_home':'call-home {{ declared | set(True) }}',
        'call_home_on':'service call-home {{ enabled | set(True) }}',
        'qfp':'platform qfp utilization monitor load {{ percent | DIGIT | to_int }}',
        'punt':'platform punt-keepalive disable-kernel-core {{ disabled | set(True) }}',
        'no_punt':'no platform punt-keepalive disable-kernel-core {{ disabled | set(False) }}',
        'tftp_source':'ip tftp source-interface {{ interface }}',
        'dns_view':'ip dns view vrf {{ vrf }} {{ name }}',
        'no_cdp_log':'no cdp log mismatch duplex {{ enabled | set(False) }}',
        'bgp_community_format':'ip bgp-community new-format {{ enabled | set(True) }}',
        'upgrade':'upgrade fpd {{ mode }}',
        'mgcp':'mgcp profile {{ name }}', 'gatekeeper':'gatekeeper {{ declared | set(True) }}',
        'virtual_service':'virtual-service {{ name }}',
        'config_register':'config-register {{ register }}',
        'boot_system':'boot system {{ image }}',
        'password_minimum':'security passwords min-length {{ length | DIGIT | to_int }}',
        'flow_aggregation':'ip flow-aggregation cache {{ aggregation }}',
        'ifindex':'snmp ifmib ifindex persist {{ enabled | set(True) }}',
        'domain_source':'ip domain lookup source-interface {{ interface }}',
        'license':'license udi pid {{ pid }} sn {{ serial }}',
        'alias':'alias exec {{ name }} {{ expansion | ORPHRASE }}',
        'archive':'archive {{ declared | set(True) }}',
        'rip':'router rip {{ declared | set(True) }}',
    }.items():add('services',name,pattern)
    add('services','call_home_contact','contact-email-addr {{ email }}','root:call-home')
    add('services','call_home_profile','profile {{ name }}','root:call-home')
    add('services','call_home_active','active {{ enabled | set(True) }}','root:call-home')
    add('services','call_home_destination','destination transport-method {{ transport }}','root:call-home')
    add('services','gatekeeper_shutdown','shutdown {{ enabled | set(False) }}','root:gatekeeper')
    add('services','archive_log','log config {{ declared | set(True) }}','root:archive')
    add('services','archive_hide','hidekeys {{ enabled | set(True) }}','root:archive')
    add('services','cache_entries','cache entries {{ entries | DIGIT | to_int }}','root:ip flow-aggregation cache')
    add('services','cache_timeout','cache timeout {{ type }} {{ timeout | DIGIT | to_int }}','root:ip flow-aggregation cache')
    add('services','cache_export','export destination {{ address | IP }} {{ port | DIGIT | to_int }}','root:ip flow-aggregation cache')
    add('services','cache_enable','enabled {{ enabled | set(True) }}','root:ip flow-aggregation cache')
    add('services','rip_network','network {{ network | IP }}','root:router rip','routing')
    add('services','rip_family','address-family {{ afi }} vrf {{ vrf }}','root:router rip','routing')
    add('services','rip_redistribute','redistribute bgp {{ local_as }} metric {{ metric | DIGIT | to_int }}','root:router rip','routing')
    add('services','rip_no_summary','no auto-summary {{ enabled | set(False) }}','root:router rip','routing')
    add('services','msdp_peer','ip msdp peer {{ address | IP }} connect-source {{ interface }}',domain='multicast')
    add('services','msdp_cache','ip msdp cache-sa-state {{ enabled | set(True) }}',domain='multicast')
    add('interfaces','dhcp4','ip address dhcp {{ method | set("dhcp") }}','root:interface','interface')
    add('interfaces','sap','ip sap listen {{ enabled | set(True) }}','root:interface','multicast')
    add('bgp','allowas','neighbor {{ peer }} allowas-in {{ count_unspecified | set(True) }}','root:router bgp','bgp')
    add('bgp','soft','neighbor {{ peer }} soft-reconfiguration inbound {{ inbound | set(True) }}','root:router bgp','bgp')
    for name,pattern in {
        'pim_autorp':'ip pim autorp listener {{ enabled | set(True) }}',
        'pim_discovery':'ip pim send-rp-discovery scope {{ scope | DIGIT | to_int }}',
        'pim_ssm':'ip pim ssm {{ range }}',
        'pim_bsr':'ip pim bsr-candidate {{ interface }} {{ hash_mask | DIGIT | to_int }}',
        'pim_rp_candidate':'ip pim rp-candidate {{ interface }}',
    }.items():add('advanced',name,pattern,domain='multicast')
    # No assumed credential encoding when the export does not print one.
    rules.append(dict(family='services',id='services_user_no_format',pattern='username {{ username }} {{ credential_type }} {{ credential }} {{ credential_format | set("not_specified") }}',choices={'credential_type':['secret','password']},scope='global',note='Encoding absent in source; never guessed as 0/5/7/9.'))
    # Constrain generic scalar captures to their documented fixed choices.
    for r in rules:
        if r['id']=='if_mop_off':r['choices']={'feature':['enabled','sysid']}
        if r['id']=='services_community_expanded':r['choices']={'action':['permit','deny']}
