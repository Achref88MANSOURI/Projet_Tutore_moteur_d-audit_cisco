"""Cisco archive, Call Home, multicast, NetFlow, MPLS, IS-IS."""
from .routing import authentication
from ipaddress import ip_address
import re
from normalizer.common.collections import collection
from schemas import router_contract_v1 as s


def _configured_feature(state,r):
    rule, v, line = (r['rule'], r['values'], r['source_line'])
    root = state.root(r)
    contexts = [state.nodes[n].text for n in r['context_lines']]
    def put(obj, field, value, path):
        state.assign(obj, field, value, path, line, list(v))
        for key in v:
            state.validation[line]['fields'][key] = 'validated'
    def bind(path):
        state.bind(path, line, list(v))
        for key in v:
            state.validation[line]['fields'][key] = 'validated'
    if rule in ('catalogue_archive', 'catalogue_archive_log', 'catalogue_archive_hide'):
        obj = state.c.system.config_archive
        if rule == 'catalogue_archive' and (not contexts):
            put(obj, 'declared', v['declared'], 'system/config_archive')
        elif rule == 'catalogue_archive_log' and contexts == ['archive']:
            put(obj.config_logging, 'declared', v['declared'], 'system/config_archive/config_logging')
        elif rule == 'catalogue_archive_hide' and contexts == ['archive', 'log config']:
            put(obj.config_logging, 'hidekeys', v['enabled'], 'system/config_archive/config_logging')
        return True
    if rule == 'catalogue_call_home_contact':
        if contexts == ['call-home'] and re.fullmatch(r'[^\s@]+@[^\s@]+', v['email']):
            put(state.c.system.call_home, 'contact_email', v['email'], 'system/call_home')
        return True
    if rule in ('catalogue_call_home', 'catalogue_call_home_on', 'catalogue_call_home_profile', 'catalogue_call_home_active', 'catalogue_call_home_destination'):
        obj = state.c.system.call_home
        if rule in ('catalogue_call_home', 'catalogue_call_home_on') and (not contexts):
            put(obj, 'declared' if rule == 'catalogue_call_home' else 'enabled', v.get('declared', v.get('enabled')), 'system/call_home')
        else:
            parent = r if rule == 'catalogue_call_home_profile' else next((state.records[n] for n in r['context_lines'] if state.records.get(n, {}).get('rule') == 'catalogue_call_home_profile'), None)
            if parent is None or not contexts or contexts[0] != 'call-home':
                return True
            if rule == 'catalogue_call_home_profile' and contexts != ['call-home']:
                return True
            if rule != 'catalogue_call_home_profile' and (len(contexts) != 2 or len(parent['context_lines']) != 1):
                return True
            name = parent['values']['name']
            if name.startswith('"') and name.endswith('"'):
                name = name[1:-1]
            if not name or '"' in name:
                raise ValueError('Unqualified profile name quoting')
            profile = next((x for x in (obj.profiles or []) if x.name == name), None)
            if profile is None:
                profile = s.CallHomeProfile(name=name)
                collection(obj, 'profiles').append(profile)
            path = f'system/call_home/profiles/{(obj.profiles or []).index(profile)}'
            if rule == 'catalogue_call_home_profile':
                bind(path + '/name')
            elif contexts[-1] != state.nodes[parent['source_line']].text:
                return True
            elif rule == 'catalogue_call_home_active':
                put(profile, 'active', v['enabled'], path)
            else:
                if v['transport'] != 'http':
                    raise ValueError('Unqualified transport')
                if v['transport'] not in (profile.transport_methods or []):
                    collection(profile, 'transport_methods').append(v['transport'])
                bind(path + '/transport_methods')
        return True
    if rule in ('catalogue_flow_aggregation', 'catalogue_cache_entries', 'catalogue_cache_timeout', 'catalogue_cache_enable', 'catalogue_cache_export'):
        parent = r if rule == 'catalogue_flow_aggregation' else root
        if not parent or parent['rule'] != 'catalogue_flow_aggregation':
            return True
        if (rule == 'catalogue_flow_aggregation' and contexts) or (rule != 'catalogue_flow_aggregation' and len(contexts) != 1):
            return True
        if parent['values']['aggregation'] != 'as':
            return True
        caches = collection(state.c.system.flow_monitoring, 'aggregation_caches')
        identity = parent['values']['aggregation']
        obj = next((x for x in caches if x.aggregation == identity), None)
        if obj is None:
            obj = s.AggregationCache(aggregation=identity)
            caches.append(obj)
        path = f'system/flow_monitoring/aggregation_caches/{caches.index(obj)}'
        state.bind(path + '/aggregation', parent['source_line'], ['aggregation'])
        if rule == 'catalogue_cache_export':
            collection(obj, 'destinations').append(s.Collector(address=v['address'], port=v['port']))
            bind(path + '/destinations')
        elif rule == 'catalogue_cache_entries':
            put(obj, 'entries', v['entries'], path)
        elif rule == 'catalogue_cache_enable':
            put(obj, 'enabled', v['enabled'], path)
        elif rule == 'catalogue_cache_timeout':
            field = {'active': 'timeout_active_minutes', 'inactive': 'timeout_inactive_seconds'}.get(v['type'])
            if field:
                put(obj, field, v['timeout'], path)
        return True
    if rule in ('catalogue_pim_autorp', 'catalogue_pim_bsr', 'catalogue_pim_discovery', 'catalogue_pim_rp_candidate', 'catalogue_pim_ssm', 'catalogue_msdp_peer'):
        if contexts:
            return True
        obj = state.c.multicast
        if rule == 'catalogue_pim_autorp':
            put(obj.auto_rp, 'listener_configured', v['enabled'], 'multicast/auto_rp')
        elif rule == 'catalogue_pim_discovery':
            put(obj.auto_rp, 'discovery_scope', v['scope'], 'multicast/auto_rp')
        elif rule == 'catalogue_pim_bsr':
            collection(obj, 'bsr_candidates').append(s.BSRCandidate(source_interface=v['interface'], hash_mask_length=v['hash_mask']))
            bind('multicast/bsr_candidates')
        elif rule == 'catalogue_pim_rp_candidate':
            collection(obj, 'rp_candidates').append(s.RPCandidate(source_interface=v['interface']))
            bind('multicast/rp_candidates')
        elif rule == 'catalogue_pim_ssm':
            put(obj.ssm, 'range_selector', v['range'], 'multicast/ssm')
        else:
            collection(obj.msdp, 'peers').append(s.MSDPPeer(address=v['address'], connect_source_interface=v['interface']))
            bind('multicast/msdp/peers')
        return True
    if contexts:
        return False
    if rule == 'catalogue_license':
        # Retain the explicit platform PID; never bind the serial number.
        state.assign(state.c.device, 'platform', v['pid'], 'device', line, ['pid'])
        return True
    if rule == 'catalogue_boot_system':
        location = v['image']
        # This mapping covers local images, not remote URLs carrying credentials.
        if '://' in location or '@' in location:
            return True
        device = location.split(':', 1)[0] if re.match(r'^[A-Za-z][\w-]*:', location) else None
        collection(state.c.system.boot, 'images').append(s.BootImage(location=location, source_device=device))
        bind('system/boot/images')
        return True
    if rule == 'catalogue_ifindex':
        put(state.c.system.snmp, 'ifindex_persistent', v['enabled'], 'system/snmp')
        return True
    native = {'catalogue_no_cdp_log': ('cdp_log_mismatch_duplex_enabled', v.get('enabled')),
        'catalogue_qfp': ('qfp_utilization_monitor_load', v.get('percent')),
        'catalogue_punt': ('punt_keepalive_kernel_core_disabled', v.get('disabled')),
        'catalogue_ioam': ('ipv6_ioam_timestamp_enabled', v.get('enabled')),
        'catalogue_bgp_community_format': ('bgp_community_new_format', v.get('enabled'))}
    if rule in native or rule in ('catalogue_scheduler', 'catalogue_scheduler_none', 'catalogue_upgrade'):
        if rule == 'catalogue_upgrade' and v['mode'] != 'auto':
            return True
        if state.c.extensions.cisco is None:
            state.c.extensions.cisco = s.CiscoExtensions()
        obj = state.c.extensions.cisco
        if rule in native:
            field, value = native[rule]
            put(obj, field, value, 'extensions/cisco')
        elif rule == 'catalogue_upgrade':
            put(obj, 'fpd_auto_upgrade', True, 'extensions/cisco')
        else:
            settings = s.SchedulerAllocation(configured=rule == 'catalogue_scheduler',
                interrupt_microseconds=v.get('interrupt'), process_microseconds=v.get('process'))
            put(obj, 'scheduler_allocation', settings, 'extensions/cisco')
        return True
    direct = {'catalogue_password_minimum': (state.c.system.aaa.password_policy, 'minimum_length', v.get('length'), 'system/aaa/password_policy'), 'catalogue_cef': (state.c.system.ip_services, 'cef_ipv4_enabled', v.get('enabled'), 'system/ip_services'), 'catalogue_cef6': (state.c.system.ip_services, 'cef_ipv6_enabled', v.get('enabled'), 'system/ip_services'), 'catalogue_no_cef6': (state.c.system.ip_services, 'cef_ipv6_enabled', v.get('enabled'), 'system/ip_services'), 'catalogue_icmp_no_limit': (state.c.system.ip_services, 'icmp_unreachable_rate_limit_enabled', v.get('limited'), 'system/ip_services'), 'catalogue_synwait': (state.c.system.ip_services, 'tcp_synwait_seconds', v.get('seconds'), 'system/ip_services'), 'catalogue_domain_source': (state.c.system.dns, 'lookup_source_interface', v.get('interface'), 'system/dns'), 'catalogue_tftp_source': (state.c.system.file_transfer.tftp, 'source_interface', v.get('interface'), 'system/file_transfer/tftp'), 'catalogue_config_register': (state.c.system.boot, 'configuration_register', v.get('register'), 'system/boot')}
    if rule in direct:
        put(*direct[rule])
        return True
    if rule == 'catalogue_dns_view':
        collection(state.c.system.dns, 'views').append(s.DNSView(name=v['name'], network_instance=v['vrf'], declared=True))
        bind('system/dns/views')
        return True
    if rule == 'catalogue_forward_protocol':
        collection(state.c.system.ip_services, 'broadcast_forwarding_protocols').append(s.BroadcastForwarding(protocol=v['protocol'], enabled=True))
        bind('system/ip_services/broadcast_forwarding_protocols')
        return True
    if rule == 'catalogue_virtual_service':
        if state.c.extensions.cisco is None:
            state.c.extensions.cisco = s.CiscoExtensions()
        collection(state.c.extensions.cisco, 'virtual_services').append(s.VirtualService(name=v['name'], declared=True))
        bind('extensions/cisco/virtual_services')
        return True
    return False

def _native_feature(state,r):
    rule = r['rule']
    root = state.root(r)
    v = r['values']
    line = r['source_line']
    if root is None:
        return
    if root['rule'] in ('advanced_isis', 'advanced_isis_unnamed'):
        items = collection(state.c.routing, 'isis')
        name = root['values'].get('process')
        obj = next((o for o in items if o.name == name), None)
        if obj is None:
            obj = s.IsisProcess(name=name, declared=True)
            items.append(obj)
        path = f'routing/isis/{items.index(obj)}'
        if rule in ('advanced_isis', 'advanced_isis_unnamed'):
            obj.declared = True
            state.bind(path, line, list(v))
        elif rule == 'advanced_isis_net':
            state.assign(obj, 'net', v['net'], path, line, list(v))
        elif rule == 'advanced_isis_passive':
            collection(obj, 'passive_interfaces').append(v['interface'])
            state.bind(path + '/passive_interfaces', line, list(v))
    elif rule == 'advanced_multicast':
        state.assign(state.c.multicast, 'routing_enabled', v['enabled'], 'multicast', line, list(v))
    elif rule == 'advanced_pim_rp':
        collection(state.c.multicast, 'rendezvous_points').append(ip_address(v['address']))
        state.bind('multicast/rendezvous_points', line, list(v))



def handle(state,r):
    if r["rule"].startswith("auth_isis_"):
        authentication.isis_process(state, r)
        return
    if _configured_feature(state,r):return
    rule,v,line=r['rule'],r['values'],r['source_line']
    if rule=='advanced_mpls_label':
        state.assign(state.c.mpls,'label_protocol',v['protocol'],'mpls',line,list(v))
    elif rule.startswith('advanced_mpls_ldp'):
        if v.get('option') not in (None,'force'):raise ValueError('LDP option')
        state.c.mpls.ldp.router_id_interface=v['interface']
        state.c.mpls.ldp.force=True if v.get('option')=='force' else None
        state.bind('mpls/ldp',line,list(v))
    else:_native_feature(state,r)
