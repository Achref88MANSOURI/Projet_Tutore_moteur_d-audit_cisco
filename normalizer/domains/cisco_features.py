"""Cisco archive, Call Home, multicast, NetFlow, MPLS, IS-IS and L2VPN."""
from ipaddress import ip_address
import re
from schemas import normalized_config as s


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
    if rule == 'advanced_l2_bridge' and root and (root['rule'] == 'advanced_l2_vfi'):
        if len(contexts) != 1:
            return True
        obj = next((x for x in state.c.cisco.l2vpn.vfis if x.identifier == root['values']['vfi']))
        put(obj, 'bridge_domain', v['domain'], f'cisco/l2vpn/vfis/{state.c.cisco.l2vpn.vfis.index(obj)}')
        return True
    if rule in ('catalogue_archive', 'catalogue_archive_log', 'catalogue_archive_hide'):
        obj = state.c.cisco.config_archive
        if rule == 'catalogue_archive' and (not contexts):
            put(obj, 'declared', v['declared'], 'cisco/config_archive')
        elif rule == 'catalogue_archive_log' and contexts == ['archive']:
            put(obj.config_logging, 'declared', v['declared'], 'cisco/config_archive/config_logging')
        elif rule == 'catalogue_archive_hide' and contexts == ['archive', 'log config']:
            put(obj.config_logging, 'hidekeys', v['enabled'], 'cisco/config_archive/config_logging')
        return True
    if rule in ('catalogue_call_home', 'catalogue_call_home_on', 'catalogue_call_home_profile', 'catalogue_call_home_active', 'catalogue_call_home_destination'):
        obj = state.c.cisco.call_home
        if rule in ('catalogue_call_home', 'catalogue_call_home_on') and (not contexts):
            put(obj, 'declared' if rule == 'catalogue_call_home' else 'enabled', v.get('declared', v.get('enabled')), 'cisco/call_home')
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
            profile = next((x for x in obj.profiles if x.name == name), None)
            if profile is None:
                profile = s.CallHomeProfile(name=name)
                obj.profiles.append(profile)
            path = f'cisco/call_home/profiles/{obj.profiles.index(profile)}'
            if rule == 'catalogue_call_home_profile':
                bind(path + '/name')
            elif contexts[-1] != state.nodes[parent['source_line']].text:
                return True
            elif rule == 'catalogue_call_home_active':
                put(profile, 'active', v['enabled'], path)
            else:
                if v['transport'] != 'http':
                    raise ValueError('Unqualified transport')
                if v['transport'] not in profile.transport_methods:
                    profile.transport_methods.append(v['transport'])
                bind(path + '/transport_methods')
        return True
    if rule == 'catalogue_cache_export':
        if not root or root['rule'] != 'catalogue_flow_aggregation' or len(contexts) != 1:
            return True
        caches = state.c.cisco.netflow.aggregation_caches
        identity = root['values']['aggregation']
        obj = next((x for x in caches if x.aggregation == identity), None)
        if obj is None:
            obj = s.AggregationCache(aggregation=identity)
            caches.append(obj)
        state.bind(f'cisco/netflow/aggregation_caches/{caches.index(obj)}/aggregation',root['source_line'],['aggregation'])
        obj.destinations.append(s.Collector(address=v['address'], port=v['port']))
        bind(f'cisco/netflow/aggregation_caches/{caches.index(obj)}/destinations')
        return True
    if rule in ('catalogue_pim_autorp', 'catalogue_pim_bsr', 'catalogue_pim_discovery', 'catalogue_pim_rp_candidate', 'catalogue_pim_ssm', 'catalogue_msdp_peer'):
        if contexts:
            return True
        obj = state.c.cisco.multicast
        if rule == 'catalogue_pim_autorp':
            put(obj.auto_rp, 'listener_configured', v['enabled'], 'cisco/multicast/auto_rp')
        elif rule == 'catalogue_pim_discovery':
            put(obj.auto_rp, 'discovery_scope', v['scope'], 'cisco/multicast/auto_rp')
        elif rule == 'catalogue_pim_bsr':
            obj.bsr_candidates.append(s.BSRCandidate(source_interface=v['interface'], hash_mask_length=v['hash_mask']))
            bind('cisco/multicast/bsr_candidates')
        elif rule == 'catalogue_pim_rp_candidate':
            obj.rp_candidates.append(s.RPCandidate(source_interface=v['interface']))
            bind('cisco/multicast/rp_candidates')
        elif rule == 'catalogue_pim_ssm':
            put(obj.ssm, 'range_selector', v['range'], 'cisco/multicast/ssm')
        else:
            obj.msdp.peers.append(s.MSDPPeer(address=v['address'], connect_source_interface=v['interface']))
            bind('cisco/multicast/msdp/peers')
        return True
    if contexts:
        return False
    direct = {'catalogue_password_minimum': (state.c.system.aaa.password_policy, 'minimum_length', v.get('length'), 'system/aaa/password_policy'), 'catalogue_cef': (state.c.cisco.ip_services, 'cef_ipv4_enabled', v.get('enabled'), 'cisco/ip_services'), 'catalogue_cef6': (state.c.cisco.ip_services, 'cef_ipv6_enabled', v.get('enabled'), 'cisco/ip_services'), 'catalogue_no_cef6': (state.c.cisco.ip_services, 'cef_ipv6_enabled', v.get('enabled'), 'cisco/ip_services'), 'catalogue_icmp_no_limit': (state.c.cisco.ip_services, 'icmp_unreachable_rate_limit_enabled', v.get('limited'), 'cisco/ip_services'), 'catalogue_synwait': (state.c.cisco.ip_services, 'tcp_synwait_seconds', v.get('seconds'), 'cisco/ip_services'), 'catalogue_domain_source': (state.c.cisco.dns, 'lookup_source_interface', v.get('interface'), 'cisco/dns'), 'catalogue_tftp_source': (state.c.cisco.file_transfer.tftp, 'source_interface', v.get('interface'), 'cisco/file_transfer/tftp'), 'catalogue_config_register': (state.c.cisco.boot, 'configuration_register', v.get('register'), 'cisco/boot')}
    if rule in direct:
        put(*direct[rule])
        return True
    if rule == 'catalogue_dns_view':
        state.c.cisco.dns.views.append(s.DNSView(name=v['name'], network_instance=v['vrf'], declared=True))
        bind('cisco/dns/views')
        return True
    if rule == 'catalogue_forward_protocol':
        state.c.cisco.ip_services.broadcast_forwarding_protocols.append(s.BroadcastForwarding(protocol=v['protocol'], enabled=True))
        bind('cisco/ip_services/broadcast_forwarding_protocols')
        return True
    if rule == 'catalogue_virtual_service':
        state.c.cisco.virtual_services.append(s.VirtualService(name=v['name'], declared=True))
        bind('cisco/virtual_services')
        return True
    return False

def _native_feature(state,r):
    rule = r['rule']
    root = state.root(r)
    v = r['values']
    line = r['source_line']
    if root is None:
        return
    if root['rule'] == 'advanced_isis':
        items = state.c.cisco.isis
        name = root['values']['process']
        obj = next((o for o in items if o.name == name), None)
        if obj is None:
            obj = s.IsisProcess(name=name)
            items.append(obj)
        path = f'cisco/isis/{items.index(obj)}'
        if rule == 'advanced_isis':
            state.bind(path, line, list(v))
        elif rule == 'advanced_isis_net':
            state.assign(obj, 'net', v['net'], path, line, list(v))
        elif rule == 'advanced_isis_passive':
            obj.passive_interfaces.append(v['interface'])
            state.bind(path + '/passive_interfaces', line, list(v))
    elif rule == 'advanced_multicast':
        state.assign(state.c.cisco.multicast, 'routing_enabled', v['enabled'], 'cisco/multicast', line, list(v))
    elif rule == 'advanced_pim_rp':
        state.c.cisco.multicast.rendezvous_points.append(ip_address(v['address']))
        state.bind('cisco/multicast/rendezvous_points', line, list(v))
    elif rule.startswith('advanced_l2_'):
        obj = state.c.cisco.l2vpn
        if rule == 'advanced_l2_evpn_global':
            state.assign(obj, 'evpn_declared', v['declaration'], 'cisco/l2vpn', line, list(v))
        elif rule == 'advanced_l2_replication' and root['rule'] == 'advanced_l2_evpn_global':
            state.assign(obj, 'replication_type', v['type'], 'cisco/l2vpn', line, list(v))
        elif rule == 'advanced_l2_rid' and root['rule'] == 'advanced_l2_evpn_global':
            state.assign(obj, 'router_id_interface', v['interface'], 'cisco/l2vpn', line, list(v))
        elif rule == 'advanced_l2_evpn':
            obj.evpn_instances.append(s.EVI(identifier=v['instance'], type=v['type']))
            state.bind('cisco/l2vpn/evpn_instances', line, list(v))
        elif root['rule'] == 'advanced_l2_bridge':
            identifier = root['values']['domain']
            bd = next((b for b in obj.bridge_domains if b.identifier == identifier), None)
            if bd is None:
                bd = s.BridgeDomain(identifier=identifier)
                obj.bridge_domains.append(bd)
            path = f'cisco/l2vpn/bridge_domains/{obj.bridge_domains.index(bd)}'
            if rule == 'advanced_l2_bridge':
                state.bind(path, line, list(v))
            elif rule == 'advanced_l2_member':
                match = re.fullmatch('(\\S+) service-instance (\\d+)', v['member'])
                if match:
                    member = s.BridgeMember(kind='interface_service', interface=match[1], service_instance=int(match[2]))
                else:
                    match = re.fullmatch('evpn-instance (\\d+) ethernet-tag (\\d+)', v['member'])
                    if match is None:
                        raise ValueError('Unsupported bridge member syntax')
                    member = s.BridgeMember(kind='evpn', evpn_instance=int(match[1]), ethernet_tag=int(match[2]))
                bd.members.append(member)
                state.validation[line]['fields']['member'] = 'validated'
                state.bind(path + '/members', line, list(v))
        elif root['rule'] == 'advanced_l2_vfi':
            identifier = root['values']['vfi']
            vf = next((o for o in obj.vfis if o.identifier == identifier), None)
            if vf is None:
                vf = s.VFI(identifier=identifier, mode=root['values']['mode'])
                obj.vfis.append(vf)
            path = f'cisco/l2vpn/vfis/{obj.vfis.index(vf)}'
            if rule == 'advanced_l2_vfi':
                state.bind(path, line, list(v))
            elif rule == 'advanced_l2_vpnid':
                state.assign(vf, 'vpn_id', v['vpn_id'], path, line, list(v))
            elif rule == 'advanced_l2_neighbor':
                vf.neighbors.append(s.VFINeighbor(address=v['address'], encapsulation=v['encapsulation']))
                state.bind(path + '/neighbors', line, list(v))



def handle(state,r):
    if _configured_feature(state,r):return
    rule,v,line=r['rule'],r['values'],r['source_line']
    if rule=='advanced_mpls_label':
        state.assign(state.c.cisco.mpls,'label_protocol',v['protocol'],'cisco/mpls',line,list(v))
    elif rule.startswith('advanced_mpls_ldp'):
        if v.get('option') not in (None,'force'):raise ValueError('LDP option')
        state.c.cisco.mpls.ldp.router_id_interface=v['interface']
        state.c.cisco.mpls.ldp.force=True if v.get('option')=='force' else None
        state.bind('cisco/mpls/ldp',line,list(v))
    else:_native_feature(state,r)
