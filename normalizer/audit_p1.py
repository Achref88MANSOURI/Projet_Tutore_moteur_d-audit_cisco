"""Reviewed P1 mappings; no TTP grammar changes or operational-state inference."""
from ipaddress import ip_address, ip_network, IPv4Address
import re
from schemas import normalizedconfig_v02 as s
from schemas import cisco_audit_v02 as a
from .mapping import asn

POLICIES={'policy_match_acl','policy_match_community','policy_match_prefix4',
          'policy_match_prefix6','policy_set_aspath','policy_set_community'}


def existing_policy(m,r):
    """Validate an existing generic object, never append a duplicate mapping."""
    rule=r['rule'];value=r['values']['value'];line=r['source_line']
    tokens=value.split()
    ok=False
    if rule=='policy_match_acl':
        ok=len(tokens)==1 and any(x.name==value and x.family=='ipv4' for x in m.c.security.acl_sets)
    elif rule in ('policy_match_prefix4','policy_match_prefix6'):
        family='ipv4' if rule.endswith('4') else 'ipv6'
        ok=len(tokens)==1 and any(x.name==value and x.family==family for x in m.c.routing.prefix_lists)
    elif rule=='policy_match_community':
        # A reference can exist while its Cisco regex dependency is unvalidated.
        # Keep it native until that language has an independent validator.
        ok=False
    elif rule=='policy_set_aspath':
        try:
            ok=bool(tokens) and all(1<=asn(t)<=4294967295 for t in tokens)
        except (ValueError,TypeError):ok=False
    elif rule=='policy_set_community':
        members=tokens[:-1] if tokens and tokens[-1]=='additive' else tokens
        ok=bool(members) and all(re.fullmatch(r'\d+:\d+',t) and all(0<=int(n)<=65535 for n in t.split(':')) for t in members)
    if not ok:
        m.partial_notes[line]='Policy expression or referenced dependency has not been semantically validated.'
        return
    proofs=[e.path for e in m.evidence if e.line_start==line and e.status=='explicit' and '/routing/routing_policies/' in e.path]
    if not proofs:return
    # Inspect the already-produced target, including action kind and exact value.
    expected_kind={'policy_match_acl':'acl','policy_match_prefix4':'prefix_set_ipv4',
        'policy_match_prefix6':'prefix_set_ipv6','policy_set_aspath':'as_path_prepend','policy_set_community':'community'}.get(rule)
    for pointer in proofs:
        target=m.result.model_dump(mode='json')
        for part in pointer.strip('/').split('/'):target=target[int(part)] if isinstance(target,list) else target[part]
        if target.get('value')==value and target.get('kind')==expected_kind:
            m.validation[line]['fields']['value']='validated'
            m.consumed[line]['value']=[pointer]
            return


def handle(m,r):
    rule,v,line=r['rule'],r['values'],r['source_line']
    root=m.root(r);contexts=[m.nodes[n].text for n in r['context_lines']]
    def put(obj,field,value,path):
        m.assign(obj,field,value,path,line,list(v))
        for key in v:m.validation[line]['fields'][key]='validated'
    def prove(path):
        m.prove(path,line,list(v))
        for key in v:m.validation[line]['fields'][key]='validated'
    if rule in ('bgp_no_auto_summary','bgp_no_sync') and m.af(r):
        if len(contexts)!=2 or not contexts[-1].startswith('address-family '):return True
        proc,path,af=m.process(r);family=m.family(proc,af)
        put(family,'auto_summary' if rule=='bgp_no_auto_summary' else 'synchronization',v['enabled'],path+f'/family_options/{proc.family_options.index(family)}')
        return True
    if rule in ('bgp_advertise_additional','catalogue_allowas'):
        if not root or root['rule']!='bgp_header':return True
        if len(contexts)!=1 and not (len(contexts)==2 and contexts[-1].startswith('address-family ')):return True
        proc,path,af=m.process(r)
        try:peer=str(ip_address(v['peer']));kind='neighbor'
        except ValueError:
            peer=v['peer'];kind='group'
            if not any(x['root_line']==r['root_line'] and x['rule']=='bgp_group_definition' and x['values']['peer']==peer for x in m.records.values()):
                m.partial_notes[line]='Referenced peer group is undeclared; parameters remain native.'
                return True
        if af:
            family=m.family(proc,af);items=family.peers;path+=f'/family_options/{proc.family_options.index(family)}/peers'
        else:items=proc.peer_options;path+='/peer_options'
        obj=next((x for x in items if x.peer==peer and x.kind==kind),None)
        if obj is None:obj=s.BGPPeerOptions(peer=peer,kind=kind);items.append(obj)
        path+='/'+str(items.index(obj))
        if rule=='bgp_advertise_additional':put(obj,'additional_paths_advertise_selection',v['selection'],path)
        else:
            if v['count_unspecified'] is not True:raise ValueError('Unsupported allowas variant')
            put(obj,'allowas_in',a.AllowASIn(enabled=True),path)
        return True
    if rule=='bgp_network' and 'mask' not in v and '/' not in v['prefix']:
        address=IPv4Address(v['prefix']);first=int(str(address).split('.')[0])
        length=8 if 1<=first<=126 else 16 if 128<=first<=191 else 24 if 192<=first<=223 else None
        if length is None:raise ValueError('Unsupported classful network')
        prefix=ip_network(str(address)+'/'+str(length),strict=True)
        proc,path,af=m.process(r)
        proc.networks.append(s.BGPNetwork(prefix=prefix,afi=af.get('afi') if af else None,safi=af.get('safi') if af else None))
        prove(path+'/networks')
        m.evidence[-1].basis='Natural mask derived from the documented IOS network syntax; no RIB or advertisement state inferred.'
        return True
    if rule in ('catalogue_dhcp4','catalogue_sap') or rule=='if_pim' and v.get('mode')=='bsr-border':
        if not root or root['rule']!='if_header' or len(contexts)!=1:return True
        obj=next(i for i in m.c.interfaces if i.name==root['values']['name']);path=f'interfaces/{m.c.interfaces.index(obj)}'
        if rule=='catalogue_dhcp4':
            if obj.ipv4_addresses or obj.unnumbered_interface:raise ValueError('Conflicting address methods')
            if v['method']!='dhcp':raise ValueError('Unsupported assignment method')
            put(obj,'ipv4_assignment_method','dhcp',path)
        elif rule=='catalogue_sap':put(obj,'sap_listen_enabled',v['enabled'],path)
        else:put(obj,'pim_bsr_border',True,path)
        return True
    if rule=='advanced_l2_bridge' and root and root['rule']=='advanced_l2_vfi':
        if len(contexts)!=1:return True
        obj=next(x for x in m.c.cisco.l2vpn.vfis if x.identifier==root['values']['vfi'])
        put(obj,'bridge_domain',v['domain'],f'cisco/l2vpn/vfis/{m.c.cisco.l2vpn.vfis.index(obj)}');return True
    if rule.startswith('catalogue_rip'):
        if rule!='catalogue_rip' and (not root or root['rule']!='catalogue_rip'):return True
        if rule=='catalogue_rip' and contexts:return True
        if rule=='catalogue_rip_family' and contexts!=['router rip']:return True
        if rule not in ('catalogue_rip','catalogue_rip_family') and not (contexts==['router rip'] or len(contexts)==2 and contexts[0]=='router rip' and m.records.get(r['context_lines'][-1],{}).get('rule')=='catalogue_rip_family'):return True
        if not m.c.routing.rip:m.c.routing.rip.append(a.RIPProcess(declared=True))
        proc=m.c.routing.rip[0];obj=proc;path='routing/rip/0'
        family=r if rule=='catalogue_rip_family' else next((m.records[n] for n in reversed(r['context_lines']) if m.records.get(n,{}).get('rule')=='catalogue_rip_family'),None)
        if family:
            f=family['values'];obj=next((x for x in proc.address_families if x.afi==f['afi'] and x.network_instance==f['vrf']),None)
            if obj is None:obj=a.RIPFamily(afi=f['afi'],network_instance=f['vrf']);proc.address_families.append(obj)
            path+=f'/address_families/{proc.address_families.index(obj)}'
        if rule=='catalogue_rip':put(proc,'declared',v['declared'],'routing/rip/0')
        elif rule=='catalogue_rip_family':prove(path)
        elif rule=='catalogue_rip_network':obj.network_statements.append(IPv4Address(v['network']));prove(path+'/network_statements')
        elif rule=='catalogue_rip_no_summary':put(obj,'auto_summary',v['enabled'],path)
        elif rule=='catalogue_rip_redistribute':
            obj.redistributions.append(a.RIPRedistribution(protocol='bgp',source_bgp_as=asn(v['local_as']),metric=v['metric']));prove(path+'/redistributions')
        return True
    if rule in ('catalogue_archive','catalogue_archive_log','catalogue_archive_hide'):
        obj=m.c.cisco.config_archive
        if rule=='catalogue_archive' and not contexts:put(obj,'declared',v['declared'],'cisco/config_archive')
        elif rule=='catalogue_archive_log' and contexts==['archive']:put(obj.config_logging,'declared',v['declared'],'cisco/config_archive/config_logging')
        elif rule=='catalogue_archive_hide' and contexts==['archive','log config']:put(obj.config_logging,'hidekeys',v['enabled'],'cisco/config_archive/config_logging')
        return True
    if rule in ('catalogue_call_home','catalogue_call_home_on','catalogue_call_home_profile','catalogue_call_home_active','catalogue_call_home_destination'):
        obj=m.c.cisco.call_home
        if rule in ('catalogue_call_home','catalogue_call_home_on') and not contexts:
            put(obj,'declared' if rule=='catalogue_call_home' else 'enabled',v.get('declared',v.get('enabled')),'cisco/call_home')
        else:
            parent=r if rule=='catalogue_call_home_profile' else next((m.records[n] for n in r['context_lines'] if m.records.get(n,{}).get('rule')=='catalogue_call_home_profile'),None)
            if parent is None or not contexts or contexts[0]!='call-home':return True
            if rule=='catalogue_call_home_profile' and contexts!=['call-home']:return True
            if rule!='catalogue_call_home_profile' and (len(contexts)!=2 or len(parent['context_lines'])!=1):return True
            name=parent['values']['name']
            if name.startswith('"') and name.endswith('"'):name=name[1:-1]
            if not name or '"' in name:raise ValueError('Unqualified profile name quoting')
            profile=next((x for x in obj.profiles if x.name==name),None)
            if profile is None:profile=a.CallHomeProfile(name=name);obj.profiles.append(profile)
            path=f'cisco/call_home/profiles/{obj.profiles.index(profile)}'
            if rule=='catalogue_call_home_profile':prove(path+'/name')
            elif contexts[-1]!=m.nodes[parent['source_line']].text:return True
            elif rule=='catalogue_call_home_active':put(profile,'active',v['enabled'],path)
            else:
                # Only the observed HTTP(S) method is qualified in this mission.
                if v['transport']!='http':raise ValueError('Unqualified transport')
                if v['transport'] not in profile.transport_methods:profile.transport_methods.append(v['transport'])
                prove(path+'/transport_methods')
        return True
    if rule=='catalogue_cache_export':
        if not root or root['rule']!='catalogue_flow_aggregation' or len(contexts)!=1:return True
        caches=m.c.cisco.netflow.aggregation_caches;identity=root['values']['aggregation']
        obj=next((x for x in caches if x.aggregation==identity),None)
        if obj is None:obj=a.AggregationCache(aggregation=identity);caches.append(obj)
        obj.destinations.append(a.Collector(address=v['address'],port=v['port']))
        prove(f'cisco/netflow/aggregation_caches/{caches.index(obj)}/destinations');return True
    if rule in ('catalogue_pim_autorp','catalogue_pim_bsr','catalogue_pim_discovery','catalogue_pim_rp_candidate','catalogue_pim_ssm','catalogue_msdp_peer'):
        if contexts:return True
        obj=m.c.cisco.multicast
        if rule=='catalogue_pim_autorp':put(obj.auto_rp,'listener_configured',v['enabled'],'cisco/multicast/auto_rp')
        elif rule=='catalogue_pim_discovery':put(obj.auto_rp,'discovery_scope',v['scope'],'cisco/multicast/auto_rp')
        elif rule=='catalogue_pim_bsr':obj.bsr_candidates.append(a.BSRCandidate(source_interface=v['interface'],hash_mask_length=v['hash_mask']));prove('cisco/multicast/bsr_candidates')
        elif rule=='catalogue_pim_rp_candidate':obj.rp_candidates.append(a.RPCandidate(source_interface=v['interface']));prove('cisco/multicast/rp_candidates')
        elif rule=='catalogue_pim_ssm':put(obj.ssm,'range_selector',v['range'],'cisco/multicast/ssm')
        else:obj.msdp.peers.append(a.MSDPPeer(address=v['address'],connect_source_interface=v['interface']));prove('cisco/multicast/msdp/peers')
        return True
    if contexts:return False
    direct={
        'catalogue_password_minimum':(m.c.system.aaa.password_policy,'minimum_length',v.get('length'),'system/aaa/password_policy'),
        'catalogue_cef':(m.c.cisco.ip_services,'cef_ipv4_enabled',v.get('enabled'),'cisco/ip_services'),
        'catalogue_cef6':(m.c.cisco.ip_services,'cef_ipv6_enabled',v.get('enabled'),'cisco/ip_services'),
        'catalogue_no_cef6':(m.c.cisco.ip_services,'cef_ipv6_enabled',v.get('enabled'),'cisco/ip_services'),
        'catalogue_icmp_no_limit':(m.c.cisco.ip_services,'icmp_unreachable_rate_limit_enabled',v.get('limited'),'cisco/ip_services'),
        'catalogue_synwait':(m.c.cisco.ip_services,'tcp_synwait_seconds',v.get('seconds'),'cisco/ip_services'),
        'catalogue_domain_source':(m.c.cisco.dns,'lookup_source_interface',v.get('interface'),'cisco/dns'),
        'catalogue_tftp_source':(m.c.cisco.file_transfer.tftp,'source_interface',v.get('interface'),'cisco/file_transfer/tftp'),
        'catalogue_config_register':(m.c.cisco.boot,'configuration_register',v.get('register'),'cisco/boot'),
    }
    if rule in direct:put(*direct[rule]);return True
    if rule=='catalogue_dns_view':
        m.c.cisco.dns.views.append(a.DNSView(name=v['name'],network_instance=v['vrf'],declared=True));prove('cisco/dns/views');return True
    if rule=='catalogue_forward_protocol':
        m.c.cisco.ip_services.broadcast_forwarding_protocols.append(a.BroadcastForwarding(protocol=v['protocol'],enabled=True));prove('cisco/ip_services/broadcast_forwarding_protocols');return True
    if rule=='catalogue_virtual_service':
        m.c.cisco.virtual_services.append(a.VirtualService(name=v['name'],declared=True));prove('cisco/virtual_services');return True
    return False
