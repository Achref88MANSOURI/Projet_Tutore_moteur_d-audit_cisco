"""Source-token expectations for newly promoted occurrences, without mapper APIs."""
from ipaddress import IPv4Address


def one(items,**keys):
    found=[i for i in items if all(i[k]==v for k,v in keys.items())]
    assert len(found)==1
    return found[0]


def source_asn(text):
    t=text.split('.')
    return int(t[0]) if len(t)==1 else int(t[0])*65536+int(t[1])


def check(text,row,doc):
    """Assert literal source values at independently selected contract locations."""
    line=text.splitlines()[row['line']-1].strip();tokens=line.split();rule=row['rule']
    c=doc['configuration'];x=c['cisco'];parents=row['context']
    def equal(actual,expected):assert actual==expected and type(actual) is type(expected)
    if rule.startswith('policy_'):
        head=parents[0].split();policy=one(c['routing']['routing_policies'],name=head[1])
        statement=one(policy['statements'],identifier=head[3])
        prefix,kind={
            'policy_match_acl':('match ip address ','acl'),
            'policy_match_prefix4':('match ip address prefix-list ','prefix_set_ipv4'),
            'policy_match_prefix6':('match ipv6 address prefix-list ','prefix_set_ipv6'),
            'policy_set_aspath':('set as-path prepend ','as_path_prepend'),
            'policy_set_community':('set community ','community'),
        }[rule]
        assert line.startswith(prefix)
        value=line[len(prefix):]
        assert any(o['kind']==kind and o['value']==value for o in statement['matches' if rule.startswith('policy_match') else 'actions'])
        return
    if rule in ('bgp_network','bgp_advertise_additional','bgp_no_auto_summary','bgp_no_sync','catalogue_allowas'):
        asn=source_asn(parents[0].split()[-1]);af=next((p.split() for p in parents if p.startswith('address-family ')),None)
        vrf=af[af.index('vrf')+1] if af and 'vrf' in af else None
        proc=one(c['routing']['bgp'],local_as=asn,network_instance=vrf)
        if rule=='bgp_network':
            first=int(tokens[1].split('.')[0]);length=8 if first<128 else 16 if first<192 else 24
            assert any(n['prefix']==tokens[1]+'/'+str(length) for n in proc['networks']);return
        owner=one(proc['family_options'],afi=af[1],safi=af[2] if len(af)>2 and af[2]!='vrf' else None) if af else proc
        if rule in ('bgp_no_auto_summary','bgp_no_sync'):equal(owner['auto_summary' if rule=='bgp_no_auto_summary' else 'synchronization'],False)
        else:
            peer=one(owner['peers'] if af else owner['peer_options'],peer=tokens[1])
            if rule=='bgp_advertise_additional':equal(peer['additional_paths_advertise_selection'],tokens[-1])
            else:equal(peer['allowas_in'],{'enabled':True,'configured_max_occurrences':None})
        return
    if rule.startswith('catalogue_rip'):
        proc,=c['routing']['rip'];af=next((p.split() for p in parents if p.startswith('address-family ')),None)
        obj=one(proc['address_families'],afi=af[1],network_instance=af[-1]) if af else proc
        if rule=='catalogue_rip':equal(proc['declared'],True)
        elif rule=='catalogue_rip_family':one(proc['address_families'],afi=tokens[1],network_instance=tokens[-1])
        elif rule=='catalogue_rip_network':assert str(IPv4Address(tokens[-1])) in obj['network_statements']
        elif rule=='catalogue_rip_no_summary':equal(obj['auto_summary'],False)
        else:
            red=one(obj['redistributions'],source_bgp_as=source_asn(tokens[2]));equal(red['metric'],int(tokens[-1]));equal(red['protocol'],'bgp')
        return
    if rule in ('catalogue_dhcp4','catalogue_sap','if_pim'):
        obj=one(c['interfaces'],name=parents[0].split()[1]);field={'catalogue_dhcp4':'ipv4_assignment_method','catalogue_sap':'sap_listen_enabled','if_pim':'pim_bsr_border'}[rule]
        equal(obj[field],'dhcp' if rule=='catalogue_dhcp4' else True);return
    if rule=='advanced_l2_bridge':equal(one(x['l2vpn']['vfis'],identifier=int(parents[0].split()[2]))['bridge_domain'],int(tokens[-1]));return
    if rule.startswith('catalogue_call_home'):
        obj=x['call_home']
        if rule=='catalogue_call_home':equal(obj['declared'],True)
        elif rule=='catalogue_call_home_on':equal(obj['enabled'],True)
        else:
            name=line.split(maxsplit=1)[1] if rule=='catalogue_call_home_profile' else next(p.split(maxsplit=1)[1] for p in parents if p.startswith('profile '))
            if len(name)>=2 and name[0]==name[-1]=='"':name=name[1:-1]
            profile=one(obj['profiles'],name=name)
            if rule=='catalogue_call_home_active':equal(profile['active'],True)
            if rule=='catalogue_call_home_destination':assert tokens[-1] in profile['transport_methods'] and 'tls' not in profile
        return
    if rule=='catalogue_archive':equal(x['config_archive']['declared'],True);return
    if rule=='catalogue_archive_log':equal(x['config_archive']['config_logging']['declared'],True);return
    if rule=='catalogue_archive_hide':equal(x['config_archive']['config_logging']['hidekeys'],True);return
    if rule=='catalogue_cache_export':
        cache=one(x['netflow']['aggregation_caches'],aggregation=parents[0].split()[-1]);one(cache['destinations'],address=tokens[-2],port=int(tokens[-1]));return
    if rule=='catalogue_dns_view':one(x['dns']['views'],name=tokens[-1],network_instance=tokens[-2],declared=True);return
    if rule=='catalogue_virtual_service':one(x['virtual_services'],name=tokens[-1],declared=True);return
    if rule=='catalogue_forward_protocol':one(x['ip_services']['broadcast_forwarding_protocols'],protocol=tokens[-1],enabled=True);return
    if rule=='catalogue_pim_bsr':one(x['multicast']['bsr_candidates'],source_interface=tokens[-2],hash_mask_length=int(tokens[-1]));return
    if rule=='catalogue_pim_rp_candidate':one(x['multicast']['rp_candidates'],source_interface=tokens[-1]);return
    if rule=='catalogue_msdp_peer':one(x['multicast']['msdp']['peers'],address=tokens[3],connect_source_interface=tokens[-1]);return
    direct={
      'catalogue_password_minimum':(c['system']['aaa']['password_policy']['minimum_length'],int(tokens[-1]) if tokens[-1].isdigit() else None),
      'catalogue_config_register':(x['boot']['configuration_register'],tokens[-1]),
      'catalogue_domain_source':(x['dns']['lookup_source_interface'],tokens[-1]),
      'catalogue_tftp_source':(x['file_transfer']['tftp']['source_interface'],tokens[-1]),
      'catalogue_cef':(x['ip_services']['cef_ipv4_enabled'],True),
      'catalogue_cef6':(x['ip_services']['cef_ipv6_enabled'],True),
      'catalogue_no_cef6':(x['ip_services']['cef_ipv6_enabled'],False),
      'catalogue_synwait':(x['ip_services']['tcp_synwait_seconds'],int(tokens[-1]) if tokens[-1].isdigit() else None),
      'catalogue_icmp_no_limit':(x['ip_services']['icmp_unreachable_rate_limit_enabled'],False),
      'catalogue_pim_autorp':(x['multicast']['auto_rp']['listener_configured'],True),
      'catalogue_pim_discovery':(x['multicast']['auto_rp']['discovery_scope'],int(tokens[-1]) if tokens[-1].isdigit() else None),
      'catalogue_pim_ssm':(x['multicast']['ssm']['range_selector'],tokens[-1]),
    }
    assert rule in direct,'No reviewed source oracle for promoted family'
    equal(*direct[rule])
