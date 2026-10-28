"""Interfaces, addressing, switching and Ethernet service instances."""
from ipaddress import IPv4Address, ip_interface
from schemas import normalized_config as s
from normalizer.common.validation import boolean
from normalizer.common.addresses import prefix_length, vlan_set, area_id


def handle(state,r):
    root_record=state.root(r)
    if r['rule']=='if_service_instance' or any(state.records.get(n,{}).get('rule')=='if_service_instance' for n in r['context_lines']):
        return ethernet_service(state,r)
    if r['rule'] in ('catalogue_dhcp4','catalogue_sap') or r['rule']=='if_pim' and r['values'].get('mode')=='bsr-border':
        return assignment_method(state,r)
    if len(r['context_lines']) != 1:
        return
    entry = state.entity(r['source_line'])
    if not entry:
        return
    item, path = entry
    rule, v, line = (r['rule'], r['values'], r['source_line'])
    fields = {'if_description': ('description', 'value'), 'if_mtu': ('mtu', 'mtu'), 'if_vrf': ('vrf', 'vrf'), 'if_legacy_vrf': ('vrf', 'vrf')}
    if rule in fields:
        field, key = fields[rule]
        state.assign(item, field, v[key], path, line)
    elif rule in ('if_shutdown', 'if_no_shutdown'):
        state.assign(item, 'admin_enabled', boolean(v['enabled']), path, line)
    elif rule in ('if_ipv4', 'if_ipv4_secondary'):
        state.unbind(path + '/ipv4_addresses',descendants=False)
        length = prefix_length(v['mask'])
        address = str(IPv4Address(v['address']))
        cidr = f'{address}/{length}'
        official = state.official_interfaces.get(item.name, {})
        match = next((s for s in official.get('ipv4_addresses', []) if s.get('ip') == cidr), None)
        if match:
            parsed = ip_interface(match['ip'])
            address, length = (str(parsed.ip), parsed.network.prefixlen)
        item.ipv4_addresses.append(s.IPv4InterfaceAddress(address=address, prefix_length=length, secondary=rule == 'if_ipv4_secondary'))
        state.bind(path + f'/ipv4_addresses/{len(item.ipv4_addresses) - 1}', line)
    elif rule == 'if_ipv6':
        item.ipv6_addresses.append(s.IPv6InterfaceAddress(address=v['address'], prefix_length=v['prefix_length']))
        state.bind(path + f'/ipv6_addresses/{len(item.ipv6_addresses) - 1}', line)
    elif rule in ('if_acl4', 'if_acl6') and v['direction'] in ('in', 'out'):
        field = 'acl_ingress' if v['direction'] == 'in' else 'acl_egress'
        getattr(item, field).append(v['acl'])
        state.bind(path + f'/{field}/{len(getattr(item, field)) - 1}', line)
        state.c.security.acl_attachments.append(s.ACLAttachment(acl_name=v['acl'], interface_name=item.name, direction='ingress' if v['direction'] == 'in' else 'egress'))
        state.bind(f'security/acl_attachments/{len(state.c.security.acl_attachments) - 1}', line)
    elif rule in ('if_switchport', 'if_routed'):
        state.assign(item, 'switchport_mode', 'routed' if rule == 'if_routed' else v['mode'], path, line)
    elif rule in ('if_access_vlan', 'if_native_vlan'):
        state.assign(item, 'access_vlan' if rule == 'if_access_vlan' else 'native_vlan', v['vlan'], path, line)
    elif rule in ('if_trunk_vlans', 'if_trunk_modify'):
        values = set(vlan_set(v['vlans']))
        op = v.get('operation')
        if op in ('add', 'remove'):
            if item.trunk_allowed_vlans is None:
                return
            current = set(item.trunk_allowed_vlans)
            item.trunk_allowed_vlans = sorted(current | values if op == 'add' else current - values)
            state.bind(path + '/trunk_allowed_vlans', line)
        elif op in (None, 'except'):
            state.assign(item, 'trunk_allowed_vlans', sorted(values if op is None else set(range(1, 4095)) - values), path, line)
    elif rule == 'if_lag':
        name = 'Port-channel' + str(v['lag_id'])
        lag = next((x for x in state.c.layer2.lags if x.name == name), None)
        if lag is None:
            lag = s.LAG(name=name, lacp_mode=v['mode'])
            state.c.layer2.lags.append(lag)
        if lag.lacp_mode != v['mode']:
            return
        lag.members.append(item.name)
        state.assign(item, 'lag', name, path, line)
        state.bind(f'layer2/lags/{state.c.layer2.lags.index(lag)}', line)
    elif rule == 'if_ospf2':
        process = next((p for p in state.c.routing.ospf if p.identifier == v['process'] and p.network_instance == item.vrf), None)
        if process is None:
            process = s.OSPFProcess(identifier=v['process'], network_instance=item.vrf, version=2)
            state.c.routing.ospf.append(process)
            state.bind(f'routing/ospf/{len(state.c.routing.ospf) - 1}/identifier', line)
            state.bind(f'routing/ospf/{len(state.c.routing.ospf) - 1}/version', line)
        area = area_id(v['area'])
        group = next((s for s in process.areas if s.area_id == area), None)
        if group is None:
            group = s.OSPFArea(area_id=area)
            process.areas.append(group)
        group.interfaces.append(item.name)
        state.bind(f'routing/ospf/{state.c.routing.ospf.index(process)}/areas/{process.areas.index(group)}', line)
    elif rule == 'if_no_ipv4':
        prefix = '/' + path + '/ipv4_addresses'
        state.unbind(prefix)
        item.ipv4_addresses = []
        state.bind(path + '/ipv4_addresses', line)
    else:
        pass
    obj = item
    direct = {'if_duplex': ('ethernet.duplex', 'duplex'), 'if_negotiation': ('ethernet.negotiation', 'negotiation'), 'if_media': ('ethernet.media', 'media'), 'if_proxyarp': ('proxy_arp', 'enabled'), 'if_redirects': ('redirects', 'enabled'), 'if_keepalive_off': ('keepalive_enabled', 'enabled'), 'if_ipv6_enable': ('ipv6_enabled', 'enabled'), 'if_unnumbered': ('unnumbered_interface', 'interface'), 'if_mss': ('tcp_mss', 'mss'), 'if_mpls': ('mpls_enabled', 'enabled'), 'if_pim': ('pim_mode', 'mode'), 'if_isis': ('isis_process', 'process'), 'if_isis_network': ('isis_network_type', 'network_type'), 'if_ospf_network': ('ospf_network_type', 'network_type'), 'if_cdp_off': ('cdp_enabled', 'enabled')}
    if rule in direct:
        target, key = direct[rule]
        fields = target.split('.')
        owner = obj.ethernet if len(fields) > 1 else obj
        state.assign(owner, fields[-1], v[key], path + ('/ethernet' if len(fields) > 1 else ''), line, [key])
    elif rule == 'if_speed':
        fields = obj.ethernet.model_dump()
        fields.update(speed_mode='auto' if v['speed'] == 'auto' else 'fixed', speed_bps=None if v['speed'] == 'auto' else int(v['speed']) * 1000000)
        obj.ethernet = s.Ethernet(**fields)
        state.bind(path + '/ethernet', line, ['speed'])
    elif rule in ('if_dot1q', 'if_dot1q_lower', 'if_qinq'):
        obj.encapsulation = s.Encapsulation(kind='qinq' if 'inner_vlan' in v else 'dot1q', outer_vlan=v['vlan'], inner_vlan=v.get('inner_vlan'))
        state.bind(path + '/encapsulation', line, list(v))
    elif rule == 'if_flow':
        if v['direction'] not in ('ingress', 'egress'):
            raise ValueError('Flow direction')
        obj.flow_directions.append(v['direction'])
        state.bind(path + '/flow_directions', line, ['direction'])
    elif rule == 'if_ospf3':
        obj.ospf_bindings.append(s.OSPFBinding(version=3, process=v['process'], area=v['area']))
        state.bind(path + '/ospf_bindings', line, list(v))
    elif rule == 'if_mop_off':
        field = {'enabled': 'mop_enabled', 'sysid': 'mop_sysid'}.get(v['feature'])
        if field is None:
            raise ValueError('MOP option')
        state.assign(obj, field, False, path, line, list(v))

def ethernet_service(state,r):
    root = state.root(r)
    if root is None or root['rule'] != 'if_header':
        return
    header = r if r['rule'] == 'if_service_instance' else next((state.records[n] for n in reversed(r['context_lines']) if state.records.get(n, {}).get('rule') == 'if_service_instance'), None)
    if header is None:
        return
    interface = root['values']['name']
    instance = header['values']['instance']
    items = state.c.cisco.ethernet_services
    obj = next((o for o in items if o.interface == interface and o.instance == instance), None)
    if obj is None:
        obj = s.EthernetService(interface=interface, instance=instance)
        items.append(obj)
    path = f'cisco/ethernet_services/{items.index(obj)}'
    v = r['values']
    line = r['source_line']
    rule = r['rule']
    if rule == 'if_service_instance':
        state.bind(path, line, list(v))
    elif rule in ('if_dot1q_lower', 'if_dot1q', 'if_qinq'):
        obj.encapsulation = s.Encapsulation(kind='qinq' if 'inner_vlan' in v else 'dot1q', outer_vlan=v['vlan'], inner_vlan=v.get('inner_vlan'))
        state.bind(path + '/encapsulation', line, list(v))
    elif rule == 'if_encap_untagged':
        obj.encapsulation = s.Encapsulation(kind='untagged')
        state.bind(path + '/encapsulation', line, list(v))
    elif rule == 'if_bridge_domain':
        state.assign(obj, 'bridge_domain', v['domain'], path, line, list(v))

def assignment_method(state,r):
    rule, v, line = (r['rule'], r['values'], r['source_line'])
    root = state.root(r)
    contexts = [state.nodes[n].text for n in r['context_lines']]
    def put(obj, field, value, path):
        state.assign(obj, field, value, path, line, list(v))
        for key in v:
            state.validation[line]['fields'][key] = 'validated'
    if rule in ('catalogue_dhcp4', 'catalogue_sap') or (rule == 'if_pim' and v.get('mode') == 'bsr-border'):
        if not root or root['rule'] != 'if_header' or len(contexts) != 1:
            return True
        obj = next((i for i in state.c.interfaces if i.name == root['values']['name']))
        path = f'interfaces/{state.c.interfaces.index(obj)}'
        if rule == 'catalogue_dhcp4':
            if obj.ipv4_addresses or obj.unnumbered_interface:
                raise ValueError('Conflicting address methods')
            if v['method'] != 'dhcp':
                raise ValueError('Unsupported assignment method')
            put(obj, 'ipv4_assignment_method', 'dhcp', path)
        elif rule == 'catalogue_sap':
            put(obj, 'sap_listen_enabled', v['enabled'], path)
        else:
            put(obj, 'pim_bsr_border', True, path)
        return True



def declare(state,r):
    rule,v,line=r['rule'],r['values'],r['source_line']
    if rule == 'if_header':
        name = v['name']
        lower = name.lower()
        kind = 'subinterface' if '.' in name else 'loopback' if lower.startswith('loopback') else 'svi' if lower.startswith(('vlan', 'bvi')) else 'lag' if lower.startswith('port-channel') else 'tunnel' if lower.startswith('tunnel') else 'physical'
        item = s.Interface(name=name, kind=kind)
        if kind == 'subinterface':
            item.parent_interface, suffix = name.rsplit('.', 1)
            item.subinterface_index = int(suffix)
        state.c.interfaces.append(item)
        path = f'interfaces/{len(state.c.interfaces) - 1}'
        state.entities[line] = path
        state.bind(path + '/name', line)
        state.bind(path + '/kind', line)
        if item.parent_interface:
            state.bind(path + '/parent_interface', line)
            state.bind(path + '/subinterface_index', line)
        return True
    return False
