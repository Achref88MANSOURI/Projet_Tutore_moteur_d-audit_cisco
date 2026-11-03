"""RIP global/VRF scopes, network statements, redistribution, and interface authentication."""
from ipaddress import IPv4Address
from normalizer.common.collections import collection
from normalizer.common.configured import leaves
from normalizer.common.contexts import at
from schemas import router_contract_v1 as s
from normalizer.common.addresses import asn


def _rip_interface_target(state, record):
    """Find or create RIP interface settings for the given interface."""
    interface, _ = state.entity(record['source_line'])
    if not isinstance(interface, s.Interface):
        return None, None
    
    # Check if there's an explicitly declared RIP process
    rip_procs = state.c.routing.rip or []
    declared_proc = next((p for p in rip_procs if p.declared), None)
    
    if declared_proc:
        # Use protocol-specific interface settings on the declared process
        proc = declared_proc
        proc_idx = rip_procs.index(proc)
        proc_path = f'routing/rip/{proc_idx}'
        
        vrf = interface.vrf
        if vrf:
            # VRF-specific: find or create address family
            families = proc.address_families or []
            family = next((f for f in families if f.network_instance == vrf), None)
            if family is None:
                family = s.RIPFamily(afi='ipv4', network_instance=vrf)
                collection(proc, 'address_families').append(family)
            family_idx = (proc.address_families or []).index(family)
            
            # Interface settings on the address family
            iface_items = collection(family, 'interface_settings')
            obj = next((i for i in iface_items if i.interface == interface.name), None)
            if obj is None:
                obj = s.RIPInterfaceSettings(interface=interface.name)
                iface_items.append(obj)
            path = f'{proc_path}/address_families/{family_idx}/interface_settings/{(iface_items or []).index(obj)}'
        else:
            # Global: interface settings on the process
            iface_items = collection(proc, 'interface_settings')
            obj = next((i for i in iface_items if i.interface == interface.name), None)
            if obj is None:
                obj = s.RIPInterfaceSettings(interface=interface.name)
                iface_items.append(obj)
            path = f'{proc_path}/interface_settings/{(iface_items or []).index(obj)}'
        
        return obj, path
    else:
        # No declared RIP process: use generic interface_authentication
        auth_items = collection(state.c.routing, 'interface_authentication')
        obj = next((i for i in auth_items if i.interface == interface.name and i.protocol == 'rip' and i.network_instance == interface.vrf), None)
        if obj is None:
            obj = s.InterfaceRoutingAuthentication(interface=interface.name, protocol='rip', network_instance=interface.vrf)
            auth_items.append(obj)
        path = f'routing/interface_authentication/{(auth_items or []).index(obj)}'
        return obj, path


def local_interface(state, record, owner, path):
    rule, v = record['rule'], record['values']
    removed = v.get('removed', False)
    if 'auth' in rule:
        previous = owner.authentication
        data = previous.model_dump(mode='python') if previous is not None else {}
        if 'chain' in rule:
            # For remove rules, the key_chain name may not be in values
            # (Cisco 'no ip rip authentication key-chain' doesn't include name)
            # So we get it from previous state if available
            ref = None if removed else v.get('key_chain')
            if removed and previous is not None:
                # Get the key_chain_reference from previous state
                removed_key = previous.key_chain_reference
                data.update(key_chain_setting='removed',
                            key_chain_reference=None,
                            removed_key_chain_reference=removed_key)
            else:
                data.update(key_chain_setting='removed' if removed else 'configured',
                            key_chain_reference=None if removed else v.get('key_chain'),
                            removed_key_chain_reference=None if not removed else v.get('key_chain'))
        else:
            mode = v.get('mode', 'text')
            data.update(mode_setting='removed' if removed else 'configured',
                        method=None if removed else 'message_digest' if mode == 'md5' else 'plaintext',
                        algorithm='md5' if mode == 'md5' else None)
        owner.authentication = s.RoutingAuthentication(**data)
    publish(state, path, record)


def publish(state, path, record):
    pointer = '/' + path.strip('/')
    valid = {p for p, _ in leaves(at(state.c, pointer), pointer)}
    state.bindings[:] = [b for b in state.bindings if not b.path.startswith(pointer + '/') or b.path in valid]
    for key in record['values']:
        state.validation[record['source_line']]['fields'][key] = 'validated'
    state.bind(pointer, record['source_line'], list(record['values']))


def handle(state, r):
    rule, v, line = (r['rule'], r['values'], r['source_line'])
    root = state.root(r)
    contexts = [state.nodes[n].text for n in r['context_lines']]
    def put(obj, field, value, path):
        state.assign(obj, field, value, path, line, list(v))
        for key in v:
            state.validation[line]['fields'][key] = 'validated'
    def bind(path):
        state.bind(path, line, list(v))
        for key in v: state.validation[line]['fields'][key] = 'validated'
    if rule.startswith('catalogue_rip'):
        if rule != 'catalogue_rip' and (not root or root['rule'] != 'catalogue_rip'):
            return True
        if rule == 'catalogue_rip' and contexts:
            return True
        if rule == 'catalogue_rip_family' and contexts != ['router rip']:
            return True
        if rule not in ('catalogue_rip', 'catalogue_rip_family') and (not (contexts == ['router rip'] or (len(contexts) == 2 and contexts[0] == 'router rip' and (state.records.get(r['context_lines'][-1], {}).get('rule') == 'catalogue_rip_family')))):
            return True
        if not (state.c.routing.rip or []):
            collection(state.c.routing, 'rip').append(s.RIPProcess(declared=True))
        proc = (state.c.routing.rip or [])[0]
        obj = proc
        path = 'routing/rip/0'
        family = r if rule == 'catalogue_rip_family' else next((state.records[n] for n in reversed(r['context_lines']) if state.records.get(n, {}).get('rule') == 'catalogue_rip_family'), None)
        if family:
            f = family['values']
            obj = next((x for x in (proc.address_families or []) if x.afi == f['afi'] and x.network_instance == f['vrf']), None)
            if obj is None:
                obj = s.RIPFamily(afi=f['afi'], network_instance=f['vrf'])
                collection(proc, 'address_families').append(obj)
            path += f'/address_families/{(proc.address_families or []).index(obj)}'
        if rule == 'catalogue_rip':
            put(proc, 'declared', v['declared'], 'routing/rip/0')
        elif rule == 'catalogue_rip_family':
            bind(path)
        elif rule == 'catalogue_rip_network':
            collection(obj, 'network_statements').append(IPv4Address(v['network']))
            bind(path + '/network_statements')
        elif rule == 'catalogue_rip_no_summary':
            put(obj, 'auto_summary', v['enabled'], path)
        elif rule == 'catalogue_rip_redistribute':
            collection(obj, 'redistributions').append(s.RIPRedistribution(protocol='bgp', source_bgp_as=asn(v['local_as']), metric=v['metric']))
            bind(path + '/redistributions')
        return True
    if rule.startswith('auth_if_rip_'):
        obj, path = _rip_interface_target(state, r)
        if obj:
            local_interface(state, r, obj, path)
        return True
    return False

