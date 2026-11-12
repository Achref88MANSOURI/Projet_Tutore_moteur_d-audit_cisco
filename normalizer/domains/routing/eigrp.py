"""Direct EIGRP mappings, preserving classic/named, AF, topology and local scopes."""
from ipaddress import ip_address, IPv4Address
from normalizer.common.collections import collection
from normalizer.common.configured import leaves
from normalizer.common.contexts import at
from parser.eigrp_commands import metric, redistribution, stub, summary
from schemas import router_contract_v1 as s


def publish(state, path, record):
    pointer = '/' + path.strip('/')
    valid = {p for p, _ in leaves(at(state.c, pointer), pointer)}
    state.bindings[:] = [b for b in state.bindings if not b.path.startswith(pointer + '/') or b.path in valid]
    for key in record['values']:
        state.validation[record['source_line']]['fields'][key] = 'validated'
    state.bind(pointer, record['source_line'], list(record['values']))


def declare(state, record):
    values = record['values']
    if record['rule'] == 'eigrp_header6':
        payload = dict(mode='classic', afi='ipv6', autonomous_system=values['autonomous_system'])
    elif values['identifier'].isdigit():
        payload = dict(mode='classic', afi='ipv4', autonomous_system=int(values['identifier']))
    else:
        payload = dict(mode='named', name=values['identifier'])
    items = collection(state.c.routing, 'eigrp')
    process = next((p for p in items if all(getattr(p, k) == v for k, v in payload.items())), None)
    if process is None:
        process = s.EIGRPProcess(**payload); items.append(process)
    path = 'routing/eigrp/' + str(items.index(process))
    state.entities[record['source_line']] = path
    publish(state, path, record)
    return True


def af_record(state, record):
    candidates = [record] + [state.records[n] for n in reversed(record['context_lines']) if n in state.records]
    return next((r for r in candidates if r['rule'].startswith('eigrp_af_') and not r['rule'].startswith('eigrp_af_interface')), None)


def target(state, record):
    root = state.root(record)
    if root is None or root['rule'] not in ('eigrp_header', 'eigrp_header6'):
        raise ValueError('Missing explicit EIGRP process')
    path = state.entities[root['source_line']]
    process = at(state.c, path); owner = process; afi = process.afi
    family = af_record(state, record)
    if family is not None:
        known = state.entities.get(family['source_line'])
        if known is None:
            v = family['values']; items = collection(process, 'address_families')
            matching = [f for f in items if (f.afi, f.safi, f.network_instance) == (v['afi'], v.get('safi'), v.get('vrf'))
                        and (v.get('autonomous_system') is None or f.autonomous_system == v['autonomous_system'])]
            if len(matching) > 1:
                raise ValueError('EIGRP AF context cannot be guessed')
            if matching:
                owner = matching[0]
            else:
                owner = s.EIGRPAddressFamily(afi=v['afi'], safi=v.get('safi'), network_instance=v.get('vrf'), autonomous_system=v.get('autonomous_system'))
                items.append(owner)
            known = path + '/address_families/' + str(items.index(owner))
            state.entities[family['source_line']] = known
        owner, path = at(state.c, known), known
        afi = owner.afi
    context = next((r for r in [record] + [state.records[n] for n in reversed(record['context_lines']) if n in state.records]
                    if r['rule'] in ('eigrp_topology', 'eigrp_topology_named', 'eigrp_af_interface')), None)
    if context is not None:
        v = context['values']
        if context['rule'] == 'eigrp_af_interface':
            items = collection(owner, 'interface_settings')
            item = next((i for i in items if i.interface == v['interface']), None)
            if item is None:
                item = s.EIGRPInterfaceSettings(interface=v['interface']); items.append(item)
            path += '/interface_settings/' + str(items.index(item))
        else:
            items = collection(owner, 'topologies')
            item = next((i for i in items if (i.name, i.identifier) == (v['name'], v.get('topology_id'))), None)
            if item is None:
                item = s.EIGRPTopology(name=v['name'], identifier=v.get('topology_id')); items.append(item)
            path += '/topologies/' + str(items.index(item))
        owner = item
    return owner, path, afi


def marker(owner, field, removed, collection_field='removed_settings'):
    current = getattr(owner, collection_field)
    values = [v for v in current or [] if v != field]
    if removed: values.append(field)
    setattr(owner, collection_field, values or None)


def local_interface(state, record, owner, path):
    rule, v = record['rule'], record['values']
    removed = v.get('removed', False)
    if 'auth' in rule:
        previous = owner.authentication
        data = previous.model_dump(mode='python') if previous is not None else {}
        if 'key_chain' in rule:
            # For remove rules, the key_chain name may not be in values (Cisco 'no authentication key-chain' doesn't include name)
            # So we clear the reference regardless of the name
            ref = None if removed else v.get('key_chain')
            data.update(key_chain_setting='removed' if removed else 'configured',
                        key_chain_reference=ref,
                        removed_key_chain_reference=v.get('key_chain') if removed else None)
        else:
            data.update(mode_setting='removed' if removed else 'configured',
                        method=None if removed else 'hmac-sha-256' if rule == 'eigrp_authentication_sha' else 'md5',
                        secret_configured=None if removed else True if 'secret_configured' in v else None,
                        credential_format=None if removed else v.get('credential_format'))
        owner.authentication = s.EIGRPAuthentication(**data)
    elif 'summary' in rule:
        data = summary(v); items = collection(owner, 'summaries')
        item = s.EIGRPSummary(**data)
        found = next((n for n, old in enumerate(items) if old.prefix == item.prefix), len(items))
        if found == len(items): items.append(item)
        else: items[found] = item
    else:
        for field in ('enabled', 'passive', 'split_horizon', 'next_hop_self', 'hello_interval_seconds', 'hold_time_seconds', 'bandwidth_percent'):
            if field in v or removed and field.replace('_seconds', '') in rule:
                setattr(owner, field, None if removed else v[field])
                if field in ('hello_interval_seconds', 'hold_time_seconds', 'bandwidth_percent'):
                    marker(owner, field, removed)
    publish(state, path, record)


def resolve(state, record):
    interface, _ = state.entity(record['source_line'])
    if not isinstance(interface, s.Interface):
        return
    v = record['values']; rule = record['rule']
    if rule in ('eigrp_if_bandwidth', 'eigrp_if_bandwidth_remove', 'eigrp_if_delay', 'eigrp_if_delay_remove'):
        field = 'bandwidth_kbps' if 'bandwidth' in rule else 'delay_tens_of_microseconds'
        removed = v.get('removed', False)
        setattr(interface, field, None if removed else v['interface_' + field])
        marker(interface, field, removed, 'removed_metric_settings')
        _, path = state.entity(record['source_line'])
        publish(state, path, record)
        return
    afi = 'ipv6' if '6' in rule else 'ipv4'
    items = collection(state.c.routing, 'eigrp_interfaces')
    identity = (interface.name, afi, v['autonomous_system'], interface.vrf)
    obj = next((i for i in items if (i.interface, i.afi, i.autonomous_system, i.network_instance) == identity), None)
    if obj is None:
        obj = s.EIGRPClassicInterface(interface=identity[0], afi=afi, autonomous_system=identity[2], network_instance=identity[3])
        items.append(obj)
    path = 'routing/eigrp_interfaces/' + str(items.index(obj))
    local_interface(state, record, obj, path)


def handle(state, record):
    rule, v = record['rule'], record['values']
    if rule.startswith('eigrp_if_'):
        state.defer(record); return
    if rule.startswith('eigrp_exit_'):
        state.structural.add(record['source_line']); return
    if rule == 'eigrp_af_interface_remove':
        from normalizer.common.collections import owned_entries, publish_entries
        owner,path,_=target(state,record)
        if isinstance(owner,s.EIGRPAddressFamily):
            field_path=path+'/interface_settings'
            entries=owned_entries(state,owner,'interface_settings',field_path)
            publish_entries(state,owner,'interface_settings',field_path,
                [(item,owners) for item,owners in entries if item.interface!=v['interface']])
        return
    owner, path, afi = target(state, record)
    if isinstance(owner, s.EIGRPInterfaceSettings):
        local_interface(state, record, owner, path); return
    if rule.startswith('eigrp_af_') or rule.startswith('eigrp_topology'):
        pass  # A block declaration preserves its explicit identity, not defaults.
    elif rule == 'eigrp_autonomous_system':
        owner.autonomous_system = v['autonomous_system']
    elif rule.startswith('eigrp_network'):
        item = s.EIGRPNetworkStatement(address=v['address'], wildcard_mask=v.get('wildcard_mask'))
        items = collection(owner, 'networks')
        if item not in items: items.append(item)
    elif rule == 'eigrp_neighbor':
        address = ip_address(v['address'])
        if address.version != (4 if afi == 'ipv4' else 6):
            raise ValueError('EIGRP neighbor family differs from its context')
        collection(owner, 'neighbors').append(s.EIGRPNeighbor(address=address, interface=v['interface']))
    elif rule in ('eigrp_passive', 'eigrp_active'):
        enabled = rule == 'eigrp_passive'
        if v['interface'] == 'default': owner.passive_default = enabled
        else:
            items = collection(owner, 'passive_interfaces')
            item = s.EIGRPPassiveInterface(interface=v['interface'], passive=enabled)
            n = next((n for n, old in enumerate(items) if old.interface == item.interface), len(items))
            if n == len(items): items.append(item)
            else: items[n] = item
    elif rule.startswith('eigrp_stub'):
        owner.stub = s.EIGRPStub(enabled=rule != 'eigrp_stub_remove', **stub(v.get('options', '')))
    elif rule.startswith('eigrp_router_id'):
        removed = rule.endswith('_remove')
        owner.router_id = None if removed else IPv4Address(v['router_id'])
        marker(owner, 'router_id', removed, 'removed_instance_settings')
    elif rule.startswith('eigrp_metric_weights'):
        removed = rule.endswith('_remove')
        owner.metric_weights = None if removed else s.EIGRPMetricWeights(**{k: v[k] for k in ('tos', 'k1', 'k2', 'k3', 'k4', 'k5', 'k6') if k in v})
        marker(owner, 'metric_weights', removed, 'removed_instance_settings')
    elif rule.startswith('eigrp_redistribute'):
        data = redistribution(v)
        if afi == 'ipv4' and data['protocol'] == 'rip' and data.get('process') is not None:
            raise ValueError('IPv4 RIP redistribution has no named process')
        collection(owner, 'redistributions').append(s.EIGRPRedistribution(**data))
    elif rule.startswith('eigrp_filter'):
        if v.get('interface') is not None and '/address_families/' in path and '/topologies/' not in path:
            raise ValueError('Distribute-list interface operand is not valid in classic AF mode')
        kind = 'route_map' if 'route_map' in rule else 'prefix_list' if 'prefix' in rule else 'acl'
        item = s.EIGRPFilter(kind=kind, reference=v['reference'], direction=v['direction'], interface=v.get('interface'), local_setting='removed' if v.get('removed') else 'configured')
        items = collection(owner, 'filters')
        n = next((n for n, old in enumerate(items) if (old.kind, old.reference, old.direction, old.interface) == (item.kind, item.reference, item.direction, item.interface)), len(items))
        if n == len(items): items.append(item)
        else: items[n] = item
    elif rule.startswith('eigrp_distance'):
        removed = v.get('removed', False)
        owner.internal_distance = None if removed else v['internal_distance']
        owner.external_distance = None if removed else v['external_distance']
        marker(owner, 'distance', removed)
    elif rule.startswith('eigrp_default_metric'):
        removed = v.get('removed', False)
        owner.default_metric = None if removed else s.EIGRPMetric(**metric(v))
        marker(owner, 'default_metric', removed)
    elif rule.startswith(('eigrp_timers_active_time', 'eigrp_active_time_disabled')):
        removed = v.get('removed', False)
        owner.active_time_minutes = None if removed or v.get('disabled') else v['active_time_minutes']
        owner.active_time_disabled = True if v.get('disabled') else None
        marker(owner, 'active_time', removed)
    elif rule.startswith('eigrp_shutdown_'):
        owner.enabled = v['enabled']
    elif rule.startswith('eigrp_auto_summary') and afi != 'ipv4':
        return
    else:
        for field in ('variance', 'maximum_paths', 'maximum_hops'):
            prefix = 'eigrp_metric_' if field == 'maximum_hops' else 'eigrp_'
            if rule in (prefix + field, prefix + field + '_remove'):
                removed = v.get('removed', False)
                setattr(owner, field, None if removed else v[field])
                marker(owner, field, removed)
                break
        for field in ('auto_summary', 'log_neighbor_changes'):
            if field in v:
                setattr(owner, field, v[field])
    publish(state, path, record)
