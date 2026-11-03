"""Canonical BGP processes, neighbors, groups and address-family scopes."""
from . import authentication
from ipaddress import IPv4Address, ip_address, ip_network
from normalizer.common.collections import collection
from schemas import router_contract_v1 as s
from normalizer.common.addresses import asn, prefix_length


def process(state, r):
    family = r['values'] if r['rule'].startswith('bgp_af') and 'afi' in r['values'] else state.af(r)
    root = r if r['rule'] == 'bgp_header' else state.root(r)
    local = asn(root['values']['local_as'])
    obj = next((p for p in (state.c.routing.bgp or []) if p.local_as == local and p.network_instance is None), None)
    if obj is None:
        obj = s.BGPProcess(local_as=local)
        collection(state.c.routing, 'bgp').append(obj)
        path = f'routing/bgp/{(state.c.routing.bgp or []).index(obj)}'
        state.bind(path + '/local_as', root['source_line'], list(root['values']))
    return obj, f'routing/bgp/{(state.c.routing.bgp or []).index(obj)}', family


def family(proc, values):
    obj = next((a for a in (proc.address_families or []) if a.afi == values['afi'] and a.safi == values.get('safi') and a.network_instance == values.get('vrf')), None)
    if obj is None:
        obj = s.BGPAddressFamily(afi=values['afi'], safi=values.get('safi'), network_instance=values.get('vrf'))
        collection(proc, 'address_families').append(obj)
    return obj


def declare(state, r):
    if r['rule'] != 'bgp_header':
        return False
    process(state, r)
    return True


def peer(state, r, proc, path, af):
    value = r['values']['peer']
    try:
        identity, kind = str(ip_address(value)), 'neighbor'
    except ValueError:
        identity, kind = value, 'group'
        if not any(rec['root_line'] == r['root_line'] and rec['rule'] == 'bgp_group_definition' and rec['values']['peer'] == value for rec in state.records.values()):
            raise ValueError('A native peer identity cannot be guessed to be a group')
    if af:
        owner = family(proc, af)
        items = collection(owner, 'peers')
        path += f'/address_families/{(proc.address_families or []).index(owner)}/peers'
        obj = next((p for p in items if p.peer == identity and p.kind == kind), None)
        if obj is None:
            obj = s.BGPPeer(peer=identity, kind=kind)
            items.append(obj)
    elif kind == 'group':
        items = collection(proc, 'peer_groups')
        path += '/peer_groups'
        obj = next((p for p in items if p.name == identity), None)
        if obj is None:
            obj = s.BGPPeerGroup(name=identity)
            items.append(obj)
    else:
        items = collection(proc, 'neighbors')
        path += '/neighbors'
        obj = next((p for p in items if p.peer == identity), None)
        if obj is None:
            obj = s.BGPNeighbor(peer=identity, kind=kind)
            items.append(obj)
    return obj, path + f'/{items.index(obj)}'


def handle(state, r):
    proc, path, af = process(state, r)
    values, rule, line = r['values'], r['rule'], r['source_line']
    if rule.startswith('auth_bgp_'):
        authentication.bgp(state, r, proc, path, peer)
        return
    if rule.startswith('bgp_af'):
        if 'afi' not in values:
            state.structural.add(line)
            return
        obj = family(proc, values)
        state.bind(path + f'/address_families/{(proc.address_families or []).index(obj)}', line, list(values))
        return
    if rule == 'bgp_router_id':
        state.assign(proc, 'router_id', IPv4Address(values['router_id']), path, line)
        return
    if rule == 'bgp_group_definition':
        # Declaration is global to this process. Address-family options live separately.
        obj = next((g for g in (proc.peer_groups or []) if g.name == values['peer']), None)
        if obj is None:
            obj = s.BGPPeerGroup(name=values['peer'])
            collection(proc, 'peer_groups').append(obj)
        state.bind(path + f'/peer_groups/{(proc.peer_groups or []).index(obj)}/name', line)
        return
    options = family(proc, af) if af else proc
    option_path = path + f'/address_families/{(proc.address_families or []).index(options)}' if af else path
    flags = {'bgp_log_changes': 'log_neighbor_changes', 'bgp_compare_med': 'compare_med', 'bgp_deterministic_med': 'deterministic_med',
        'bgp_no_default_ipv4': 'default_ipv4_unicast', 'bgp_no_sync': 'synchronization', 'bgp_no_auto_summary': 'auto_summary', 'bgp_no_enforce_first_as': 'enforce_first_as'}
    if rule in flags:
        if af and rule not in ('bgp_no_sync', 'bgp_no_auto_summary'):
            return
        if af and (len(r['context_lines']) != 2 or not state.nodes[r['context_lines'][-1]].text.startswith('address-family ')):
            return
        state.assign(options, flags[rule], values['enabled'], option_path, line, list(values))
        return
    if rule == 'bgp_dampening':
        state.assign(options, 'dampening', values['enabled'], option_path, line, list(values))
    elif rule == 'bgp_additional_select':
        state.assign(options, 'additional_paths_selection', values['selection'], option_path, line, list(values))
    elif rule == 'bgp_additional_send':
        if {values['send'], values['receive']} != {'send', 'receive'}:
            raise ValueError('Additional paths flags')
        state.assign(options, 'additional_paths_send', True, option_path, line, list(values))
        state.assign(options, 'additional_paths_receive', True, option_path, line, list(values))
    elif rule == 'bgp_maximum_paths':
        collection(options, 'maximum_paths').append(s.MaximumPaths(type=values['type'], count=values['count']))
        state.bind(option_path + '/maximum_paths', line, list(values))
    elif rule == 'bgp_aggregate':
        prefix = ip_network(values['prefix'] + '/' + str(prefix_length(values['mask'])), strict=False)
        collection(proc, 'aggregates').append(s.Aggregate(prefix=prefix, options=values['option'].split(), afi=af.get('afi') if af else None, safi=af.get('safi') if af else None, network_instance=af.get('vrf') if af else None))
        state.validation[line]['fields']['option'] = 'validated'
        state.bind(path + '/aggregates', line, list(values))
    elif rule.startswith('bgp_redistribute'):
        collection(proc, 'redistributions').append(s.Redistribution(protocol=values['protocol'], process=values.get('process'), route_map=values.get('policy'), afi=af.get('afi') if af else None, safi=af.get('safi') if af else None, network_instance=af.get('vrf') if af else None))
        state.bind(path + '/redistributions', line, list(values))
    elif rule in ('bgp_network', 'bgp_network4'):
        if 'mask' in values:
            prefix = ip_network(values['prefix'] + '/' + str(prefix_length(values['mask'])), strict=False)
        elif '/' in values['prefix']:
            prefix = ip_network(values['prefix'], strict=False)
        else:
            address = IPv4Address(values['prefix'])
            first = int(str(address).split('.')[0])
            length = 8 if 1 <= first <= 126 else 16 if 128 <= first <= 191 else 24 if 192 <= first <= 223 else None
            if length is None:
                raise ValueError('Unsupported classful network')
            prefix = ip_network(f'{address}/{length}', strict=True)
        collection(proc, 'networks').append(s.BGPNetwork(prefix=prefix, afi=af.get('afi') if af else ('ipv4' if prefix.version == 4 else 'ipv6'), safi=af.get('safi') if af else None, network_instance=af.get('vrf') if af else None))
        state.bind(path + '/networks', line, list(values))
    elif rule in PEER_RULES:
        if rule in ('bgp_advertise_additional', 'catalogue_allowas'):
            contexts = r['context_lines']
            if len(contexts) != 1 and not (len(contexts) == 2 and state.nodes[contexts[-1]].text.startswith('address-family ')):
                return
        if rule in ('bgp_shutdown', 'bgp_no_shutdown') and af:
            return
        obj, peer_path = peer(state, r, proc, path, af)
        if rule == 'bgp_remote_as':
            fields = {'remote_as': asn(values['remote_as'])}
        elif rule == 'bgp_route_map':
            fields = {'import_policies' if values['direction'] == 'in' else 'export_policies': [values['policy']]}
        elif rule in ('bgp_send_community', 'bgp_send_community_option'):
            fields = {'send_community': 'command_without_option' if values['option'] == 'unspecified' else values['option']}
        elif rule == 'catalogue_allowas':
            if values['count_unspecified'] is not True:
                raise ValueError('Unsupported allowas variant')
            fields = {'allowas_in': s.AllowASIn(enabled=True)}
        else:
            target, source = PEER_RULES[rule]
            fields = {target: values[source]}
        for field, value in fields.items():
            setattr(obj, field, value)
        state.bind(peer_path, line, list(values))


PEER_RULES = {
    'bgp_remote_as': None, 'bgp_route_map': None, 'bgp_send_community': None, 'bgp_send_community_option': None, 'catalogue_allowas': None,
    'bgp_description': ('description', 'description'), 'bgp_group_member': ('inherited_group', 'group'),
    'bgp_update_source': ('update_source', 'source'), 'bgp_activate': ('active', 'enabled'), 'bgp_deactivate': ('active', 'enabled'),
    'bgp_shutdown': ('enabled', 'enabled'), 'bgp_no_shutdown': ('enabled', 'enabled'), 'bgp_reflector': ('route_reflector_client', 'enabled'),
    'bgp_next_hop': ('next_hop_self', 'enabled'), 'bgp_advertise_additional': ('additional_paths_advertise_selection', 'selection'),
}
