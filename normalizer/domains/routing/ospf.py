"""Versioned OSPF processes, areas, interface participation and redistribution."""
from . import authentication
from ipaddress import IPv4Address,IPv4Network
from normalizer.common.collections import collection
from schemas import router_contract_v1 as s
from normalizer.common.addresses import prefix_length, area_id

def handle(state, r):
    root = state.root(r)
    if not root or root['rule'] not in ('ospf_header', 'ospf_header_vrf', 'ospf3_header'):
        return
    version = 3 if root['rule'] == 'ospf3_header' else 2
    rv = root['values']
    v = r['values']
    line = r['source_line']
    rule = r['rule']
    proc = next((p for p in (state.c.routing.ospf or []) if p.identifier == rv['process'] and p.version == version and (p.network_instance == rv.get('vrf'))), None)
    if proc is None:
        proc = s.OSPFProcess(identifier=rv['process'], version=version, network_instance=rv.get('vrf'))
        collection(state.c.routing, 'ospf').append(proc)
    path = f'routing/ospf/{(state.c.routing.ospf or []).index(proc)}'
    if rule.startswith('auth_ospf_'):
        authentication.ospf_area(state, r, proc, path)
        return
    if rule in ('ospf_header', 'ospf_header_vrf', 'ospf3_header'):
        state.bind(path, line, list(v))
    elif rule == 'ospf_router_id':
        state.assign(proc, 'router_id', IPv4Address(v['router_id']), path, line, list(v))
    elif rule == 'ospf_log':
        state.assign(proc, 'log_adjacency_changes', v['enabled'], path, line, list(v))
    elif rule == 'ospf_area':
        if v['type'] not in ('stub', 'nssa', 'normal'):
            raise ValueError('Area type')
        area = area_id(v['area'])
        obj = next((a for a in (proc.areas or []) if a.area_id == area), None)
        if obj is None:
            obj = s.OSPFArea(area_id=area)
            collection(proc, 'areas').append(obj)
        obj.type = v['type']
        state.bind(path + '/areas', line, list(v))
    elif rule == 'ospf_virtual_link':
        collection(proc, 'virtual_links').append(s.VirtualLink(area=area_id(v['area']), peer_router_id=v['peer']))
        state.bind(path + '/virtual_links', line, list(v))
    elif rule in ('ospf_redistribute', 'ospf_redistribute_simple'):
        options = v.get('options', '').split()
        process = None
        subnets = None
        route_map = None
        if options and options[0].isdigit():
            process = options.pop(0)
        if 'subnets' in options:
            subnets = True
            options.remove('subnets')
        if len(options) == 2 and options[0] == 'route-map':
            route_map = options[1]
            options = []
        if options:
            raise ValueError('Unparsed redistribution qualifier')
        collection(proc, 'redistributions').append(s.Redistribution(protocol=v['protocol'], process=process, subnets=subnets, route_map=route_map))
        if 'options' in v:
            state.validation[line]['fields']['options'] = 'validated'
        state.bind(path + '/redistributions', line, list(v))
    elif rule == 'ospf_default':
        if v['options'] != 'always':
            raise ValueError('Unparsed default origination option')
        proc.default_origination = s.DefaultOrigination(enabled=True, always=True)
        state.validation[line]['fields']['options'] = 'validated'
        state.bind(path + '/default_origination', line, list(v))
    if rule == 'ospf_network':
        wildcard = IPv4Address(v['wildcard'])
        mask = int(wildcard) ^ 0xffffffff
        bits = f'{mask:032b}'
        prefix = None if '01' in bits else IPv4Network(f"{v['address']}/{bits.count('1')}", strict=False)
        collection(proc, 'network_statements').append(s.OSPFNetworkStatement(
            prefix=prefix, area=area_id(v['area']), address=v['address'], wildcard_mask=wildcard))
        state.bind(path + f'/network_statements/{len((proc.network_statements or [])) - 1}', line)
    elif rule in ('ospf_passive', 'ospf_no_passive'):
        if v['interface'] == 'default':
            state.assign(proc, 'passive_default', rule == 'ospf_passive', path, line)
        else:
            field = 'passive_interfaces' if rule == 'ospf_passive' else 'non_passive_interfaces'
            opposite = 'non_passive_interfaces' if rule == 'ospf_passive' else 'passive_interfaces'
            previous = getattr(proc, opposite)
            if previous and v['interface'] in previous:
                state.unbind(path + '/' + opposite)
                remaining = [name for name in previous if name != v['interface']]
                setattr(proc, opposite, remaining or None)
                if remaining:
                    state.bind(path + '/' + opposite, line)
            items = collection(proc, field)
            if v['interface'] not in items:
                items.append(v['interface'])
            state.bind(path + '/' + field, line)



def declare(state,r):
    if r["rule"] not in ("ospf_header","ospf_header_vrf"):return False
    handle(state,r)
    state.entities[r["source_line"]]=f"routing/ospf/{len((state.c.routing.ospf or []))-1}"
    return True
