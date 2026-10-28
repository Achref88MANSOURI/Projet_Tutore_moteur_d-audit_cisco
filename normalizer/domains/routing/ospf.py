"""Versioned OSPF processes, areas, interface participation and redistribution."""
from ipaddress import IPv4Address,IPv4Network
from schemas import normalized_config as s
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
    proc = next((p for p in state.c.routing.ospf if p.identifier == rv['process'] and p.version == version and (p.network_instance == rv.get('vrf'))), None)
    if proc is None:
        proc = s.OSPFProcess(identifier=rv['process'], version=version, network_instance=rv.get('vrf'))
        state.c.routing.ospf.append(proc)
    path = f'routing/ospf/{state.c.routing.ospf.index(proc)}'
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
        obj = next((a for a in proc.areas if a.area_id == area), None)
        if obj is None:
            obj = s.OSPFArea(area_id=area)
            proc.areas.append(obj)
        obj.type = v['type']
        state.bind(path + '/areas', line, list(v))
    elif rule == 'ospf_virtual_link':
        proc.virtual_links.append(s.VirtualLink(area=v['area'], peer_router_id=v['peer']))
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
        proc.redistributions.append(s.Redistribution(protocol=v['protocol'], process=process, subnets=subnets, route_map=route_map))
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
        mask = str(IPv4Address(int(IPv4Address(v['wildcard'])) ^ 4294967295))
        prefix = str(IPv4Network(v['address'] + '/' + str(prefix_length(mask)), strict=False))
        area = area_id(v['area'])
        proc.network_statements.append(s.OSPFNetworkStatement(prefix=prefix, area=area))
        state.bind(path + f'/network_statements/{len(proc.network_statements) - 1}', line)
    elif rule == 'ospf_passive' and v['interface'] != 'default':
        proc.passive_interfaces.append(v['interface'])
        state.bind(path + f'/passive_interfaces/{len(proc.passive_interfaces) - 1}', line)


def declare(state,r):
    if r["rule"] not in ("ospf_header","ospf_header_vrf"):return False
    handle(state,r)
    state.entities[r["source_line"]]=f"routing/ospf/{len(state.c.routing.ospf)-1}"
    return True
