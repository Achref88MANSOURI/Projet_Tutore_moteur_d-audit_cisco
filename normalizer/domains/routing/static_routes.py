"""Static IPv4/IPv6 routes and next-hop validation."""
from ipaddress import IPv4Network, ip_address, ip_network
from normalizer.common.collections import collection
from schemas import router_contract_v1 as s
from normalizer.common.addresses import prefix_length


def handle(state,r):
    v, line = (r['values'], r['source_line'])
    ipv6 = r['rule'].startswith('route_ipv6')
    if ipv6:
        destination = ip_network(v['destination'], strict=False)
        if destination.version != 6:
            raise ValueError('Wrong route family')
    else:
        destination = IPv4Network(v['destination'] + '/' + str(prefix_length(v['mask'])), strict=False)
    interface, hop = (v.get('interface'), v['hop'])
    try:
        hop = str(ip_address(hop))
    except ValueError:
        if interface is not None or not any((c.isdigit() for c in hop)):
            raise ValueError('Invalid route next-hop')
        interface, hop = (hop, None)
    route = s.StaticRoute(destination=destination, next_hop=hop, outgoing_interface=interface, network_instance=v.get('vrf'), admin_distance=v.get('distance'), description=v.get('name'))
    collection(state.c.routing, 'static_routes').append(route)
    state.bind(f'routing/static_routes/{len((state.c.routing.static_routes or [])) - 1}', line)

