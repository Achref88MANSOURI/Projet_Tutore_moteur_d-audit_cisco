"""Tunnel endpoints and explicit interface references within the same VRF."""
from ipaddress import ip_address
from schemas.normalized_config import VPNTunnel


def ensure_tunnel(state, interface, line):
    obj = next((t for t in state.c.vpn_tunnels if t.identifier == interface.name), None)
    if obj is None:
        obj = VPNTunnel(identifier=interface.name, tunnel_interface=interface.name, network_instance=interface.vrf)
        state.c.vpn_tunnels.append(obj)
        path = f'vpn_tunnels/{len(state.c.vpn_tunnels) - 1}'
        state.bind(path + '/identifier', state.nodes[line].root)
        state.bind(path + '/tunnel_interface', state.nodes[line].root)
    return obj


def handle(state, record):
    if len(record['context_lines']) != 1:
        return
    entry = state.entity(record['source_line'])
    if not entry or entry[0].kind != 'tunnel':
        return
    interface = entry[0]
    if record['rule'] == 'if_tunnel_source':
        state.defer(record)
        return
    obj = ensure_tunnel(state, interface, record['source_line'])
    path = f'vpn_tunnels/{state.c.vpn_tunnels.index(obj)}'
    state.assign(obj, 'remote_endpoint', str(ip_address(record['values']['destination'])), path, record['source_line'])


def resolve(state, record):
    interface = state.entity(record['source_line'])[0]
    value = record['values']['source']
    try:
        value = str(ip_address(value))
    except ValueError:
        source = next((i for i in state.c.interfaces if i.name == value and i.vrf == interface.vrf), None)
        if source is None or len(source.ipv4_addresses) != 1:
            return
        value = str(source.ipv4_addresses[0].address)
    obj = ensure_tunnel(state, interface, record['source_line'])
    state.assign(obj, 'local_endpoint', value, f'vpn_tunnels/{state.c.vpn_tunnels.index(obj)}', record['source_line'])
