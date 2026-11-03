"""Tunnel endpoints and explicit interface references within the same VRF."""
from ipaddress import ip_address
from normalizer.common.collections import collection
from schemas.router_contract_v1 import VPNTunnel


def ensure_tunnel(state, interface, line):
    obj = next((t for t in (state.c.vpn.tunnels or []) if t.identifier == interface.name), None)
    if obj is None:
        obj = VPNTunnel(technology='unknown', identifier=interface.name, tunnel_interface=interface.name, network_instance=interface.vrf)
        collection(state.c.vpn, 'tunnels').append(obj)
        path = f'vpn/tunnels/{len((state.c.vpn.tunnels or [])) - 1}'
        state.bind(path + '/identifier', state.nodes[line].root)
        state.bind(path + '/tunnel_interface', state.nodes[line].root)
        state.bind(path + '/technology', state.nodes[line].root)
        if interface.vrf is not None:
            state.bind(path + '/network_instance', line)
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
    path = f'vpn/tunnels/{(state.c.vpn.tunnels or []).index(obj)}'
    state.assign(obj, 'remote_endpoint', str(ip_address(record['values']['destination'])), path, record['source_line'])


def resolve(state, record):
    interface = state.entity(record['source_line'])[0]
    value = record['values']['source']
    obj = ensure_tunnel(state, interface, record['source_line'])
    path = f'vpn/tunnels/{(state.c.vpn.tunnels or []).index(obj)}'
    try:
        value = str(ip_address(value))
    except ValueError:
        state.assign(obj, 'local_source_interface', value, path, record['source_line'])
        source = next((i for i in (state.c.interfaces or []) if i.name == value and i.vrf == interface.vrf), None)
        if source is None or len((source.ipv4.addresses or []) or []) != 1:
            return
        value = str((source.ipv4.addresses or [])[0].address)
    state.assign(obj, 'local_endpoint', value, path, record['source_line'])
