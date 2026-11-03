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
    rule = record['rule']
    if rule == 'if_tunnel_source':
        state.defer(record)
        return
    obj = ensure_tunnel(state, interface, record['source_line'])
    path = f'vpn/tunnels/{(state.c.vpn.tunnels or []).index(obj)}'
    if rule == 'if_tunnel_destination':
        state.assign(obj, 'remote_endpoint', str(ip_address(record['values']['destination'])), path, record['source_line'])
    elif rule == 'if_tunnel_mode':
        state.assign(obj, 'mode', record['values']['mode'], path, record['source_line'])
    elif rule == 'if_tunnel_mode_off':
        obj.mode = None
        state.unbind(path + '/mode')
    elif rule == 'if_tunnel_protection':
        state.assign(obj, 'ipsec_profile_reference', record['values']['profile'], path, record['source_line'])
        # Set technology to ipsec when protection is configured
        if obj.technology == 'unknown':
            obj.technology = 'ipsec'
            state.bind(path + '/technology', record['source_line'])
    elif rule == 'if_tunnel_protection_off':
        obj.ipsec_profile_reference = None
        state.unbind(path + '/ipsec_profile_reference')
    elif rule == 'if_tunnel_path_mtu':
        # path-mtu-discovery enable|disable
        # Not directly modeled in VPNTunnel, could add if needed
        pass
    elif rule == 'if_tunnel_path_mtu_off':
        pass


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