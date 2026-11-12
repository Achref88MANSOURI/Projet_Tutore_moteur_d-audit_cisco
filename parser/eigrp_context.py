"""Immediate IOS/IOS-XE EIGRP contexts; no inheritance across unknown blocks."""
import re
from .inventory import ancestors

AF = re.compile(r'address-family (ipv4|ipv6)(?: (unicast|multicast))?(?: vrf (\S+))?(?: autonomous-system (\d+))?')
IF = re.compile(r'(?:default|[A-Za-z][A-Za-z-]*\s*\d[\w./:-]*)')


def header(text):
    match = re.fullmatch(r'ipv6 router eigrp (\d+)', text)
    if match:
        return 'classic', 'ipv6'
    match = re.fullmatch(r'router eigrp ([\w.-]+)', text)
    if not match or re.fullmatch(r'-\d+|\d+\.\d+', match[1]):
        return None
    return ('classic', 'ipv4') if match[1].isdigit() else ('named', None)


def allowed(rule, node, nodes, values):
    if rule == 'policy_set_eigrp_metric':
        parents = ancestors(node, nodes)
        return len(parents) == 1 and parents[0].text.startswith('route-map ')
    if not rule.startswith('eigrp_'):
        return True
    parents = ancestors(node, nodes)
    if rule.startswith('eigrp_if_'):
        return len(parents) == 1 and parents[0].text.startswith('interface ')
    if rule in ('eigrp_header', 'eigrp_header6'):
        return not parents and header(node.text) is not None
    if not parents or not (root := header(parents[0].text)):
        return False
    mode, afi = root
    af = AF.fullmatch(parents[1].text) if len(parents) > 1 else None
    if len(parents) > 1:
        if not af or mode == 'named' and af[4] is None:
            return False
        if mode == 'classic' and (afi == 'ipv6' or af[1] != 'ipv4'):
            return False
        afi = af[1]
        if afi == 'ipv6' and af[2] == 'multicast':
            return False
    direct = len(parents) == 1 and mode == 'classic' or len(parents) == 2 and af is not None
    interface_block = re.fullmatch(r'af-interface (.+)', parents[2].text) if len(parents) == 3 else None
    af_interface = interface_block is not None and IF.fullmatch(interface_block[1]) is not None
    topology = len(parents) == 3 and re.fullmatch(r'topology (?:base|\S+ tid \d+)', parents[2].text) is not None
    if len(parents) > 3:
        return False
    if rule == 'eigrp_af_interface':
        return len(parents) == 2 and af is not None and IF.fullmatch(values['interface']) is not None
    if rule == 'eigrp_af_interface_remove':
        return len(parents) == 2 and af is not None and IF.fullmatch(values['interface']) is not None
    if rule.startswith('eigrp_af_interface_auth_'):
        return af_interface or (len(parents) >= 2 and af is not None)
    if rule.startswith('eigrp_af_') and rule != 'eigrp_af_interface':
        target = AF.fullmatch(node.text)
        return len(parents) == 1 and target is not None and (
            mode == 'named' and target[4] is not None or
            mode == 'classic' and root[1] == 'ipv4' and target[1] == 'ipv4') and not (target[1] == 'ipv6' and target[2] == 'multicast')
    if rule.startswith('eigrp_topology'):
        return len(parents) == 2 and af is not None
    if rule.startswith('eigrp_exit_'):
        return len(parents) <= 2
    if rule == 'eigrp_autonomous_system':
        return mode == 'classic' and len(parents) == 2 and af is not None
    if rule.startswith('eigrp_shutdown_'):
        return af_interface or len(parents) == 2 and af is not None or len(parents) == 1 and (mode == 'named' or afi == 'ipv6')
    if any(rule.startswith('eigrp_' + key) for key in ('authentication_', 'hello_interval', 'hold_time', 'bandwidth_percent', 'split_horizon_', 'next_hop_self_', 'summary', 'interface_passive')):
        if rule.startswith('eigrp_summary') and ('summary4' in rule) != (afi == 'ipv4'):
            return False
        return af_interface
    if rule.startswith(('eigrp_passive', 'eigrp_active')) and not rule.startswith('eigrp_active_time'):
        return mode == 'classic' and direct
    if rule.startswith('eigrp_network'):
        return afi == 'ipv4' and (direct or topology)
    if rule.startswith(('eigrp_router_id', 'eigrp_metric_weights', 'eigrp_stub', 'eigrp_eigrp_log_', 'eigrp_log_neighbor', 'eigrp_neighbor')):
        if rule == 'eigrp_metric_weights6' and mode != 'named':
            return False
        return direct
    if rule.startswith('eigrp_auto_summary') and afi != 'ipv4':
        return False
    if rule.startswith('eigrp_filter'):
        if 'acl' in rule and afi == 'ipv6':
            return False
        if 'prefix_list' in rule and afi != 'ipv6' or 'prefix' in rule and 'prefix_list' not in rule and afi != 'ipv4':
            return False
        if values.get('interface') and len(parents) == 2:
            return False
        if 'route_map' in rule and afi == 'ipv6' and not topology:
            return False
    return topology or mode == 'classic' and direct
