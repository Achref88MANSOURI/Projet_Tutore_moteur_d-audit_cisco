"""Strict validation of supported EIGRP operands, without secrets or defaults."""
from ipaddress import IPv4Address, ip_address, ip_network
from .eigrp_context import IF


def bounded(value, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError('EIGRP numeric operand outside documented bounds')


def metric(values):
    names = ('bandwidth', 'delay', 'reliability', 'load', 'mtu')
    limits = (4294967295, 4294967295, 255, 255, 65535)
    for name, maximum in zip(names, limits):
        bounded(values[name], 0, maximum)
    return dict(zip(('bandwidth_kbps', 'delay_tens_of_microseconds', 'reliability', 'load', 'mtu'), (values[n] for n in names)))


def stub(options):
    words = options.split()
    data = {}; routes = []
    while words:
        word = words.pop(0)
        if word in ('connected', 'static', 'summary', 'redistributed') and word not in routes:
            routes.append(word)
        elif word == 'receive-only' and not data.get('receive_only'):
            data['receive_only'] = True
        elif word == 'leak-map' and words and 'leak_map' not in data:
            data['leak_map'] = words.pop(0)
        else:
            raise ValueError('Unsupported or repeated EIGRP stub option')
    if data.get('receive_only') and (routes or data.get('leak_map')):
        raise ValueError('Receive-only is exclusive')
    if routes:
        data['route_types'] = routes
    return data


def redistribution(values):
    protocol = values['protocol']; words = values.get('options', '').split()
    data = dict(protocol=protocol)
    if words and words[0] not in ('metric', 'route-map'):
        if protocol in ('connected', 'static') or words[0].startswith('level-'):
            raise ValueError('Unsupported redistribution scope')
        data['process'] = words.pop(0)
    if protocol in ('bgp', 'ospf', 'eigrp'):
        token = data.get('process', '')
        if protocol == 'bgp':
            parts = token.split('.')
            if len(parts) == 2:
                if any(not p.isdigit() or not 0 <= int(p) <= 65535 for p in parts):
                    raise ValueError('Invalid source AS')
                bounded(int(parts[0]) * 65536 + int(parts[1]), 1, 4294967295)
            elif token.isdigit():
                bounded(int(token), 1, 4294967295)
            else:
                raise ValueError('Invalid source AS')
        elif not token.isdigit() or not 1 <= int(token) <= 65535:
            raise ValueError('Invalid source process')
    while words:
        keyword = words.pop(0)
        if keyword == 'metric' and 'metric' not in data and len(words) >= 5:
            tokens, words = words[:5], words[5:]
            if not all(t.isdigit() for t in tokens):
                raise ValueError('Invalid composite metric')
            data['metric'] = metric(dict(zip(('bandwidth', 'delay', 'reliability', 'load', 'mtu'), map(int, tokens))))
        elif keyword == 'route-map' and words and 'route_map' not in data:
            data['route_map'] = words.pop(0)
        else:
            raise ValueError('Unsupported redistribution option; never publish a partial rule')
    return data


def summary(values):
    if 'prefix' in values:
        prefix = ip_network(values['prefix'], strict=False)
        if prefix.version != 6:
            raise ValueError('IPv6 summary expected')
    else:
        prefix = ip_network(values['address'] + '/' + values['mask'], strict=False)
        if prefix.version != 4:
            raise ValueError('IPv4 summary expected')
    data = dict(prefix=prefix)
    words = values.get('options', '').split()
    if words and words[0].isdigit():
        data['admin_distance'] = int(words.pop(0)); bounded(data['admin_distance'], 0 if prefix.version == 6 else 1, 255)
    if words:
        if len(words) != 2 or words[0] != 'leak-map' or prefix.version != 4:
            raise ValueError('Unsupported EIGRP summary option')
        data['leak_map'] = words[1]
    data['local_setting'] = 'removed' if values.get('removed') else 'configured'
    return data


def validate(rule, values):
    if rule == 'policy_set_eigrp_metric':
        metric(values)
        return
    if not rule.startswith('eigrp_'):
        return
    for key in ('autonomous_system',):
        if key in values: bounded(values[key], 1, 65535)
    if rule == 'eigrp_header' and values['identifier'].isdigit():
        bounded(int(values['identifier']), 1, 65535)
    limits = {'variance': (1, 128), 'maximum_paths': (1, 64), 'maximum_hops': (1, 255),
              'internal_distance': (1, 255), 'external_distance': (1, 255),
              'active_time_minutes': (0, 65535), 'hello_interval_seconds': (1, 65535),
              'hold_time_seconds': (1, 65535), 'bandwidth_percent': (1, 999999), 'topology_id': (1, 255),
              'interface_bandwidth_kbps': (1, 10000000), 'interface_delay_tens_of_microseconds': (1, 16777215)}
    for key, bounds in limits.items():
        if key in values: bounded(values[key], *bounds)
    if 'interface' in values and IF.fullmatch(values['interface']) is None:
        raise ValueError('Unsupported EIGRP interface operand')
    if 'router_id' in values: IPv4Address(values['router_id'])
    if 'wildcard_mask' in values: IPv4Address(values['wildcard_mask'])
    if rule.startswith('eigrp_network'): IPv4Address(values['address'])
    if rule.startswith('eigrp_metric_weights') and not rule.endswith('_remove'):
        bounded(values['tos'], 0, 0)
        for key in ('k1', 'k2', 'k3', 'k4', 'k5', 'k6'):
            if key in values: bounded(values[key], 0, 255)
    if rule == 'eigrp_default_metric': metric(values)
    if rule.startswith('eigrp_redistribute'): redistribution(values)
    if 'summary' in rule and not 'auto_summary' in rule: summary(values)
    if rule == 'eigrp_stub_options': stub(values['options'])
    if rule == 'eigrp_topology_named' and values['name'] == 'base':
        raise ValueError('Base topology has no configured TID')
    if rule.startswith('eigrp_neighbor'): ip_address(values['address'])
