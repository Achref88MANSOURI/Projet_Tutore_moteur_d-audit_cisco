"""Literal ACL operands, ordered entries and port constraints."""
from ipaddress import ip_address, ip_network, IPv4Address
from schemas import normalized_config as s


def acl_operand(value):
    tokens = value.split()
    if tokens[0] in ('any', 'any4', 'any6'):
        result = {'kind': 'any'}
        if tokens[0] != 'any':
            result['address_family'] = 'ipv4' if tokens[0] == 'any4' else 'ipv6'
        return result
    if tokens[0] == 'host':
        return {'kind': 'host', 'address': str(ip_address(tokens[1]))}
    if tokens[0] == 'object-group':
        return {'kind': 'object_group', 'name': tokens[1]}
    if len(tokens) == 2:
        return {'kind': 'wildcard', 'address': str(IPv4Address(tokens[0])), 'wildcard_mask': str(IPv4Address(tokens[1]))}
    if '/' in value:
        return {'kind': 'prefix', 'prefix': str(ip_network(value, strict=False))}
    return {'kind': 'host', 'address': str(ip_address(value))}


def port(value):
    if not value:
        return None
    tokens = value.split()
    aliases = {'ssh': 22, 'telnet': 23, 'www': 80, 'http': 80, 'https': 443, 'domain': 53, 'bgp': 179, 'snmp': 161, 'snmptrap': 162, 'ntp': 123}
    def number(token):
        return int(token) if token.isdigit() else aliases[token]
    return s.PortMatch(operator=tokens[0], start=number(tokens[1]), end=number(tokens[2]) if tokens[0] == 'range' else None)


def handle(state, r):
    values, line = r['values'], r['source_line']
    root = state.root(r)
    name = values.get('name') or values.get('acl_name') or (root or {}).get('values', {}).get('name')
    if not name:
        return
    family = 'ipv6' if root and root['rule'] == 'acl_header_ipv6' else 'ipv4'
    obj = next((a for a in state.c.security.acl_sets if a.name == name and a.family == family), None)
    if obj is None:
        obj = s.ACLSet(name=name, family=family)
        state.c.security.acl_sets.append(obj)
    path = f'security/acl_sets/{state.c.security.acl_sets.index(obj)}'
    state.bind(path + '/name', line)
    state.bind(path + '/family', line)
    if r['rule'].startswith('acl_header'):
        return
    options = values.get('options')
    if options not in (None, 'log', 'log-input'):
        return
    entry = s.ACLEntry(sequence=values.get('sequence'), action=values['action'], protocol=values.get('protocol'),
        source=acl_operand(values['source']), destination=acl_operand(values['destination']) if values.get('destination') else None,
        source_port=port(values.get('source_port')), destination_port=port(values.get('destination_port')), log=True if options else None)
    if entry.sequence is not None and any(e.sequence == entry.sequence for e in obj.entries):
        raise ValueError('Duplicate ACL sequence')
    obj.entries.append(entry)
    state.bind(path + f'/entries/{len(obj.entries) - 1}', line)
