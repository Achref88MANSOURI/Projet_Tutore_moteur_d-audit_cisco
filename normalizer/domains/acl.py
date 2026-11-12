"""Literal ACL operands, ordered entries and port constraints."""
from ipaddress import ip_address, ip_network, IPv4Address
from normalizer.common.collections import collection, owned_entries, publish_entries
from schemas import router_contract_v1 as s


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
    if r['rule'] in ('acl_no_extended','services_acl_no_extended','acl_no_numbered','services_acl_no_numbered'):
        entries=[entry for entry in owned_entries(state,state.c.security,'acls','security/acls') if not (entry[0].name==name and entry[0].family==family)]
        publish_entries(state,state.c.security,'acls','security/acls',entries)
        return
    obj = next((a for a in (state.c.security.acls or []) if a.name == name and a.family == family), None)
    if obj is None:
        obj = s.ACLSet(name=name, family=family)
        collection(state.c.security, 'acls').append(obj)
    path = f'security/acls/{(state.c.security.acls or []).index(obj)}'
    state.bind(path + '/name', line)
    state.bind(path + '/family', line)
    rule = r['rule']
    if rule.startswith('acl_header'):
        return
    if rule in ('acl_remark', 'services_acl_remark', 'services_acl_remark_no_seq'):
        # Remark entries don't have action/protocol, store as description in a special entry
        # We store it as a special entry with action='remark'
        remark_entry = s.ACLEntry(
            sequence=values.get('sequence'),
            action='remark',
            description=values.get('text')
        )
        if remark_entry.sequence is not None and any(e.sequence == remark_entry.sequence for e in (obj.entries or [])):
            raise ValueError('Duplicate ACL sequence')
        collection(obj, 'entries').append(remark_entry)
        state.bind(path + f'/entries/{len((obj.entries or [])) - 1}', line)
        return
    if rule in ('acl_resequence', 'services_acl_resequence'):
        # Resequence is a metadata operation - store the parameters
        state.bind(path + '/resequence_start', line)
        state.bind(path + '/resequence_increment', line)
        return
    if rule in ('acl_no_seq', 'services_acl_no_seq'):
        # Remove ACE by sequence number
        seq = values.get('sequence')
        entries = obj.entries or []
        for i, e in enumerate(entries):
            if e.sequence == seq:
                del entries[i]
                state.unbind(f'{path}/entries/{i}')
                break
        return
    if rule in ('acl_no_ace', 'acl_no_ace_options', 'services_acl_no_ace', 'services_acl_no_ace_options'):
        # Remove ACE by matching action, protocol, source, destination (and options)
        action = values.get('action')
        protocol = values.get('protocol')
        source = values.get('source')
        destination = values.get('destination')
        options = values.get('options')
        entries = obj.entries or []
        for i, e in enumerate(entries):
            if (e.action == action and e.protocol == protocol and
                str(e.source) == str(acl_operand(source)) and
                (destination is None or str(e.destination) == str(acl_operand(destination))) and
                (options is None or 'options' not in values or values.get('options') == options)):
                del entries[i]
                state.unbind(f'{path}/entries/{i}')
                break
        return
    if rule in ('acl_no_extended', 'services_acl_no_extended'):
        # Remove entire named extended ACL
        acls = state.c.security.acls or []
        for i, a in enumerate(acls):
            if a.name == name and a.family == family:
                del acls[i]
                state.unbind(f'{path}')
                break
        return
    if rule in ('acl_no_numbered', 'services_acl_no_numbered'):
        # Remove entire numbered ACL
        acls = state.c.security.acls or []
        for i, a in enumerate(acls):
            if a.name == name and a.family == family:
                del acls[i]
                state.unbind(f'{path}')
                break
        return
    options = values.get('options')
    tokens = options.split() if options else []
    # Check for supported option combinations
    valid_tokens = set()
    time_range = None
    i = 0
    while i < len(tokens):
        if tokens[i] == 'log':
            valid_tokens.add('log')
            i += 1
        elif tokens[i] == 'log-input':
            valid_tokens.add('log-input')
            i += 1
        elif tokens[i] == 'established':
            valid_tokens.add('established')
            i += 1
        elif tokens[i] == 'fragments':
            valid_tokens.add('fragments')
            i += 1
        elif tokens[i] == 'time-range' and i + 1 < len(tokens):
            time_range = tokens[i + 1]
            i += 2
        else:
            i += 1
    if len(valid_tokens) != len(tokens) - (2 if time_range else 0):
        # Unsupported option combination - reject this ACE
        return
    if 'established' in valid_tokens and values.get('protocol') not in ('tcp', '6'):
        return
    if options is not None:
        state.validation[line]['fields']['options'] = 'validated'
    entry = s.ACLEntry(sequence=values.get('sequence'), action=values['action'], protocol=values.get('protocol'),
        source=acl_operand(values['source']), destination=acl_operand(values['destination']) if values.get('destination') else None,
        source_port=port(values.get('source_port')), destination_port=port(values.get('destination_port')),
        log=True if 'log' in valid_tokens else None, log_input=True if 'log-input' in valid_tokens else None,
        tcp_established=True if 'established' in valid_tokens else None,
        fragments=True if 'fragments' in valid_tokens else None,
        time_range=time_range)
    if entry.sequence is not None and any(e.sequence == entry.sequence for e in (obj.entries or [])):
        raise ValueError('Duplicate ACL sequence')
    collection(obj, 'entries').append(entry)
    state.bind(path + f'/entries/{len((obj.entries or [])) - 1}', line)
