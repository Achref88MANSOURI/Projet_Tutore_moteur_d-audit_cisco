"""Reduce captured object generations before the two-pass mapper.

Only TTP facts and validated identities are consumed here. Retired commands
remain in the original extraction/provenance inventory; they own no live facts.
"""
from normalizer.common.addresses import asn
from parser.validation import validate_record


def identity(record):
    rule, v = record['rule'], record['values']
    if rule in ('eigrp_header', 'lifecycle_eigrp'):
        return ('eigrp', v['identifier'])
    if rule in ('eigrp_header6', 'lifecycle_eigrp6'):
        return ('eigrp6', v['autonomous_system'])
    if rule in ('ospf_header', 'ospf_header_vrf', 'lifecycle_ospf', 'lifecycle_ospf_vrf'):
        return ('ospf', str(v['process']), v.get('vrf'))
    if rule in ('ospf3_header', 'lifecycle_ospf6'):
        return ('ospf6', str(v['process']))
    if rule in ('bgp_header', 'lifecycle_bgp'):
        try:
            return ('bgp', asn(v['local_as']))
        except ValueError:
            return None
    if rule in ('catalogue_rip', 'lifecycle_rip'):
        return ('rip',)
    if rule in ('if_header', 'lifecycle_interface', 'lifecycle_interface_default'):
        return ('interface', v['name'])
    if rule in ('auth_key_chain', 'lifecycle_key_chain'):
        return ('key_chain', v['name'])
    return None


def family(record):
    v = record['values']
    return (v['afi'], v.get('safi') or 'unicast', v.get('vrf'), v.get('autonomous_system'))


def prepare(records):
    active, retired, events = {}, set(), {}
    for line, record in sorted(records.items()):
        rule, v = record['rule'], record['values']
        if rule == 'eigrp_af_interface_remove':
            root = records.get(record['root_line'])
            parent = identity(root) if root else None
            scope = next((records[n] for n in record['context_lines'] if 'afi' in records.get(n, {}).get('values', {})), None)
            events[line] = ('reset', rule, (*parent, 'address_family', *family(scope)) if parent and scope else parent)
            if parent and scope and len(record['context_lines']) == 2 and validate_record(record)['valid']:
                # Retire removed AF-interface generations before mapping, just
                # like parent/AF deletion. Unbinding later must not relabel the
                # retired authentication commands as current coverage gaps.
                for old_line, old in list(active.items()):
                    old_root = records.get(old['root_line'])
                    old_af = next((records[n] for n in old['context_lines']
                                   if 'afi' in records.get(n, {}).get('values', {})), None)
                    old_interface = next((records[n] for n in [old_line, *old['context_lines']]
                                          if records.get(n, {}).get('rule') == 'eigrp_af_interface'), None)
                    if (old_root and identity(old_root) == parent and old_af and family(old_af) == family(scope)
                            and old_interface and old_interface['values']['interface'] == v['interface']):
                        retired.add(old_line)
                        del active[old_line]
                        events.pop(old_line, None)
        if not rule.startswith('lifecycle_'):
            active[line] = record
            continue
        valid = validate_record(record)['valid']
        contexts = record['context_lines']
        root = records.get(record['root_line'])
        # Restrict removal commands to their exact immediate Cisco context.
        child = rule == 'lifecycle_key' or '_af' in rule or rule.startswith('lifecycle_bgp_') or '_network' in rule
        scoped_network = '_network' in rule and rule.startswith('lifecycle_eigrp')
        if not valid or (len(contexts) not in (1, 2) if scoped_network else len(contexts) != 1 if child else bool(contexts)):
            active[line] = record
            events[line] = ('unsupported', rule, None)
            continue
        target = identity(record)
        if rule == 'lifecycle_interface':
            name = v['name'].lower()
            if '.' not in name and not name.startswith(('tunnel', 'loopback', 'vlan', 'port-channel', 'virtual-template')):
                active[line] = record
                events[line] = ('platform_dependent', rule, target)
                continue
        parent = identity(root) if root else None
        if rule.startswith('lifecycle_eigrp_af_legacy') and (parent is None or not str(parent[1]).isdigit()):
            active[line] = record
            events[line] = ('unsupported', rule, parent)
            continue
        def matches(old):
            old_root = records.get(old['root_line'])
            old_parent = identity(old_root) if old_root else None
            if target is not None:
                return old_parent == target
            if old_parent != parent:
                return False
            if rule == 'lifecycle_key':
                return any(records.get(n, {}).get('rule') == 'auth_key_id' and records[n]['values']['key_id'] == v['key_id']
                           for n in [old['source_line'], *old['context_lines']])
            if rule in ('lifecycle_bgp_neighbor', 'lifecycle_bgp_group', 'lifecycle_bgp_member'):
                # Global neighbor deletion removes all its AF contributions.
                return old['values'].get('peer') == v['peer']
            if rule == 'lifecycle_bgp_template':
                return any(records.get(n, {}).get('rule') == 'bgp_session_template' and records[n]['values']['name'] == v['name']
                           for n in [old['source_line'], *old['context_lines']])
            if '_network' in rule:
                if scoped_network:
                    old_af = next((records[n] for n in old['context_lines'] if 'afi' in records.get(n, {}).get('values', {})), None)
                    this_af = next((records[n] for n in contexts if 'afi' in records.get(n, {}).get('values', {})), None)
                    if (family(old_af) if old_af else None) != (family(this_af) if this_af else None):
                        return False
                if not old['rule'].startswith(('eigrp_network', 'ospf_network')):
                    return False
                if rule == 'lifecycle_ospf_network':
                    from normalizer.common.addresses import area_id
                    return (old['values'].get('address') == v['address'] and old['values'].get('wildcard') == v['wildcard'] and
                            area_id(old['values']['area']) == area_id(v['area']))
                return old['values'].get('address') == v['address'] and old['values'].get('wildcard_mask') == v.get('wildcard_mask')
            if '_af' in rule:
                return any('afi' in records.get(n, {}).get('values', {}) and
                           family(records[n]) == family(record)
                           for n in [old['source_line'], *old['context_lines']])
            return False
        for old_line, old in list(active.items()):
            if not old['rule'].startswith('lifecycle_') and matches(old):
                retired.add(old_line)
                del active[old_line]
                events.pop(old_line, None)
        # default interface retains a fresh identity, with no assumed defaults.
        if rule == 'lifecycle_interface_default':
            active[line] = {**record, 'rule': 'if_header', 'values': {'name': v['name']}}
        else:
            active[line] = record
        events[line] = ('reset' if rule.endswith('_default') else 'removed', rule, target or parent)
    return active, retired, events


def handle(state, record):
    """Deletion facts are public, explicit and cannot serve as active objects."""
    from normalizer.common.collections import collection
    from schemas.router_contract_v1 import ConfigurationChange
    line = record['source_line']
    operation, kind, target = state.lifecycle_events[line]
    changes = collection(state.c, 'configuration_changes')
    changes.append(ConfigurationChange(operation=operation, kind=kind, identity=[str(v) for v in target] if target else None,
                                       selector=record['values']))
    state.bind(f'configuration_changes/{len(changes)-1}', line)
