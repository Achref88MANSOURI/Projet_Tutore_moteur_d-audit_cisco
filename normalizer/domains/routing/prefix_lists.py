"""Ordered IPv4/IPv6 prefix lists with explicit length bounds."""
from ipaddress import ip_network
from schemas import normalized_config as s


def handle(state,r):
    v = r['values']
    family = 'ipv6' if r['rule'].startswith('prefix_ipv6') else 'ipv4'
    entry = s.PrefixListEntry(sequence=v.get('sequence'), action=v['action'], prefix=ip_network(v['prefix'], strict=False), ge=v.get('ge'), le=v.get('le'))
    obj = next((p for p in state.c.routing.prefix_lists if p.name == v['name'] and p.family == family), None)
    if obj is None:
        obj = s.PrefixList(name=v['name'], family=family)
        state.c.routing.prefix_lists.append(obj)
    if entry.sequence is not None and any((e.sequence == entry.sequence for e in obj.entries)):
        raise ValueError('Duplicate prefix sequence')
    obj.entries.append(entry)
    s.PrefixList.model_validate(obj.model_dump(mode='json'))
    state.bind(f'routing/prefix_lists/{state.c.routing.prefix_lists.index(obj)}', r['source_line'], list(v))

