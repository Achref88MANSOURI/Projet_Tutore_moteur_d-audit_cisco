"""Ordered IPv4/IPv6 prefix lists with explicit length bounds."""
from ipaddress import ip_network
from normalizer.common.collections import collection
from schemas import router_contract_v1 as s


def handle(state,r):
    v = r['values']
    family = 'ipv6' if r['rule'].startswith('prefix_ipv6') else 'ipv4'
    entry = s.PrefixListEntry(sequence=v.get('sequence'), action=v['action'], prefix=ip_network(v['prefix'], strict=False), ge=v.get('ge'), le=v.get('le'))
    obj = next((p for p in (state.c.routing_policies.prefix_lists or []) if p.name == v['name'] and p.family == family), None)
    if obj is None:
        obj = s.PrefixList(name=v['name'], family=family)
        collection(state.c.routing_policies, 'prefix_lists').append(obj)
    if entry.sequence is not None and any((e.sequence == entry.sequence for e in (obj.entries or []))):
        raise ValueError('Duplicate prefix sequence')
    collection(obj, 'entries').append(entry)
    s.PrefixList.model_validate(obj.model_dump(mode='json'))
    state.bind(f'routing_policies/prefix_lists/{(state.c.routing_policies.prefix_lists or []).index(obj)}', r['source_line'], list(v))

