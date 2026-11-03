"""Qualified static address translations; unsupported NAT forms stay unknown."""
from ipaddress import IPv4Address
from normalizer.common.collections import collection
from schemas.router_contract_v1 import NATRule


def handle(state, record):
    if record['rule'] != 'services_nat_static':
        return
    values = record['values']
    collection(state.c.nat, 'rules').append(NATRule(type='static', source_match=str(IPv4Address(values['inside'])), translated_source=str(IPv4Address(values['outside']))))
    state.bind(f'nat/rules/{len((state.c.nat.rules or [])) - 1}', record['source_line'])
