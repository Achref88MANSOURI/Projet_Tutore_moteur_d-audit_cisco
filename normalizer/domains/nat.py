"""Qualified static address translations; unsupported NAT forms stay unknown."""
from ipaddress import IPv4Address
from schemas.normalized_config import NATRule


def handle(state, record):
    if record['rule'] != 'services_nat_static':
        return
    values = record['values']
    state.c.nat.append(NATRule(type='static', source_match=str(IPv4Address(values['inside'])), translated_source=str(IPv4Address(values['outside']))))
    state.bind(f'nat/{len(state.c.nat) - 1}', record['source_line'])
