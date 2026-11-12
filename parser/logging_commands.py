"""Decode arguments captured by TTP; retain target identity on unsupported updates.

No defaults, DNS resolution or operational state is inferred here. Bounded port
conversion deliberately runs after the greedy capture, so malformed rewrites
can revoke an earlier fact instead of silently preserving it.
"""
from ipaddress import ip_address
import re


def target(values):
    tokens = str(values.get('target', values.get('address', ''))).split()
    ipv6 = bool(tokens and tokens[0] == 'ipv6')
    if ipv6: tokens.pop(0)
    if not tokens: return {'supported': False}
    address = tokens.pop(0)
    try:
        ip = ip_address(address)
        address = str(ip)
        valid = not ipv6 or ip.version == 6
    except ValueError:
        address = address.lower()
        labels = address.removesuffix('.').split('.')
        valid = (len(address) <= 254 and not re.fullmatch(r'[0-9.]+', address)
                 and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in labels))
    result = {'address': address, 'supported': bool(valid)}
    seen = set()
    while tokens:
        key = tokens.pop(0)
        if key not in ('vrf', 'transport', 'port') or key in seen or not tokens:
            result['supported'] = False
            break
        seen.add(key)
        value = tokens.pop(0)
        if key == 'transport':
            if value == 'beep':
                pass  # Valid IOS transport absent from V1's enum; address remains a witness.
            elif value not in ('udp', 'tcp'): result['supported'] = False
            else: result[key] = value
        elif key == 'port':
            if not value.isascii() or not value.isdigit() or len(value) > 5 or not 1 <= int(value) <= 65535 or 'transport' not in seen:
                result['supported'] = False
            else: result[key] = int(value)
        else:
            result[key] = value
    return result
