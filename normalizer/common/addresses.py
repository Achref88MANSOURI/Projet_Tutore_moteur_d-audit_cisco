"""Address, ASN and VLAN conversions shared by parser validation and domains."""
from ipaddress import IPv4Address

def asn(value):
    parts = str(value).split('.')
    number = int(parts[0]) if len(parts) == 1 else int(parts[0]) * 65536 + int(parts[1])
    if len(parts) > 2 or not 1 <= number <= 4294967295 or (len(parts) == 2 and any((not 0 <= int(x) <= 65535 for x in parts))):
        raise ValueError('Invalid ASN')
    return number

def prefix_length(mask):
    number = int(IPv4Address(mask))
    inverse = number ^ 4294967295
    if inverse & inverse + 1:
        raise ValueError('Non-contiguous subnet mask')
    return 32 - inverse.bit_length()

def vlan_set(expression):
    if expression == 'all':
        return list(range(1, 4095))
    if expression == 'none':
        return []
    result = set()
    for part in expression.split(','):
        ends = part.split('-')
        if len(ends) > 2:
            raise ValueError('Invalid VLAN range')
        low, high = (int(ends[0]), int(ends[-1]))
        if not 1 <= low <= high <= 4094:
            raise ValueError('Invalid VLAN range')
        result.update(range(low, high + 1))
    return sorted(result)

def flat_official(value):
    if isinstance(value, list):
        for child in value:
            yield from flat_official(child)
    elif isinstance(value, dict):
        yield value

def area_id(value):
    return str(IPv4Address(int(value))) if str(value).isdigit() else str(IPv4Address(value))
