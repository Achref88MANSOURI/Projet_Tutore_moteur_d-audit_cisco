"""Disjoint inclusive intervals, with surviving contribution ownership."""
from .collections import owned_entries, publish_entries
from schemas.router_contract_v1 import NTPTrustedKey


def update(state, record):
    owner, path = state.c.system.ntp, 'system/ntp/trusted_keys'
    v, line = record['values'], record['source_line']
    removed = v.get('removed', False)
    lo, hi = (1, 65535) if record['rule'].endswith('_all') else (v.get('identifier', v.get('start')), v.get('identifier', v.get('end')))
    if not 1 <= lo <= hi <= 65535:
        raise ValueError('NTP trusted key interval')
    entries = []
    for item, owners in owned_entries(state, owner, 'trusted_keys', path):
        start, end = item.identifier, item.range_end or item.identifier
        surviving = [(start, end)] if end < lo or start > hi else [(start, min(end, lo - 1)), (max(start, hi + 1), end)]
        source = owners['identifier']
        for a, b in surviving:
            if a <= b:
                entries.append((NTPTrustedKey(identifier=a, range_end=b if a != b else None),
                                {'identifier': source, **({'range_end': owners.get('range_end', source)} if a != b else {})}))
    if not removed:
        entries.append((NTPTrustedKey(identifier=lo, range_end=hi if lo != hi else None),
                        {'identifier': line, **({'range_end': line} if lo != hi else {})}))
    entries.sort(key=lambda entry: entry[0].identifier)
    publish_entries(state, owner, 'trusted_keys', path, entries)
    if not entries:
        state.assign(owner, 'trusted_keys', [], 'system/ntp', line, explicit_empty=True)
    else:
        state.consumed[line].update(v)
        state.mapped.add(line)
