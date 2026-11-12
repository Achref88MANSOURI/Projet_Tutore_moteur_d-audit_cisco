"""Bounded partitions of captured management-line identities, not a CLI parser.

All declaration boundaries are known before applying properties. Every native
range addresses a set of non-overlapping V1 objects; existing property handlers
then run in source order on those objects. No device inventory is inferred.
"""
from bisect import bisect_left
from collections import defaultdict
from dataclasses import dataclass
import re


MAX_ORDINAL = 2**31 - 1  # Representation bound, not a Cisco hardware limit.
MAX_SEGMENTS = 10000
MAX_TARGET_LINKS = 100000


@dataclass(frozen=True)
class Interval:
    kind: str
    first: int
    last: int


def identity(name):
    """Validate a captured identity without expanding its physical line count."""
    match = re.fullmatch(r'(vty|tty|aux|con|console)[ \t]+([0-9]{1,10})(?:[ \t]+([0-9]{1,10}))?', name)
    if match is None:
        raise ValueError('Unsupported management-line identity')
    kind = 'con' if match[1] == 'console' else match[1]
    first, last = int(match[2]), int(match[3] or match[2])
    if first > last or last > MAX_ORDINAL or kind in ('con', 'aux') and match[3] is not None:
        raise ValueError('Invalid management-line bounds')
    return Interval(kind, first, last)


class LineIntervals:
    def __init__(self, records, validation):
        self.targets = {}
        self.names = {}
        grouped = defaultdict(list)
        for line, record in sorted(records.items()):
            if record['rule'] != 'services_line':
                continue
            try:
                if record['context_lines'] or not validation[line]['valid']:
                    raise ValueError('Invalid line context')
                span = identity(record['values']['name'])
            except (ValueError, KeyError, TypeError):
                validation[line] = dict(valid=False, invalid_fields=list(record['values']),
                                        fields={k: 'invalid' for k in record['values']})
                continue
            # Canonicalize decimal spelling and spacing, without guessing an
            # absolute/relative line table or changing console/con aliases.
            tokens = record['values']['name'].split()
            native = tokens[0] + ' ' + ' '.join(str(int(token)) for token in tokens[1:])
            grouped[span.kind].append((line, span, native))
        links = 0
        for kind, headers in grouped.items():
            changes = defaultdict(int)
            for _, span, _ in headers:
                changes[span.first] += 1
                changes[span.last + 1] -= 1
            boundaries = sorted(changes)
            coverage = 0
            segments = []
            for start, end in zip(boundaries, boundaries[1:]):
                coverage += changes[start]
                if coverage:
                    segments.append(Interval(kind, start, end - 1))
            if len(self.names) + len(segments) > MAX_SEGMENTS:
                raise ValueError('Management-line partition limit exceeded')
            starts = [span.first for span in segments]
            for line, original, native in headers:
                a, b = bisect_left(starts, original.first), bisect_left(starts, original.last + 1)
                selected = tuple(segments[a:b])
                links += len(selected)
                if links > MAX_TARGET_LINKS:
                    raise ValueError('Management-line target limit exceeded')
                self.targets[line] = selected
                for span in selected:
                    # Preserve original spellings for unchanged identities. A
                    # derived segment is a native range expression, not a claim
                    # that this exact header appeared in the source document.
                    self.names.setdefault(span, native if span == original else
                                          f'{kind} {span.first}' + (f' {span.last}' if span.last != span.first else ''))
        self.paths = {}

