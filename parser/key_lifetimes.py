"""Validate non-secret IOS key lifetime operands; no wall-clock inference."""
import re
from datetime import datetime

MONTHS = {name: i for i, name in enumerate(('jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'), 1)}


def validate(specification):
    tokens = specification.split()
    if tokens and tokens[0] == 'local':
        tokens.pop(0)
    def date():
        if len(tokens) < 4 or re.fullmatch(r'\d{1,2}:\d{2}:\d{2}', tokens[0]) is None:
            raise ValueError('Unsupported lifetime timestamp')
        time, first, second, year = [tokens.pop(0) for _ in range(4)]
        if first.lower() in MONTHS:
            month, day = MONTHS[first.lower()], int(second)
        else:
            month, day = MONTHS[second.lower()], int(first)
        hour, minute, sec = map(int, time.split(':'))
        return datetime(int(year), month, day, hour, minute, sec)
    try:
        start = date()
        if start.year < 1993:
            raise ValueError('Lifetime predates IOS supported epoch')
        if tokens == ['infinite']:
            return
        if len(tokens) == 2 and tokens[0] == 'duration' and tokens[1].isdigit() and 1 <= int(tokens[1]) <= 2147483646:
            return
        end = date()
        if tokens or end <= start:
            raise ValueError('Lifetime ordering')
    except (KeyError, IndexError, TypeError) as exc:
        raise ValueError('Invalid lifetime') from exc
