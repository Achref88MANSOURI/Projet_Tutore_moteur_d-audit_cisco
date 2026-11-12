"""Erase routing credentials before inventory, TTP, logs or official templates.

Only safe syntax and an irreversible presence marker cross the parser boundary.
No digest or identifier is derived from a secret.
"""
import re

MARKER = '__ROUTING_SECRET_PRESENT__'
UNSUPPORTED = '__ROUTING_SECRET_UNSUPPORTED_SYNTAX__'
PREFIXES = (
    (re.compile(r'^(?:no\s+)?authentication\s+mode\s+hmac-sha-256\s+', re.IGNORECASE), {'0', '7'}),
    (re.compile(r'^(?:no\s+)?neighbor\s+\S+\s+password\s+', re.IGNORECASE), {'0', '7'}),
    (re.compile(r'^(?:no\s+)?ip\s+ospf\s+authentication-key\s+', re.IGNORECASE), {'0', '7'}),
    # IOS accepts an optional 0/7 storage indicator before the OSPF MD5
    # secret.  Retain only that non-secret format token and replace the
    # credential itself before TTP sees the line.
    (re.compile(r'^(?:no\s+)?ip\s+ospf\s+message-digest-key\s+\S+\s+md5\s+', re.IGNORECASE), {'0', '7'}),
    (re.compile(r'^(?:no\s+)?(?:area-password|domain-password)\s+', re.IGNORECASE), set()),
    (re.compile(r'^(?:no\s+)?key-string\s+', re.IGNORECASE), {'0', '6', '7'}),
    (re.compile(r'^(?:no\s+)?ntp\s+authentication-key\s+\d+\s+md5\s+', re.IGNORECASE), {'0', '7'}),
)


def redact_routing_secrets(text):
    safe = []
    for raw in text.splitlines(keepends=True):
        line = raw.lstrip()
        indent = raw[:len(raw)-len(line)]
        ending = '\r\n' if raw.endswith('\r\n') else '\n' if raw.endswith('\n') else ''
        value = line.rstrip('\r\n')
        for pattern, formats in PREFIXES:
            match = pattern.match(value)
            if match is None:
                continue
            payload = value[match.end():].strip()
            if not payload:
                break
            if payload in (MARKER, UNSUPPORTED) or re.fullmatch(r'\d+ (?:' + MARKER + '|' + UNSUPPORTED + ')', payload):
                break  # Idempotent; never reinterpret our own presence marker.
            tokens = payload.split(maxsplit=1)
            # Retain an explicit numeric format, including unsupported ones so
            # that an unsupported type cannot match a bare-password rule.
            prefix = tokens[0] + ' ' if len(tokens) == 2 and tokens[0].isdigit() and formats else ''
            word_command = re.match(r'^(?:no\s+)?(?:ip\s+ospf\s+|area-password|domain-password)', value, re.IGNORECASE)
            secret_words = tokens[1].split() if prefix else payload.split()
            marker = UNSUPPORTED if word_command and len(secret_words) > 1 else MARKER
            value = value[:match.end()] + prefix + marker
            raw = indent + value + ending
            break
        safe.append(raw)
    return ''.join(safe)
