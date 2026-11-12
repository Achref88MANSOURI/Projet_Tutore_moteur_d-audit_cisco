"""Scrub administrative credentials before inventory and all TTP execution.

Keep names, declared formats and irreversible presence markers. The routing
redactor remains separate and unchanged. No secret-derived reference is made.
"""
import re

MARKER = '__ADMIN_SECRET_PRESENT__'
CREDENTIALS = (
    re.compile(r'^(?:no\s+)?username\s+\S+(?:\s+privilege\s+\d+)?\s+algorithm-type\s+\S+\s+secret\s+', re.I),
    re.compile(r'^(?:no\s+)?enable\s+algorithm-type\s+\S+\s+secret\s+', re.I),
    re.compile(r'^(?:no\s+)?username\s+\S+(?:\s+privilege\s+\d+)?\s+(?:password|secret)\s+', re.I),
    re.compile(r'^(?:no\s+)?enable\s+(?:password|secret)(?:\s+level\s+\d+)?\s+', re.I),
    re.compile(r'^(?:no\s+)?password\s+', re.I),
    re.compile(r'^(?:no\s+)?(?:radius-server|tacacs-server)\s+key\s+', re.I),
    re.compile(r'^(?:no\s+)?(?:radius-server|tacacs-server)\s+host\s+.+?\s+key\s+', re.I),
)


def community_category(value):
    """Only fixed equality categories escape this private redaction boundary."""
    return 'FORBIDDEN_152' if value == 'private' else 'FORBIDDEN_153' if value == 'public' else 'OTHER'


def redact_admin_secrets(text, *, identities=None, community_categories=None):
    result = []
    root = ''
    private_communities = {}
    for number, raw in enumerate(text.splitlines(keepends=True), 1):
        value = raw.strip()
        if value and not value.startswith('!') and not raw[0].isspace():
            root = value
        # Mask v1/v2c host credentials before inventory, templates or logs.
        # Keep v3 user references (non-secret identities) unchanged.
        if re.match(r'^(?:no\s+)?snmp-server\s+host\s+', value, re.I):
            tokens = value.split()
            version = tokens.index('version') if 'version' in tokens else None
            if version is not None and version + 1 < len(tokens) and tokens[version + 1] == '3':
                result.append(raw)
                continue
            start = tokens.index('host') + 2
            if version is not None:
                target = version + 2
            else:
                target = start
                while target < len(tokens):
                    if tokens[target] in ('vrf', 'udp-port'): target += 2
                    elif tokens[target] in ('traps', 'informs'): target += 1
                    else: break
            if version is None and target < len(tokens) and tokens[target] in ('1', '2c', '3'):
                if tokens[target] == '3':
                    result.append(raw)
                    continue
                target += 1
            if target < len(tokens):
                tokens[target] = MARKER
            indent = raw[:len(raw)-len(raw.lstrip())]
            ending = '\r\n' if raw.endswith('\r\n') else '\n' if raw.endswith('\n') else ''
            result.append(indent + ' '.join(tokens) + ending)
            continue
        snmp = re.match(r'^((?:no\s+)?snmp-server\s+(community|user)\s+)(\S+)(.*)$', value, re.I)
        if snmp:
            # Community access/ACL syntax is supported and remains available.
            # User payloads: keep structure for parsing, redact secrets.
            if snmp[2].lower() == 'community':
                if community_categories is not None:
                    community_categories[number] = community_category(snmp[3])
                if identities is not None:
                    # Operation-local ordinal, never a secret-derived hash or
                    # serialized credential. Raw keys die with this redaction.
                    identities[number] = private_communities.setdefault(snmp[3], 'community-' + str(len(private_communities) + 1))
                suffix = snmp[4]
                indent = raw[:len(raw)-len(raw.lstrip())]
                ending = '\r\n' if raw.endswith('\r\n') else '\n' if raw.endswith('\n') else ''
                result.append(indent + snmp[1] + MARKER + suffix + ending)
            else:
                # User: preserve structure for parsing, redact secret values
                suffix = snmp[4]
                # A generic TTP params capture must never treat an unsupported
                # credential token as a public algorithm name. Preserve only a
                # recognized identity header and a safe opaque rewrite marker.
                # This is a redaction boundary, not an additional audit parser.
                header = re.fullmatch(r'(\s+\S+(?:\s+remote\s+\S+(?:\s+udp-port\s+\d+)?)?\s+v3)(?:\s+(.*))?', suffix, re.I)
                plain_remove = re.match(r'^no\s', snmp[1], re.I) and re.fullmatch(r'\s+\S+', suffix)
                grammar = r'(?:encrypted\s+)?auth\s+(?:sha|md5)\s+\S+(?:\s+priv\s+(?:aes\s+(?:128|192|256)|des|3des)\s+\S+)?(?:\s+access\s+\S+)?|access\s+\S+|'
                if not plain_remove and (header is None or re.fullmatch(grammar, header[2] or '', re.I) is None):
                    indent = raw[:len(raw)-len(raw.lstrip())]
                    ending = '\r\n' if raw.endswith('\r\n') else '\n' if raw.endswith('\n') else ''
                    safe = snmp[1] + snmp[3] + header[1] + ' ' + MARKER if header else MARKER
                    result.append(indent + safe + ending)
                    continue
                # Replace secret values after auth/priv keywords with marker
                # Pattern: auth <algorithm> <secret> or priv <algorithm> <secret>
                # We want to keep the algorithm names (sha, md5, aes, des, 3des) but redact the secret values
                def redact_secret(match):
                    # match groups: (auth|priv), algorithm, secret
                    if len(match.groups()) >= 2:
                        return match.group(1) + ' ' + match.group(2) + ' ' + MARKER
                    return MARKER
                
                redacted_suffix = re.sub(
                    r'\b(auth|priv)\s+(sha|md5|aes\s+\d+|des|3des)\s+\S+',
                    redact_secret,
                    suffix,
                    flags=re.I
                )
                indent = raw[:len(raw)-len(raw.lstrip())]
                ending = '\r\n' if raw.endswith('\r\n') else '\n' if raw.endswith('\n') else ''
                result.append(indent + snmp[1] + snmp[3] + redacted_suffix + ending)
            continue
        prefix = None
        for pattern in CREDENTIALS:
            match = pattern.match(value)
            if match:
                prefix = match.end()
                break
        if prefix is None and re.match(r'^aaa group server (?:radius|tacacs\+) ', root, re.I):
            private = re.match(r'^(?:no\s+)?(?:server-private|server)\s+.+?\s+key\s+', value, re.I)
            if private:
                prefix = private.end()  # Redact unsupported legacy/private endpoints too.
        key = re.match(r'^(?:no\s+)?key\s+', value, re.I)
        routing_chain_removal = bool(raw) and not raw[0].isspace() and re.fullmatch(r'no key chain \S+', value, re.I) is not None
        if prefix is None and key and not root.lower().startswith('key chain ') and not routing_chain_removal:
            # A routing key ID is not a credential. Within named AAA servers,
            # even a numeric one-word key is a secret and must be erased.
            payload = value[key.end():]
            named_server = re.match(r'^(?:radius|tacacs) server \S+$', root, re.I)
            if named_server or not payload.isdigit():
                prefix = key.end()
        if prefix is None:
            result.append(raw)
            continue
        payload = value[prefix:].strip()
        if not payload or payload == MARKER or re.fullmatch(r'\d+ ' + MARKER, payload):
            result.append(raw)
            continue
        # A lone IOS type token is not a credential. Leave the malformed line
        # recognizable to coverage, but never manufacture a presence marker.
        if payload.isdigit():
            result.append(raw)
            continue
        tokens = payload.split(maxsplit=1)
        format_prefix = tokens[0] + ' ' if len(tokens) == 2 and tokens[0].isdigit() else ''
        indent = raw[:len(raw)-len(raw.lstrip())]
        ending = '\r\n' if raw.endswith('\r\n') else '\n' if raw.endswith('\n') else ''
        result.append(indent + value[:prefix] + format_prefix + MARKER + ending)
    return ''.join(result)
