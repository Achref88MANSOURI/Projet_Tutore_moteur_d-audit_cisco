"""Fail-closed source presentation, using existing captures, never CLI semantics.

Only reviewed pilot syntax is displayable. A recognized rule is necessary but
not sufficient. Credentials, comments, unknown commands and opaque blocks are
masked in their entirety. No original text is retained by the returned model.
"""
import re
from pydantic import BaseModel, ConfigDict, Field
from typing import Literal

from .admin_secrets import redact_admin_secrets
from .routing_secrets import redact_routing_secrets
from .validation import validate_record

MASK = '[MASKED]'


class SourceLine(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)
    number: int = Field(ge=1)
    text: str = Field(max_length=512)
    ending: Literal['', '\n', '\r\n']
    masked: bool


class SafeView(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)
    lines: tuple[SourceLine, ...]

    def render(self):
        return ''.join(line.text + line.ending for line in self.lines)


def displayable(record):
    """Presentation allowlist over TTP operands; does not create business facts."""
    rule, v = record['rule'], record['values']
    if not validate_record(record)['valid']:
        return False
    if rule in {'services_ssh_version', 'services_ssh_version_remove', 'admin_ssh_version_remove',
                'services_cdp_run', 'services_cdp_run_off', 'services_aaa_on', 'services_aaa_off'}:
        return not record['context_lines'] and (rule != 'services_ssh_version' or str(v['version']) in ('1', '2'))
    if rule == 'services_line':
        return not record['context_lines'] and bool(re.fullmatch(r'vty [0-9]{1,5}(?: [0-9]{1,5})?', v['name']))
    if rule == 'if_header':
        return (not record['context_lines']
                and bool(re.fullmatch(r'Serial[0-9]+(?:/[0-9]+){1,3}(?:\.[0-9]+)?', v['name'])))
    if rule == 'if_ppp':
        return len(record['context_lines']) == 1
    if rule in {'services_transport', 'services_transport_remove', 'services_transport_default',
                'services_timeout', 'services_timeout_minutes', 'services_timeout_remove', 'services_timeout_default',
                'services_login', 'services_login_plain', 'services_login_authentication_remove'}:
        if len(record['context_lines']) != 1:
            return False
        if rule == 'services_transport':
            tokens = v['transports'].split()
            return bool(tokens) and (tokens in (['none'], ['all']) or all(t in ('ssh', 'telnet') for t in tokens))
        if rule == 'services_login':
            return v['method'] == 'local' or bool(re.fullmatch(r'authentication [A-Za-z0-9_.-]{1,64}', v['method']))
        if 'method_list' in v:
            return bool(re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', v['method_list']))
        return True
    if rule in {'services_logging_update', 'services_logging_remove',
                'services_logging_legacy', 'services_logging_legacy_remove'}:
        # The existing argument decoder rejects unknown suffixes. Do not expose
        # its greedy target capture merely because an address was recovered.
        return (not record['context_lines'] and v.get('supported') is True
                and ('vrf' not in v or bool(re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', v['vrf']))))
    return False


def build_safe_view(text, extracted):
    safe = redact_admin_secrets(redact_routing_secrets(text)).splitlines(keepends=True)
    original = text.splitlines(keepends=True)
    if len(safe) != len(original):
        raise ValueError('Source line boundaries unavailable')
    lines = []
    for number, (raw, redacted) in enumerate(zip(original, safe), 1):
        ending = '\r\n' if raw.endswith('\r\n') else '\n' if raw.endswith('\n') else ''
        body = raw[:-len(ending)] if ending else raw
        node, record = extracted['nodes'].get(number), extracted['records'].get(number)
        visible = bool(record and node and node.kind == 'command'
                       and number not in extracted.get('ambiguous_lines', ())
                       and len(body) <= 512 and raw == redacted
                       and node.text == body.strip() and displayable(record))
        if visible and record['context_lines']:
            root = extracted['records'].get(record['root_line'])
            visible = bool(root and root['rule'] in ('services_line', 'if_header') and displayable(root))
        blank = not body.strip(' \t') and len(body) <= 512
        lines.append(SourceLine(number=number, text=body if visible or blank else MASK,
                                ending=ending, masked=not (visible or blank)))
    return SafeView(lines=tuple(lines))
