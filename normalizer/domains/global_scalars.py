"""Shared invalidation of explicitly captured global scalar resets.

The TTP rule owns syntax recognition. This table only projects reviewed reset
identities, in the same normalization phase as their corresponding setters.
It establishes no platform defaults and is not an alternate CLI parser.
"""
from normalizer.common.contexts import at


RESETS = {
    'hostname': ('system/identity', ('hostname',), False),
    'ip domain-name': ('system/identity', ('domain_name',), False),
    'ip domain name': ('system/identity', ('domain_name',), False),
    'ip ssh time-out': ('system/management/ssh', ('timeout_seconds',), False),
    'ip ssh timeout': ('system/management/ssh', ('timeout_seconds',), False),
    'ip ssh authentication-retries': ('system/management/ssh', ('authentication_retries',), False),
    'ip bootp server': ('system/ip_services', ('bootp_server_enabled',), True),
    'ip dhcp bootp ignore': ('system/ip_services', ('dhcp_bootp_ignore',), True),
    'service dhcp': ('system/ip_services', ('dhcp_service_enabled',), True),
    'ip identd': ('system/ip_services', ('ident_enabled',), True),
    'service tcp-keepalives-in': ('system/ip_services', ('tcp_keepalives_in',), True),
    'service tcp-keepalives-out': ('system/ip_services', ('tcp_keepalives_out',), True),
    'service pad': ('system/ip_services', ('pad_enabled',), True),
    'logging on': ('system/logging', ('enabled',), False),
    'logging buffered': ('system/logging', ('buffered_size', 'buffered_severity', 'buffered_discriminator'), False),
    'logging console': ('system/logging', ('console_severity', 'console_logging'), False),
    'logging trap': ('system/logging', ('trap_severity',), True),
}


def reset(state, record, *, resolving=False):
    if record['context_lines']:
        return
    command = record['values']['command']
    if command in ('service timestamps', 'service timestamps debug', 'service timestamps log'):
        from normalizer.domains.services import timestamp
        timestamp(state, record, reset=True,
                  reset_category=command.rsplit(' ',1)[-1] if command != 'service timestamps' else None)
        return
    if command in ('banner exec', 'banner login', 'banner motd'):
        if not resolving:
            state.defer(record)
        else:
            banner(state, record, kind=command.removeprefix('banner '), removed=True)
        return
    path, fields, deferred = RESETS[command]
    if deferred and not resolving:
        state.defer(record)
        return
    obj = at(state.c, path)
    for field in fields:
        setattr(obj, field, None)
        state.unbind(path + '/' + field)
    if command in ('ip ssh time-out', 'ip ssh timeout'):
        state.assign(obj, 'timeout_setting', 'default', path, record['source_line'])


def banner(state, record, *, kind=None, removed=False):
    """One global banner per type; reindex survivors with their original owners.

    Only text presence from inventory is retained. Unknown/unclosed bodies are
    never promoted to text-present, and their opaque text is never inspected.
    """
    if record['context_lines']:
        return
    from schemas.router_contract_v1 import Banner
    kind = kind or record['values'].get('type', 'incoming')
    prefix = 'system/identity/banners'
    items = state.c.system.identity.banners or []
    owners = {(i, field): next((b.record for b in state.bindings if b.path == f'/{prefix}/{i}/{field}'), None)
              for i in range(len(items)) for field in ('type', 'text_present')}
    index = next((i for i, item in enumerate(items) if item.type == kind), len(items))
    if removed:
        if index == len(items):
            return
        state.unbind(prefix)
        kept = [(i, item) for i, item in enumerate(items) if i != index]
        state.c.system.identity.banners = [item for _, item in kept]
        for new, (old, item) in enumerate(kept):
            for field in ('type', 'text_present'):
                owner = owners[(old, field)]
                if owner is not None and getattr(item, field) is not None:
                    # Scalar binds bypass the changed-value shortcut; moving
                    # an unchanged leaf still requires a new coordinate.
                    state.bind(f'{prefix}/{new}/{field}', owner)
        return
    node = state.nodes.get(record['source_line'])
    item = Banner(type=kind, text_present=node.text_present if node is not None else None)
    if index == len(items):
        items.append(item)
    else:
        state.unbind(f'{prefix}/{index}')
        items[index] = item
    state.c.system.identity.banners = items
    # Bind individual fields even for an identical repeated declaration. No
    # stale ownership is inherited from the superseded object.
    for field in ('type', 'text_present'):
        if getattr(item, field) is not None:
            state.bind(f'{prefix}/{index}/{field}', record['source_line'])
