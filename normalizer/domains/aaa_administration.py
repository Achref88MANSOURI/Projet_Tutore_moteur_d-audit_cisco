"""Direct canonical AAA and SSH mappings; no inferred service activation."""
from normalizer.common.collections import collection
from normalizer.common.configured import leaves
from schemas import router_contract_v1 as s

PROTOCOL = {'radius': 'radius', 'tacacs+': 'tacacs'}
SIMPLE = {
    ('authentication','login'): {'local','local-case','enable','line','none','krb5','krb5-telnet','passwd-expiry'},
    ('authentication','enable'): {'enable','line','none'},
    ('authorization','exec'): {'local','none','if-authenticated'},
    ('authorization','commands'): {'local','none','if-authenticated'},
    ('accounting','exec'): set(), ('accounting','commands'): set(), ('accounting','system'): set(),
}


def methods(text, category, service):
    tokens = text.split()
    result = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == 'group':
            index += 1
            if index == len(tokens) or tokens[index] in SIMPLE[(category, service)] | {'group','ldap','cache'}:
                raise ValueError('Incomplete or unsupported AAA group method')
            group = tokens[index]
            result.append(s.AAAMethod(method='group', group_protocol=PROTOCOL.get(group),
                                      group_reference=None if group in PROTOCOL else group))
        elif token in SIMPLE[(category, service)]:
            result.append(s.AAAMethod(method=token))
        else:
            raise ValueError('Unsupported AAA method; no partial method list is exported')
        index += 1
    if category == 'authentication' and len(result) > 4:
        raise ValueError('AAA authentication supports at most four methods')
    return result


def _publish(state, path, record):
    from normalizer.common.contexts import at
    pointer = '/' + path.strip('/')
    current = at(state.c, pointer)
    valid = {p for p, _ in leaves(current, pointer)}
    state.bindings[:] = [b for b in state.bindings if not b.path.startswith(pointer + '/') or b.path in valid]
    state.bind(pointer, record['source_line'], list(record['values']))


def invalidate_method_list(state, path, record, item):
    """A captured rewrite whose effect is unknown revokes the old certainty.

    The list identity (name/service/level) stays established; its content and
    its current setting become unknown, so no stale method survives and no new
    method is invented.
    """
    item.methods = None
    item.accounting_mode = None
    item.local_setting = None
    _publish(state, path, record)


def method_list(state, record):
    _, category, service, *_ = record['rule'].split('_')
    values = record['values']
    mode = values.get('accounting_mode', 'none' if record['rule'].endswith('_none') else None)
    field = category + '_method_lists'
    key = values['name'], service, values.get('level')
    items = collection(state.c.system.aaa, field)
    index = next((n for n, item in enumerate(items) if (item.name,item.service,item.privilege_level) == key), len(items))
    removed = values.get('removed', False)
    try:
        parsed = methods(values.get('methods', ''), category, service)
        if not parsed and not (category == 'accounting' and mode == 'none'):
            raise ValueError('An AAA method list must not be silently empty')
    except ValueError:
        # Nothing was interpreted: a removal keeps its documented effect, but a
        # captured redefinition must not preserve the previous methods.
        if removed or index == len(items):
            raise
        return invalidate_method_list(state, f'system/aaa/{field}/{index}', record, items[index])
    item = s.AAAMethodList(name=key[0], service=service, privilege_level=key[2],
                          accounting_mode=None if removed else mode,
                          methods=None if removed else parsed,
                          local_setting='removed' if removed else 'configured')
    if index == len(items):items.append(item)
    else:items[index] = item
    path = f'system/aaa/{field}/{index}'
    if not removed and parsed == []:
        state.absences.confirm(path + '/methods', explicit=True)
    _publish(state, path, record)


def server_declare(state, record):
    values = record['values']
    protocol = 'radius' if record['rule'] == 'services_radius' else 'tacacs'
    items = collection(state.c.system.aaa, 'servers')
    item = next((server for server in items if server.protocol == protocol and server.name == values['name']), None)
    if item is None:
        item = s.AuthServer(protocol=protocol, name=values['name'])
        items.append(item)
    path = f'system/aaa/servers/{items.index(item)}'
    state.entities[record['source_line']] = path
    _publish(state, path, record)
    return True


def group_declare(state, record):
    values = record['values']
    items = collection(state.c.system.aaa, 'server_groups')
    protocol = PROTOCOL[values['protocol']]
    item = next((group for group in items if group.name == values['name'] and group.protocol == protocol), None)
    if item is None:
        item = s.AAAServerGroup(name=values['name'], protocol=protocol)
        items.append(item)
    path = f'system/aaa/server_groups/{items.index(item)}'
    state.entities[record['source_line']] = path
    _publish(state, path, record)
    return True


def server_update(state, record):
    entry = state.entity(record['source_line'])
    if entry is None or not isinstance(entry[0], s.AuthServer):return
    item, path = entry
    values = record['values']
    if record['rule'] in ('services_auth_address','services_auth_ports'):
        item.address = values['address']
        if 'auth_port' in values:item.auth_port = values['auth_port']
        if 'acct_port' in values:item.accounting_port = values['acct_port']
    else:
        removed = values.get('removed', False)
        item.key_configured = not removed
        item.key_setting = 'removed' if removed else 'configured'
        item.key_format = None if removed else values.get('credential_format')
    _publish(state, path, record)


def ssh(state, record):
    item = state.c.system.management.ssh
    values = record['values']
    path = 'system/management/ssh'
    rule = record['rule']
    if rule == 'services_ssh_version':
        item.version = int(values['version'])
        item.version_setting = 'configured'
    elif rule == 'admin_ssh_version_remove':
        item.version = None
        item.version_setting = 'removed'
    elif rule == 'services_ssh_version_remove':
        item.version = None
        item.version_setting = 'removed'
    elif rule == 'admin_ssh_timeout':
        item.timeout_seconds = values['seconds']
    elif rule == 'services_ssh_timeout':
        item.timeout_seconds = values['seconds']
    elif rule == 'services_ssh_timeout_remove':
        item.timeout_seconds = None
    elif rule == 'admin_ssh_retries':
        item.authentication_retries = values['retries']
    elif rule == 'admin_ssh_retries_remove':
        item.authentication_retries = None
    elif rule == 'services_ssh_rsa_keypair':
        item.rsa_keypair_name = values['name']
    elif rule == 'services_ssh_rsa_keypair_remove':
        item.rsa_keypair_name = None
    elif rule == 'services_ssh_source':
        item.source_interface = values['interface']
    elif rule == 'services_ssh_source_remove':
        item.source_interface = None
    elif rule == 'services_ssh_pubkey_chain':
        item.pubkey_chain_enabled = True
    elif rule == 'services_ssh_pubkey_chain_remove':
        item.pubkey_chain_enabled = False
    _publish(state, path, record)


def handle(state, record):
    rule = record['rule']
    if rule.startswith(('admin_authentication_','admin_authorization_','admin_accounting_')):
        return method_list(state, record)
    if rule.startswith('admin_ssh_') or rule == 'services_ssh_version' or rule.startswith('services_ssh_'):
        return ssh(state, record)
    if rule in ('services_accounting_commands', 'services_accounting_connection', 'services_accounting_exec', 'services_accounting_network', 'services_accounting_system'):
        return method_list(state, record)
    if rule in ('admin_aaa_group_member', 'services_aaa_group_member'):
        entry = state.entity(record['source_line'])
        if entry is None or not isinstance(entry[0], s.AAAServerGroup):return
        group, path = entry
        refs = collection(group, 'servers')
        if not any(ref.name == record['values']['name'] for ref in refs):
            refs.append(s.AAAServerReference(name=record['values']['name']))
        _publish(state, path, record)
    if rule in ('services_aaa_group_server_private',):
        entry = state.entity(record['source_line'])
        if entry is None or not isinstance(entry[0], s.AAAServerGroup):return
        group, path = entry
        # server-private adds a server with a private key
        name = record['values']['name']
        key = record['values'].get('key', '')
        refs = collection(group, 'servers')
        if not any(ref.name == name for ref in refs):
            refs.append(s.AAAServerReference(name=name))
        _publish(state, path, record)
    if rule in ('services_aaa_authentication_enable_remove',):
        state.c.system.aaa.authentication_enable = None
        state.unbind('system/aaa/authentication_enable')
    if rule in ('services_auth_address', 'services_auth_ports'):
        return server_update(state, record)
    if rule in ('admin_server_key_format', 'admin_server_key', 'admin_server_key_remove', 'admin_server_key_remove_format'):
        return server_update(state, record)
    if rule in ('services_user', 'services_user_simple', 'services_user_no_format'):
        v = record['values']
        users = collection(state.c.system.aaa, 'local_users')
        cred_configured = True
        cred_type = v.get('credential_type')
        cred_format = v.get('credential_format')
        if rule == 'services_user_no_format':
            cred_configured = True
            cred_type = v.get('credential_type', 'secret')
            cred_format = 'not_specified'
        users.append(s.UserAccount(
            username=v['username'],
            privilege_level=v.get('privilege'),
            credential_configured=cred_configured,
            credential_type=f'{cred_type}:{cred_format}' if cred_type and cred_format else None
        ))
        _publish(state, f'system/aaa/local_users/{len(users) - 1}', record)
