"""Direct canonical AAA and SSH mappings; no inferred service activation."""
from normalizer.common.collections import collection
from normalizer.common.configured import leaves
from schemas import router_contract_v1 as s

PROTOCOL = {'radius': 'radius', 'tacacs+': 'tacacs'}
SIMPLE = {
    ('authentication','login'): {'local','local-case','enable','line','none','krb5','krb5-telnet'},
    ('authentication','enable'): {'enable','line','none'},
    ('authorization','exec'): {'local','none','if-authenticated'},
    ('authorization','commands'): {'local','none','if-authenticated'},
    ('accounting','exec'): set(), ('accounting','commands'): set(), ('accounting','system'): set(),
    ('accounting','connection'): set(), ('accounting','network'): set(),
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
    item.password_expiry = None
    state.uncertain.add(record['source_line'])
    _publish(state, path, record)


def method_list(state, record):
    if record['rule']=='services_aaa_authentication_enable_remove':category,service='authentication','enable'
    else:_, category, service, *_ = record['rule'].split('_')
    values = record['values']
    mode = values.get('accounting_mode', 'none' if record['rule'].endswith('_none') else None)
    field = category + '_method_lists'
    key = values.get('name','default'), service, values.get('level')
    items = collection(state.c.system.aaa, field)
    index = next((n for n, item in enumerate(items) if (item.name,item.service,item.privilege_level) == key), len(items))
    removed = values.get('removed', False)
    method_text = values.get('methods', '')
    expiry = None
    if category == 'authentication' and service == 'login' and method_text.split()[:1] == ['passwd-expiry']:
        expiry = True
        method_text = method_text.partition(' ')[2]
    try:
        parsed = [] if removed else methods(method_text, category, service)
        if not removed and not parsed and not (category == 'accounting' and mode == 'none'):
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
                          password_expiry=None if removed else expiry,
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
    legacy = record['rule'].startswith('services_tacacs_legacy_host')
    name = None if legacy else values['name']
    address = values.get('address') if legacy else None
    items = collection(state.c.system.aaa, 'servers')
    item = next((server for server in items
                 if server.protocol == protocol and server.name == name
                 and (not legacy or server.address == address)), None)
    if item is None:
        item = s.AuthServer(protocol=protocol, name=name, address=address)
        items.append(item)
    if legacy:
        item.address = address
        if values.get('key_configured') is True:
            item.key_configured = True
            item.key_setting = 'configured'
            item.key_format = values.get('credential_format')
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


def source_interface(state, record):
    """Project global and server-group AAA source-interface settings.

    Group-local settings remain on their declared group and therefore do not
    overwrite the global fallback.  A negation removes only the setting in its
    own scope.
    """
    rule = record['rule']
    values = record['values']
    removed = values.get('removed', False)
    local = rule.startswith('admin_aaa_group_')
    protocol = 'radius' if 'radius' in rule else 'tacacs'
    if local:
        entry = state.entity(record['source_line'])
        if entry is None or not isinstance(entry[0], s.AAAServerGroup):
            return
        owner, path = entry
        if owner.protocol != protocol:
            return
        if removed:
            owner.source_interface = None
            state.unbind(path + '/source_interface')
            state.consumed[record['source_line']].update(values)
        else:
            state.assign(owner, 'source_interface', values['interface'], path,
                         record['source_line'], ['interface'])
        return
    aaa = state.c.system.aaa
    field = protocol + '_source_interface'
    path = 'system/aaa'
    if removed:
        setattr(aaa, field, None)
        state.unbind(path + '/' + field)
        state.consumed[record['source_line']].update(values)
    else:
        state.assign(aaa, field, values['interface'], path,
                     record['source_line'], ['interface'])


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
    elif rule == 'services_ssh_version_default':
        item.version = None
        item.version_setting = None
        state.unbind(path + '/version')
        state.unbind(path + '/version_setting')
        return
    elif rule == 'admin_ssh_timeout':
        item.timeout_seconds = values['seconds']
    elif rule == 'services_ssh_timeout':
        item.timeout_seconds = values['seconds']
    elif rule in ('services_ssh_timeout_remove', 'admin_ssh_timeout_remove'):
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
    if rule in ('admin_ssh_timeout','services_ssh_timeout','services_ssh_timeout_remove','admin_ssh_timeout_remove'):
        item.timeout_setting = 'removed' if rule.endswith('_remove') else 'configured'
    _publish(state, path, record)


def enable_secret(state, record):
    """Publish presence/format only; plaintext never enters the contract."""
    if record['context_lines']:
        return
    values = record['values']
    level = values.get('level', 15)  # IOS enable-secret command's explicit syntax default.
    items = collection(state.c.system.aaa, 'enable_secrets')
    index = next((i for i, item in enumerate(items) if item.level == level), len(items))
    removed = values.get('removed') is True
    item = s.EnableSecret(level=level, secret_configured=not removed, removed=removed,
                          secret_type=values.get('secret_type'), algorithm_type=values.get('algorithm_type'))
    if index == len(items): items.append(item)
    else: items[index] = item
    path = f'system/aaa/enable_secrets/{index}'
    state.unbind(path)
    _publish(state, path, record)


def enable_password(state, record):
    """Publish only presence, level and format for the weaker IOS password."""
    if record['context_lines']:
        return
    values = record['values']
    level = values.get('level', 15)
    items = collection(state.c.system.aaa, 'enable_passwords')
    index = next((i for i, item in enumerate(items) if item.level == level), len(items))
    removed = values.get('removed') is True
    item = s.EnablePassword(
        level=level,
        credential_format=None if removed else values.get('credential_format'),
        secret_configured=not removed,
        removed=removed,
    )
    if index == len(items):
        items.append(item)
    else:
        items[index] = item
    path = f'system/aaa/enable_passwords/{index}'
    state.unbind(path)
    _publish(state, path, record)


def handle(state, record):
    rule = record['rule']
    if rule in ('services_radius','services_tacacs') or rule.startswith('services_tacacs_legacy_host'):
        if rule == 'services_tacacs_legacy_host_remove':
            from normalizer.common.collections import owned_entries, publish_entries
            address = record['values']['address']
            aaa = state.c.system.aaa
            publish_entries(state, aaa, 'servers', 'system/aaa/servers', [
                (item, owners) for item, owners in owned_entries(state, aaa, 'servers', 'system/aaa/servers')
                if not (item.protocol == 'tacacs' and item.name is None and item.address == address)
            ])
            return
        return server_declare(state,record)
    if rule=='admin_aaa_group':return group_declare(state,record)
    if rule in (
            'services_radius_source', 'services_radius_source_remove',
            'services_tacacs_source', 'services_tacacs_source_remove',
            'admin_aaa_group_radius_source', 'admin_aaa_group_radius_source_remove',
            'admin_aaa_group_tacacs_source', 'admin_aaa_group_tacacs_source_remove'):
        return source_interface(state, record)
    if rule in ('admin_radius_remove','admin_tacacs_remove','admin_aaa_group_remove'):
        from normalizer.common.collections import owned_entries,publish_entries
        v=record['values'];aaa=state.c.system.aaa
        field='server_groups' if rule=='admin_aaa_group_remove' else 'servers'
        protocol=PROTOCOL[v['protocol']] if field=='server_groups' else 'radius' if rule=='admin_radius_remove' else 'tacacs'
        path='system/aaa/'+field
        publish_entries(state,aaa,field,path,[(item,owners) for item,owners in owned_entries(state,aaa,field,path) if not (item.name==v['name'] and item.protocol==protocol)])
        return
    if rule.startswith(('admin_authentication_','admin_authorization_','admin_accounting_')):
        return method_list(state, record)
    if rule.startswith('admin_ssh_') or rule == 'services_ssh_version' or rule.startswith('services_ssh_'):
        return ssh(state, record)
    if rule in ('services_accounting_commands', 'services_accounting_connection', 'services_accounting_exec', 'services_accounting_network', 'services_accounting_system'):
        return method_list(state, record)
    if rule in ('admin_aaa_group_member', 'services_aaa_group_member','admin_aaa_group_member_remove'):
        entry = state.entity(record['source_line'])
        if entry is None or not isinstance(entry[0], s.AAAServerGroup):return
        group, path = entry
        if record['values'].get('removed'):
            from normalizer.common.collections import owned_entries,publish_entries
            publish_entries(state,group,'servers',path+'/servers',[(item,owners) for item,owners in owned_entries(state,group,'servers',path+'/servers') if item.name!=record['values']['name']])
            return
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
        return method_list(state,record)
    if rule in ('services_auth_address', 'services_auth_ports'):
        return server_update(state, record)
    if rule in ('admin_server_key_format', 'admin_server_key', 'admin_server_key_remove', 'admin_server_key_remove_format'):
        return server_update(state, record)
    if rule.startswith('services_enable_password'):
        return enable_password(state, record)
    if rule in ('services_user', 'services_user_simple', 'services_user_no_format', 'services_user_privilege_no_format',
                'services_user_privilege', 'services_user_remove', 'services_user_algorithm', 'services_user_nopassword'):
        return user(state,record)


def user(state,record):
    """Update one public username identity; credentials never enter V1."""
    from normalizer.common.collections import owned_entries,publish_entries
    if record['context_lines']:return
    rule=record['rule'];v=record['values'];line=record['source_line']
    aaa=state.c.system.aaa
    if rule=='services_user_remove':
        entries=owned_entries(state,aaa,'local_users','system/aaa/local_users')
        publish_entries(state,aaa,'local_users','system/aaa/local_users',[(u,o) for u,o in entries if u.username!=v['username']])
        return
    users=collection(aaa,'local_users');item=next((u for u in users if u.username==v['username']),None)
    if item is None:item=s.UserAccount(username=v['username']);users.append(item)
    path=f'system/aaa/local_users/{users.index(item)}'
    def assign(field,value):
        if value is None:
            setattr(item,field,None);state.unbind(path+'/'+field)
        else:state.assign(item,field,value,path,line)
    assign('username',v['username'])
    if 'privilege' in v:assign('privilege_level',v['privilege'])
    if rule=='services_user_privilege':return
    if rule=='services_user_nopassword':
        assign('credential_configured',False);assign('nopassword',True)
        assign('credential_type',None);assign('algorithm_type',None)
        return
    kind=v.get('credential_type','secret');fmt=v.get('credential_format','not_specified')
    assign('credential_configured',True);assign('credential_type',kind+':'+str(fmt))
    assign('algorithm_type',v.get('algorithm_type'))
    if item.nopassword is True:assign('nopassword',False)
