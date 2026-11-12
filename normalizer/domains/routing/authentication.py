"""Non-secret routing authentication settings shared by existing domains.

Settings are local configuration; no effective inheritance or session state is
computed. Interface settings without an explicit process link remain unbound.
"""
from normalizer.common.collections import collection
from normalizer.common.configured import leaves
from schemas import router_contract_v1 as s


def publish(state, owner, field, path, record, updates, model=s.RoutingAuthentication):
    previous = getattr(owner, field)
    payload = previous.model_dump(mode='python') if previous is not None else {}
    payload.update(updates)
    value = model.model_validate(payload)
    setattr(owner, field, value)
    pointer = '/' + (path + '/' + field).strip('/')
    present = {p for p, _ in leaves(value, pointer)}
    # Clear ownership of values explicitly removed; retain other local settings.
    state.bindings[:] = [b for b in state.bindings if not b.path.startswith(pointer + '/') or b.path in present]
    state.bind(pointer, record['source_line'], list(record['values']))
    return value


def bgp(state, record, process, path, peer_factory):
    owner, peer_path = peer_factory(state, record, process, path, state.af(record))
    for identity in ('name',) if isinstance(owner, s.BGPPeerGroup) else ('peer', 'kind'):
        state.bind(peer_path + '/' + identity, record['source_line'])
    removed = record['values'].get('removed', False)
    updates = dict(local_setting='removed' if removed else 'configured',
                   secret_configured=not removed,
                   credential_format=record['values'].get('credential_format'),
                   method=None if removed else 'tcp_md5', algorithm=None if removed else 'md5')
    publish(state, owner, 'authentication', peer_path, record, updates, s.BGPAuthentication)


def ospf_area(state, record, process, path):
    from normalizer.common.addresses import area_id
    identifier = area_id(record['values']['area'])
    areas = collection(process, 'areas')
    area = next((a for a in areas if a.area_id == identifier), None)
    if area is None:
        area = s.OSPFArea(area_id=identifier)
        areas.append(area)
    area_path = path + f'/areas/{areas.index(area)}'
    state.bind(area_path + '/area_id', record['source_line'])
    removed = record['values'].get('removed', False)
    digest = record['rule'].endswith('_digest')
    publish(state, area, 'authentication', area_path, record,
            dict(mode_setting='removed' if removed else 'configured',
                 method=None if removed else 'message_digest' if digest else 'plaintext',
                 algorithm='md5' if digest and not removed else None))


def _interface_target(state, record, protocol):
    interface, _ = state.entity(record['source_line'])
    routing = state.c.routing
    process = None
    if protocol == 'ospf':
        ids = {b.process for b in interface.ospf_bindings or [] if b.version == 2}
        candidates = [p for p in routing.ospf or [] if p.version == 2 and p.identifier in ids and p.network_instance == interface.vrf]
    elif protocol == 'isis':
        candidates = [p for p in routing.isis or [] if interface.isis_process is not None and p.name == interface.isis_process and p.network_instance == interface.vrf]
    else:
        candidates = []
        for p in routing.rip or []:
            if interface.vrf is None and p.network_instance is None:
                candidates.append(p)
            elif interface.vrf is not None:
                candidates.extend(af for af in p.address_families or [] if af.network_instance == interface.vrf)
    if len(candidates) == 1:
        process = candidates[0]
    if process is not None:
        if protocol == 'rip' and isinstance(process, s.RIPFamily):
            parent = next(p for p in routing.rip if any(af is process for af in p.address_families or []))
            path = f'routing/rip/{routing.rip.index(parent)}/address_families/{parent.address_families.index(process)}'
        else:
            items = getattr(routing, protocol)
            path = f'routing/{protocol}/{items.index(process)}'
        settings = collection(process, 'interface_settings')
        owner = next((x for x in settings if x.interface == interface.name), None)
        if owner is None:
            model = {'ospf': s.OSPFInterfaceSettings, 'isis': s.ISISInterfaceSettings, 'rip': s.RIPInterfaceSettings}[protocol]
            owner = model(interface=interface.name)
            settings.append(owner)
        path += f'/interface_settings/{settings.index(owner)}'
        state.bind(path + '/interface', record['source_line'])
        return owner, path, 'authentication'
    items = collection(routing, 'interface_authentication')
    owner = next((x for x in items if x.interface == interface.name and x.protocol == protocol and x.network_instance == interface.vrf), None)
    if owner is None:
        owner = s.InterfaceRoutingAuthentication(interface=interface.name, protocol=protocol, network_instance=interface.vrf)
        items.append(owner)
    path = f'routing/interface_authentication/{items.index(owner)}'
    for field in ('interface', 'protocol', 'network_instance'):
        if getattr(owner, field) is not None:
            state.bind(path + '/' + field, record['source_line'])
    return owner, path, 'isis_authentication' if protocol == 'isis' else 'authentication'


def _keys(state, owner, path, record):
    current = owner.authentication
    keys = list(current.keys or []) if current is not None else []
    md5 = '_md5_' in record['rule']
    key_id = record['values'].get('key_id')
    kind = 'message_digest' if md5 else 'plaintext'
    key = next((k for k in keys if k.kind == kind and k.key_id == key_id), None)
    if key is None:
        key = s.RoutingAuthenticationKey(kind=kind, key_id=key_id)
        keys.append(key)
    removed = record['values'].get('removed', False)
    replacement = key.model_dump(mode='python')
    replacement.update(secret_configured=not removed, local_setting='removed' if removed else 'configured',
                       credential_format=record['values'].get('credential_format'),
                       algorithm='md5' if md5 else None)
    keys[keys.index(key)] = s.RoutingAuthenticationKey(**replacement)
    ids = [k.key_id for k in keys if k.key_id is not None and k.secret_configured is True]
    publish(state, owner, 'authentication', path, record,
            dict(keys=keys, key_ids=ids or None,
                 secret_configured=True if any(k.secret_configured is True for k in keys) else None))


def interface(state, record):
    protocol = record['rule'].split('_')[2]
    owner, path, field = _interface_target(state, record, protocol)
    if protocol == 'isis':
        isis_settings(state, owner, field, path, record, 'interface')
        return
    rule, values = record['rule'], record['values']
    removed = values.get('removed', False)
    if protocol == 'ospf' and ('_key' in rule or '_md5_' in rule):
        _keys(state, owner, path, record)
        return
    if '_chain' in rule:
        updates = dict(key_chain_reference=None if removed else values['key_chain'],
                       key_chain_setting='removed' if removed else 'configured',
                       removed_key_chain_reference=values.get('key_chain') if removed else None)
        # Selecting an OSPF key-chain is an explicit interface authentication mode.
        if protocol == 'ospf':updates.update(method='key_chain', mode_setting='configured', algorithm=None)
    elif removed:
        updates = dict(method=None, algorithm=None, mode_setting='removed')
        if protocol == 'ospf':updates.update(key_chain_reference=None, key_chain_setting='removed')
    else:
        mode = values.get('mode') or ('md5' if rule.endswith('_digest') else 'none' if rule.endswith('_null') else 'text')
        updates = dict(method={'md5':'message_digest', 'text':'plaintext', 'none':'none'}[mode],
                       algorithm='md5' if mode == 'md5' else None, mode_setting='configured')
        if protocol == 'ospf':updates.update(key_chain_reference=None, key_chain_setting='removed')
    publish(state, owner, 'authentication', path, record, updates)


def isis_settings(state, owner, field, path, record, scope='process'):
    rule, values = record['rule'], record['values']
    area = '_area_' in rule
    domain = '_domain_' in rule
    if area or domain:
        scope = 'area' if area else 'domain'
        level = 'level-1' if area else 'level-2'
    else:
        level = values.get('level', 'level-1-2')
    items = collection(owner, field)
    obj = next((x for x in items if x.scope == scope and x.level == level), None)
    if obj is None:
        obj = s.ISISAuthentication(scope=scope, level=level)
        items.append(obj)
    targets = [obj]
    removed = values.get('removed', False)
    if not values.get('level') and not (area or domain):
        targets = [x for x in items if x.scope == scope]
    for target in targets:
        if area or domain:
            updates = dict(secret_configured=not removed, method=None if removed else 'plaintext',
                           mode_setting='removed' if removed else 'configured')
        elif '_mode' in rule:
            updates = dict(mode_setting='removed' if removed else 'configured',
                           method=None if removed else 'message_digest' if values['mode'] == 'md5' else 'plaintext',
                           algorithm=None if removed or values['mode'] == 'text' else 'md5')
        elif '_chain' in rule:
            updates = dict(key_chain_reference=None if removed else values['key_chain'],
                           key_chain_setting='removed' if removed else 'configured',
                           removed_key_chain_reference=values.get('key_chain') if removed else None)
        else:
            updates = dict(send_only=not removed, send_only_setting='removed' if removed else 'configured')
        # Publishing an item via a one-element holder would lose list identity;
        # replace it directly, retaining independent scopes and level settings.
        index = items.index(target)
        payload = target.model_dump(mode='python');payload.update(updates)
        items[index] = s.ISISAuthentication(**payload)
    pointer = '/' + (path + '/' + field).strip('/')
    present = {p for p, _ in leaves(items, pointer)}
    state.bindings[:] = [b for b in state.bindings if not b.path.startswith(pointer + '/') or b.path in present]
    state.bind(pointer, record['source_line'], list(values))


def isis_process(state, record):
    root = state.root(record)
    name = root['values'].get('process')
    process = next(p for p in state.c.routing.isis or [] if p.name == name)
    path = f'routing/isis/{state.c.routing.isis.index(process)}'
    isis_settings(state, process, 'authentication', path, record)
