"""BGP TCP-MD5 local/peer-group configuration, without session claims."""
from .routing_common import Scope, Relation, Property, Authentication, prop, guarded
from collections import Counter
from ipaddress import ip_address


def peer_identity(value):
    try:
        return str(ip_address(value))
    except ValueError:
        return value


def resolve(c):
    scopes = []
    for p, process in enumerate(c['routing'].get('bgp') or []):
        pp = f'/routing/bgp/{p}'
        group_counts = Counter(g['name'] for g in process.get('peer_groups') or [])
        template_counts = Counter(t['name'] for t in process.get('peer_session_templates') or [])
        groups = {g['name']: (g, f'{pp}/peer_groups/{i}') for i, g in enumerate(process.get('peer_groups') or []) if group_counts[g['name']] == 1}
        templates = {t['name']: (t, f'{pp}/peer_session_templates/{i}') for i, t in enumerate(process.get('peer_session_templates') or []) if template_counts[t['name']] == 1}
        def template_auth(name, visited=()):
            if template_counts[name] > 1:
                return None, None, 'AMBIGUOUS', []
            if name in visited or len(visited) >= 8:
                return None, None, 'AMBIGUOUS', []
            if name not in templates:
                return None, None, 'UNRESOLVED_REFERENCE', []
            template, tp = templates[name]
            local = template.get('authentication')
            if local:
                if local.get('local_setting') == 'removed' and template.get('parent_template'):
                    return None, None, 'PLATFORM_DEPENDENT', [tp]
                return local, tp + '/authentication', 'RESOLVED', [tp]
            if template.get('parent_template'):
                inherited, source, state, pointers = template_auth(template['parent_template'], (*visited, name))
                return inherited, source, state, [tp, *pointers]
            return None, None, 'UNKNOWN', [tp]
        global_entries = [(n, f'{pp}/neighbors/{i}') for i, n in enumerate(process.get('neighbors') or [])]
        global_counts = Counter(peer_identity(n['peer']) for n, _ in global_entries)
        global_neighbors = {peer_identity(n['peer']): (n, np) for n, np in global_entries if global_counts[peer_identity(n['peer'])] == 1}
        instances = [(process, pp, global_entries)]
        for i, af in enumerate(process.get('address_families') or []):
            path = f'{pp}/address_families/{i}'
            instances.append((af, path, [(n, f'{path}/peers/{j}') for j, n in enumerate(af.get('peers') or []) if n['kind'] == 'neighbor']))
        for instance, path, neighbors in instances:
            vrf = instance.get('network_instance')
            local_counts = Counter(g['peer'] for g in instance.get('peers') or [] if g['kind'] == 'group')
            local_groups = {g['peer']: (g, f'{path}/peers/{i}') for i, g in enumerate(instance.get('peers') or []) if g['kind'] == 'group' and local_counts[g['peer']] == 1}
            neighbor_counts = Counter(peer_identity(n['peer']) for n, _ in neighbors)
            relations = []
            for neighbor, np in neighbors:
                base, base_path = (neighbor, np)
                # Global transport parameters apply to non-VRF AF references.
                # Identical addresses in a VRF never fall back to global peers.
                identity = peer_identity(neighbor['peer'])
                if path != pp and vrf is None and identity in global_neighbors:
                    base, base_path = global_neighbors[identity]
                auth, ap = neighbor.get('authentication'), np + '/authentication'
                if auth is None:
                    auth, ap = base.get('authentication'), base_path + '/authentication'
                group_name = neighbor.get('inherited_group') or base.get('inherited_group')
                target = local_groups.get(group_name) or (groups.get(group_name) if vrf is None else None)
                duplicate_group = group_name is not None and (local_counts[group_name] > 1 if group_name in local_counts else vrf is None and group_counts[group_name] > 1)
                group_prop = prop(group_name, (np if neighbor.get('inherited_group') else base_path) + '/inherited_group') if group_name else Property()
                status, pointers = 'RESOLVED', [np]
                session_name = neighbor.get('session_template') or base.get('session_template')
                template, template_path, template_status, template_pointers = template_auth(session_name) if session_name else (None, None, 'UNKNOWN', [])
                if session_name:
                    group_prop = prop(session_name, (np if neighbor.get('session_template') else base_path) + '/session_template')
                    group_prop = group_prop.model_copy(update={'status': template_status, 'pointers': group_prop.pointers + template_pointers, 'rule': 'BGP_PEER_SESSION_TEMPLATE_CHAIN'})
                    pointers += template_pointers
                    if template_status not in ('RESOLVED', 'UNKNOWN'):
                        status = template_status
                    if group_name:
                        status = 'AMBIGUOUS'
                if group_name and target is None:
                    status = 'AMBIGUOUS' if duplicate_group else 'UNRESOLVED_REFERENCE'
                    group_prop = group_prop.model_copy(update={'status': status, 'rule': 'BGP_GROUP_TARGET_MISSING_IN_SCOPE'})
                effective_remote_as = neighbor.get('remote_as') or base.get('remote_as') or (target[0].get('remote_as') if target else None)
                if effective_remote_as is None and status == 'RESOLVED':
                    status = 'UNKNOWN'
                secret, mode = Property(), Property()
                if auth and auth.get('local_setting') == 'configured':
                    secret = prop(auth.get('secret_configured'), ap + '/secret_configured')
                    mode = prop(auth['method'], ap + '/method') if auth.get('method') else Property()
                elif auth and auth.get('local_setting') == 'removed':
                    if target:
                        # IOS command references establish peer-group inheritance
                        # and local removal separately, but do not establish the
                        # interaction for every target release. Do not guess it.
                        secret = Property(status='PLATFORM_DEPENDENT', pointers=[ap + '/local_setting', target[1]], rule='BGP_LOCAL_REMOVAL_WITH_GROUP_REQUIRES_RELEASE_RULE')
                        mode = Property(status='PLATFORM_DEPENDENT', rule=secret.rule)
                    else:
                        secret = prop(False, ap + '/secret_configured', origin='removed')
                        mode = Property(status='RESOLVED', origin='removed', pointers=[ap + '/local_setting'], rule='BGP_LOCAL_PASSWORD_REMOVED')
                elif target:
                    group, gp = target
                    ga = group.get('authentication') or {}
                    pointers += [gp]
                    if ga.get('local_setting') == 'configured':
                        secret = prop(ga.get('secret_configured'), gp + '/authentication/secret_configured', origin='inherited', rule='BGP_PEER_GROUP_PASSWORD_INHERITANCE')
                        mode = prop(ga['method'], gp + '/authentication/method', origin='inherited', rule='BGP_PEER_GROUP_PASSWORD_INHERITANCE')
                elif template:
                    if template.get('local_setting') == 'configured':
                        secret = prop(template.get('secret_configured'), template_path + '/secret_configured', origin='inherited', rule='BGP_PEER_SESSION_PASSWORD_INHERITANCE')
                        mode = prop(template['method'], template_path + '/method', origin='inherited', rule='BGP_PEER_SESSION_PASSWORD_INHERITANCE')
                        if neighbor.get('remote_as') is None and base.get('remote_as') is None:
                            secret = Property(rule='BGP_TEMPLATE_REMOTE_AS_PREREQUISITE_NOT_DEMONSTRATED', pointers=group_prop.pointers)
                            mode = Property(rule=secret.rule)
                            status = 'UNKNOWN'
                if session_name and auth and auth.get('local_setting') == 'removed' and template:
                    secret = Property(status='PLATFORM_DEPENDENT', pointers=[ap + '/local_setting', template_path], rule='BGP_LOCAL_REMOVAL_WITH_TEMPLATE_REQUIRES_RELEASE_RULE')
                    mode = Property(status='PLATFORM_DEPENDENT', rule=secret.rule)
                if duplicate_group or neighbor_counts[identity] > 1 or (path != pp and vrf is None and global_counts[identity] > 1):
                    status = 'AMBIGUOUS'
                    secret = Property(status='AMBIGUOUS', rule='BGP_IDENTITY_NOT_UNIQUE')
                    mode = Property(status='AMBIGUOUS', rule=secret.rule)
                    if duplicate_group:
                        group_prop = group_prop.model_copy(update={'status':'AMBIGUOUS', 'rule':'BGP_GROUP_IDENTITY_NOT_UNIQUE'})
                relations.append(guarded(c, Relation(protocol='bgp', subject=neighbor['peer'], subject_kind='neighbor',
                    status=status, derivation='explicit', rule='BGP_LOCAL_OR_DECLARED_PEER_GROUP', pointers=pointers,
                    enabled=prop(neighbor['enabled'], np + '/enabled') if neighbor.get('enabled') is not None else Property(),
                    authentication=Authentication(mode=mode, secret=secret, inherited_from=group_prop))))
            scopes.append(Scope(protocol='bgp', identifier=str(process['local_as']), pointer=path, process_pointer=pp,
                autonomous_system=process['local_as'], afi=instance.get('afi'), safi=instance.get('safi'), network_instance=vrf,
                relations=relations))
    return scopes, []
