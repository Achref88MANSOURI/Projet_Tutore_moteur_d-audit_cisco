"""RIP network membership, explicit version and local authentication joins."""
from .routing_common import (Scope, Relation, Property, prop, network_match, passive,
                             interface_auth, local_property, chain_auth, guarded)


def resolve(c):
    scopes, used = [], set()
    for p, process in enumerate(c['routing'].get('rip') or []):
        if process.get('declared') is not True:
            continue
        pp = f'/routing/rip/{p}'
        instances = [(process, pp)] + [(f, f'{pp}/address_families/{i}') for i, f in enumerate(process.get('address_families') or [])]
        for instance, path in instances:
            vrf = instance.get('network_instance')
            relations = []
            settings = [(f'{path}/interface_settings/{n}', item) for n, item in enumerate(instance.get('interface_settings') or [])]
            settings += [(f'/routing/rip_interfaces/{n}', item) for n, item in enumerate(c['routing'].get('rip_interfaces') or [])
                         if item.get('network_instance') == vrf]
            for i, interface in enumerate(c.get('interfaces') or []):
                if interface.get('vrf') != vrf:
                    continue
                matches = [n for n, network in enumerate(instance.get('network_statements') or []) if network_match(interface, {'address': network})]
                if not matches:
                    continue
                auth, ap, ambiguous = interface_auth(c, 'rip', interface['name'], vrf, instance, path)
                if ap:
                    used.add(ap)
                resolved = chain_auth(c, local_property(auth, ap, 'method', 'mode_setting'), local_property(auth, ap, 'key_chain_reference', 'key_chain_setting'))
                local_versions = [(ip, item) for ip, item in settings if item['interface'] == interface['name']]
                if len(local_versions) == 1:
                    ip, item = local_versions[0]
                    send_versions = (prop(item['send_versions'], ip + '/send_versions') if item.get('send_versions') is not None else
                        Property(origin='reset', pointers=[ip + '/send_version_setting'], rule='RIP_INTERFACE_SEND_VERSION_RESET') if item.get('send_version_setting') == 'reset' else Property())
                    receive_versions = (prop(item['receive_versions'], ip + '/receive_versions') if item.get('receive_versions') is not None else
                        Property(origin='reset', pointers=[ip + '/receive_version_setting'], rule='RIP_INTERFACE_RECEIVE_VERSION_RESET') if item.get('receive_version_setting') == 'reset' else Property())
                else:
                    send_versions = Property(status='AMBIGUOUS', rule='RIP_INTERFACE_VERSION_SCOPE_NOT_UNIQUE') if local_versions else Property()
                    receive_versions = Property(status='AMBIGUOUS', rule='RIP_INTERFACE_VERSION_SCOPE_NOT_UNIQUE') if local_versions else Property()
                relations.append(guarded(c, Relation(protocol='rip', subject=interface['name'],
                    status='AMBIGUOUS' if ambiguous else 'RESOLVED', rule='RIP_CLASSFUL_NETWORK_AND_VRF',
                    pointers=[f'/interfaces/{i}/name'] + [f'{path}/network_statements/{n}' for n in matches],
                    passive=passive(instance, path, interface['name']), authentication=resolved,
                    send_versions=send_versions, receive_versions=receive_versions)))
            version = prop(instance['version'], path + '/version') if instance.get('version') is not None else Property(
                origin='reset', pointers=[path + '/version_setting'], rule='RIP_VERSION_RESET_NO_RELEASE_DEFAULT') if instance.get('version_setting') == 'reset' else Property()
            send_versions = prop([instance['version']], path + '/version') if instance.get('version') is not None else Property(
                origin='reset', pointers=[path + '/version_setting'], rule='RIP_VERSION_RESET_TO_DOCUMENTED_DEFAULT') if instance.get('version_setting') == 'reset' else Property()
            receive_versions = send_versions
            scopes.append(Scope(protocol='rip', identifier=process.get('identifier') or 'rip', pointer=path, process_pointer=pp,
                afi='ipv4', network_instance=vrf, version=version, send_versions=send_versions, receive_versions=receive_versions, relations=relations,
                network_pointers=[f'{path}/network_statements/{n}' for n, _ in enumerate(instance.get('network_statements') or [])]))
    orphans = []
    candidates = [(a, f'/routing/interface_authentication/{i}/authentication') for i, a in enumerate(c['routing'].get('interface_authentication') or []) if a['protocol'] == 'rip']
    for scope in scopes:
        from normalizer.common.contexts import at
        owner = at(c, scope.pointer)
        candidates += [(a, f'{scope.pointer}/interface_settings/{i}/authentication') for i, a in enumerate(owner.get('interface_settings') or []) if a.get('authentication')]
    for item, path in candidates:
        if path not in used:
            orphans.append(Relation(protocol='rip', subject=item['interface'], subject_kind='reference', status='UNRESOLVED_REFERENCE',
                derivation='explicit', rule='NO_PARTICIPATING_RIP_SCOPE', pointers=[path]))
    return scopes, orphans
