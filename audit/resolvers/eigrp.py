"""EIGRP configured membership and per-property AF-interface inheritance."""
from .routing_common import (Scope, Relation, Property, prop, local_property, chain_auth,
                             network_match, passive, guarded, interface_identity)


def resolve(c):
    scopes, used = [], set()
    for p, process in enumerate(c['routing'].get('eigrp') or []):
        process_path = f'/routing/eigrp/{p}'
        instances = [(process, process_path)] if process.get('mode') == 'classic' else []
        instances += [(f, f'{process_path}/address_families/{i}') for i, f in enumerate(process.get('address_families') or [])]
        for instance, path in instances:
            afi, vrf, asn = instance.get('afi'), instance.get('network_instance'), instance.get('autonomous_system')
            networks = [(s, f'{path}/networks/{i}') for i, s in enumerate(instance.get('networks') or [])]
            for t, topology in enumerate(instance.get('topologies') or []):
                if topology['name'] == 'base':
                    networks += [(s, f'{path}/topologies/{t}/networks/{i}') for i, s in enumerate(topology.get('networks') or [])]
            settings = {interface_identity(s['interface']): (s, f'{path}/interface_settings/{i}') for i, s in enumerate(instance.get('interface_settings') or [])}
            default, default_path = settings.get('default', ({}, ''))
            relations = []
            for n, interface in enumerate(c.get('interfaces') or []):
                if interface.get('vrf') != vrf:
                    continue
                name, ipath = interface['name'], f'/interfaces/{n}'
                local, local_path = settings.get(interface_identity(name), ({}, ''))
                classic = [(i, s) for i, s in enumerate(c['routing'].get('eigrp_interfaces') or []) if
                           s['interface'] == name and s['afi'] == afi and s['autonomous_system'] == asn and s.get('network_instance') == vrf]
                if process['mode'] == 'classic' and classic:
                    i, local = classic[0]
                    local_path = f'/routing/eigrp_interfaces/{i}'
                matches = [(s, sp, addresses) for s, sp in networks if (addresses := network_match(interface, s))] if afi == 'ipv4' else []
                explicit6 = afi == 'ipv6' and process['mode'] == 'classic' and local.get('enabled') is not None
                named6 = afi == 'ipv6' and process['mode'] == 'named' and bool((interface.get('ipv6') or {}).get('addresses') or (interface.get('ipv6') or {}).get('enabled'))
                if not matches and not explicit6 and not named6:
                    continue
                if classic:
                    used.add(classic[0][0])
                pointers = [ipath + '/name', path]
                pointers += [sp for _, sp, _ in matches]
                pointers += [ipath + f'/ipv4/addresses/{i}/address' for _, _, addresses in matches for i, _ in addresses]
                mode = local_property(local.get('authentication'), local_path + '/authentication', 'method', 'mode_setting')
                chain = local_property(local.get('authentication'), local_path + '/authentication', 'key_chain_reference', 'key_chain_setting')
                if process['mode'] == 'named':
                    if mode.origin == 'unknown':
                        mode = local_property(default.get('authentication'), default_path + '/authentication', 'method', 'mode_setting', inherited=True)
                    if chain.origin == 'unknown':
                        chain = local_property(default.get('authentication'), default_path + '/authentication', 'key_chain_reference', 'key_chain_setting', inherited=True)
                is_passive = prop(local['passive'], local_path + '/passive') if local.get('passive') is not None else prop(default['passive'], default_path + '/passive', origin='inherited') if default.get('passive') is not None else passive(instance, path, name)
                # IPv6 named automatic enabling remains platform-qualified until
                # an explicit per-interface setting supplies the required proof.
                status = 'PLATFORM_DEPENDENT' if named6 and local.get('enabled') is None else 'RESOLVED'
                rule = 'EIGRP_IPV4_PRIMARY_NETWORK_MATCH' if afi == 'ipv4' else 'EIGRP_IPV6_INTERFACE_CONFIGURATION'
                auth = chain_auth(c, mode, chain)
                enabled = prop(local['enabled'], local_path + '/enabled') if local.get('enabled') is not None else prop(default['enabled'], default_path + '/enabled', origin='inherited') if default.get('enabled') is not None else Property()
                relations.append(guarded(c, Relation(protocol='eigrp', subject=name, status=status,
                    rule=rule, pointers=list(dict.fromkeys(pointers)), passive=is_passive, authentication=auth,
                    enabled=enabled,
                    derivation='explicit' if explicit6 else 'derived')))
            scopes.append(Scope(protocol='eigrp', identifier=str(process.get('name') or process.get('autonomous_system')),
                pointer=path, process_pointer=process_path, afi=afi, safi=instance.get('safi'), autonomous_system=asn,
                network_instance=vrf, enabled=prop(instance['enabled'], path + '/enabled') if instance.get('enabled') is not None else Property(),
                network_pointers=[sp for _, sp in networks], relations=relations))
    orphans = [Relation(protocol='eigrp', subject=s['interface'], subject_kind='reference', status='UNRESOLVED_REFERENCE',
                       derivation='explicit', rule='NO_PARTICIPATING_EIGRP_SCOPE', pointers=[f'/routing/eigrp_interfaces/{i}'])
               for i, s in enumerate(c['routing'].get('eigrp_interfaces') or []) if i not in used]
    interfaces = {interface_identity(i['name']) for i in c.get('interfaces') or []}
    from normalizer.common.contexts import at
    for scope in scopes:
        for n, item in enumerate(at(c, scope.pointer).get('interface_settings') or []):
            if item['interface'] != 'default' and interface_identity(item['interface']) not in interfaces:
                orphans.append(Relation(protocol='eigrp', subject=item['interface'], subject_kind='reference', status='UNRESOLVED_REFERENCE',
                    derivation='explicit', rule='EIGRP_AF_INTERFACE_TARGET_MISSING', pointers=[f'{scope.pointer}/interface_settings/{n}']))
    return scopes, orphans
