"""Remaining configuration-only CIS Level 2 predicates.

The evaluators consume RouterContractV1 facts only.  They neither parse CLI nor
invent operational state.  A complete supplied configuration may prove a
missing command; SNMPv3 user visibility and external-interface classification
remain explicit source limitations.
"""
from audit.models import AuditStatus as S
from audit.resolvers.effective_configuration import effective_context


def section(value, *path):
    for key in path:
        value = dict.get(value, key) if isinstance(value, dict) else None
    return value


def _qualified(context, family=None):
    effective = effective_context(context)
    return bool(effective and effective.qualifies(family=family))


def _identity(name):
    """Compare native interface names without guessing Cisco abbreviations."""
    return ''.join(str(name or '').split()).casefold()


def _interfaces(raw):
    return section(raw, 'interfaces') or []


def _has_ipv4_address(interface):
    return bool(section(interface, 'ipv4', 'addresses'))


def _loopback_reference(raw, source, source_path):
    matches = [(i, interface) for i, interface in enumerate(_interfaces(raw))
               if _identity(interface.get('name')) == _identity(source)]
    if len(matches) != 1:
        return S.FAIL, [source_path], (
            'Configured source-interface does not resolve to exactly one declared interface')
    index, interface = matches[0]
    base = ['interfaces', str(index)]
    if interface.get('kind') != 'loopback':
        return S.FAIL, [source_path, base + ['kind']], (
            'Configured source-interface resolves to a non-Loopback interface')
    if not _has_ipv4_address(interface):
        return S.FAIL, [source_path, base + ['ipv4', 'addresses']], (
            'Configured Loopback source has no declared IPv4 address')
    return S.PASS, [source_path, base + ['name'], base + ['ipv4', 'addresses']], (
        'Configured source-interface resolves to a declared Loopback with an IPv4 address')


def snmpv3_user_aes(raw, context=None):
    """CIS 1.5.10 partial negative predicate over visible user declarations.

    Cisco does not fully expose persistent SNMPv3 users in running-config, so
    compliant visible users can never establish the universal positive claim.
    An explicitly visible weak or absent privacy algorithm is still decisive.
    """
    base = ['system', 'snmp', 'users']
    users = section(raw, *base) or []
    v3 = [(i, user) for i, user in enumerate(users) if user.get('version') == '3']
    weak = []
    unresolved = []
    accepted = {'aes128', 'aes192', 'aes256'}
    for index, user in v3:
        algorithm = str(user.get('privacy_algorithm') or '').lower().replace('-', '')
        path = base + [str(index), 'privacy_algorithm']
        if algorithm in accepted:
            continue
        if not algorithm or algorithm in {'des', '3des'}:
            weak.append(path)
        else:
            unresolved.append(path)
    if weak:
        return S.FAIL, weak, (
            'A visible SNMPv3 user declaration explicitly lacks AES-128-or-stronger privacy; '
            'credential values remain withheld')
    paths = [base + [str(i), 'privacy_algorithm'] for i, _ in v3]
    if unresolved:
        return S.NEEDS_REVIEW, unresolved, (
            'A visible SNMPv3 user uses a privacy algorithm outside the qualified AES domain')
    if v3:
        return S.NEEDS_REVIEW, paths, (
            'Visible SNMPv3 users use AES-128-or-stronger privacy, but Cisco does not fully '
            'expose persistent SNMPv3 user state in running-config; show snmp user is required '
            'for a universal positive claim')
    return S.NEEDS_REVIEW, base, (
        'No SNMPv3 user declaration is visible; Cisco does not fully expose persistent '
        'SNMPv3 user state in running-config, so absence and compliance are not proven')


def single_loopback(raw, context=None):
    """CIS 2.4.1: exactly one declared Loopback with an IPv4 address."""
    base = ['interfaces']
    loopbacks = [(i, interface) for i, interface in enumerate(_interfaces(raw))
                 if interface.get('kind') == 'loopback']
    if not loopbacks:
        if _qualified(context):
            return S.FAIL, base, 'No Loopback interface is declared in the complete interface inventory'
        return S.NEEDS_REVIEW, base, 'The complete interface inventory is not qualified'
    if len(loopbacks) != 1:
        return S.FAIL, [base + [str(i), 'name'] for i, _ in loopbacks], (
            'More than one Loopback interface is declared; the strict single-Loopback policy is not satisfied')
    index, interface = loopbacks[0]
    path = base + [str(index)]
    if not _has_ipv4_address(interface):
        return S.FAIL, [path + ['name'], path + ['ipv4', 'addresses']], (
            'The single declared Loopback has no configured IPv4 address')
    if not _qualified(context):
        return S.NEEDS_REVIEW, [path + ['name'], path + ['ipv4', 'addresses']], (
            'One addressed Loopback is observed, but the complete interface inventory is not qualified')
    return S.PASS, [path + ['name'], path + ['kind'], path + ['ipv4', 'addresses']], (
        'Exactly one Loopback interface with an IPv4 address is declared')


def _aaa_remote_contexts(raw):
    aaa = section(raw, 'system', 'aaa') or {}
    groups = list(enumerate(aaa.get('server_groups') or []))
    servers = list(enumerate(aaa.get('servers') or []))
    protocols = {item.get('protocol') for _, item in groups + servers
                 if item.get('protocol') in ('radius', 'tacacs')}
    unresolved = []
    for field in ('authentication_method_lists', 'authorization_method_lists', 'accounting_method_lists'):
        for li, method_list in enumerate(aaa.get(field) or []):
            for mi, method in enumerate(method_list.get('methods') or []):
                if method.get('method') != 'group':
                    continue
                if method.get('group_protocol') in ('radius', 'tacacs'):
                    protocols.add(method['group_protocol'])
                    continue
                reference = method.get('group_reference')
                matches = [(gi, group) for gi, group in groups if group.get('name') == reference]
                if len(matches) == 1:
                    protocols.add(matches[0][1]['protocol'])
                else:
                    unresolved.append(['system', 'aaa', field, str(li), 'methods', str(mi), 'group_reference'])
    if aaa.get('radius_source_interface') is not None:
        protocols.add('radius')
    if aaa.get('tacacs_source_interface') is not None:
        protocols.add('tacacs')

    contexts = []
    for protocol in sorted(protocols):
        global_field = protocol + '_source_interface'
        global_source = aaa.get(global_field)
        protocol_groups = [(i, item) for i, item in groups if item.get('protocol') == protocol]
        referenced = {reference.get('name') for _, group in protocol_groups
                      for reference in (group.get('servers') or [])}
        for index, group in protocol_groups:
            contexts.append((group.get('source_interface') or global_source,
                ['system', 'aaa', 'server_groups', str(index), 'source_interface']
                if group.get('source_interface') else ['system', 'aaa', global_field]))
        for index, server in servers:
            if server.get('protocol') != protocol:
                continue
            identity = server.get('name') or server.get('address')
            if identity in referenced:
                continue
            contexts.append((server.get('source_interface') or global_source,
                ['system', 'aaa', 'servers', str(index), 'source_interface']
                if server.get('source_interface') else ['system', 'aaa', global_field]))
        if not protocol_groups and not any(server.get('protocol') == protocol for _, server in servers):
            contexts.append((global_source, ['system', 'aaa', global_field]))
    return protocols, contexts, unresolved


def aaa_source_interfaces(raw, context=None):
    """CIS 2.4.2 over configured RADIUS/TACACS scopes and overrides."""
    protocols, contexts, unresolved = _aaa_remote_contexts(raw)
    base = ['system', 'aaa']
    if not protocols:
        if _qualified(context, 'aaa_servers') and _qualified(context, 'aaa_source_interface'):
            return S.NOT_APPLICABLE, base, (
                'No RADIUS or TACACS configuration exists in the qualified complete AAA inventory')
        return S.NEEDS_REVIEW, base, 'Remote AAA applicability is not established'
    failures = []
    passes = []
    unknowns = list(unresolved)
    qualified = _qualified(context, 'aaa_source_interface')
    for source, path in contexts:
        if source is None:
            (failures if qualified else unknowns).append(path)
            continue
        status, pointers, _ = _loopback_reference(raw, source, path)
        (passes if status == S.PASS else failures).extend(pointers)
    if failures:
        return S.FAIL, failures, (
            'At least one configured remote AAA scope lacks a valid addressed Loopback source-interface')
    if unknowns:
        return S.NEEDS_REVIEW, unknowns + passes, (
            'A remote AAA group/reference or source-interface cannot be resolved completely')
    if not qualified:
        return S.NEEDS_REVIEW, passes, (
            'Observed remote AAA source-interface settings are valid, but command coverage is not qualified')
    return S.PASS, passes, (
        'Every configured RADIUS/TACACS scope resolves through its local override or global fallback '
        'to a declared addressed Loopback')


def ntp_source_interface(raw, context=None):
    """CIS 2.4.3 with per-association source overriding the global source."""
    base = ['system', 'ntp']
    ntp = section(raw, *base) or {}
    associations = list(enumerate(ntp.get('servers') or []))
    configured = bool(associations or ntp.get('source_interface') is not None
                      or ntp.get('authentication_enabled') is not None
                      or ntp.get('authentication_keys') or ntp.get('trusted_keys')
                      or ntp.get('master') is not None)
    if not configured:
        if _qualified(context, 'ntp_servers') and _qualified(context, 'ntp_source'):
            return S.NOT_APPLICABLE, base, 'No NTP service configuration exists in the qualified complete inventory'
        return S.NEEDS_REVIEW, base, 'NTP applicability is not established'
    targets = [(server.get('source_interface') or ntp.get('source_interface'),
                base + ['servers', str(index), 'source_interface']
                if server.get('source_interface') else base + ['source_interface'])
               for index, server in associations]
    if not targets:
        targets = [(ntp.get('source_interface'), base + ['source_interface'])]
    qualified = _qualified(context, 'ntp_source')
    failures = []
    passes = []
    unknowns = []
    for source, path in targets:
        if source is None:
            (failures if qualified else unknowns).append(path)
            continue
        status, pointers, _ = _loopback_reference(raw, source, path)
        (passes if status == S.PASS else failures).extend(pointers)
    if failures:
        return S.FAIL, failures, (
            'At least one configured NTP scope uses no explicit source or a source that is not an addressed Loopback')
    if unknowns or not qualified:
        return S.NEEDS_REVIEW, unknowns + passes, (
            'NTP source-interface coverage is insufficient for a universal decision')
    return S.PASS, passes, (
        'Every configured NTP association resolves its local override or global source to an addressed Loopback')


def tftp_source_interface(raw, context=None):
    """CIS 2.4.4: the benchmark requires an explicit Loopback source."""
    path = ['system', 'file_transfer', 'tftp', 'source_interface']
    source = section(raw, *path)
    if source is None:
        if _qualified(context, 'tftp_source'):
            return S.FAIL, path, (
                'No explicit TFTP source-interface is configured; Cisco otherwise selects an outgoing interface address')
        return S.NEEDS_REVIEW, path, 'TFTP source-interface absence is not qualified'
    return _loopback_reference(raw, source, path)


def no_tunnel_interfaces(raw, context=None):
    """CIS 3.1.3 over configured Tunnel interface declarations only."""
    base = ['interfaces']
    tunnels = [(i, interface) for i, interface in enumerate(_interfaces(raw))
               if interface.get('kind') == 'tunnel']
    if tunnels:
        return S.FAIL, [base + [str(i), 'name'] for i, _ in tunnels], (
            'At least one Tunnel interface is declared; shutdown does not remove the declaration')
    if _qualified(context):
        return S.PASS, base, (
            'No Tunnel interface is declared in the complete configured-interface inventory; '
            'no claim is made about purely operational interfaces')
    return S.NEEDS_REVIEW, base, 'Absence of configured Tunnel interfaces is not qualified'


def strict_urpf(raw, context=None):
    """CIS 3.1.4 partial predicate without guessing external interfaces."""
    base = ['interfaces']
    targets = []
    for index, interface in enumerate(_interfaces(raw)):
        ipv4 = interface.get('ipv4') or {}
        if interface.get('kind') == 'loopback':
            continue
        if not (ipv4.get('addresses') or ipv4.get('unnumbered_interface')
                or ipv4.get('assignment_method')):
            continue
        targets.append((index, interface))
    if not targets:
        return S.NEEDS_REVIEW, base, (
            'No configured IPv4 L3 interface establishes the external/high-risk target set')
    paths = [base + [str(i), 'urpf', 'mode'] for i, _ in targets]
    if all((interface.get('urpf') or {}).get('mode') == 'rx' for _, interface in targets):
        if _qualified(context, 'interface_urpf'):
            return S.PASS, paths, (
                'Strict uRPF is configured on every declared non-Loopback IPv4 L3 interface, '
                'which covers any external/high-risk interface within that configured superset')
        return S.NEEDS_REVIEW, paths, 'Strict uRPF is observed, but interface-command coverage is not qualified'
    return S.NEEDS_REVIEW, paths, (
        'Strict uRPF is not configured on every declared IPv4 L3 interface, while the running-config '
        'does not identify which interfaces are external or high-risk; loose mode is not treated as strict mode')

