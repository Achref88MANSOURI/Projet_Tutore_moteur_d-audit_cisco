"""AAA-02: one declared centralized login chain for at least one observed VTY.

Existential and configuration-only. A positive chain is: VTY -> explicit AAA
login association -> declared login method list -> prioritized named group
method -> declared server group -> declared member server with an interpretable
address. Internal coverage, reachability, shared secrets, fallback behaviour and
effective authentication are out of scope and never inferred.
"""
import re

from ..models import AuditStatus as S
from .logging import _remote_address as _declared_address


def _vty(name):
    # Validate the normalized native identity, not raw CLI or a platform inventory.
    match = re.fullmatch(r'vty ([0-9]+)(?: ([0-9]+))?', name) if isinstance(name, str) else None
    if match is None:
        return False
    start = match[1].lstrip('0') or '0'
    end = (match[2] or match[1]).lstrip('0') or '0'
    # Decimal comparison without an unbounded int() conversion on imported data.
    return (len(start), start) <= (len(end), end)


def _login_lists(method_lists, name):
    """Positions of login lists with this identity; the VTY binds name + login."""
    return [position for position, item in enumerate(method_lists or [])
            if item.name == name and item.service == 'login' and item.privilege_level is None]


def _groups(groups, name):
    """Positions of groups with this exact name; more than one means two protocols."""
    return [position for position, group in enumerate(groups or []) if group.name == name]


def _server_hits(servers, name, protocol):
    """Members are resolved by declared name *and* the group's own protocol."""
    return [position for position, server in enumerate(servers or [])
            if server.name == name and server.protocol == protocol]


def resolve_group(aaa, method, *, allow_generic=False):
    """Resolve canonical method identities for both legacy AAA-02 and CIS.

    Return group/member/server positions, or a safe missing-relation reason.
    Reachability, shared credentials and complete pool inventory are not proved.
    """
    if method.group_protocol is not None:
        if not allow_generic:
            return None, 'generic protocol pool is outside the named-group chain scope'
        usable=[i for i,s in enumerate(aaa.servers or []) if s.protocol==method.group_protocol and s.address is not None and _declared_address(s.address)]
        return ((None,None,usable[0]),None) if usable else (None,'No declared usable server in the referenced protocol pool')
    if not method.group_reference:return None,'Group method has no established reference'
    groups=_groups(aaa.server_groups,method.group_reference)
    if not groups:return None,f'server group {method.group_reference!r} is not declared'
    if len(groups)>1:return None,f'server group {method.group_reference!r} is declared for more than one protocol; the reference is ambiguous'
    gi=groups[0];group=aaa.server_groups[gi]
    if not group.servers:return None,f'server group {group.name!r} declares no member server'
    pairs=[]
    for mi,member in enumerate(group.servers or []):
        hits=_server_hits(aaa.servers,member.name,group.protocol)
        if len(hits)==1:pairs.append((mi,hits[0]))
        if len(hits)==1 and aaa.servers[hits[0]].address is not None and _declared_address(aaa.servers[hits[0]].address):return (gi,mi,hits[0]),None
    if not pairs:return None,f'no member of server group {group.name!r} is declared as a {group.protocol} server'
    return None,f'members of server group {group.name!r} declare no interpretable server address'


def _chain(position, line, aaa):
    """Return (proof, None) for a resolved chain, else (None, missing relation)."""
    auth = line.authentication
    if auth is None:
        return None, f'line {line.name!r} has no established AAA login association'
    if auth.method != 'aaa' or not auth.method_list:
        return None, f"line {line.name!r} does not use an AAA method list (method {auth.method!r})"
    lists = _login_lists(aaa.authentication_method_lists, auth.method_list)
    if not lists:
        return None, (f'line {line.name!r} references login method list {auth.method_list!r}, '
                      'which is not declared in this document')
    if len(lists) > 1:
        return None, f'login method list {auth.method_list!r} is declared more than once'
    index = lists[0]
    item = aaa.authentication_method_lists[index]
    base = ('system', 'aaa', 'authentication_method_lists', str(index))
    if item.local_setting == 'removed':
        return None, f'login method list {auth.method_list!r} is explicitly removed'
    if item.methods is None:
        return None, f'login method list {auth.method_list!r} has no established methods'
    if not item.methods:
        return None, f'login method list {auth.method_list!r} is empty'
    first = item.methods[0]
    if first.method != 'group':
        return None, (f'login method list {auth.method_list!r} does not start with a centralized '
                      f'group method (first method {first.method!r})')
    if first.group_protocol is not None or not first.group_reference:
        return None, (f'login method list {auth.method_list!r} uses the generic '
                      f'{first.group_protocol or "group"} keyword, which is not a resolvable '
                      'named server group')
    resolved,missing=resolve_group(aaa,first)
    if resolved is None:return None,missing
    group_index,member_index,server_index=resolved
    group=aaa.server_groups[group_index]
    members=group.servers
    server = aaa.servers[server_index]
    proof = [
        (('system', 'aaa', 'enabled'), True),
        (('system', 'management', 'lines', str(position), 'name'), line.name),
        (('system', 'management', 'lines', str(position), 'authentication', 'method'), 'aaa'),
        (('system', 'management', 'lines', str(position), 'authentication', 'method_list'),
         auth.method_list),
        (base + ('name',), item.name),
        (base + ('service',), item.service),
        (base + ('methods', '0', 'method'), 'group'),
        (base + ('methods', '0', 'group_reference'), first.group_reference),
        (('system', 'aaa', 'server_groups', str(group_index), 'name'), group.name),
        (('system', 'aaa', 'server_groups', str(group_index), 'protocol'), group.protocol),
        (('system', 'aaa', 'server_groups', str(group_index), 'servers', str(member_index), 'name'),
         members[member_index].name),
        (('system', 'aaa', 'servers', str(server_index), 'name'), server.name),
        (('system', 'aaa', 'servers', str(server_index), 'protocol'), server.protocol),
        (('system', 'aaa', 'servers', str(server_index), 'address'), server.address),
    ]
    return proof, None


def aaa02(aaa, lines):
    """Return (status, proof, detail); proof entries are (pointer parts, value)."""
    if aaa.enabled is False:
        return S.FAIL, [(('system', 'aaa', 'enabled'), False)], ''
    if aaa.enabled is not True:
        return S.NEEDS_REVIEW, [], ('Global AAA activation is unknown or omitted, so no '
                                    'centralized login chain can be established and defaults '
                                    'are not inferred.')
    observed = [(position, line) for position, line in enumerate(lines or []) if _vty(line.name)]
    if not observed:
        return S.NEEDS_REVIEW, [], ('No VTY management line is present in the document; the '
                                    'check is existential and an omitted collection is not a '
                                    'proven absence.')
    unresolved = []
    for position, line in observed:
        proof, detail = _chain(position, line, aaa)
        if proof is not None:
            return S.PASS, proof, ''
        unresolved.append(detail)
    return S.NEEDS_REVIEW, [], 'No positive chain can be established: ' + ' | '.join(unresolved[:3])
