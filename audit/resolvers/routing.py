"""Public routing foundation entry point, consuming the normalized contract."""
from .routing_common import RoutingResolution, Property, document
from . import eigrp, ospf, rip, bgp


def resolve_routing(contract, *, input_completeness='unknown', platform_family='unknown'):
    if input_completeness not in ('complete', 'partial', 'unknown'):
        raise ValueError('Invalid routing input completeness')
    if platform_family not in ('ios', 'iosxe', 'unknown'):
        raise ValueError('Invalid routing platform family')
    c = document(contract)
    scopes, orphans = [], []
    for resolver in (eigrp.resolve, ospf.resolve, rip.resolve, bgp.resolve):
        resolved, unresolved = resolver(c)
        scopes.extend(resolved)
        orphans.extend(unresolved)
    for i, scope in enumerate(scopes):
        if scope.network_instance is None:
            vrf = Property(status='RESOLVED', origin='derived', pointers=[scope.pointer], rule='GLOBAL_ROUTING_SCOPE')
        else:
            targets = [n for n, v in enumerate(c.get('network_instances') or []) if v['name'] == scope.network_instance]
            vrf = Property(value=scope.network_instance, status='RESOLVED' if targets else 'UNRESOLVED_REFERENCE', origin='configured',
                           pointers=[scope.pointer + '/network_instance'] + [f'/network_instances/{n}/name' for n in targets],
                           rule='VRF_DECLARATION_REFERENCE')
        state = scope.status
        if state == 'RESOLVED' and any(issue['protocol'] in (scope.protocol, 'interface', 'key_chain') for issue in c['routing'].get('integrity_issues') or []):
            state = 'NOT_SUPPORTED'
        if state == 'RESOLVED' and vrf.status != 'RESOLVED':
            state = vrf.status
        relations = [relation.model_copy(update={'status':state, 'rule':relation.rule + '; SCOPE_NOT_RESOLVED'})
                     if relation.status == 'RESOLVED' and state != 'RESOLVED' else relation for relation in scope.relations]
        scopes[i] = scope.model_copy(update={'vrf': vrf, 'status': state, 'relations': relations})
    from .effective_configuration import apply_scope
    scopes = [apply_scope(scope, input_completeness, platform_family) for scope in scopes]
    return RoutingResolution(input_completeness=input_completeness, platform_family=platform_family,
                             scopes=scopes, orphans=orphans,
                             integrity_issues=c['routing'].get('integrity_issues') or [])
