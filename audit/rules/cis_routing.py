"""Seventeen scoped configuration predicates over the R2 graph. No Cisco CLI.

FAIL witnesses are collected before uncertainty is aggregated. Effective R2
properties may carry documented Cisco defaults or proven absence, but no rule
parses CLI or claims an operational adjacency.
"""
from dataclasses import dataclass, field
from audit.models import AuditStatus as S
from audit.resolvers.routing import resolve_routing
from normalizer.common.contexts import at

CONTROL_IDS = tuple([f'3.3.1.{i}' for i in range(1, 10)] +
                    [f'3.3.2.{i}' for i in range(1, 3)] +
                    [f'3.3.3.{i}' for i in range(1, 6)] + ['3.3.4.1'])


@dataclass
class RoutingContext:
    graph: object


@dataclass
class Decisions:
    observations: list = field(default_factory=list)

    def add(self, status, pointers, reason):
        self.observations.append((status, list(dict.fromkeys(pointers)), reason))

    def finish(self):
        # A confirmed local violation survives a separate unknown object.
        failures = [o for o in self.observations if o[0] == S.FAIL]
        unknowns = [o for o in self.observations if o[0] == S.NEEDS_REVIEW]
        selected = failures or unknowns or self.observations
        if not selected:
            return S.NEEDS_REVIEW, [], 'Routing applicability is not demonstrated; no applicable resolved target. No vacuous PASS.'
        status = S.FAIL if failures else S.NEEDS_REVIEW if unknowns else S.PASS
        paths = list(dict.fromkeys(p for o in selected for p in o[1]))
        reasons = list(dict.fromkeys(o[2] for o in selected))
        # Reasons contain rule names only, never native identifiers or secrets.
        detail = '; '.join(reasons)
        if failures and unknowns:
            detail += '; other targets remain indeterminate; confirmed violation takes precedence'
        if status == S.PASS:
            detail += '; scoped supplied-configuration predicate only; no operational or temporal usability claim'
        return status, [p.lstrip('/').split('/') for p in paths], detail


def _event(raw, kind, identity=None, selector=None):
    """Return real normalized deletion pointers, never synthesize a source line."""
    result = []
    for i, e in enumerate(raw.get('configuration_changes') or []):
        if e['kind'] != kind or e['operation'] not in ('removed', 'reset'):
            continue
        if identity is not None and e.get('identity') != identity:
            continue
        if selector and any((e.get('selector') or {}).get(k) != v for k, v in selector.items()):
            continue
        # Child tombstones belong to their parent generation. An old key/AF
        # removal cannot condemn an empty parent deleted then re-created later.
        parent = e.get('identity') or []
        ancestor_kinds = ('lifecycle_key_chain',) if kind == 'lifecycle_key' else (
            'lifecycle_eigrp', 'lifecycle_eigrp_af', 'lifecycle_eigrp_af_safi',
            'lifecycle_eigrp_af_vrf', 'lifecycle_eigrp_af_safi_vrf') if kind == 'eigrp_af_interface_remove' else ()
        def ancestor_removal(later):
            if (later['kind'] not in ancestor_kinds or later['operation'] != 'removed'
                    or (later.get('identity') or []) != parent[:2]):
                return False
            if kind == 'eigrp_af_interface_remove' and later['kind'] != 'lifecycle_eigrp':
                s = later.get('selector') or {}
                return [s.get('afi'), s.get('safi') or 'unicast', str(s.get('vrf')), str(s.get('autonomous_system'))] == parent[3:7]
            return True
        if any(ancestor_removal(later) for later in (raw.get('configuration_changes') or [])[i+1:]):
            continue
        result.append(f'/configuration_changes/{i}')
    return result


def _property(decisions, value, accepted, description, context_pointers=()):
    # A selector such as OSPF key-chain, or a native method classified "other",
    # is not an established incompatible algorithm. Keep a closed negative set.
    incompatible = {False} if accepted == {True} else {'tcp_ao', 'none'} if accepted == {'tcp_md5'} else {'none', 'plaintext', 'text', 'hmac-sha-256'}
    if value.status != 'RESOLVED':
        decisions.add(S.NEEDS_REVIEW, value.pointers or context_pointers, description + ': property unresolved')
    elif value.origin == 'removed' or value.value in incompatible:
        origin = (f'documented Cisco default {value.reference_id}' if value.origin == 'documented_default'
                  else 'proven absence' if value.origin == 'proven_absent' else 'explicit incompatible or removed setting')
        decisions.add(S.FAIL, value.pointers or context_pointers, f'{description}: {origin}; {value.rule}')
    elif value.value in accepted:
        decisions.add(S.PASS, value.pointers or context_pointers, description + ': configured or inherited requirement demonstrated')
    else:
        decisions.add(S.NEEDS_REVIEW, value.pointers or context_pointers, description + ': required value unavailable or method outside qualified domain')


def _chain(raw, decisions, auth, requirement, context_pointers=()):
    chain = auth.key_chain
    if chain.origin == 'proven_absent':
        label = {'chain': 'key-chain association or declaration',
                 'key': 'key declaration in the required key-chain',
                 'secret': 'key-string in the required key-chain'}[requirement]
        decisions.add(S.FAIL, chain.pointers or context_pointers,
                      f'Required {label} is proven absent for an applicable routing relation; '
                      f'{chain.rule}; {chain.reference_id}')
        return
    if chain.origin == 'removed' and chain.status == 'RESOLVED':
        decisions.add(S.FAIL, chain.pointers, 'Required key-chain reference explicitly removed')
        return
    if chain.status != 'RESOLVED' or chain.value is None:
        # A deleted target still matters only when this live relation references it.
        removed = _event(raw, 'lifecycle_key_chain', ['key_chain', str(chain.value)]) if chain.value is not None else []
        decisions.add(S.FAIL if removed and chain.status == 'UNRESOLVED_REFERENCE' else S.NEEDS_REVIEW,
                      chain.pointers + removed or list(context_pointers), 'Referenced chain explicitly deleted' if removed else 'Key-chain reference or declaration unresolved')
        return
    if requirement == 'chain':
        decisions.add(S.PASS, chain.pointers, 'Participating interface references a declared key-chain')
        return
    if not auth.keys:
        removed = _event(raw, 'lifecycle_key', ['key_chain', str(chain.value)])
        proven = auth.key_presence.origin == 'proven_absent'
        fail = bool(removed) or proven and requirement in ('key', 'secret')
        reason = ('All declared chain keys explicitly deleted' if removed else
                  'Key declaration proven absent in complete referenced chain; required key-string cannot exist' if fail and requirement == 'secret' else
                  'Key declaration proven absent in complete referenced chain' if fail else
                  'No declared child key target exists; key-string requirement remains indeterminate')
        decisions.add(S.FAIL if fail else S.NEEDS_REVIEW, chain.pointers + removed or list(context_pointers), reason)
        return
    for key in auth.keys:
        if key.identifier is None:
            decisions.add(S.NEEDS_REVIEW, [key.pointer], 'Key identifier unavailable')
        elif requirement == 'key':
            decisions.add(S.PASS, [key.pointer + '/identifier'], 'Referenced chain declares a key identifier')
        else:
            status = S.PASS if key.secret_configured is True else S.FAIL if key.secret_configured is False else S.NEEDS_REVIEW
            decisions.add(status, [key.pointer + '/identifier'] + ([key.pointer + '/secret_configured'] if key.secret_configured is not None else []),
                          'Declared key secret presence demonstrated' if status == S.PASS else
                          'Declared key secret proven absent in complete key scope' if key.secret_origin == 'proven_absent' else
                          'Declared key secret explicitly removed' if status == S.FAIL else 'Declared key secret presence unknown')


def _absence_qualified(graph, protocol):
    if graph.input_completeness != 'complete' or graph.platform_family not in ('ios', 'iosxe'):
        return False
    return not any(issue.protocol in (protocol, 'interface', 'key_chain') for issue in graph.integrity_issues)


def _protocol_inventory_qualified(graph, protocol):
    """Whether absence of a protocol/variant can establish applicability.

    An unrelated interface or key-chain gap must not manufacture a routing
    process, nor keep every absent protocol indeterminate. A gap attributed
    to the protocol itself still prevents a negative inventory claim.
    """
    if graph.input_completeness != 'complete' or graph.platform_family not in ('ios', 'iosxe'):
        return False
    return not any(issue.protocol == protocol for issue in graph.integrity_issues)


def _eigrp_variant(control_id):
    number = int(control_id.split('.')[-1])
    if number in (4, 5, 6, 7):
        return 'named'
    if number in (8, 9):
        return 'classic'
    return None


def _not_applicable_reason(raw, graph, control_id):
    """Return a qualified control-specific non-applicability reason.

    This deliberately handles only an absent routing protocol and the unused
    EIGRP syntax. Missing children of an applicable process remain obligations
    evaluated by the normal predicates below.
    """
    protocol = {'1':'eigrp', '2':'ospf', '3':'rip', '4':'bgp'}[control_id.split('.')[2]]
    processes = ((raw.get('routing') or {}).get(protocol) or [])
    if not processes:
        if _protocol_inventory_qualified(graph, protocol):
            return (
                f'No {protocol.upper()} process is configured in the qualified complete '
                'routing-process inventory; this protocol-specific control has no target')
        return None
    variant = _eigrp_variant(control_id) if protocol == 'eigrp' else None
    if variant and not any(process.get('mode') == variant for process in processes):
        if _protocol_inventory_qualified(graph, protocol):
            return (
                f'EIGRP is configured, but no {variant} process exists in the qualified '
                'complete inventory; this syntax-specific control has no target')
    return None


def _scopes(raw, graph, protocol, variant=None):
    result = []
    for scope in graph.scopes:
        if scope.protocol != protocol:
            continue
        if protocol == 'eigrp':
            process = at(raw, scope.process_pointer)
            if variant and process.get('mode') != variant:
                continue
        result.append(scope)
    return result


def _scope_guard(decisions, scope):
    if scope.status != 'RESOLVED':
        decisions.add(S.NEEDS_REVIEW, [scope.pointer], 'Routing scope unresolved: ' + scope.status)
        return False
    return True


def _relations(raw, graph, decisions, protocol, variant=None):
    scopes = _scopes(raw, graph, protocol, variant)
    if protocol == 'eigrp' and variant != 'classic':
        for i, process in enumerate(raw['routing'].get('eigrp') or []):
            pp = f'/routing/eigrp/{i}'
            if process.get('mode') == 'named' and not any(s.process_pointer == pp for s in scopes):
                decisions.add(S.NEEDS_REVIEW, [pp+'/mode'], 'Named EIGRP process has no resolved AF applicability')
    for scope in scopes:
        if not _scope_guard(decisions, scope):
            continue
        if protocol in ('eigrp', 'ospf') and (scope.afi != 'ipv4' or protocol == 'eigrp' and scope.safi not in (None, 'unicast')):
            decisions.add(S.NEEDS_REVIEW, [scope.pointer], 'Variant outside this IPv4 predicate')
            continue
        if protocol == 'eigrp':
            # R2 resolves base topology only. Other declared topologies must not
            # disappear from the universal obligation, even when the base
            # members satisfy it. Do not implement another membership resolver.
            for i, topology in enumerate(at(raw, scope.pointer).get('topologies') or []):
                if topology['name'] != 'base':
                    decisions.add(S.NEEDS_REVIEW, [scope.pointer+f'/topologies/{i}/name'],
                                  'EIGRP topology outside validated membership domain; universal target coverage unknown')
        if not scope.relations:
            # RIP often has an intentionally empty global shell containing VRF AFs.
            owner = at(raw, scope.pointer)
            if protocol == 'rip' and scope.pointer == scope.process_pointer and owner.get('address_families') and not scope.network_pointers and not owner.get('interface_settings'):
                continue
            if protocol == 'bgp' and scope.pointer == scope.process_pointer and owner.get('address_families'):
                continue
            decisions.add(S.NEEDS_REVIEW, [scope.pointer], 'No participating target demonstrated for configured scope')
        for relation in scope.relations:
            if relation.status != 'RESOLVED':
                decisions.add(S.NEEDS_REVIEW, relation.pointers, 'Routing relation unresolved: ' + relation.status)
                continue
            if protocol == 'rip':
                versions = (relation.send_versions, relation.receive_versions)
                if any(value.status != 'RESOLVED' or not isinstance(value.value, list) for value in versions):
                    decisions.add(S.NEEDS_REVIEW, [p for value in versions for p in value.pointers] + relation.pointers,
                                  'RIPv2 applicability unknown; effective send/receive versions are unresolved')
                    continue
                if 2 not in set(relation.send_versions.value + relation.receive_versions.value):
                    continue
            yield scope, relation


def _named_structure(raw, graph, decisions, default=False):
    for i, process in enumerate(raw['routing'].get('eigrp') or []):
        if process.get('mode') != 'named':
            continue
        pp = f'/routing/eigrp/{i}'
        scopes = [s for s in graph.scopes if s.process_pointer == pp and s.afi == 'ipv4' and s.safi in (None, 'unicast')]
        if not scopes:
            changes = raw.get('configuration_changes') or []
            removed = [f'/configuration_changes/{j}' for j, event in enumerate(changes)
                       if event['kind'].startswith('lifecycle_eigrp_af') and event['operation'] == 'removed'
                       and (event.get('identity') or [])[:2] == ['eigrp', process['name']]
                       and (event.get('selector') or {}).get('afi') == 'ipv4'
                       and not any(e['kind'] == 'lifecycle_eigrp' and e.get('identity') == ['eigrp', process['name']]
                                   for e in changes[j+1:])]
            proven = _absence_qualified(graph, 'eigrp')
            decisions.add(S.FAIL if removed or proven else S.NEEDS_REVIEW, [pp+'/mode'] + removed,
                          'Last named IPv4 AF explicitly removed' if removed else
                          'Named IPv4 AF proven absent in complete qualified scope' if proven else 'No named IPv4 AF demonstrated')
        for scope in scopes:
            if not _scope_guard(decisions, scope):
                continue
            if scope.autonomous_system is None:
                decisions.add(S.NEEDS_REVIEW, [scope.pointer], 'Named AF autonomous system unavailable')
            elif not default:
                decisions.add(S.PASS, [pp+'/mode', scope.pointer+'/afi', scope.pointer+'/autonomous_system'], 'Named IPv4 AF and autonomous system demonstrated')
            else:
                owner = at(raw, scope.pointer)
                matches = [j for j, s in enumerate(owner.get('interface_settings') or []) if s['interface'] == 'default']
                if len(matches) == 1:
                    decisions.add(S.PASS, [scope.pointer+f'/interface_settings/{matches[0]}/interface'], 'AF-interface default declared in applicable named scope')
                else:
                    selector = {'interface': 'default'}
                    # The event identity holds the exact AF owner and selector.
                    expected = ['eigrp', process['name'], 'address_family', scope.afi, scope.safi or 'unicast',
                                str(scope.network_instance), str(scope.autonomous_system)]
                    removed = _event(raw, 'eigrp_af_interface_remove', expected, selector)
                    proven = _absence_qualified(graph, 'eigrp')
                    decisions.add(S.FAIL if removed or proven else S.NEEDS_REVIEW, [scope.pointer] + removed,
                                  'AF-interface default explicitly removed' if removed else
                                  'AF-interface default proven absent in complete qualified scope' if proven else 'AF-interface default not demonstrated')


def _ospf_area(raw, graph, decisions):
    for scope in _scopes(raw, graph, 'ospf'):
        # This control's local catalogue audit is the literal area policy.
        # A separate interface override belongs to 3.3.2.2 and must not turn a
        # demonstrated area declaration into a failure here.  A routing gap
        # still prevents proof of an absent policy through _absence_qualified.
        if scope.afi != 'ipv4':
            continue
        process = at(raw, scope.pointer)
        from audit.resolvers.routing_common import local_property
        areas = process.get('areas') or []
        if not areas:
            decisions.add(S.FAIL if _absence_qualified(graph, 'ospf') else S.NEEDS_REVIEW, [scope.pointer],
                          'OSPF area MD5 policy proven absent in complete qualified scope' if _absence_qualified(graph, 'ospf') else 'OSPF area policy unavailable')
        for i, area in enumerate(areas):
            path = f'{scope.pointer}/areas/{i}/authentication'
            value = local_property(area.get('authentication'), path, 'method', 'mode_setting')
            if value.status == 'UNKNOWN' and _absence_qualified(graph, 'ospf'):
                from audit.resolvers.effective_configuration import documented_default
                value = documented_default('none', 'ospf', 'OSPF_AREA_DEFAULT_NULL')
            _property(decisions, value, {'message_digest'}, 'OSPF area MD5 policy', [scope.pointer])
        required = {n['area'] for n in process.get('network_statements') or []}
        required.update(r.area for r in scope.relations if r.area is not None)
        if required - {a['area_id'] for a in areas}:
            decisions.add(S.FAIL if _absence_qualified(graph, 'ospf') else S.NEEDS_REVIEW, scope.network_pointers or [scope.pointer],
                          'A declared or resolved OSPF area has no MD5 area policy in the complete qualified scope' if _absence_qualified(graph, 'ospf') else
                          'A declared or resolved OSPF area has no demonstrated area policy')


def applicability(raw, graph, control_id):
    protocol = {'1':'eigrp', '2':'ospf', '3':'rip', '4':'bgp'}[control_id.split('.')[2]]
    number = int(control_id.split('.')[-1])
    if _not_applicable_reason(raw, graph, control_id):
        return 'NOT_APPLICABLE'
    scopes = _scopes(raw, graph, protocol,
        'named' if protocol == 'eigrp' and number in (6, 7) else
        'classic' if protocol == 'eigrp' and number in (8, 9) else None)
    if not scopes:
        # A configured process without a resolved scope is not equivalent to
        # an absent protocol. Its applicability remains unresolved.
        return 'APPLICABILITY_UNKNOWN'
    resolved = [scope for scope in scopes if scope.status == 'RESOLVED']
    if not resolved:
        return 'APPLICABILITY_UNKNOWN'
    if protocol == 'ospf' and number == 1:
        return 'APPLICABLE'
    relations = [relation for scope in resolved for relation in scope.relations]
    if protocol == 'rip':
        if any(relation.applicability == 'APPLICABLE' and relation.send_versions.status == 'RESOLVED' and
               relation.receive_versions.status == 'RESOLVED' and
               2 in set(relation.send_versions.value + relation.receive_versions.value) for relation in relations):
            return 'APPLICABLE'
        if relations and all(relation.applicability == 'NOT_APPLICABLE' for relation in relations):
            return 'NOT_APPLICABLE'
    if any(relation.status == 'RESOLVED' for relation in relations):
        return 'APPLICABLE'
    return 'APPLICABILITY_UNKNOWN' if relations or any(scope.relations for scope in scopes) else 'NOT_APPLICABLE'


def evaluate(raw, control, context=None):
    cid = control['id']
    graph = context.graph if isinstance(context, RoutingContext) else resolve_routing(raw)
    d = Decisions()
    protocol = {'1':'eigrp', '2':'ospf', '3':'rip', '4':'bgp'}[cid.split('.')[2]]
    number = int(cid.split('.')[-1])
    not_applicable = _not_applicable_reason(raw, graph, cid)
    if not_applicable:
        return S.NOT_APPLICABLE, [], not_applicable
    if protocol == 'eigrp' and number in (4, 5):
        _named_structure(raw, graph, d, default=number == 5)
    elif protocol == 'ospf' and number == 1:
        _ospf_area(raw, graph, d)
    else:
        variant = 'named' if protocol == 'eigrp' and number in (6, 7) else 'classic' if protocol == 'eigrp' and number in (8, 9) else None
        for scope, relation in _relations(raw, graph, d, protocol, variant):
            auth = relation.authentication
            if protocol in ('eigrp', 'rip'):
                if number in (7, 9) and protocol == 'eigrp' or number == 5 and protocol == 'rip':
                    _property(d, auth.mode, {'md5', 'message_digest'}, 'Effective MD5 authentication mode', relation.pointers)
                else:
                    _chain(raw, d, auth, {1:'chain', 2:'key', 3:'secret'}.get(number, 'chain'), relation.pointers)
            elif protocol == 'ospf':
                _property(d, auth.mode, {'message_digest'}, 'OSPF member effective MD5 mode', relation.pointers)
                # OSPF R2 keys can include plaintext. Only native MD5 keys count.
                keys = [k for k in auth.keys if (at(raw, k.pointer) or {}).get('kind') == 'message_digest' and
                        (at(raw, k.pointer) or {}).get('algorithm') == 'md5']
                good = [k for k in keys if k.identifier is not None and k.secret_configured is True]
                if good:
                    d.add(S.PASS, [p for k in good for p in (k.pointer+'/key_id', k.pointer+'/secret_configured')], 'OSPF participating interface declares an MD5 key and secret')
                elif keys and all(k.secret_configured is False for k in keys):
                    d.add(S.FAIL, [k.pointer+'/secret_configured' for k in keys], 'All interface MD5 keys explicitly removed')
                else:
                    d.add(S.FAIL if _absence_qualified(graph, 'ospf') else S.NEEDS_REVIEW, relation.pointers,
                          'MD5 interface key proven absent in complete qualified OSPF scope' if _absence_qualified(graph, 'ospf') else
                          'No configured MD5 key demonstrated on participating interface')
            else:
                _property(d, auth.secret, {True}, 'BGP effective password presence', relation.pointers)
                _property(d, auth.mode, {'tcp_md5'}, 'BGP effective TCP-MD5 method', relation.pointers)
    # Guards are additional unknown obligations. They never hide a different
    # established FAIL witness. Orphans do not satisfy a target obligation.
    for orphan in graph.orphans:
        if orphan.protocol == protocol:
            d.add(S.NEEDS_REVIEW, orphan.pointers, 'Orphan routing reference prevents positive claim')
    for i, issue in enumerate(graph.integrity_issues):
        if issue.protocol in (protocol, 'interface', 'key_chain'):
            d.add(S.NEEDS_REVIEW, [f'/routing/integrity_issues/{i}'], 'Relevant routing syntax or semantic coverage gap')
    return d.finish()


def _make(cid):
    def evaluator(raw, control, context=None):
        return evaluate(raw, control, context)
    evaluator.__name__ = '_eval_' + cid.replace('.', '_')
    evaluator.__qualname__ = evaluator.__name__
    evaluator.__doc__ = 'R3 configuration predicate for CIS ' + cid
    return evaluator


EVALUATORS = {cid: _make(cid) for cid in CONTROL_IDS}
globals().update({fn.__name__: fn for fn in EVALUATORS.values()})
