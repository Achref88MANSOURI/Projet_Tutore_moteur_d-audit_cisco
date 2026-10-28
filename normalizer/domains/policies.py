"""Typed route-map clauses and dependency qualification before publication."""
import re
from schemas import normalized_config as s
from normalizer.common.addresses import asn
from normalizer.common.contexts import at


def declare(state, r):
    if r['rule'] != 'policy_header':
        return False
    v, line = r['values'], r['source_line']
    obj = next((p for p in state.c.routing.routing_policies if p.name == v['name']), None)
    if obj is None:
        obj = s.RoutingPolicy(name=v['name'])
        state.c.routing.routing_policies.append(obj)
    obj.statements.append(s.RoutingPolicyStatement(identifier=str(v['sequence']), decision='accept' if v['action'] == 'permit' else 'reject'))
    path = f'routing/routing_policies/{state.c.routing.routing_policies.index(obj)}'
    state.bind(path + '/name', line)
    path += f'/statements/{len(obj.statements) - 1}'
    state.entities[line] = path
    state.bind(path, line)
    return True


def handle(state, r):
    entry = state.entity(r['source_line'])
    if not entry:
        return
    obj, path = entry
    rule, value, line = r['rule'], r['values'].get('value'), r['source_line']
    if rule.startswith('policy_match_'):
        state.defer(r)
        return
    if rule in ('policy_set_localpref', 'policy_set_metric', 'policy_set_weight'):
        kind = {'policy_set_localpref': 'local_preference', 'policy_set_metric': 'metric', 'policy_set_weight': 'cisco_weight'}[rule]
        action = s.NumericPolicyAction(kind=kind, value=int(value))
    elif rule == 'policy_set_aspath':
        action = s.ASPathPolicyAction(kind='as_path_prepend', as_numbers=[asn(token) for token in value.split()])
        if not action.as_numbers:
            return
    elif rule == 'policy_set_community':
        tokens = value.split()
        additive = bool(tokens and tokens[-1] == 'additive')
        members = tokens[:-1] if additive else tokens
        if not members or not all(re.fullmatch(r'\d+:\d+', t) and all(0 <= int(n) <= 65535 for n in t.split(':')) for t in members):
            return
        action = s.CommunityPolicyAction(kind='community', communities=members, additive=additive)
    else:
        return
    obj.actions.append(action)
    state.validation[line]['fields']['value'] = 'validated'
    state.bind(path + f'/actions/{len(obj.actions) - 1}', line, ['value'])


def resolve(state, r):
    kinds = {'policy_match_acl': ('acl', state.c.security.acl_sets, 'ipv4'),
        'policy_match_prefix4': ('prefix_set_ipv4', state.c.routing.prefix_lists, 'ipv4'),
        'policy_match_prefix6': ('prefix_set_ipv6', state.c.routing.prefix_lists, 'ipv6')}
    if r['rule'] not in kinds:
        return
    value = r['values']['value']
    kind, collection, family = kinds[r['rule']]
    if len(value.split()) != 1 or not any(x.name == value and x.family == family for x in collection):
        return
    obj, path = state.entity(r['source_line'])
    obj.matches.append(s.RoutingPolicyMatch(kind=kind, name=value))
    state.validation[r['source_line']]['fields']['value'] = 'validated'
    state.bind(path + f'/matches/{len(obj.matches) - 1}', r['source_line'], ['value'])


def blocked_objects(state):
    """Never publish partial ordered policies, or policies depending on them."""
    incomplete = set()
    for line, node in state.nodes.items():
        if state.is_complete(line) or line in state.structural or node.kind in ('boundary', 'metadata', 'wrapper', 'footer') or node.kind.startswith('opaque') or node.text.startswith('remark '):
            continue
        incomplete.add(state.nodes[node.root].text)
    config = state.c.model_dump(mode='json')
    collections = [
        ('routing/routing_policies', lambda o: [f'route-map {o["name"]} ']),
        ('security/acl_sets', lambda o: [f'ip access-list standard {o["name"]}', f'ip access-list extended {o["name"]}', f'ipv6 access-list {o["name"]}', f'access-list {o["name"]} ']),
        ('routing/prefix_lists', lambda o: [f'{"ipv6" if o["family"] == "ipv6" else "ip"} prefix-list {o["name"]} ']),
        ('qos/class_maps', lambda o: [f'class-map match-all {o["name"]}', f'class-map match-any {o["name"]}']),
        ('qos/policy_maps', lambda o: [f'policy-map {o["name"]}']),
    ]
    blocked = set()
    for collection, prefixes in collections:
        for i, obj in enumerate(at(config, collection)):
            if any(root == prefix or root.startswith(prefix) for root in incomplete for prefix in prefixes(obj)):
                blocked.add('/' + collection + '/' + str(i))
    acl_names = {at(config, path)['name'] for path in blocked if path.startswith('/security/acl_sets/')}
    prefix_names = {at(config, path)['name'] for path in blocked if path.startswith('/routing/prefix_lists/')}
    for collection in ('routing/routing_policies', 'qos/class_maps'):
        for i, obj in enumerate(at(config, collection)):
            matches = [m for statement in obj['statements'] for m in statement['matches']] if collection.startswith('routing') else obj['matches']
            if any((m['kind'] == 'acl' and m.get('name', m.get('value')) in acl_names) or (m['kind'].startswith('prefix_set_') and m.get('name') in prefix_names) for m in matches):
                blocked.add('/' + collection + '/' + str(i))
    classes = {at(config, path)['name'] for path in blocked if path.startswith('/qos/class_maps/')}
    for i, obj in enumerate(config['qos']['policy_maps']):
        if any(c['name'] in classes for c in obj['classes']):
            blocked.add(f'/qos/policy_maps/{i}')
    return blocked
