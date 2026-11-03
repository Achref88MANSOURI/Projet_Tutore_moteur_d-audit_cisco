"""Class maps, policy maps, ordered actions and interface attachments."""
from normalizer.common.collections import collection
from schemas import router_contract_v1 as s


def handle(state,r):
    if r["rule"]=="if_service_policy":
        return attachment(state,r)
    rule = r['rule']
    v = r['values']
    line = r['source_line']
    root = state.root(r)
    if root is None:
        return
    if root['rule'] == 'advanced_qos_classmap':
        name = root['values']['name']
        obj = next((state for state in (state.c.qos.class_maps or []) if state.name == name), None)
        if obj is None:
            obj = s.ClassMap(name=name, match_mode=root['values']['mode'])
            collection(state.c.qos, 'class_maps').append(obj)
        path = f'qos/class_maps/{(state.c.qos.class_maps or []).index(obj)}'
        if rule == 'advanced_qos_classmap':
            state.bind(path, line, list(v))
            return
        kind = {'advanced_qos_match_dscp': ('dscp', 'dscp'), 'advanced_qos_match_protocol': ('protocol', 'protocol'), 'advanced_qos_match_precedence': ('precedence', 'precedence'), 'advanced_qos_match_precedence_both': ('precedence', 'precedence'), 'advanced_qos_match_acl': ('acl', 'acl')}.get(rule)
        if kind:
            afi = 'ipv4' if rule == 'advanced_qos_match_precedence' else 'ipv4_ipv6' if rule == 'advanced_qos_match_precedence_both' else None
            collection(obj, 'matches').append(s.QoSMatch(kind=kind[0], value=str(v[kind[1]]), address_family=afi))
            state.bind(path + '/matches', line, list(v))
    elif root['rule'] == 'advanced_qos_policymap':
        name = root['values']['name']
        obj = next((state for state in (state.c.qos.policy_maps or []) if state.name == name), None)
        if obj is None:
            obj = s.PolicyMap(name=name)
            collection(state.c.qos, 'policy_maps').append(obj)
        path = f'qos/policy_maps/{(state.c.qos.policy_maps or []).index(obj)}'
        if rule == 'advanced_qos_policymap':
            state.bind(path, line, list(v))
            return
        class_record = r if rule == 'advanced_qos_class' else next((state.records[n] for n in reversed(r['context_lines']) if state.records.get(n, {}).get('rule') == 'advanced_qos_class'), None)
        if class_record is None:
            return
        name = class_record['values']['name']
        cl = next((c for c in (obj.classes or []) if c.name == name), None)
        if cl is None:
            cl = s.PolicyClass(name=name)
            collection(obj, 'classes').append(cl)
        if rule == 'advanced_qos_class':
            state.bind(path + '/classes', line, list(v))
            return
        action = {'advanced_qos_set_dscp': ('set_dscp', 'dscp'), 'advanced_qos_set_precedence': ('set_precedence', 'precedence'), 'advanced_qos_priority': ('priority_percent', 'percent'), 'advanced_qos_fair': ('fair_queue', 'enabled')}.get(rule)
        if action:
            collection(cl, 'actions').append(s.QoSAction(kind=action[0], value=v[action[1]]))
            state.bind(path + '/classes', line, list(v))



def attachment(state,r):
    if len(r['context_lines'])!=1:return
    entry=state.entity(r['source_line'])
    if not entry:return
    interface=entry[0];v=r['values']
    collection(state.c.qos, 'attachments').append(s.QoSAttachment(policy_name=v['policy'],interface_name=interface.name,direction='ingress' if v['direction']=='input' else 'egress'))
    state.bind(f'qos/attachments/{len((state.c.qos.attachments or []))-1}',r['source_line'])
