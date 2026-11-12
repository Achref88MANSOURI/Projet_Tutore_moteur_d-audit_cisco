"""Classify routing inventory gaps at the parser boundary, without raw output."""


def domain(node, nodes):
    root = nodes[node.root]
    text = node.text.lower()
    if node.family in ('eigrp', 'ospf', 'bgp'):
        return node.family
    for protocol in ('eigrp', 'ospf', 'bgp'):
        if node.text.startswith(('no router ' + protocol + ' ', 'no ipv6 router ' + protocol + ' ')):
            return protocol
    if root.text == 'router rip' or node.text == 'no router rip':
        return 'rip'
    if root.text.startswith('key chain ') or node.text.startswith('no key chain '):
        return 'key_chain'
    if node.family == 'interfaces':
        # Interface authentication gaps affect only their routing protocol.
        # Known posture-only commands such as Proxy ARP are independent of
        # routing authentication and must not poison every R2 scope.
        if text.startswith(('ip ospf ', 'no ip ospf ', 'default ip ospf ')):
            return 'ospf'
        if text.startswith(('ip rip ', 'no ip rip ', 'default ip rip ')):
            return 'rip'
        if (text.startswith(('ip authentication ', 'no ip authentication ',
                             'default ip authentication ')) and ' eigrp ' in ' ' + text + ' '):
            return 'eigrp'
        if text in ('ip proxy-arp', 'no ip proxy-arp', 'default ip proxy-arp'):
            return None
        return 'interface'
    if node.text.startswith(('no interface ', 'default interface ', 'no vrf definition ', 'no ip vrf ')):
        return 'interface'
    return None


def issues(engine):
    from schemas.router_contract_v1 import RoutingIntegrityIssue
    result = []
    for line, node in engine.nodes.items():
        protocol = domain(node, engine.nodes)
        if not protocol or line in engine.retired or node.kind != 'command':
            continue
        reason = None
        if line not in engine.records:
            reason = 'UNRECOGNIZED'
        elif not engine.validation[line]['valid']:
            reason = 'INVALID'
        elif line in engine.failed or line in engine.uncertain or line in engine.ambiguous:
            reason = 'UNMAPPED'
        elif line in engine.lifecycle_events and engine.lifecycle_events[line][0] in ('unsupported', 'platform_dependent'):
            reason = 'UNSUPPORTED_OPERATION'
        elif (not engine.is_complete(line) and line not in engine.completed_history
              and line not in engine.structural and line not in engine.lifecycle_events):
            reason = 'UNMAPPED'
        if reason:
            result.append(RoutingIntegrityIssue(protocol=protocol, source_line=line, reason=reason))
    return result or None
