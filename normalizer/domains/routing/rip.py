"""RIP global/VRF scopes, network statements and redistribution."""
from ipaddress import IPv4Address
from schemas import normalized_config as s
from normalizer.common.addresses import asn


def handle(state,r):
    rule, v, line = (r['rule'], r['values'], r['source_line'])
    root = state.root(r)
    contexts = [state.nodes[n].text for n in r['context_lines']]
    def put(obj, field, value, path):
        state.assign(obj, field, value, path, line, list(v))
        for key in v:
            state.validation[line]['fields'][key] = 'validated'
    def bind(path):
        state.bind(path,line,list(v))
        for key in v:state.validation[line]['fields'][key]='validated'
    if rule.startswith('catalogue_rip'):
        if rule != 'catalogue_rip' and (not root or root['rule'] != 'catalogue_rip'):
            return True
        if rule == 'catalogue_rip' and contexts:
            return True
        if rule == 'catalogue_rip_family' and contexts != ['router rip']:
            return True
        if rule not in ('catalogue_rip', 'catalogue_rip_family') and (not (contexts == ['router rip'] or (len(contexts) == 2 and contexts[0] == 'router rip' and (state.records.get(r['context_lines'][-1], {}).get('rule') == 'catalogue_rip_family')))):
            return True
        if not state.c.routing.rip:
            state.c.routing.rip.append(s.RIPProcess(declared=True))
        proc = state.c.routing.rip[0]
        obj = proc
        path = 'routing/rip/0'
        family = r if rule == 'catalogue_rip_family' else next((state.records[n] for n in reversed(r['context_lines']) if state.records.get(n, {}).get('rule') == 'catalogue_rip_family'), None)
        if family:
            f = family['values']
            obj = next((x for x in proc.address_families if x.afi == f['afi'] and x.network_instance == f['vrf']), None)
            if obj is None:
                obj = s.RIPFamily(afi=f['afi'], network_instance=f['vrf'])
                proc.address_families.append(obj)
            path += f'/address_families/{proc.address_families.index(obj)}'
        if rule == 'catalogue_rip':
            put(proc, 'declared', v['declared'], 'routing/rip/0')
        elif rule == 'catalogue_rip_family':
            bind(path)
        elif rule == 'catalogue_rip_network':
            obj.network_statements.append(IPv4Address(v['network']))
            bind(path + '/network_statements')
        elif rule == 'catalogue_rip_no_summary':
            put(obj, 'auto_summary', v['enabled'], path)
        elif rule == 'catalogue_rip_redistribute':
            obj.redistributions.append(s.RIPRedistribution(protocol='bgp', source_bgp_as=asn(v['local_as']), metric=v['metric']))
            bind(path + '/redistributions')
        return True

