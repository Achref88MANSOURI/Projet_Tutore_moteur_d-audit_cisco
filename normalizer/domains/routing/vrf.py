"""VRF identities, route distinguishers and import/export targets."""
from normalizer.common.collections import collection
from schemas import router_contract_v1 as s


def handle(state,r):
    entry = state.entity(r['source_line'])
    if not entry:
        return
    item, path = entry
    rule, v, line = (r['rule'], r['values'], r['source_line'])
    if rule == 'vrf_rd':
        value = v['rd']
        official = state.official_vrfs.get(item.name, {})
        if official.get('rd') == value:
            value = official['rd']
        state.assign(item, 'route_distinguisher', value, path, line)
    elif rule == 'vrf_target' and v['direction'] in ('import', 'export', 'both'):
        family_line = next((n for n in reversed(r['context_lines'])
                            if state.records.get(n, {}).get('rule') == 'vrf_af'), None)
        owner, owner_path = item, path
        if family_line is not None:
            afi = state.records[family_line]['values']['afi']
            owner = family(item, afi)
            owner_path += f'/address_families/{(item.address_families or []).index(owner)}'
            state.bind(owner_path + '/afi', family_line)
        for direction in ('import', 'export') if v['direction'] == 'both' else (v['direction'],):
            field = 'route_targets_' + direction
            targets = collection(owner, field)
            if v['target'] not in targets:
                targets.append(v['target'])
            state.bind(owner_path + f'/{field}/{targets.index(v["target"])}', line)
    elif rule == 'vrf_af':
        obj = family(item, v['afi'])
        state.bind(path + f'/address_families/{(item.address_families or []).index(obj)}/afi', line)
    elif rule == 'vrf_af_exit':
        state.structural.add(line)
    if rule=='vrf_description':state.assign(item,'description',v['description'],path,line,list(v))



def declare(state,r):
    rule,v,line=r['rule'],r['values'],r['source_line']
    if rule in ('vrf_header', 'vrf_legacy_header'):
        item = s.NetworkInstance(name=v['name'], kind='L3VRF')
        collection(state.c, 'network_instances').append(item)
        path = f'network_instances/{len((state.c.network_instances or [])) - 1}'
        state.entities[line] = path
        state.bind(path + '/name', line)
        state.bind(path + '/kind', line)
        return True
    return False


def family(instance, afi):
    items = collection(instance, 'address_families')
    obj = next((f for f in items if f.afi == afi), None)
    if obj is None:
        obj = s.NetworkInstanceAF(afi=afi)
        items.append(obj)
    return obj
