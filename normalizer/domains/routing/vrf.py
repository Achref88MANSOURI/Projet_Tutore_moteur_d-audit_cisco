"""VRF identities, route distinguishers and import/export targets."""
from schemas import normalized_config as s


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
        for direction in ('import', 'export') if v['direction'] == 'both' else (v['direction'],):
            field = 'route_targets_' + direction
            if v['target'] not in getattr(item, field):
                getattr(item, field).append(v['target'])
            state.bind(path + f"/{field}/{getattr(item, field).index(v['target'])}", line)
    elif rule in ('vrf_af', 'vrf_af_exit'):
        state.structural.add(line)
    if rule=='vrf_description':state.assign(item,'description',v['description'],path,line,list(v))



def declare(state,r):
    rule,v,line=r['rule'],r['values'],r['source_line']
    if rule in ('vrf_header', 'vrf_legacy_header'):
        item = s.NetworkInstance(name=v['name'], kind='L3VRF')
        state.c.network_instances.append(item)
        path = f'network_instances/{len(state.c.network_instances) - 1}'
        state.entities[line] = path
        state.bind(path + '/name', line)
        state.bind(path + '/kind', line)
        return True
    return False
