"""VLAN declarations and configured names."""
from schemas import normalized_config as s
from normalizer.common.addresses import vlan_set

def handle(state,r):
    if r["rule"]=="advanced_vlan_name" and state.entity(r["source_line"]):
        obj,path=state.entity(r["source_line"])
        state.assign(obj,"name",r["values"]["name"],path,r["source_line"])


def declare(state,r):
    rule,v,line=r['rule'],r['values'],r['source_line']
    if rule == 'advanced_vlan':
        for identifier in vlan_set(v['vlan']):
            item = s.VLAN(vlan_id=identifier)
            state.c.layer2.vlans.append(item)
            path = f'layer2/vlans/{len(state.c.layer2.vlans) - 1}'
            state.entities[line] = path
            state.bind(path + '/vlan_id', line)
        return True
    return False
