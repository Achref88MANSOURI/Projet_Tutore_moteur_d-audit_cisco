"""Allocate only collections being populated by a recognized command."""


def collection(owner, field):
    value = getattr(owner, field)
    if value is None:
        value = []
        setattr(owner, field, value)
    return getattr(owner, field)


def owned_entries(state,owner,field,path):
    """Snapshot leaf ownership before removing/reindexing canonical objects."""
    from .configured import leaves
    result=[]
    bindings={b.path:b.record for b in state.bindings}
    for i,item in enumerate(getattr(owner,field) or []):
        prefix='/'+path.strip('/')+'/'+str(i)
        owners={p[len(prefix)+1:]:bindings[p] for p,_ in leaves(item,prefix) if p in bindings}
        result.append((item,owners))
    return result


def publish_entries(state,owner,field,path,entries):
    """Reproject surviving leaves with their original command owners."""
    prefix='/'+path.strip('/')
    old=getattr(owner,field) or []
    positions={id(item):i for i,(item,_) in enumerate(entries)}
    for line,entity in list(state.entities.items()):
        if isinstance(entity,str) and entity.strip('/').startswith(path.strip('/')+'/'):
            suffix=entity.strip('/')[len(path.strip('/'))+1:].split('/',1)
            index=int(suffix[0])
            if index<len(old) and id(old[index]) in positions:
                state.entities[line]=path.strip('/')+'/'+str(positions[id(old[index])])+('/'+suffix[1] if len(suffix)>1 else '')
            else:state.entities.pop(line)
    state.unbind(prefix)
    state._before={p:v for p,v in state._before.items() if p!=prefix and not p.startswith(prefix+'/')}
    setattr(owner,field,[item for item,_ in entries] or None)
    for i,(_,owners) in enumerate(entries):
        for relative,line in owners.items():state.bind(f'{prefix}/{i}' + ('/' + relative if relative else ''),line)
