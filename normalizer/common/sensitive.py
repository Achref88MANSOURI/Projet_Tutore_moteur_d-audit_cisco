"""Safe conclusions from active normalizer owners, never raw community values."""


def community_facts(engine, categories):
    active={b.record for b in engine.bindings if b.path.startswith('/system/snmp/communities/')}
    disabled=max((line for line,r in engine.records.items() if r['rule']=='services_snmp_server_disable'
                  and not r['context_lines'] and engine.validation[line]['valid']),default=0)
    facts={}
    from .coverage import summary
    facts['coverage']=summary(engine)
    for suffix,category in [('152','FORBIDDEN_152'),('153','FORBIDDEN_153')]:
        matching={line for line,value in categories.items() if value==category}
        witnesses=[line for line in matching & active if line>disabled]
        removals=[line for line in matching if line in engine.records and
                  engine.records[line]['rule']=='services_snmp_community_remove' and
                  not engine.records[line]['context_lines'] and engine.validation[line]['valid']]
        facts['forbidden_'+suffix+'_active']=True if witnesses else None
        facts['forbidden_'+suffix+'_removed']=bool(removals and not witnesses)
    return facts
