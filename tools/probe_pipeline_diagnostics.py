"""Controlled, in-memory observations. No production template or mapper edits."""
from collections import Counter
import ast
import json
from pathlib import Path
import sys
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from ttp import ttp
import parser.run_ttp as runtime
from normalizer.mapping import Mapper
from parser.coverage import build_coverage
from normalizer.validation import validate

OUT=ROOT/'outputs/diagnostic_pipeline'


def convert(text):
    x=runtime.extract(text,official=False)
    mapper=Mapper(x,text,'diagnostic-fixture.cfg','ios')
    normalized=mapper.run();validate(normalized.model_dump(mode='json'))
    return x,normalized,build_coverage(x,mapper)


def main():
    OUT.mkdir(parents=True,exist_ok=True)
    probes=[]
    variants=[
        ('numbered_match_set','1 shutdown\n','{{ source_line | DIGIT | to_int }} shutdown {{ enabled | set(False) }}',''),
        ('plain_match_set','shutdown\n','shutdown {{ enabled | set(False) }}',''),
        ('numbered_group_set','1 shutdown\n','{{ source_line | DIGIT | to_int }} shutdown',' set="False, enabled"'),
    ]
    for name,data,pattern,attrs in variants:
        engine=ttp(data=data,template=f'<group name="result*" method="table"{attrs}>\n{pattern}\n</group>')
        engine.parse(one=True);value=engine.result()[0][0]['result'][0]
        expected={'source_line':1} if name=='numbered_match_set' else {'enabled':False} if name=='plain_match_set' else {'source_line':1,'enabled':False}
        assert value==expected
        probes.append(dict(id=name,scope='isolated_diagnostic_template_only',data=data,pattern=pattern,
            group_attributes=attrs,observed=value,observation_confirmed=True,
            interpretation='Controlled comparison: adding the source-line placeholder breaks match-level set constant materialization; group-level set keeps the constant.'))
    x,n,c=convert('interface Ethernet1\n speed potato\n')
    assert x['records'][2]['values']['speed']=='potato'
    probes.append(dict(id='untyped_speed',scope='synthetic_not_corpus',observed=x['records'][2]['values'],
        observation_confirmed=True,interpretation='The template captures a token without validating that it is a Cisco speed value; it remains unmapped.'))
    x,n,c=convert('interface Ethernet1\n mtu 1\n')
    assert x['records'][2]['values']['mtu']==1 and c['commands'][1]['status']=='invalid_value'
    probes.append(dict(id='mtu_range_guard',scope='synthetic_not_corpus',observed=dict(captured=1,status='invalid_value'),
        observation_confirmed=True,interpretation='DIGIT captures the integer; Pydantic range validation rejects it and preserves the command.'))
    x,n,c=convert('ip access-list extended FILTER\n permit madeup-protocol any any\n')
    protocol=n.configuration.security.acl_sets[0].entries[0].protocol
    assert protocol=='madeup-protocol'
    probes.append(dict(id='acl_protocol_not_domain_validated',scope='synthetic_not_corpus',
        observed=dict(native_protocol=x['records'][2]['values']['protocol'],normalized_protocol=protocol),
        observation_confirmed=True,interpretation='An arbitrary protocol token passes this template and the open string field in the contract. Type/schema validity does not establish IOS semantic validity.'))
    x,n,c=convert('router bgp 65000\n neighbor 192.0.2.1 remote-as 65001\n neighbor 192.0.2.1 route-map FILTER sideways\n')
    row=next(r for r in c['commands'] if r['line']==3)
    assert row['status']=='normalized_values' and n.configuration.routing.bgp[0].neighbors[0].import_policies==[]
    probes.append(dict(id='partial_command_status',scope='synthetic_not_corpus',
        observed=dict(native_direction=x['records'][3]['values']['direction'],status=row['status'],paths=row['normalized_paths'],
            import_policies=n.configuration.routing.bgp[0].neighbors[0].import_policies),observation_confirmed=True,
        interpretation='The peer field is proved before direction validation. normalized_values means at least one mapped field, not full interpretation of this command. This observation is not attributed to any real corpus command.'))
    x,n,c=convert('interface Ethernet1\n unknown vendor-command\n ip address 192.0.2.1 255.255.255.0\n')
    assert str(n.configuration.interfaces[0].ipv4_addresses[0].address)=='192.0.2.1'
    probes.append(dict(id='unknown_interface_child_recovery',scope='synthetic_not_corpus',observed=dict(interface='Ethernet1',address='192.0.2.1',unknown_command_preserved=True),
        observation_confirmed=True,interpretation='The unrecognized child does not break indentation-based context; the following address stays on the interface.'))
    x,n,c=convert('interface Ethernet1\n description PHYSICAL\n service instance 10 ethernet\n  description CHILD\n  service-policy input CHILD-POLICY\n')
    assert n.configuration.interfaces[0].description=='PHYSICAL' and not n.configuration.qos.attachments
    probes.append(dict(id='nested_service_instance_guard',scope='synthetic_not_corpus',observed=dict(physical_description='PHYSICAL',child_description_not_applied=True,child_policy_not_attached_to_physical=True),
        observation_confirmed=True,interpretation='The mapper deliberately refuses nested interface captures; the child semantics remain unsupported rather than overwriting the parent.'))
    x,n,c=convert('router bgp 65000\n neighbor 192.0.2.1 remote-as 65001\n address-family ipv4\n  neighbor 192.0.2.1 route-map ONLY-V4 in\n exit-address-family\n address-family ipv6\n  neighbor 192.0.2.1 route-map ONLY-V6 out\n exit-address-family\n')
    neighbor=n.configuration.routing.bgp[0].neighbors[0]
    assert neighbor.import_policies==neighbor.export_policies==[]
    assert x['records'][4]['context_lines']==[1,3] and x['records'][7]['context_lines']==[1,6]
    probes.append(dict(id='bgp_address_family_guard',scope='synthetic_not_corpus',observed=dict(ipv4_context=[1,3],ipv6_context=[1,6],global_policies_not_widened=True),
        observation_confirmed=True,interpretation='AF context exists natively; mapping is withheld because the contract has no per-neighbor AF policy container.'))
    x,n,c=convert('router bgp 65000\n address-family ipv4 vrf BLUE\n  neighbor 192.0.2.1 remote-as 65001\n exit-address-family\n address-family ipv4 vrf RED\n  neighbor 192.0.2.1 remote-as 65002\n exit-address-family\n')
    processes={p.network_instance:p for p in n.configuration.routing.bgp}
    assert processes['BLUE'].neighbors[0].remote_as==65001 and processes['RED'].neighbors[0].remote_as==65002
    probes.append(dict(id='bgp_same_neighbor_two_vrfs',scope='synthetic_not_corpus',observed=dict(BLUE=65001,RED=65002),
        observation_confirmed=True,interpretation='The same neighbor address is attached to the correct native address-family VRF and normalized process.'))
    x,n,c=convert('ip access-list extended A\n 10 permit tcp host 192.0.2.1 eq 1024 host 198.51.100.1 eq 443\nip access-list extended B\n 10 deny ip any any\nroute-map POLICY permit 10\n set local-preference 150\nroute-map POLICY deny 20\n match ip address B\n')
    a,b=n.configuration.security.acl_sets;one,two=n.configuration.routing.routing_policies[0].statements
    assert a.name=='A' and b.name=='B' and a.entries[0].source_port.start==1024 and a.entries[0].destination_port.start==443
    assert one.identifier=='10' and two.identifier=='20' and one.actions[0].value=='150' and two.matches[0].value=='B'
    probes.append(dict(id='acl_and_route_map_ownership',scope='synthetic_not_corpus',observed=dict(acl_A_source_port=1024,acl_A_destination_port=443,acl_B_action='deny',route_map_sequences=['10','20'],clauses_not_mixed=True),
        observation_confirmed=True,interpretation='ACL identities/ports and route-map clause identities and actions remain separated.'))
    x,n,c=convert('login on-success log\n')
    assert x['records'][1]['rule']=='services_login' and not n.configuration.system.management.lines
    probes.append(dict(id='global_login_misclassification',scope='synthetic_matches_real_corpus_pattern',
        observed=dict(rule='services_login',native=x['records'][1]['values'],management_lines_created=0),
        observation_confirmed=True,interpretation='The generic template labels login logging as an authentication method; context guard prevents an incorrect VTY mapping.'))
    (OUT/'controlled_probes.json').write_text(json.dumps(probes,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    # Measure execution during existing tests. Being executed does NOT mean that
    # every field of that rule has an independent expected-value assertion.
    selected=Counter();original=runtime.extract
    def observed_extract(*args,**kwargs):
        result=original(*args,**kwargs)
        selected.update(r['rule'] for r in result['records'].values())
        return result
    import pytest
    with patch.object(runtime,'extract',observed_extract):
        code=pytest.main([str(ROOT/'tests'),'-q','-p','no:cacheprovider','--junitxml='+str(OUT/'regression_tests.xml')])
    assert code==0
    rule_ids={r['id'] for r in json.loads((ROOT/'templates/rules.json').read_text())}
    literal_refs=set()
    for path in (ROOT/'tests').glob('test_*.py'):
        tree=ast.parse(path.read_text(encoding='utf-8'))
        literal_refs.update(node.value for node in ast.walk(tree) if isinstance(node,ast.Constant) and isinstance(node.value,str) and node.value in rule_ids)
    coverage=dict(selected_rule_occurrences=dict(selected),selected_distinct_rules=len(selected),
        literal_rule_ids_in_test_code=sorted(literal_refs),literal_rule_id_count=len(literal_refs),
        caveat='Execution or a literal reference is not exhaustive semantic assertion coverage.',
        controlled_probes=len(probes),all_controlled_observations_confirmed=True,existing_tests_exit_code=int(code))
    (OUT/'test_rule_execution.json').write_text(json.dumps(coverage,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in coverage.items() if k not in ('selected_rule_occurrences','literal_rule_ids_in_test_code')},indent=2))


if __name__=='__main__':main()
