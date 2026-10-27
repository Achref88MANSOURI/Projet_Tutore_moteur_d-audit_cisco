"""Read-only diagnostic of TTP extraction, native export, mapping and coverage.

All new artifacts go under outputs/diagnostic_pipeline. Runtime sources, original
templates, schema, corpus and earlier results must retain their hashes.
"""
from __future__ import annotations
import ast
from collections import Counter, defaultdict
import copy
import csv
import hashlib
from ipaddress import ip_address
import json
from pathlib import Path
import re
import sys
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from ttp import ttp as RealTTP
import parser.run_ttp as runtime
from parser.inventory import redacted
from normalizer.mapping import Mapper
from normalizer.validation import validate

OUT=ROOT/'outputs/diagnostic_pipeline'


def read(path):return json.loads(path.read_text(encoding='utf-8'))
def dump(name,data):(OUT/name).write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def write_csv(name,rows):
    if not rows:return
    with (OUT/name).open('w',encoding='utf-8-sig',newline='') as stream:
        fields=list(dict.fromkeys(k for row in rows for k in row))
        writer=csv.DictWriter(stream,fieldnames=fields);writer.writeheader()
        writer.writerows({k:json.dumps(v,ensure_ascii=False) if isinstance(v,(list,dict)) else v for k,v in row.items()} for row in rows)


def protected():
    files=[]
    for directory in ('parser','normalizer','schemas','templates','configs','baseline','tests','outputs/corpus_20','outputs/pilot_5','outputs/analysis_777'):
        files.extend(p for p in (ROOT/directory).rglob('*') if p.is_file() and '__pycache__' not in p.parts)
    files.extend(ROOT.glob('*.py'))
    return {p.relative_to(ROOT).as_posix():sha(p) for p in sorted(set(files))}


class TracedEngine:
    """Observe the actual runtime TTP calls; never change their data or results."""
    calls=[]
    project_rules=set()
    def __init__(self,*args,**kwargs):
        self.inner=RealTTP(*args,**kwargs)
        template=kwargs.get('template','')
        self.rule_ids=[r for r in re.findall(r'<group name="([^"]+)\*"',template) if r in self.project_rules]
    def parse(self,*args,**kwargs):return self.inner.parse(*args,**kwargs)
    def result(self,*args,**kwargs):
        value=self.inner.result(*args,**kwargs)
        if self.rule_ids:self.calls.append((self.rule_ids,value))
        return value


def safe_values(values):
    # _ignore_ may contain a credential intentionally discarded by the runtime.
    return runtime.clean_json({k:v for k,v in values.items() if k not in ('source_line','_ignore_')})


def flatten_candidates(calls):
    by_line=defaultdict(list)
    for rule_ids,value in calls:
        if not value:continue
        for group in value[0]:
            if not isinstance(group,dict):continue
            for rule,values in group.items():
                assert rule in rule_ids
                for r in runtime.flatten_records(values):
                    by_line[r['source_line']].append(dict(rule=rule,values=safe_values(r)))
    return by_line


def cross_family_probe(uninterpreted,rules):
    """Match existing patterns only, outside their dispatch family, as a diagnosis.

    A cross-family match is NOT adopted as an extraction: homonyms and broad
    patterns may describe a different CLI concept and scope.
    """
    from xml.sax.saxutils import escape
    # Keep the original ACL regexp variables, then all existing rule groups.
    templates=[]
    for p in sorted((ROOT/'templates/cisco_ios').glob('*.ttp')):
        templates.append(p.read_text(encoding='utf-8'))
    # Inputs are numbered uniquely across files for this isolated experiment.
    data='\n'.join(f'{i} {row["source_command"]}' for i,row in enumerate(uninterpreted,1))+'\n'
    engine=RealTTP(data=data,template='\n'.join(templates));engine.parse(one=True)
    calls=[([r['id'] for r in rules],engine.result())]
    return flatten_candidates(calls)


def family_uninterpreted(command):
    if command.startswith(('no mop ','no cdp ','no logging console','logging synchronous','privilege level ','stopbits ','length ','transport ','ip http authentication','no ip source-route','security passwords')):
        return 'Gestion, accès et sécurité de base'
    if command.startswith(('boot-','boot system ','config-register ','upgrade fpd','platform ','no platform ','diagnostic ','license ','memory ','redundancy','subscriber ','service call-home','multilink ','mmi ','no mmi ','scheduler ','no scheduler ','spanning-tree ')):
        return 'Plateforme, démarrage et services système'
    if command.startswith(('service timestamps','no service password','archive','log config','hidekeys','call-home','contact-email','profile ','active','destination transport','virtual-service','mgcp ','gatekeeper','shutdown','alias exec')):
        return 'Journalisation, services annexes et contextes'
    if command.startswith(('bgp ','no bgp ','no synchronization','no auto-summary','neighbor ','ip bgp-community','ip community-list')):
        return 'BGP et filtres de communautés'
    if command.startswith(('mpls ','service instance ','encapsulation ','bridge-domain ')):
        return 'MPLS/LDP et services Ethernet'
    if command.startswith(('ip flow','cache ','export destination','enabled','ipv6 ioam')):
        return 'Télémétrie et NetFlow'
    if command.startswith(('ip pim ','ip msdp ')):
        return 'Multicast/PIM/MSDP'
    return 'IP global, DNS, CEF et autres réglages'


def main():
    OUT.mkdir(parents=True,exist_ok=True)
    before=protected()
    rules=read(ROOT/'templates/rules.json');definitions={r['id']:r for r in rules}
    TracedEngine.project_rules=set(definitions)
    previous777={(r['file_id'],r['line']):r for r in read(ROOT/'outputs/analysis_777/occurrences_777.json')}
    manifest=read(ROOT/'configs/manifest.json')
    rows=[];uninterpreted=[];opaque=[];rule_hits=Counter();raw_rule_hits=Counter();rule_examples=defaultdict(list)
    captured_status=Counter();legacy_status=Counter();inventory_status=Counter();file_summaries=[]
    all_constants=[];export_changes=[];scope_checks=[];all_candidates=[]
    for entry in manifest:
        file_id=entry['id'];folder=ROOT/'outputs/corpus_20'/file_id
        source=ROOT/entry['config_file'];raw=source.read_bytes();text=raw.decode('utf-8-sig');lines=text.splitlines()
        coverage=read(folder/'coverage_report.json');native=read(folder/'parsed_native.json');normalized=read(folder/'normalized_config.json')
        assert hashlib.sha256(raw).hexdigest()==entry['description_sha256']==normalized['metadata']['source_sha256']
        archived_records={r['source_line']:r for r in native['records']}
        TracedEngine.calls=[]
        with patch.object(runtime,'ttp',TracedEngine):
            x=runtime.extract(text,official=True)
        assert not x['official_errors']
        assert runtime.public_native(x)==native, f'Frozen native output no longer reproducible: {file_id}'
        mapper=Mapper(x,text,str(source.resolve()),entry['os_family'],hashlib.sha256(raw).hexdigest())
        regenerated=mapper.run().model_dump(mode='json')
        regenerated['parsing']['native_tree_file']=normalized['parsing']['native_tree_file']
        validate(regenerated)
        assert regenerated==normalized, f'Frozen normalized output no longer reproducible: {file_id}'
        candidates=flatten_candidates(TracedEngine.calls)
        for line,items in candidates.items():
            for item in items:
                raw_rule_hits[item['rule']]+=1
                all_candidates.append(dict(file_id=file_id,line=line,**item))
        for record in x['records'].values():
            rule=record['rule'];line=record['source_line'];rule_hits[rule]+=1
            if len(rule_examples[rule])<3:rule_examples[rule].append(dict(file_id=file_id,line=line,command=redacted(lines[line-1].strip())))
            const=re.findall(r'{{\s*(\w+)\s*\|\s*set\((True|False|"[^"]*")\)',definitions[rule]['pattern'])
            for name,value in const:
                expected=ast.literal_eval(value)
                all_constants.append(dict(file_id=file_id,line=line,rule=rule,field=name,expected=expected,
                    present=name in record['values'],actual=record['values'].get(name)))
            exported=archived_records[line]['values']
            for key,value in record['values'].items():
                if exported.get(key)!=value:
                    # Do not copy raw values to reports: keys and known type literals suffice.
                    export_changes.append(dict(file_id=file_id,line=line,rule=rule,field=key,
                        raw_type=type(value).__name__,raw_is_literal_type=value in ('secret','password') if isinstance(value,str) else False,
                        exported=exported.get(key),stage='native_export_redaction'))
        for row in coverage['legacy_comparison']:
            legacy_status[row['ttp_status']]+=1
            if row['ttp_extracted']:captured_status[row['ttp_status']]+=1
        for row in coverage['commands']:
            inventory_status[row['status']]+=1
            line=row['line'];node=x['nodes'][line];record=x['records'].get(line)
            assert redacted(node.text)==row['text']
            parent_chain=[n.line for n in runtime.ancestors(node,x['nodes'])]
            if record:assert parent_chain==record['context_lines']
            if node.kind.startswith('opaque'):
                body='\n'.join(lines[line-1:node.end_line]);assert hashlib.sha256(body.encode()).hexdigest()==node.opaque_sha256
                old_count=sum(1 for old in coverage['legacy_comparison'] if old['ttp_status']=='preserved_opaque' and line<=old['line']<=node.end_line)
                opaque.append(dict(file_id=file_id,line=line,line_end=node.end_line,kind=node.kind,
                    physical_lines=node.end_line-line+1,legacy_positions=old_count,parent_line=node.parent,
                    parent_command=redacted(x['nodes'][node.parent].text),sha256_verified=True))
            if row['status'] not in ('extracted_unmapped','preserved_uninterpreted'):continue
            paths=[e['path'] for e in normalized['evidence'] if e['status']=='explicit' and e.get('line_start')==line]
            current=dict(file_id=file_id,config_file=entry['config_file'],line=line,source_command=row['text'],
                ttp_rule=record['rule'] if record else None,native_extraction=archived_records[line]['values'] if record else None,
                context=[dict(line=n,text=redacted(x['nodes'][n].text)) for n in parent_chain],
                extraction_family=node.family,normalized_field=paths or None,
                coverage_status=row['status'],raw_candidates=candidates.get(line,[]),
                source_and_context_verified=True,validation_status='trace_verified_semantics_not_exhaustively_certified')
            if row['status']=='extracted_unmapped':
                prior=previous777[(file_id,line)]
                stage={'A_mapping_v01':'normalization_mapping','B_resolution_v01':'reference_resolution',
                    'C_convention':'normalization_semantic_convention','D_capture_contexte':'extraction_context_classification',
                    'E_structure':'normalized_schema_structure','F_champ':'normalized_schema_field'}[prior['cause']]
                current.update(failure_stage=stage,analysis_category=prior['cause'],diagnosis=prior['explanation'],
                    target=prior['target'],quality_flags=prior['quality_flags'])
            else:
                assert record is None, 'Uninterpreted row actually has a selected record'
                current.update(failure_stage='pending_cross_family_diagnosis',diagnosis='',target=None,quality_flags=[],
                    functional_family=family_uninterpreted(node.text))
                uninterpreted.append(current)
            rows.append(current)
        # Independent target-identity checks use raw stanza text and final target
        # objects; a correct lexical ancestor chain alone would be insufficient.
        for e in normalized['evidence']:
            if e['status']!='explicit':continue
            line=e.get('line_start');r=x['records'].get(line)
            if not r:continue
            path=e['path'];m=re.match(r'/configuration/interfaces/(\d+)(?:/|$)',path)
            if m:
                target=normalized['configuration']['interfaces'][int(m[1])]['name']
                root_command=lines[r['root_line']-1].strip()
                assert root_command=='interface '+target,(file_id,line,path)
                scope_checks.append(dict(file_id=file_id,line=line,path=path,kind='interface_identity',target=target,passed=True))
            m=re.match(r'/configuration/routing/bgp/(\d+)/neighbors/(\d+)(?:/|$)',path)
            if m:
                process=normalized['configuration']['routing']['bgp'][int(m[1])]
                neighbor=process['neighbors'][int(m[2])]
                source_af=[x['nodes'][n].text for n in r['context_lines'] if x['nodes'][n].text.startswith('address-family ')]
                source_vrf=source_af[-1].split(' vrf ',1)[1] if source_af and ' vrf ' in source_af[-1] else None
                actual_vrf=process['network_instance']
                source_peer=r['values'].get('peer')
                try:source_identity=str(ip_address(source_peer))
                except ValueError:source_identity=source_peer
                valid=source_vrf==actual_vrf and source_identity in (neighbor['peer'],neighbor['peer_group'])
                scope_checks.append(dict(file_id=file_id,line=line,path=path,kind='bgp_neighbor_vrf_or_group_identity',
                    target=f'{actual_vrf or "default"}:{neighbor["peer"]}',passed=valid))
                if path.endswith('/enabled') or path.endswith('/import_policies') or path.endswith('/export_policies'):
                    scope_checks.append(dict(file_id=file_id,line=line,path=path,kind='bgp_af_not_widened_to_global',
                        target=neighbor['peer'],passed=not source_af))
            m=re.match(r'/configuration/routing/routing_policies/(\d+)/statements/(\d+)(?:/|$)',path)
            if m:
                policy=normalized['configuration']['routing']['routing_policies'][int(m[1])]
                stmt=policy['statements'][int(m[2])]
                root=lines[r['root_line']-1].strip().split()
                assert root[0]=='route-map' and root[1]==policy['name'] and root[-1]==stmt['identifier']
                scope_checks.append(dict(file_id=file_id,line=line,path=path,kind='route_map_statement_identity',target=policy['name']+':'+stmt['identifier'],passed=True))
            m=re.match(r'/configuration/security/acl_sets/(\d+)/entries/(\d+)(?:/|$)',path)
            if m:
                acl=normalized['configuration']['security']['acl_sets'][int(m[1])]
                root=lines[r['root_line']-1].strip()
                source_name=root.split()[1] if root.startswith('access-list ') else root.split()[-1]
                assert root.startswith(('ip access-list ','ipv6 access-list ','access-list ')) and source_name==acl['name']
                scope_checks.append(dict(file_id=file_id,line=line,path=path,kind='acl_identity',target=acl['name'],passed=True))
        file_summaries.append(dict(file_id=file_id,source_sha256=hashlib.sha256(raw).hexdigest(),native_replay_identical=True,
            normalized_replay_identical=True,selected_captures=len(x['records']),raw_candidate_occurrences=sum(map(len,candidates.values())),
            legacy_statuses=coverage['legacy_comparison_status_counts']))
        print(file_id,'replay identical',flush=True)
    dump('replay_files.json',file_summaries)
    dump('raw_candidates.json',all_candidates)
    cross=cross_family_probe(uninterpreted,rules)
    for ordinal,row in enumerate(uninterpreted,1):
        alternatives=cross.get(ordinal,[])
        row['other_family_pattern_matches']=alternatives
        cmd=row['source_command']
        if row['raw_candidates']:
            row['failure_stage']='candidate_rejected_or_not_selected'
            row['diagnosis']='Le moteur a produit un candidat dans la famille assignée, mais le runtime ne l’a pas conservé. Voir les filtres et la sélection.'
        elif cmd.startswith('mpls ldp router-id ') and len(cmd.split())==4:
            row['failure_stage']='template_variant_missing'
            row['diagnosis']='advanced_mpls_ldp existe dans la bonne famille mais impose un deuxième paramètre option ; la forme sans option ne correspond pas.'
            row['related_rule']='advanced_mpls_ldp'
        elif cmd.startswith('bridge-domain ') and row['extraction_family']=='interfaces' and any(a['rule']=='advanced_l2_bridge' for a in alternatives):
            row['failure_stage']='family_dispatch_gap'
            row['diagnosis']='Une règle bridge-domain existe sous advanced, mais ce bloc est imbriqué dans une interface/service-instance : seul le template interfaces est exécuté.'
        elif alternatives:
            row['failure_stage']='other_scope_pattern_match_not_reusable_as_is'
            row['diagnosis']='Un motif d’une autre famille peut lire les mots, mais son concept/sa portée diffère ou reste générique. Ce rapprochement n’est pas une extraction valide adoptée.'
        else:
            row['failure_stage']='no_matching_current_template'
            row['diagnosis']='Aucun candidat produit par les templates de la famille assignée ; aucun motif existant ne correspond dans le test transversal.'
    dump('diagnostic_occurrences_1359.json',rows);write_csv('diagnostic_occurrences_1359.csv',rows)
    dump('uninterpreted_582.json',uninterpreted);write_csv('uninterpreted_582.csv',uninterpreted)
    dump('opaque_blocks.json',opaque);write_csv('opaque_blocks.csv',opaque)
    dump('constant_fields.json',all_constants);write_csv('constant_fields.csv',all_constants)
    dump('native_export_changes.json',export_changes)
    dump('hierarchy_checks.json',scope_checks)
    catalogue=[]
    for rule in rules:
        variables=re.findall(r'{{\s*(.*?)\s*}}',rule['pattern'])
        constants=[v for v in variables if '| set(' in v]
        untyped=[v for v in variables if '|' not in v]
        catalogue.append(dict(**rule,selected_occurrences=rule_hits[rule['id']],raw_candidate_occurrences=raw_rule_hits[rule['id']],
            observed_selected=bool(rule_hits[rule['id']]),observed_raw=bool(raw_rule_hits[rule['id']]),
            untyped_variables=untyped,orphrase_variables=[v for v in variables if 'ORPHRASE' in v],set_variables=constants,
            examples=rule_examples[rule['id']],semantic_precision_status='not_exhaustively_validated'))
    dump('rules_272.json',catalogue);write_csv('rules_272.csv',catalogue)
    for label,key in [('uninterpreted_command_frequencies.csv','source_command'),('uninterpreted_families.csv','functional_family')]:
        freq=[]
        for value,count in Counter(r[key] for r in uninterpreted).most_common():
            subset=[r for r in uninterpreted if r[key]==value]
            freq.append(dict(value=value,occurrences=count,files=len({r['file_id'] for r in subset}),
                failure_stages=dict(Counter(r['failure_stage'] for r in subset)),locations=[f'{r["file_id"]}:{r["line"]}' for r in subset]))
        write_csv(label,freq)
    summary=dict(legacy_statuses=dict(legacy_status),selected_captures_by_legacy_status=dict(captured_status),
        actual_inventory_statuses=dict(inventory_status),actual_selected_captures=sum(rule_hits.values()),
        diagnostic_occurrences=len(rows),uninterpreted_count=len(uninterpreted),uninterpreted_unique_texts=len({r['source_command'] for r in uninterpreted}),
        uninterpreted_causes=dict(Counter(r['failure_stage'] for r in uninterpreted)),
        rules_total=len(rules),rules_selected=len(rule_hits),rules_with_raw_candidates=len(raw_rule_hits),
        set_fields_total=len(all_constants),set_fields_missing=sum(not r['present'] for r in all_constants),
        native_export_changes=len(export_changes),opaque_blocks=len(opaque),opaque_physical_lines=sum(r['physical_lines'] for r in opaque),
        opaque_legacy_positions=sum(r['legacy_positions'] for r in opaque),hierarchy_target_checks=len(scope_checks),
        hierarchy_checks_failed=sum(not r['passed'] for r in scope_checks),
        all_20_native_replays_identical=True,all_20_normalized_replays_identical=True)
    assert len(uninterpreted)==582 and len(rows)==1359 and sum(captured_status.values())==1995
    assert captured_status==Counter(normalized_values=1148,extracted_unmapped=777,structure_or_metadata=70)
    after=protected();assert before==after
    dump('integrity.json',dict(unchanged=True,files=len(before),before=before,after=after))
    dump('summary.json',summary)
    print(json.dumps(summary,ensure_ascii=False,indent=2))


if __name__=='__main__':main()
