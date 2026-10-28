"""No full-command credit from a partial proof or native preservation alone."""
from collections import Counter
from .inventory import redacted
from .run_ttp import clean_json


def build_coverage(x,mapper,legacy_lines=None):
    rows=[];by_line={};doc=mapper.result.model_dump(mode='json')
    native_paths={}
    for i,o in enumerate(doc['configuration']['cisco']['observations']):
        for j,p in enumerate(o['parameters']):native_paths[(o['source_line'],p['name'])]=f'/configuration/cisco/observations/{i}/parameters/{j}/value'
    for line,node in x['nodes'].items():
        record=x['records'].get(line);consumed=mapper.consumed[line]
        validation=mapper.validation.get(line,{'valid':False,'fields':{},'invalid_fields':[]})
        if node.kind.startswith('opaque'):status='opaque_preserved'
        elif node.kind in ('wrapper','footer'):status='export_wrapper'
        elif node.kind=='metadata':status='structure_or_metadata'
        elif node.kind=='boundary' or line in mapper.base.structural:status='structure_or_metadata'
        elif record is None:status='uninterpreted'
        elif not validation['valid'] or line in mapper.base.failed or line in mapper.ambiguous:status='invalid_or_ambiguous'
        elif record['values'] and set(consumed)==set(record['values']) and all(v=='validated' for v in validation['fields'].values()) and line not in mapper.extra_invalid:status='fully_normalized'
        elif consumed:status='partially_normalized'
        else:status='extracted_unmapped'
        fields=[]
        if record:
            for key,value in record['values'].items():
                fields.append(dict(name=key,raw_value=clean_json(value,key),validation=validation['fields'][key],
                    mapping='normalized' if key in consumed else 'native_preserved' if (line,key) in native_paths else 'unmapped',
                    normalized_paths=consumed.get(key,[]),native_preservation_path=native_paths.get((line,key))))
        row=dict(line=line,line_end=node.end_line or line,text=redacted(node.text),kind=node.kind,family=node.family,
            root_line=node.root,context_line=node.parent,context=[dict(line=a,text=redacted(x['nodes'][a].text)) for a in (record['context_lines'] if record else [])],
            template_rule=record['rule'] if record else None,status=status,fields=fields,
            selection=x.get('selection',{}).get(line),
            normalized_paths=sorted({p for ps in consumed.values() for p in ps}),
            reason=mapper.extra_invalid.get(line) or ('Some parameters or semantic relations are not normalized.' if status in ('partially_normalized','extracted_unmapped') else None))
        rows.append(row)
        for number in range(line,(node.end_line or line)+1):by_line[number]=row
    legacy=[]
    for old in legacy_lines or []:
        row=by_line[old['line']]
        legacy.append(dict(line=old['line'],old_recognized=old['old_recognized'],status=row['status'],ttp_extracted=old['line'] in x['records']))
    return dict(format_version='2.0',definitions={
        'fully_normalized':'All captured significant parameters validated and mapped by an explicit semantic handler; not proof that no additional device semantics exist.',
        'partially_normalized':'At least one semantic parameter mapped, but another parameter is unvalidated, unmapped or a relation remains unsupported.',
        'extracted_unmapped':'Record retained; native extension preservation alone is not semantic normalization.',
        'uninterpreted':'No selected template record.', 'opaque_preserved':'Whole original block retained by source coordinates and content hash.',
        'invalid_or_ambiguous':'A captured domain is invalid, or safe selection/normalization cannot be made.',
        'historical_denominator':'Unchanged 3051 source coordinates; opaque blocks expanded only for historical comparison.'},
        legacy_denominator=len(legacy),legacy_comparison=legacy,legacy_comparison_status_counts=dict(Counter(r['status'] for r in legacy)),
        inventory_status_counts=dict(Counter(r['status'] for r in rows)),commands=rows,
        field_counts=dict(Counter(f['mapping'] for r in rows for f in r['fields'])),official_template_errors=x['official_errors'],
        official_fields_consumed=mapper.base.official_usage)
