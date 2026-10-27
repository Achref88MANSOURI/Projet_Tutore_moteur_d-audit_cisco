"""Separate template extraction, schema mapping, structure and opaque content."""
from collections import Counter
from .inventory import redacted


def reason(record):
    if record is None: return 'No project template matched this command.'
    rule = record['rule']
    if rule.startswith(('advanced_', 'if_pim', 'if_mpls', 'if_isis', 'if_nat_role', 'if_speed', 'if_duplex', 'if_media', 'if_negotiation', 'if_ospf3', 'if_unnumbered')):
        return 'Captured by TTP; this property/version has no adequate dedicated field in the unchanged v0.1 contract.'
    if rule.startswith('bgp_'):
        return 'Captured by TTP; advanced BGP / AF scope or peer-group property is not completely representable by this mapping.'
    if rule.startswith('prefix_'):
        return 'Captured list action/ge/le/order cannot be reduced to an unconditional list of permitted prefixes.'
    return 'Captured by TTP; mapping unsupported or only partial. See native values and diagnostics.'


def build_coverage(extracted, mapper, legacy_lines=None):
    nodes, records = extracted['nodes'], extracted['records']
    rows, by_line = [], {}
    for node in nodes.values():
        paths = [e.path for e in mapper.evidence if e.line_start == node.line and e.status == 'explicit']
        if node.line in mapper.failed: status = 'invalid_value'
        elif node.kind.startswith('opaque'): status = 'preserved_opaque'
        elif node.kind in ('wrapper','footer'): status = 'export_wrapper'
        elif node.line in mapper.mapped: status = 'normalized_values'
        elif node.line in mapper.structural or node.kind == 'boundary': status = 'structure_or_metadata'
        elif node.line in records: status = 'extracted_unmapped'
        else: status = 'preserved_uninterpreted'
        record = records.get(node.line)
        row = {'line':node.line,'line_end':node.end_line or node.line,'family':node.family,'kind':node.kind,
            'context_line':node.parent,'root_line':node.root,'text':redacted(node.text),'status':status,
            'template_rule':record['rule'] if record else None,'normalized_paths':paths,
            'reason':reason(record) if status in ('extracted_unmapped','preserved_uninterpreted') else None}
        rows.append(row)
        for line in range(node.line, (node.end_line or node.line)+1): by_line[line]=row
    comparison=[]
    if legacy_lines is not None:
        for old in legacy_lines:
            row=by_line.get(old['line'])
            if row is None: raise ValueError('Baseline source node missing from new inventory')
            comparison.append({'line':old['line'],'old_recognized':old['old_recognized'],
                'ttp_status':row['status'],'ttp_extracted':old['line'] in records,
                'ttp_has_normalized_values':row['status']=='normalized_values',
                'ttp_taken_into_account':row['status'] in ('normalized_values','structure_or_metadata')})
    commands=[row for row in rows if row['kind']=='command']
    return {'definitions':{
        'normalized_values':'At least documented values mapped with evidence; not a claim of complete device semantics.',
        'extracted_unmapped':'Values captured by an explicit TTP rule, but not fully mapped into v0.1.',
        'preserved_opaque':'Banner/certificate payload treated as one opaque block; never credited as interpreted commands.',
        'legacy_comparison':'Frozen old 3,051 source-node coordinates, expanded only for equal-denominator comparison.',
        'taken_into_account':'Mapped values or handled structural/metadata command; excludes mere TTP capture and opaque payloads.'},
        'inventory_status_counts':dict(Counter(row['status'] for row in rows)),
        'command_count':len(commands),'command_with_ttp_capture':sum(row['line'] in records for row in commands),
        'commands_with_normalized_values':sum(row['status']=='normalized_values' for row in commands),
        'official_template_errors':extracted['official_errors'], 'official_fields_consumed':mapper.official_usage,
        'legacy_denominator':len(comparison) if legacy_lines is not None else None,
        'legacy_comparison_status_counts':dict(Counter(row['ttp_status'] for row in comparison)),
        'legacy_comparison':comparison,'commands':rows}
