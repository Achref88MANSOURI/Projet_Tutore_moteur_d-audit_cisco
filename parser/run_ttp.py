"""Execute frozen official templates and source-numbered project TTP groups."""
from collections import defaultdict
import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import re

from ttp import ttp
from ttp_templates import get_template
from .inventory import inventory, ancestors, redacted

ROOT = Path(__file__).resolve().parents[1]
OFFICIAL = {
    'interfaces': 'cisco_ios_show_running_config_pipe_section_interface.txt',
    'vrfs': 'cisco_ios_show_running_config_pipe_section_vrf.txt',
    'bgp_asns': 'cisco_ios_show_running_config_pipe_section_router_bgp.txt',
    'nat_static': 'cisco_ios_show_running_config_pipe_include_source_static.txt',
}


def complete_line(pattern,text):
    """A TTP prefix match must not hide an unparsed option at line end."""
    pattern=re.sub(r'{{\s*\w+\s*\|\s*set\(.*?\)\s*}}','',pattern).strip()
    parts=[];start=0
    for match in re.finditer(r'{{(.*?)}}',pattern):
        parts.append(re.escape(pattern[start:match.start()]))
        parts.append('.+?' if 'ORPHRASE' in match[1] or 're(' in match[1] else r'\S+')
        start=match.end()
    parts.append(re.escape(pattern[start:]))
    return bool(re.fullmatch(re.sub(r'(?:\\ )+',r'\\s+',''.join(parts)),text))


def scope_allowed(definition,node,nodes):
    scope=definition.get('scope')
    if scope=='global':return node.parent is None
    if scope and scope.startswith('root:'):
        prefix=scope[5:];root=nodes[node.root].text
        return root==prefix or root.startswith(prefix+' ')
    return True


def clean_json(value, key=''):
    if isinstance(value, dict):
        return {k: clean_json(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [clean_json(v, key) for v in value]
    if isinstance(value, str):
        if key == 'credential_type' and value in ('secret','password'):
            return value
        if key in ('community_secret', 'password', 'secret', 'credential', 'serial'):
            return '[REDACTED]'
        return redacted(value)
    return value


def flatten_records(value):
    if isinstance(value, list):
        for item in value:
            yield from flatten_records(item)
    elif isinstance(value, dict):
        if 'source_line' in value:
            yield value
        else:
            for item in value.values():
                yield from flatten_records(item)


def extract(text, *, official=True):
    nodes = inventory(text)
    rules = json.loads((ROOT / 'templates/rules.json').read_text(encoding='utf-8'))
    definitions = {r['id']: r for r in rules}
    grouped = defaultdict(list)
    for node in nodes.values():
        if node.kind == 'command' or node.kind == 'boundary':
            grouped[node.family].append(f'{node.line} {node.text}')
    records, candidates = {}, defaultdict(list)
    for family, data in grouped.items():
        template = ROOT / 'templates/cisco_ios' / (family + '.ttp')
        if not template.is_file():
            continue
        engine = ttp(data='\n'.join(data) + '\n', template=template.read_text(encoding='utf-8'))
        engine.parse(one=True)
        for result in engine.result()[0]:
            if not isinstance(result, dict):
                continue
            for rule, values in result.items():
                for record in flatten_records(values):
                    line = record['source_line']
                    definition = definitions[rule]
                    if any(record.get(k) not in allowed for k,allowed in definition.get('choices',{}).items()):continue
                    if not scope_allowed(definition,nodes[line],nodes) or not complete_line(definition['pattern'],nodes[line].text):continue
                    if rule in ('services_login','services_login_plain'):
                        if not nodes[nodes[line].root].text.startswith('line '):
                            continue
                        if rule=='services_login' and not (record.get('method')=='local' or re.fullmatch(r'authentication \S+',record.get('method',''))):continue
                    if rule.startswith('services_line_') and not nodes[nodes[line].root].text.startswith('line '):continue
                    global_rules={'services_login_logging','services_timestamp','services_timestamp_plain','services_console_off','services_source_route_off',
                        'services_lookup_off','services_password_encryption_off','services_ipv6_routing','services_http_auth','services_community_expanded',
                        'services_flow_source','services_flow_version','services_flow_timeout'}
                    if rule in global_rules and nodes[line].parent is not None:continue
                    if rule in ('if_bridge_domain','if_encap_untagged') and not any(nodes[a.line].text.startswith('service instance ') for a in ancestors(nodes[line],nodes)):continue
                    # Specific fixed keywords take precedence over greedy text.
                    literal = re.sub(r'\{\{.*?\}\}', '', definition['pattern'])
                    score = len(literal.split()) * 20 - definition['pattern'].count('ORPHRASE') * 5
                    score += 30 * sum(key in record for key in ('source_port', 'destination_port'))
                    score += 10 * sum(key in record for key in ('distance', 'sequence'))
                    if family == 'routes' and 'interface' in record:
                        from ipaddress import ip_address
                        try:
                            ip_address(record['interface'])
                            continue
                        except ValueError:
                            pass
                        try:
                            ip_address(record['hop'])
                        except ValueError:
                            continue
                    candidates[line].append((score, rule, {k: v for k, v in record.items() if k not in ('source_line','_ignore_')}))
    selection={}
    for line, items in candidates.items():
        ranked=sorted(items,key=lambda x:(-x[0],x[1]));score, rule, values=ranked[0]
        top=[item for item in ranked if item[0]==score]
        ambiguous=len({json.dumps(item[2],sort_keys=True) for item in top})>1
        selection[line]={'selected_rule':rule,'candidate_rules':[item[1] for item in ranked],
            'scores':[item[0] for item in ranked],'ambiguous':ambiguous}
        node = nodes[line]
        records[line] = {'rule': rule, 'values': values, 'source_line': line,
                         'root_line': node.root, 'family': node.family,
                         'context_lines': [x.line for x in ancestors(node, nodes)]}
        if definitions[rule].get('native_domain'):records[line]['native_domain']=definitions[rule]['native_domain']
    official_results, official_errors, official_hashes = {}, [], {}
    if official:
        for name, filename in OFFICIAL.items():
            try:
                template = get_template(path='platform/' + filename)
                official_hashes[name] = hashlib.sha256(template.encode()).hexdigest()
                frozen = ROOT / 'templates/upstream' / filename
                if frozen.is_file() and hashlib.sha256(frozen.read_text(encoding='utf-8').encode()).hexdigest() != official_hashes[name]:
                    raise ValueError('Installed upstream template differs from the frozen snapshot')
                engine = ttp(data=text, template=template)
                engine.parse(one=True)
                official_results[name] = engine.result()
            except Exception as exc:
                # Do not echo configurations or validation exception payloads.
                official_errors.append({'template': name, 'error_type': type(exc).__name__})
                official_results[name] = None
    return {'nodes': nodes, 'records': records, 'official': official_results, 'selection':selection,
            'official_errors': official_errors, 'official_template_hashes': official_hashes,
            'versions': {'ttp': version('ttp'), 'ttp_templates': version('ttp-templates')}}


def public_native(extracted):
    return clean_json({
        'engine': extracted['versions'],
        'official_templates': extracted['official'], 'official_template_errors': extracted['official_errors'],
        'official_template_sha256': extracted['official_template_hashes'],
        'records': list(extracted['records'].values()),
        'selection':extracted.get('selection',{}),
        'source_inventory': [node.public() for node in extracted['nodes'].values()],
    })
