"""Execute frozen official templates and source-numbered project TTP groups."""
from collections import defaultdict
from dataclasses import dataclass
import json
import logging
from pathlib import Path
import re
from xml.etree import ElementTree

from ttp import ttp
from ttp_templates import get_template
from .inventory import inventory, ancestors
from .logging_commands import target as logging_target
from .routing_secrets import redact_routing_secrets
from .admin_secrets import redact_admin_secrets
from .admin_context import allowed as admin_context_allowed
from .eigrp_context import allowed as eigrp_context_allowed

ROOT = Path(__file__).resolve().parents[1]
LOGGER = logging.getLogger(__name__)
OFFICIAL = {
    'interfaces': 'cisco_ios_show_running_config_pipe_section_interface.txt',
    'vrfs': 'cisco_ios_show_running_config_pipe_section_vrf.txt',
    'bgp_asns': 'cisco_ios_show_running_config_pipe_section_router_bgp.txt',
    'nat_static': 'cisco_ios_show_running_config_pipe_include_source_static.txt',
}
REQUIRED_OFFICIAL = frozenset({'interfaces', 'vrfs'})


class OfficialTemplateError(RuntimeError):
    """A safe, identifiable failure of an installed or frozen TTP template."""

    def __init__(self, template_id, code, stage, cause_type=None):
        self.template_id = template_id
        self.code = code
        self.stage = stage
        self.cause_type = cause_type
        suffix = f' ({cause_type})' if cause_type else ''
        super().__init__(f'Official TTP template {template_id}: {code} at {stage}{suffix}')


def run_official_template(name, filename, text):
    """Keep template failures distinct from a successfully parsed empty result."""
    text = redact_admin_secrets(redact_routing_secrets(text))
    try:
        template = get_template(path='platform/' + filename)
    except (OSError, ImportError) as exc:
        raise OfficialTemplateError(name, 'unavailable', 'load', type(exc).__name__) from None
    except Exception as exc:
        raise OfficialTemplateError(name, 'load_error', 'load', type(exc).__name__) from None
    if not isinstance(template, str) or not template.strip():
        raise OfficialTemplateError(name, 'unavailable', 'load')

    frozen = ROOT / 'templates/upstream' / filename
    try:
        frozen_template = frozen.read_text(encoding='utf-8')
    except FileNotFoundError as exc:
        raise OfficialTemplateError(name, 'snapshot_missing', 'snapshot', type(exc).__name__) from None
    except (OSError, UnicodeError) as exc:
        raise OfficialTemplateError(name, 'snapshot_unavailable', 'snapshot', type(exc).__name__) from None
    if frozen_template != template:
        raise OfficialTemplateError(name, 'version_mismatch', 'snapshot')

    try:
        engine = ttp(data=text, template=template)
        engine.parse(one=True)
    except Exception as exc:
        raise OfficialTemplateError(name, 'execution_error', 'parse', type(exc).__name__) from None
    try:
        result = engine.result()
    except Exception as exc:
        raise OfficialTemplateError(name, 'execution_error', 'result', type(exc).__name__) from None
    if result is None:
        raise OfficialTemplateError(name, 'execution_error', 'result', 'NoneResult')
    return result

# Command families emitted by inventory.root_family; directory domains may differ.
TEMPLATE_FAMILIES = frozenset({
    'interfaces', 'bgp', 'ospf', 'vrf', 'acl_standard', 'acl_extended',
    'policies', 'prefix', 'routes', 'advanced', 'services', 'eigrp',
})


@dataclass(frozen=True, slots=True)
class TemplateSource:
    path: str
    source: str
    rule_ids: tuple[str, ...]


def template_family(relative_path):
    """The nearest family directory owns a file; flat files use their stem."""
    # RIP is still classified as services by the unchanged source inventory.
    if relative_path.as_posix() in ('routing/rip.ttp', 'routing/key_chains.ttp'):
        return 'services'
    for part in reversed(relative_path.parts[:-1]):
        if part in TEMPLATE_FAMILIES:
            return part
    if relative_path.stem in TEMPLATE_FAMILIES:
        return relative_path.stem
    raise ValueError(f'No command family associated with template {relative_path.as_posix()}')


def load_templates(template_directory=None):
    """Read rule identities/patterns and the exact source passed to TTP.

    Project groups are flat tables with one numbered capture line. Constants,
    regex variables and conversion functions remain owned and executed by TTP.
    Only context restrictions and allowed choices come from the metadata file.
    Each family owns an ordered tuple of independent template sources. Rule
    identifiers remain unique across every discovered file and directory.
    """
    directory = Path(template_directory) if template_directory is not None else ROOT / 'templates'
    metadata = json.loads((directory / 'rule_metadata.json').read_text(encoding='utf-8'))
    if not isinstance(metadata, dict):
        raise ValueError('Rule metadata must be indexed by rule identifier')
    for identifier, restrictions in metadata.items():
        if not isinstance(restrictions, dict) or not restrictions or set(restrictions) - {'scope', 'choices'}:
            raise ValueError(f'Invalid metadata for rule {identifier}')
        if 'scope' in restrictions:
            scope = restrictions['scope']
            if not isinstance(scope, str) or not (scope == 'global' or scope.startswith('root:') and scope[5:].strip()):
                raise ValueError(f'Invalid scope for rule {identifier}')
        if 'choices' in restrictions:
            choices = restrictions['choices']
            if not isinstance(choices, dict) or not choices or any(
                not isinstance(field, str) or not isinstance(allowed, list) or not allowed
                for field, allowed in choices.items()
            ):
                raise ValueError(f'Invalid choices for rule {identifier}')

    definitions, templates = {}, defaultdict(list)
    prefix = re.compile(r'^{{\s*source_line\s*\|\s*DIGIT\s*\|\s*to_int\s*}}\s+')
    template_root = directory / 'cisco_ios'
    paths = sorted(template_root.rglob('*.ttp'), key=lambda path: path.relative_to(template_root).as_posix())
    for path in paths:
        relative_path = path.relative_to(template_root)
        family = template_family(relative_path)
        source = path.read_text(encoding='utf-8')
        document = ElementTree.fromstring('<template>' + source + '</template>')
        groups = document.findall('group')
        if not groups:
            raise ValueError(f'No rule groups in {path.name}')
        identifiers = []
        for group in groups:
            name = group.get('name', '')
            if not re.fullmatch(r'\w+\*', name) or group.get('method') != 'table' or len(group):
                raise ValueError(f'Expected a flat named table group in {path.name}')
            identifier = name[:-1]
            if identifier in definitions:
                raise ValueError(f'Duplicate TTP rule identifier: {identifier}')
            lines = [line.strip() for line in (group.text or '').splitlines() if line.strip()]
            if len(lines) != 1 or not prefix.match(lines[0]):
                raise ValueError(f'Expected one source-numbered capture line for rule {identifier}')
            pattern = prefix.sub('', lines[0], count=1)
            if not pattern:
                raise ValueError(f'Empty capture pattern for rule {identifier}')
            definitions[identifier] = {'pattern': pattern, **metadata.get(identifier, {})}
            identifiers.append(identifier)
        templates[family].append(TemplateSource(relative_path.as_posix(), source, tuple(identifiers)))
    if not templates:
        raise ValueError('No project TTP templates found')
    unknown = set(metadata) - set(definitions)
    if unknown:
        raise ValueError('Metadata refers to unknown TTP rules: ' + ', '.join(sorted(unknown)))
    return definitions, {family: tuple(sources) for family, sources in templates.items()}


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


def routing_auth_context(rule, node, nodes):
    """Exact immediate contexts; unknown nesting cannot inherit a valid root."""
    if not rule.startswith('auth_'):
        return True
    parents = ancestors(node, nodes)
    if rule.startswith('auth_bgp_'):
        return (len(parents) == 1 and parents[0].text.startswith('router bgp ') or
                len(parents) == 2 and parents[0].text.startswith('router bgp ') and parents[1].text.startswith('address-family '))
    if rule == 'auth_key_chain':
        return not parents
    if rule.startswith('auth_key_'):
        if not parents or re.fullmatch(r'key chain \S+', parents[0].text) is None:
            return False
        if rule == 'auth_key_id':
            return len(parents) == 1
        return len(parents) == 2 and re.fullmatch(r'key \d+', parents[1].text) is not None
    if len(parents) != 1:
        return False
    root_text = parents[0].text
    if rule.startswith('auth_if_'):
        return root_text.startswith('interface ')
    if rule.startswith('auth_bgp_'):
        return root_text.startswith('router bgp ')
    if rule.startswith('auth_ospf_'):
        return root_text.startswith('router ospf ')
    if rule.startswith('auth_isis_'):
        return root_text == 'router isis' or root_text.startswith('router isis ')
    return False


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


def extract(text, *, official=True, community_categories=None):
    identities = {}
    text = redact_admin_secrets(redact_routing_secrets(text), identities=identities, community_categories=community_categories)
    nodes = inventory(text)
    definitions, templates = load_templates()
    grouped = defaultdict(list)
    for node in nodes.values():
        if node.kind == 'command' or node.kind == 'boundary':
            grouped[node.family].append(f'{node.line} {node.text}')
    records, candidates = {}, defaultdict(list)
    for family, data in grouped.items():
        for template in templates.get(family, ()):
            engine = ttp(data='\n'.join(data) + '\n', template=template.source)
            engine.parse(one=True)
            for result in engine.result()[0]:
                if not isinstance(result, dict):
                    continue
                for rule, values in result.items():
                    for record in flatten_records(values):
                        line = record['source_line']
                        definition = definitions[rule]
                        # Generic legacy host tables must not reinterpret the
                        # literal 'version' token or a v3 security level as a
                        # community/port. Specific v3 TTP groups own that syntax.
                        if rule.startswith('services_snmp_host') and not rule.startswith('services_snmp_host_remove'):
                            if 'version' in record and record['version'] not in ('1', '2c'):
                                continue
                        if any(record.get(k) not in allowed for k,allowed in definition.get('choices',{}).items()):continue
                        if not scope_allowed(definition,nodes[line],nodes) or not complete_line(definition['pattern'],nodes[line].text):continue
                        if not routing_auth_context(rule,nodes[line],nodes):continue
                        if not admin_context_allowed(rule,nodes[line],nodes,record):continue
                        if not eigrp_context_allowed(rule,nodes[line],nodes,record):continue
                        if rule in ('services_login','services_login_plain','services_login_authentication_remove','services_login_authentication_remove_args'):
                            if not nodes[nodes[line].root].text.startswith('line '):
                                continue
                            if rule=='services_login' and not (record.get('method')=='local' or re.fullmatch(r'authentication \S+',record.get('method',''))):continue
                        if rule.startswith('services_line_') and not nodes[nodes[line].root].text.startswith('line '):continue
                        if rule.startswith('services_timeout') and not nodes[nodes[line].root].text.startswith('line '):continue
                        if rule.startswith(('services_logging', 'services_password_encryption', 'services_timestamp')) or rule in ('services_http_on', 'services_http_off', 'services_https_on', 'services_https_off'):
                            if nodes[line].parent is not None: continue
                        if rule in {'services_logging', 'services_logging_vrf', 'services_logging_vrf_transport', 'services_logging_transport', 'services_logging_port', 'services_logging_vrf_port'}:
                            continue  # canonical update retains malformed suffixes for invalidation
                        if rule in ('services_logging_update', 'services_logging_remove', 'services_logging_legacy', 'services_logging_legacy_remove'):
                            record.update(logging_target(record))
                        global_rules={'services_login_logging','services_timestamp','services_timestamp_plain','services_console_off','services_source_route_off',
                            'services_lookup_off','services_password_encryption_off','services_ipv6_routing','services_http_auth','services_community_expanded',
                            'services_flow_source','services_flow_version','services_flow_timeout',
                            'services_aaa_on','services_aaa_off','services_aaa_default','services_cdp_run_default'}
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
    ambiguous_lines=set()
    for line, items in candidates.items():
        ranked=sorted(items,key=lambda x:(-x[0],x[1]));score, rule, values=ranked[0]
        top=[item for item in ranked if item[0]==score]
        ambiguous=len({json.dumps(item[2],sort_keys=True) for item in top})>1
        if ambiguous:ambiguous_lines.add(line)
        node = nodes[line]
        records[line] = {'rule': rule, 'values': values, 'source_line': line,
                         'root_line': node.root, 'family': node.family,
                         'context_lines': [x.line for x in ancestors(node, nodes)]}
        if line in identities:
            records[line]['identity_ref'] = identities[line]
    official_results = {}
    if official:
        for name, filename in OFFICIAL.items():
            try:
                official_results[name] = run_official_template(name, filename, text)
            except OfficialTemplateError as exc:
                if name in REQUIRED_OFFICIAL:
                    raise
                LOGGER.warning('%s', exc)
                official_results[name] = None
    return {'nodes': nodes, 'records': records, 'official': official_results, 'ambiguous_lines':ambiguous_lines}
