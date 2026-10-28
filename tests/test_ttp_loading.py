"""Direct template loading, metadata association and selection invariants."""
import json
from pathlib import Path
import shutil
from xml.etree import ElementTree

import pytest

import parser.run_ttp as parsing

PREFIX = '{{ source_line | DIGIT | to_int }} '


def group(identifier, pattern, functions=None):
    element = ElementTree.Element('group', name=identifier + '*', method='table')
    if functions:
        element.set('functions', functions)
    element.text = '\n' + PREFIX + pattern + '\n'
    return ElementTree.tostring(element, encoding='unicode')


def project(tmp_path, monkeypatch, groups, metadata=None):
    templates = tmp_path / 'templates'
    (templates / 'cisco_ios').mkdir(parents=True)
    (templates / 'cisco_ios/services.ttp').write_text('\n'.join(groups), encoding='utf-8')
    (templates / 'rule_metadata.json').write_text(json.dumps(metadata or {}), encoding='utf-8')
    monkeypatch.setattr(parsing, 'ROOT', tmp_path)
    return templates


def test_all_project_groups_have_the_exact_metadata_association():
    definitions, templates = parsing.load_templates()
    metadata = json.loads((parsing.ROOT / 'templates/rule_metadata.json').read_text(encoding='utf-8'))
    assert len(templates) == 11
    assert sum(len(sources) for sources in templates.values()) == 28
    assert len(definitions) == 374
    assert len(metadata) == 73
    assert sum('scope' in value for value in metadata.values()) == 71
    assert sum('choices' in value for value in metadata.values()) == 3
    for identifier, definition in definitions.items():
        assert {key: value for key, value in definition.items() if key != 'pattern'} == metadata.get(identifier, {})
        assert set(metadata.get(identifier, {})) <= {'scope', 'choices'}
        assert 'source_line' not in definition['pattern']
    assert definitions['if_mop_off']['choices'] == {'feature': ['enabled', 'sysid']}
    assert definitions['services_community_expanded']['choices'] == {'action': ['permit', 'deny']}
    assert definitions['services_user_no_format']['choices'] == {'credential_type': ['secret', 'password']}
    owned = [identifier for sources in templates.values() for template in sources for identifier in template.rule_ids]
    assert len(owned) == len(set(owned)) == 374
    assert set(owned) == set(definitions)


def write_template(directory, relative_path, groups, variables=''):
    path = directory / 'cisco_ios' / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(variables + '\n'.join(groups), encoding='utf-8')


@pytest.mark.parametrize('path,family', [
    ('services.ttp', 'services'),
    ('routing/bgp/neighbors.ttp', 'bgp'),
    ('routing/bgp/af/options.ttp', 'bgp'),
    ('security/acl_standard.ttp', 'acl_standard'),
    ('routing/bgp/interfaces.ttp', 'bgp'),
    ('services/routing/ospf/networks.ttp', 'ospf'),
    ('routing/rip.ttp', 'services'),
])
def test_family_association_uses_nearest_directory_then_file_stem(path, family):
    assert parsing.template_family(Path(path)) == family


def test_recursive_files_for_one_family_have_deterministic_path_order(tmp_path, monkeypatch):
    directory = project(tmp_path, monkeypatch, [group('seed', 'seed {{ value }}')])
    write_template(directory, 'routing/bgp/z.ttp', [group('last', 'last {{ value }}')])
    write_template(directory, 'routing/bgp/a.ttp', [group('first', 'first {{ value }}')])
    write_template(directory, 'system/services/dns.ttp', [group('dns', 'dns {{ value }}')])
    original = Path.rglob

    def reversed_discovery(path, pattern):
        return iter(reversed(list(original(path, pattern))))

    monkeypatch.setattr(Path, 'rglob', reversed_discovery)
    definitions, families = parsing.load_templates()
    assert [source.path for source in families['bgp']] == ['routing/bgp/a.ttp', 'routing/bgp/z.ttp']
    assert [source.path for source in families['services']] == ['services.ttp', 'system/services/dns.ttp']
    assert [source.rule_ids for source in families['bgp']] == [('first',), ('last',)]
    assert set(definitions) == {'seed', 'dns', 'first', 'last'}


def test_same_filename_in_distinct_directories_does_not_replace_a_template(tmp_path, monkeypatch):
    directory = project(tmp_path, monkeypatch, [group('seed', 'seed {{ value }}')])
    write_template(directory, 'one/services/common.ttp', [group('first', 'first {{ value }}')])
    write_template(directory, 'two/services/common.ttp', [group('second', 'second {{ value }}')])
    definitions, families = parsing.load_templates()
    assert len(families['services']) == 3
    result = parsing.extract('first A\nsecond B\n', official=False)
    assert [result['records'][line]['rule'] for line in (1, 2)] == ['first', 'second']
    assert set(definitions) == {'seed', 'first', 'second'}


def test_overlapping_rules_from_separate_files_share_selection_and_metadata(tmp_path, monkeypatch):
    directory = project(tmp_path, monkeypatch, [group('generic', 'logging {{ address | ORPHRASE }}')],
        {'specific': {'choices': {'address': ['192.0.2.1']}, 'scope': 'global'}})
    write_template(directory, 'system/services/logging.ttp', [group('specific', 'logging host {{ address }}')])
    result = parsing.extract('logging host 192.0.2.1\nlogging host 192.0.2.2\n', official=False)
    assert result['records'][1]['rule'] == 'specific'
    assert result['records'][2]['rule'] == 'generic'
    assert not result['ambiguous_lines']


def test_equal_scores_across_files_keep_ambiguity_and_identifier_tie_break(tmp_path, monkeypatch):
    directory = project(tmp_path, monkeypatch, [group('beta', 'marker {{ right }}')])
    write_template(directory, 'system/services/marker.ttp', [group('alpha', 'marker {{ left }}')])
    result = parsing.extract('marker VALUE\n', official=False)
    assert result['records'][1]['rule'] == 'alpha'
    assert result['records'][1]['values'] == {'left': 'VALUE'}
    assert result['ambiguous_lines'] == {1}


def test_template_regex_variables_are_isolated_between_files(tmp_path, monkeypatch):
    directory = project(tmp_path, monkeypatch, [group('seed', 'seed {{ value }}')])
    write_template(directory, 'services/a.ttp', [group('first', 'tag {{ value | re("token") }}')],
        "<vars>\ntoken = 'ALPHA'\n</vars>\n")
    write_template(directory, 'services/b.ttp', [group('second', 'tag {{ value | re("token") }}')],
        "<vars>\ntoken = 'BETA'\n</vars>\n")
    result = parsing.extract('tag ALPHA\ntag BETA\n', official=False)
    assert [result['records'][line]['rule'] for line in (1, 2)] == ['first', 'second']


def test_duplicate_ids_in_nested_files_of_one_family_are_rejected(tmp_path, monkeypatch):
    directory = project(tmp_path, monkeypatch, [group('duplicate', 'marker {{ value }}')])
    write_template(directory, 'system/services/another.ttp', [group('duplicate', 'another {{ value }}')])
    with pytest.raises(ValueError, match='Duplicate TTP rule identifier'):
        parsing.load_templates()


def test_unassociated_template_family_is_rejected(tmp_path, monkeypatch):
    directory = project(tmp_path, monkeypatch, [group('seed', 'seed {{ value }}')])
    write_template(directory, 'routing/unknown.ttp', [group('unknown', 'marker {{ value }}')])
    with pytest.raises(ValueError, match='No command family associated'):
        parsing.load_templates()


def test_all_374_groups_can_load_from_a_nested_split_copy(tmp_path, monkeypatch):
    definitions_before, sources = parsing.load_templates()
    text = ('hostname R\ninterface E1\n ip address 192.0.2.1 255.255.255.0\n'
        'router bgp 65000\n neighbor G peer-group\n neighbor G remote-as 65001\n'
        'ntp server 192.0.2.10\nno ip http server\n')
    before = parsing.extract(text, official=False)
    directory = tmp_path / 'templates'
    directory.mkdir()
    shutil.copyfile(parsing.ROOT / 'templates/rule_metadata.json', directory / 'rule_metadata.json')
    for family, templates in sources.items():
        for template in templates:
            if family == 'services' and template.path == 'services/system.ttp':
                groups = ElementTree.fromstring('<template>' + template.source + '</template>').findall('group')
                half = len(groups) // 2
                for filename, items in [('a.ttp', groups[:half]), ('b.ttp', groups[half:])]:
                    write_template(directory, 'network/services/' + filename,
                        [ElementTree.tostring(item, encoding='unicode') for item in items])
            else:
                path = directory / 'cisco_ios' / 'network' / family / template.path
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(template.source, encoding='utf-8')
    monkeypatch.setattr(parsing, 'ROOT', tmp_path)
    definitions_after, families = parsing.load_templates()
    assert definitions_after == definitions_before
    assert sum(len(templates) for templates in families.values()) == 29
    assert len(families['services']) == 14
    owned = [identifier for templates in families.values() for source in templates for identifier in source.rule_ids]
    assert len(owned) == len(set(owned)) == 374
    after = parsing.extract(text, official=False)
    assert after['records'] == before['records']
    assert after['ambiguous_lines'] == before['ambiguous_lines']


def test_advanced_domains_keep_all_42_groups_and_their_dispatch():
    definitions, families = parsing.load_templates()
    sources = families['advanced']
    assert [(source.path, len(source.rule_ids)) for source in sources] == [
        ('advanced/isis.ttp', 3), ('advanced/layer2.ttp', 11),
        ('advanced/mpls.ttp', 3), ('advanced/multicast.ttp', 7),
        ('advanced/pki.ttp', 7), ('advanced/qos.ttp', 11),
    ]
    assert not (parsing.ROOT / 'templates/cisco_ios/advanced.ttp').exists()
    owned = [identifier for source in sources for identifier in source.rule_ids]
    assert len(owned) == len(set(owned)) == 42
    assert set(owned) == {identifier for identifier in definitions
        if identifier.startswith(('advanced_', 'catalogue_pim_'))}
    assert {identifier: definitions[identifier]['scope'] for identifier in owned
        if 'scope' in definitions[identifier]} == {
            'catalogue_pim_autorp': 'global', 'catalogue_pim_discovery': 'global',
            'catalogue_pim_ssm': 'global', 'catalogue_pim_bsr': 'global',
            'catalogue_pim_rp_candidate': 'global',
        }


def test_advanced_split_keeps_shared_inputs_sensitive_contexts_and_selection(monkeypatch):
    text = ('router isis CORE\n passive-interface Loopback0\n router-id Loopback1\n'
        'l2vpn evpn\n router-id Loopback0\nbridge-domain 100\n member Gi0/1 service-instance 100\n'
        'vlan 100\n name USERS\npolicy-map WAN\n class GOLD\n  set dscp ef\n'
        'class-map match-any GOLD\n ip pim autorp listener\nip pim autorp listener\n'
        'interface Gi0/1\n ip router isis CORE\n')
    definitions, families = parsing.load_templates()
    paths = {source.source: source.path for source in families['advanced']}
    inputs = {}
    real_ttp = parsing.ttp

    def observed(*args, **kwargs):
        path = paths.get(kwargs.get('template'))
        if path is not None:
            inputs[path] = kwargs['data']
        return real_ttp(*args, **kwargs)

    monkeypatch.setattr(parsing, 'ttp', observed)
    result = parsing.extract(text, official=False)
    assert set(inputs) == set(paths.values())
    assert len(set(inputs.values())) == 1
    assert next(iter(inputs.values())).splitlines() == [
        f'{number} {line.strip()}' for number, line in enumerate(text.splitlines(), 1) if number <= 15]
    expected = {
        2: ('advanced_isis_passive', 1, [1]),
        3: ('advanced_l2_rid', 1, [1]),  # Existing generic match in an IS-IS context stays valid.
        5: ('advanced_l2_rid', 4, [4]),
        6: ('advanced_l2_bridge', 6, []),
        7: ('advanced_l2_member', 6, [6]),
        9: ('advanced_vlan_name', 8, [8]),
        11: ('advanced_qos_class', 10, [10]),
    }
    for line, (rule, root, context) in expected.items():
        record = result['records'][line]
        assert (record['rule'], record['root_line'], record['context_lines'], record['family']) == (
            rule, root, context, 'advanced')
    assert 14 not in result['records']
    assert result['records'][15]['rule'] == 'catalogue_pim_autorp'
    assert not result['ambiguous_lines']
    reversed_families = {family: tuple(reversed(sources)) for family, sources in families.items()}
    monkeypatch.setattr(parsing, 'load_templates', lambda: (definitions, reversed_families))
    assert parsing.extract(text, official=False) == result


def test_rip_file_contains_only_the_five_original_groups_in_order():
    expected = ('catalogue_rip', 'catalogue_rip_network', 'catalogue_rip_family',
        'catalogue_rip_redistribute', 'catalogue_rip_no_summary')
    definitions, families = parsing.load_templates()
    sources = {template.path: template for template in families['services']}
    assert sources['routing/rip.ttp'].rule_ids == expected
    service_ids = [identifier for path, source in sources.items()
        if path.startswith('services/') for identifier in source.rule_ids]
    assert len(service_ids) == 117
    assert not set(expected).intersection(service_ids)
    scoped = {identifier for identifier, rule in definitions.items() if rule.get('scope') == 'root:router rip'}
    assert scoped | {'catalogue_rip'} == set(expected)
    groups = ElementTree.fromstring('<template>' + sources['routing/rip.ttp'].source + '</template>').findall('group')
    assert groups[0].get('functions') == 'set(True, declared)'
    assert groups[-1].get('functions') == 'set(False, enabled)'


def test_rip_and_service_templates_receive_the_exact_same_dispatch_lines(monkeypatch):
    _, families = parsing.load_templates()
    sources = {template.source: template.path for template in families['services']}
    inputs = {}
    real_ttp = parsing.ttp

    def observed(*args, **kwargs):
        path = sources.get(kwargs.get('template'))
        if path is not None:
            inputs[path] = kwargs['data']
        return real_ttp(*args, **kwargs)

    monkeypatch.setattr(parsing, 'ttp', observed)
    result = parsing.extract('hostname R\nrouter rip\n network 192.0.2.0\n'
        ' address-family ipv4 vrf CLIENT\n  redistribute bgp 65000 metric 1\n'
        '  no auto-summary\nntp server 192.0.2.10\nrouter bgp 65001\n', official=False)
    assert set(inputs) == set(sources.values())
    assert len(inputs) == 13
    assert len(set(inputs.values())) == 1
    assert inputs['routing/rip.ttp'].splitlines() == [
        '1 hostname R', '2 router rip', '3 network 192.0.2.0',
        '4 address-family ipv4 vrf CLIENT', '5 redistribute bgp 65000 metric 1',
        '6 no auto-summary', '7 ntp server 192.0.2.10',
    ]
    assert [result['records'][line]['rule'] for line in range(2, 7)] == [
        'catalogue_rip', 'catalogue_rip_network', 'catalogue_rip_family',
        'catalogue_rip_redistribute', 'catalogue_rip_no_summary',
    ]
    assert all(result['records'][line]['family'] == 'services' for line in range(2, 7))
    assert result['records'][1]['rule'] == 'services_hostname'
    assert result['records'][7]['rule'] == 'services_ntp'


def test_template_is_authoritative_without_a_generated_catalogue(tmp_path, monkeypatch):
    templates = project(tmp_path, monkeypatch, [group('services_hostname', 'node-name {{ hostname }}')])
    assert not (templates / 'rules.json').exists()
    result = parsing.extract('node-name ROUTER\n', official=False)
    assert result['records'][1]['values'] == {'hostname': 'ROUTER'}
    assert parsing.extract('hostname ROUTER\n', official=False)['records'] == {}
    assert parsing.extract('node-name ROUTER EXTRA\n', official=False)['records'] == {}
    # Reading the next call's source directly also avoids stale catalogue caches.
    (templates / 'cisco_ios/services.ttp').write_text(group('services_hostname', 'hostname {{ hostname }}'), encoding='utf-8')
    assert parsing.extract('hostname ROUTER\n', official=False)['records'][1]['rule'] == 'services_hostname'


def test_parsing_requires_no_retired_generation_files():
    for name in ('tools/build_templates.py', 'tools/catalogue_rules.py',
        'docs/deferred/reliability_rules.json', 'templates/rules.json'):
        assert not (parsing.ROOT / name).exists()
    result = parsing.extract('hostname READY\n', official=False)
    assert result['records'][1]['values'] == {'hostname': 'READY'}


def test_global_scope_and_choices_still_filter_captures(tmp_path, monkeypatch):
    project(tmp_path, monkeypatch, [group('services_hostname', 'hostname {{ hostname }}')],
        {'services_hostname': {'scope': 'global', 'choices': {'hostname': ['ROOT']}}})
    assert parsing.extract('hostname ROOT\n', official=False)['records'][1]['values'] == {'hostname': 'ROOT'}
    assert parsing.extract('hostname OTHER\n', official=False)['records'] == {}
    assert parsing.extract('line vty 0 4\n hostname ROOT\n', official=False)['records'] == {}


def test_root_scope_and_ttp_constants_are_preserved(tmp_path, monkeypatch):
    project(tmp_path, monkeypatch, [group('catalogue_call_home_active', 'active', 'set(True, enabled)')],
        {'catalogue_call_home_active': {'scope': 'root:call-home'}})
    result = parsing.extract('call-home\n active\narchive\n active\n', official=False)
    assert set(result['records']) == {2}
    assert result['records'][2]['values'] == {'enabled': True}
    assert result['records'][2]['context_lines'] == [1]


def test_specific_rule_wins_over_greedy_overlap(tmp_path, monkeypatch):
    project(tmp_path, monkeypatch, [group('generic', 'logging {{ address | ORPHRASE }}'),
        group('specific', 'logging host {{ address }}')])
    result = parsing.extract('logging host 192.0.2.1\n', official=False)
    assert result['records'][1]['rule'] == 'specific'
    assert result['records'][1]['values'] == {'address': '192.0.2.1'}
    assert not result['ambiguous_lines']


@pytest.mark.parametrize('second_field,ambiguous', [('left', False), ('right', True)])
def test_equal_scores_keep_lexical_tie_break_and_value_ambiguity(tmp_path, monkeypatch, second_field, ambiguous):
    project(tmp_path, monkeypatch, [group('beta', 'marker {{ ' + second_field + ' }}'),
        group('alpha', 'marker {{ left }}')])
    result = parsing.extract('marker VALUE\n', official=False)
    assert result['records'][1]['rule'] == 'alpha'
    assert result['records'][1]['values'] == {'left': 'VALUE'}
    assert result['ambiguous_lines'] == ({1} if ambiguous else set())


@pytest.mark.parametrize('metadata', [
    {'missing_rule': {'scope': 'global'}},
    {'services_hostname': {'scope': 'root:'}},
    {'services_hostname': {'scope': 'unsupported'}},
    {'services_hostname': {'choices': {'hostname': 'ROOT'}}},
    {'services_hostname': {'choices': {}}},
    {'services_hostname': {'pattern': 'hostname {{ hostname }}'}},
])
def test_invalid_or_stale_metadata_cannot_silently_disable_restrictions(tmp_path, monkeypatch, metadata):
    project(tmp_path, monkeypatch, [group('services_hostname', 'hostname {{ hostname }}')], metadata)
    with pytest.raises(ValueError):
        parsing.load_templates()


def test_duplicate_ids_across_domains_are_rejected(tmp_path, monkeypatch):
    templates = project(tmp_path, monkeypatch, [group('duplicate', 'marker {{ value }}')])
    (templates / 'cisco_ios/interfaces.ttp').write_text(group('duplicate', 'interface {{ name }}'), encoding='utf-8')
    with pytest.raises(ValueError, match='Duplicate TTP rule identifier'):
        parsing.load_templates()


@pytest.mark.parametrize('source', [
    '<group name="broken*" method="table">hostname {{ hostname }}</group>',
    '<group name="broken*" method="table">' + PREFIX + 'hostname {{ hostname }}\nshutdown</group>',
])
def test_unsupported_group_layout_is_rejected_explicitly(tmp_path, monkeypatch, source):
    project(tmp_path, monkeypatch, [source])
    with pytest.raises(ValueError, match='source-numbered capture line'):
        parsing.load_templates()
