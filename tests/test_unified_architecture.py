"""Independent pre-refactor outputs and explicit architectural invariants."""
import ast
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

import cli
from normalizer.engine import NormalizationEngine
from normalizer.serialization import to_dict, to_json
from parser.run_ttp import extract
from schemas.normalized_config import NormalizedConfig, business_schema
from tools.validate_normalized import entries, REPRESENTATIVE_IDS
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = json.loads((ROOT / 'tests/fixtures/normalization_reference.json').read_text(encoding='utf-8'))
CORPUS = [row for row in entries() if row[0] in REPRESENTATIVE_IDS]


def expected_business(identifier):
    expected = deepcopy(REFERENCE[identifier])
    # These are corrections of old projection artifacts, not newly parsed syntax.
    if identifier == 'C0017':
        expected['routing']['bgp'][0]['networks'] = [{'prefix': '192.168.10.0/24'}]
    if identifier in ('C0019', 'F0049'):
        process = expected['routing']['bgp'][1]
        assert process['network_instance'] == 'ENTERPRISE'
        assert process['neighbors'] == [{'peer': '192.168.100.2', 'remote_as': 65010}]
        assert process['address_families'][0]['peers'][0]['remote_as'] == 65010
        del process['neighbors']
    if identifier in ('C0042', 'C0043', 'F0456', 'F0457'):
        expected['system']['snmp']['communities'][0]['access'] = 'ro'
    return expected


@pytest.mark.parametrize('identifier,source,family,expected_hash', CORPUS, ids=[r[0] for r in CORPUS])
def test_existing_corpus_matches_independent_reference(identifier, source, family, expected_hash):
    raw = source.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == expected_hash
    actual = cli.normalize(raw.decode('utf-8-sig'), os_family=family)
    Draft202012Validator(business_schema(), format_checker=FormatChecker()).validate(actual)
    assert actual == expected_business(identifier)
    assert source.read_bytes() == raw


def test_reference_and_representative_sample():
    assert len(entries()) == len(REFERENCE) == 105
    assert len(CORPUS) == 10
    assert {row[0] for row in CORPUS} == set(REPRESENTATIVE_IDS)
    assert set(REPRESENTATIVE_IDS) <= set(REFERENCE)


@pytest.mark.parametrize('text,expected', [
    ('router bgp 65010\n network 192.168.10.0\n', {'prefix': '192.168.10.0/24'}),
    ('router bgp 65010\n network 10.0.0.0\n', {'prefix': '10.0.0.0/8'}),
])
def test_classful_mapping_reaches_public_model(text, expected):
    assert cli.normalize(text, official=False)['routing']['bgp'][0]['networks'] == [expected]


def test_uppercase_snmp_access_is_an_explicit_configured_value():
    result = cli.normalize('snmp-server community CANARY RO A\n', official=False)
    assert result['system']['snmp']['communities'] == [{'name': '[REDACTED]', 'access': 'ro', 'access_list': 'A'}]


def test_address_family_neighbor_is_not_copied_into_process_scope():
    result = cli.normalize('router bgp 65000\n address-family ipv4 vrf BLUE\n  neighbor 192.0.2.1 remote-as 65001\n', official=False)
    process = next(p for p in result['routing']['bgp'] if p.get('network_instance') == 'BLUE')
    assert 'neighbors' not in process
    assert process['address_families'][0]['peers'] == [{'peer': '192.0.2.1', 'kind': 'neighbor', 'remote_as': 65001}]


def test_serializer_has_no_capture_or_engine_dependency():
    import normalizer.serialization as serialization
    source = ast.parse(Path(serialization.__file__).read_text())
    imports = [n for n in ast.walk(source) if isinstance(n, (ast.Import, ast.ImportFrom))]
    assert len(imports) == 1 and imports[0].names[0].name == 'json'
    model = NormalizedConfig.model_validate({'interfaces': [{'name': 'E1', 'admin_enabled': False, 'ipv4_addresses': []}],
        'system': {'management': {'lines': [{'name': 'vty 0 4', 'idle_timeout_seconds': 0}]}}})
    text = to_json(model)
    assert json.loads(text) == to_dict(model)
    assert ': ' not in text and '\n' not in text.rstrip('\n')


def test_active_modules_do_not_import_retired_implementations():
    forbidden = {'normalizer.mapping', 'normalizer.v02', 'normalizer.audit_p1', 'normalizer.exports',
        'schemas.normalizedconfig', 'schemas.normalizedconfig_v02', 'schemas.cisco_audit_v02', 'schemas.export_formats'}
    for module in forbidden:
        assert not (ROOT / (module.replace('.', '/') + '.py')).exists()
    paths = [ROOT / 'cli.py', *list((ROOT / 'normalizer').rglob('*.py')), *list((ROOT / 'schemas').glob('*.py')), ROOT / 'parser/validation.py']
    for path in paths:
        tree = ast.parse(path.read_text(encoding='utf-8-sig'))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                assert node.module not in forbidden, str(path)


def test_engine_returns_the_public_model_without_a_version_wrapper():
    engine = NormalizationEngine(extract('hostname R\n', official=False))
    model = engine.run()
    assert engine.run() is model
    assert to_dict(model) == {'system': {'hostname': 'R'}}
    assert 'configuration' not in type(model).model_fields
    assert not hasattr(engine, 'base')


def test_each_capture_has_one_domain_execution(monkeypatch):
    from normalizer.domains import interfaces
    calls = []
    original = interfaces.handle

    def counted(state, record):
        calls.append(record['source_line'])
        return original(state, record)

    monkeypatch.setattr(interfaces, 'handle', counted)
    engine = NormalizationEngine(extract('interface E1\n description CUSTOMER\n mtu 1500\n', official=False))
    assert to_dict(engine.run())['interfaces'][0]['mtu'] == 1500
    engine.run()
    assert calls == [2, 3]


@pytest.mark.parametrize('value', ['false', 'true', 0, 1, None])
def test_boolean_conversion_never_guesses_from_strings_or_numbers(value):
    from normalizer.common.validation import boolean
    with pytest.raises(ValueError):
        boolean(value)


def test_typed_actions_preserve_public_parameter_constraints():
    from pydantic import ValidationError
    from schemas.normalized_config import CommunityPolicyAction, NumericPolicyAction
    with pytest.raises(ValidationError):
        CommunityPolicyAction(kind='community', communities=['unqualified-expression'], additive=False)
    with pytest.raises(ValidationError):
        NumericPolicyAction(kind='metric', value='0')
