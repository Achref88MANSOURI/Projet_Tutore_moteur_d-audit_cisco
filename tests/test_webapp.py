"""Exercise real HTTP request parsing and normalization using in-memory transport."""
from .contract_fixtures import expected_config
import io
import json
import threading
from email import message_from_bytes
from pathlib import Path
from types import SimpleNamespace

import pytest

import cli
import webapp


@pytest.fixture(scope='module')
def server():
    return SimpleNamespace(server_port=8765, normalization_lock=threading.Lock(), audit_lock=threading.Lock())


class MemorySocket:
    """Socket-compatible transport, so checks also run without network access."""
    def __init__(self, data):
        self.input = io.BytesIO(data)
        self.output = bytearray()

    def makefile(self, *args, **kwargs):
        return self.input

    def sendall(self, data):
        self.output.extend(data)

    def settimeout(self, timeout):
        pass


def request(server, payload=None, *, path='/api/normalize', method='POST', headers=None, raw=None):
    body = raw if raw is not None else json.dumps(payload).encode('utf-8')
    if method != 'POST':
        body = b''
    fields = {'Host': f'127.0.0.1:{server.server_port}',
              'Content-Type': 'application/json', 'Content-Length': str(len(body)),
              **(headers or {})}
    head = f'{method} {path} HTTP/1.1\r\n' + ''.join(f'{key}: {value}\r\n' for key, value in fields.items())
    transport = MemorySocket(head.encode('ascii') + b'\r\n' + body)
    webapp.Handler(transport, ('127.0.0.1', 12345), server)
    raw_head, data = bytes(transport.output).split(b'\r\n\r\n', 1)
    status_line, raw_headers = raw_head.split(b'\r\n', 1)
    return int(status_line.split()[1]), dict(message_from_bytes(raw_headers)), data


@pytest.mark.parametrize('family', ['ios', 'iosxe'])
def test_http_output_matches_existing_engine(server, family):
    source = 'hostname LAB-R01\ninterface GigabitEthernet0/0\n ip address 192.0.2.1 255.255.255.0\n no shutdown\n'
    status, headers, body = request(server, {'configuration': source, 'os_family': family})
    result = json.loads(body)
    assert status == 200
    assert result['normalized'] == cli.normalize(source, os_family=family)
    assert result['normalized']['system']['identity']['hostname'] == 'LAB-R01'
    assert result['duration_ms'] >= 0
    assert headers['Cache-Control'] == 'no-store'


def test_repository_configuration_matches_cli_without_writing(server, tmp_path, monkeypatch):
    source = Path(__file__).resolve().parents[1] / 'configs' / '01_F0456_rt1.bsqmk.cfg'
    if not source.exists():
        pytest.skip('Optional local configuration corpus is not installed')
    text = source.read_text(encoding='utf-8-sig')
    monkeypatch.chdir(tmp_path)
    status, _, body = request(server, {'configuration': text})
    assert status == 200
    assert json.loads(body)['normalized'] == cli.normalize(text)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize('payload,status', [
    ({'configuration': ''}, 400),
    ({'configuration': '   '}, 400),
    ({'configuration': 4}, 400),
    ([], 400),
    ({'configuration': 'hostname R\n', 'os_family': 'nxos'}, 400),
    ({'configuration': 'hostname R\n', 'os_family': []}, 400),
    ({'configuration': 'ASA Version 9.1\n'}, 422),
    ({'configuration': '\ufeffASA Version 9.1\n'}, 422),
    ({'configuration': 'hostname R\x00'}, 400),
    ({'configuration': '\ud800'}, 400),
    ({'configuration': 'x' * (webapp.MAX_CONFIG_BYTES + 1)}, 413),
])
def test_invalid_inputs(server, payload, status):
    code, _, body = request(server, payload)
    assert code == status
    assert json.loads(body)['error']


def test_bom_and_secrets(server):
    status, _, body = request(server, {'configuration': '\ufeffhostname LAB\nusername admin secret 9 PRIVATE_CANARY_123\n'})
    assert status == 200
    assert json.loads(body)['normalized']['system']['identity']['hostname'] == 'LAB'
    assert b'PRIVATE_CANARY_123' not in body


def test_empty_output_is_valid_json(server):
    status, _, body = request(server, {'configuration': '! Only a comment\n'})
    assert status == 200
    assert json.loads(body)['normalized'] == expected_config()


@pytest.mark.parametrize('headers,status', [
    ({'Origin': 'https://example.com'}, 403),
    ({'Origin': 'null'}, 403),
    ({'Host': 'untrusted.example'}, 403),
    ({'Content-Type': 'text/plain'}, 415),
    ({'Content-Length': str(webapp.MAX_REQUEST_BYTES + 1)}, 413),
    ({'Content-Length': 'invalid'}, 400),
])
def test_request_guards(server, headers, status):
    code, _, _ = request(server, {'configuration': 'hostname R\n'}, headers=headers)
    assert code == status


def test_malformed_json(server):
    status, _, _ = request(server, raw=b'not json')
    assert status == 400


def test_busy_engine(server):
    with server.normalization_lock:
        status, _, _ = request(server, {'configuration': 'hostname R\n'})
    assert status == 429


def test_engine_failure_releases_lock_and_hides_details(server, monkeypatch):
    def failing(*args, **kwargs):
        raise RuntimeError('PRIVATE_INTERNAL_DETAIL')
    with monkeypatch.context() as patch:
        patch.setattr(webapp, 'normalize', failing)
        status, _, body = request(server, {'configuration': 'hostname R\n'})
    assert status == 500
    assert b'PRIVATE_INTERNAL_DETAIL' not in body
    status, _, _ = request(server, {'configuration': 'hostname R\n'})
    assert status == 200


def test_only_page_is_served(server):
    status, headers, body = request(server, method='GET', path='/')
    assert status == 200
    assert b'Config Studio' in body
    assert headers['Content-Type'].startswith('text/html')
    for path in ['/cli.py', '/configs/01_F0456_rt1.bsqmk.cfg', '/../README.md']:
        assert request(server, method='GET', path=path)[0] == 404


def test_health_identifies_current_contract(server):
    status, _, body = request(server, method='GET', path='/api/health')
    assert status == 200
    assert json.loads(body) == {'status': 'ok', 'engine': 'cli.normalize',
                                'contract': 'RouterContractV1', 'ready': True}


def test_v1_authentication_aaa_and_value_semantics_over_http(server):
    from jsonschema import Draft202012Validator, FormatChecker
    from schemas.router_contract_v1 import RouterContractV1, router_contract_v1_schema
    configuration = '''aaa authentication login VTY group RAD local
ip ssh version 2
ip ssh time-out 45
ip ssh authentication-retries 2
interface GigabitEthernet0/1
 no ip address
 shutdown
router bgp 65000
 neighbor 192.0.2.2 remote-as 65001
 neighbor 192.0.2.2 password 7 WEB_SYNTHETIC_CANARY
line vty 0 4
 login authentication VTY
 transport input ssh
'''
    status, _, body = request(server, {'configuration': configuration})
    assert status == 200
    document = json.loads(body)['normalized']
    model = RouterContractV1.model_validate(document)
    Draft202012Validator(router_contract_v1_schema(), format_checker=FormatChecker()).validate(document)
    assert model.contract_version == '1.0.0'
    assert model.interfaces[0].ipv4.addresses == []
    assert model.interfaces[0].admin_enabled is False
    assert model.system.management.ssh.enabled is None
    assert model.system.management.ssh.timeout_seconds == 45
    assert model.system.management.ssh.authentication_retries == 2
    assert [m.method for m in model.system.aaa.authentication_method_lists[0].methods] == ['group', 'local']
    assert model.system.aaa.authentication_method_lists[0].methods[0].group_reference == 'RAD'
    assert model.system.management.lines[0].authentication.method_list == 'VTY'
    assert model.routing.bgp[0].neighbors[0].authentication.secret_configured is True
    assert b'WEB_SYNTHETIC_CANARY' not in body


def test_timeout_hides_diagnostics_and_releases_lock(server, monkeypatch):
    def timed_out(*args, **kwargs):
        raise webapp.subprocess.TimeoutExpired('PRIVATE_COMMAND', 120, output='PRIVATE_OUTPUT')
    with monkeypatch.context() as patch:
        patch.setattr(webapp.subprocess, 'run', timed_out)
        status, _, body = request(server, {'configuration': 'hostname R\n'})
    assert status == 504
    assert b'PRIVATE' not in body
    assert server.normalization_lock.acquire(blocking=False)
    server.normalization_lock.release()




def test_catalog_exposes_real_catalog_and_evaluator_registry(server):
    status, _, body = request(server, method='GET', path='/api/catalog')
    result = json.loads(body)
    assert status == 200
    assert result['total_controls'] == 90
    assert result['evaluator_count'] == 63
    assert len(result['controls']) == 90
    assert sum(f['level1'] for f in result['families'].values()) == 53
    assert sum(f['level2'] for f in result['families'].values()) == 90
    assert len(result['registered_evaluator_ids']) == 63


def test_manifest_and_audit_profiles_use_real_results(server):
    status, _, body = request(server, method='GET', path='/api/manifest')
    assert status == 200 and len(json.loads(body)['rules']) == 90
    normalized = cli.normalize('hostname LAB\\naaa new-model\\nip ssh version 2\\n')
    for level, expected in ((1, 53), (2, 90)):
        status, _, body = request(server, {'normalized': normalized, 'profile_level': level, 'include_lower': True}, path='/api/audit')
        report = json.loads(body)
        assert status == 200
        assert len(report['findings']) == expected
        assert all(f['check_id'].startswith('CIS-') for f in report['findings'])
        assert set(report['counts']).issubset({'PASS', 'FAIL', 'NEEDS_REVIEW', 'NOT_APPLICABLE'})


@pytest.mark.parametrize('payload', [
    {'normalized': expected_config(), 'profile_level': True},
    {'normalized': expected_config(), 'profile_level': 1, 'include_lower': 1},
    {'normalized': expected_config(), 'profile_level': 1, 'evidence': []},
    {'normalized': {'unexpected': 'secret-canary'}, 'profile_level': 1},
])
def test_audit_rejects_invalid_payloads_without_leaking_input(server, payload):
    status, _, body = request(server, payload, path='/api/audit')
    assert status == 400
    assert b'secret-canary' not in body
