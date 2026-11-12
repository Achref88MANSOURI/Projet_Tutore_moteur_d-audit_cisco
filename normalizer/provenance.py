"""Optional pilot provenance. Observes normalization; never decides facts/audits.

The event journal is independent of eligibility bindings. Only reviewed leaf
bindings can establish origins. Final coordinates come from select_configured,
not value searches or the indices that happened to exist during a handler.
"""
from dataclasses import dataclass
from enum import Enum
import hmac
import json
import secrets
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, PrivateAttr
from parser.safe_view import SafeView, build_safe_view
from .common.contexts import at


class ProvenanceError(ValueError):
    """Public errors deliberately contain no input values or chained details."""


class Quality(str, Enum):
    EXACT = 'EXACT'
    CONTEXTUAL = 'CONTEXTUAL'
    PARTIAL = 'PARTIAL'
    UNAVAILABLE = 'UNAVAILABLE'


class Role(str, Enum):
    DECLARATION = 'DECLARATION'
    ASSIGNMENT = 'ASSIGNMENT'
    REPLACEMENT = 'REPLACEMENT'
    REMOVAL = 'REMOVAL'
    REFERENCE = 'REFERENCE'


class State(str, Enum):
    ACTIVE = 'ACTIVE'
    REPLACED = 'REPLACED'
    CANCELLED = 'CANCELLED'
    AMBIGUOUS = 'AMBIGUOUS'


class Model(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)


class Capture(Model):
    capture_id: str
    rule_id: str
    source_line: int
    root_line: int
    context_lines: tuple[int, ...]
    ambiguous: bool


class Contribution(Model):
    contribution_id: str
    fact_id: str
    capture_id: str
    role: Role
    state: State
    quality: Quality


class ReferenceLink(Model):
    status: Literal['RESOLVED_DECLARATION', 'UNRESOLVED']
    target_pointer: str | None = None
    target_capture_ids: tuple[str, ...] = ()
    quality: Quality = Quality.UNAVAILABLE


class Entry(Model):
    fact_id: str | None
    json_pointer: str | None
    quality: Quality
    contribution_ids: tuple[str, ...] = ()
    related_pointers: tuple[str, ...] = ()
    references: tuple[ReferenceLink, ...] = ()


class SourceMap(Model):
    format_version: Literal['0.1.0'] = '0.1.0'
    document_id: str
    coverage: Literal['pilot-only; no exhaustive absence proof'] = 'pilot-only; no exhaustive absence proof'
    source: SafeView
    captures: tuple[Capture, ...]
    contributions: tuple[Contribution, ...]
    entries: tuple[Entry, ...]
    _key: bytes = PrivateAttr(default=b'')
    _mac: bytes = PrivateAttr(default=b'')
    _sidecar_mac: bytes = PrivateAttr(default=b'')

    def assert_matches(self, document, *, document_id):
        if not self._key or document_id != self.document_id:
            raise ProvenanceError('SourceMap document or execution mismatch')
        try:
            payload = _payload(document)
        except Exception:
            raise ProvenanceError('SourceMap document or execution mismatch') from None
        if (not hmac.compare_digest(self._mac, hmac.digest(self._key, payload, 'sha256'))
                or not hmac.compare_digest(self._sidecar_mac, hmac.digest(self._key, self.model_dump_json().encode('utf-8'), 'sha256'))):
            raise ProvenanceError('SourceMap document or execution mismatch')

    def lookup(self, pointer, document, *, document_id):
        """A collective pointer returns context links, never candidate highlights."""
        self.assert_matches(document, document_id=document_id)
        for entry in self.entries:
            if entry.json_pointer == pointer:
                return entry
        return Entry(fact_id=None, json_pointer=None, quality=Quality.UNAVAILABLE)

    def validate_links(self, document, *, document_id):
        self.assert_matches(document, document_id=document_id)
        captures = {c.capture_id: c for c in self.captures}
        contributions = {c.contribution_id: c for c in self.contributions}
        facts = {e.fact_id for e in self.entries if e.fact_id is not None}
        pointers = {e.json_pointer for e in self.entries if e.json_pointer is not None}
        if any(line.number != index for index, line in enumerate(self.source.lines, 1)):
            raise ProvenanceError('Invalid SourceMap physical lines')
        if len(captures) != len(self.captures) or len(contributions) != len(self.contributions):
            raise ProvenanceError('Invalid SourceMap identities')
        for c in self.captures:
            if not c.capture_id.startswith(self.document_id + ':c') or not 1 <= c.source_line <= len(self.source.lines):
                raise ProvenanceError('Invalid SourceMap capture')
            if not 1 <= c.root_line <= c.source_line or any(not 1 <= n < c.source_line for n in c.context_lines):
                raise ProvenanceError('Invalid SourceMap context')
        for c in self.contributions:
            if c.capture_id not in captures or c.fact_id not in facts or not c.contribution_id.startswith(self.document_id + ':e'):
                raise ProvenanceError('Invalid SourceMap contribution')
        for entry in self.entries:
            if entry.fact_id is not None and not entry.fact_id.startswith(self.document_id + ':f'):
                raise ProvenanceError('Invalid SourceMap fact')
            if entry.json_pointer is not None:
                try:
                    value = at(document, entry.json_pointer)
                except (KeyError, IndexError, TypeError, AttributeError, ValueError):
                    raise ProvenanceError('Invalid SourceMap final pointer') from None
                if entry.quality == Quality.EXACT and (value is None or not entry.contribution_ids):
                    raise ProvenanceError('Invalid SourceMap exact claim')
            for cid in entry.contribution_ids:
                c = contributions.get(cid)
                if c is None or c.state != State.ACTIVE or c.fact_id != entry.fact_id:
                    raise ProvenanceError('Inactive SourceMap contribution')
                if entry.quality == Quality.EXACT and (c.quality != Quality.EXACT or self.source.lines[captures[c.capture_id].source_line - 1].masked):
                    raise ProvenanceError('Unsafe SourceMap exact claim')
            for pointer in entry.related_pointers:
                if pointer not in pointers:
                    raise ProvenanceError('Invalid SourceMap contextual link')
            for reference in entry.references:
                if reference.target_pointer is not None:
                    try:
                        at(document, reference.target_pointer)
                    except (KeyError, IndexError, TypeError, AttributeError, ValueError):
                        raise ProvenanceError('Invalid SourceMap reference') from None
                if any(cid not in captures for cid in reference.target_capture_ids):
                    raise ProvenanceError('Invalid SourceMap reference capture')


@dataclass(frozen=True)
class Limits:
    max_input_bytes: int = 2 * 1024 * 1024
    max_lines: int = 20000
    max_captures: int = 10000
    max_context_links: int = 100000
    max_contributions: int = 50000
    max_entries: int = 30000
    max_output_bytes: int = 8 * 1024 * 1024

    def check(self):
        defaults = Limits()
        if any(type(v) is not int or v <= 0 or v > getattr(defaults, k) for k, v in vars(self).items()):
            raise ProvenanceError('Invalid provenance limits')


@dataclass(frozen=True)
class NormalizationResult:
    normalized: dict
    source_map: SourceMap | None
    provenance_error: Literal['PROVENANCE_UNAVAILABLE'] | None = None

    @property
    def document_id(self):
        return self.source_map.document_id if self.source_map is not None else None


def _payload(document):
    return json.dumps(document, sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def check_input(text, limits):
    limits.check()
    if not isinstance(text, str) or len(text.encode('utf-8')) > limits.max_input_bytes:
        raise ProvenanceError('Provenance input limit exceeded')
    # Inventory uses splitlines: reject other line/control separators rather
    # than silently changing physical LF/CRLF coordinates in the sidecar.
    remaining = text.replace('\r\n', '').replace('\n', '').replace('\t', '')
    if any(ord(c) < 32 or c in '\x7f\x85\u2028\u2029' for c in remaining):
        raise ProvenanceError('Unsupported source line boundaries')
    if len(text.splitlines()) > limits.max_lines:
        raise ProvenanceError('Provenance line limit exceeded')


@dataclass(frozen=True)
class Fact:
    pointer: str
    value: object


def _facts(model):
    """Coordinates/identities only, read from canonical objects, never CLI."""
    result = {}
    for path in ('system/management/ssh/version', 'system/management/ssh/version_setting',
                 'system/ip_services/cdp_enabled', 'system/aaa/enabled'):
        result[('scalar', path)] = Fact('/' + path, at(model, path))
    for index, item in enumerate(model.system.management.lines or []):
        if not item.name.startswith('vty '):
            continue
        path = f'/system/management/lines/{index}'
        for field in ('name', 'allowed_transports', 'idle_timeout_seconds'):
            value = getattr(item, field)
            result[('vty', item.name, field)] = Fact(path + '/' + field, tuple(value) if isinstance(value, list) else value)
        for field in ('method', 'method_list'):
            value = getattr(item.authentication, field) if item.authentication is not None else None
            result[('vty', item.name, 'authentication/' + field)] = Fact(path + '/authentication/' + field, value)
    for index, item in enumerate(model.system.logging.destinations or []):
        for field in ('address', 'vrf', 'transport', 'port'):
            result[('syslog', item.address, item.vrf, field)] = Fact(f'/system/logging/destinations/{index}/{field}', getattr(item, field))
    for index, item in enumerate(model.interfaces or []):
        if item.encapsulation is not None and item.encapsulation.kind == 'ppp':
            result[('interface_encapsulation', item.name)] = Fact(
                f'/interfaces/{index}/encapsulation',
                item.encapsulation.model_dump(mode='json'))
    for index, item in enumerate(model.system.aaa.authentication_method_lists or []):
        if item.service == 'login' and item.local_setting == 'configured':
            result[('aaa_list', item.name, item.service, item.privilege_level)] = Fact(f'/system/aaa/authentication_method_lists/{index}/name', item.name)
    return result


def _supports(rule, key):
    if key[0] == 'scalar':
        return rule in {
            'system/management/ssh/version': {'services_ssh_version', 'services_ssh_version_remove', 'admin_ssh_version_remove'},
            'system/management/ssh/version_setting': {'services_ssh_version', 'services_ssh_version_remove', 'admin_ssh_version_remove'},
            'system/ip_services/cdp_enabled': {'services_cdp_run', 'services_cdp_run_off'},
            'system/aaa/enabled': {'services_aaa_on', 'services_aaa_off'},
        }[key[1]]
    if key[0] == 'vty':
        field = key[-1]
        if field == 'name':
            return rule == 'services_line'
        if field == 'allowed_transports':
            return rule.startswith('services_transport') and not rule.startswith('services_transport_output')
        if field == 'idle_timeout_seconds':
            return rule.startswith('services_timeout')
        return rule in {'services_login', 'services_login_plain', 'services_login_authentication_remove', 'services_login_authentication_remove_args'}
    if key[0] == 'syslog':
        return rule in {'services_logging_update', 'services_logging_legacy', 'services_logging_remove', 'services_logging_legacy_remove'}
    if key[0] == 'interface_encapsulation':
        return rule == 'if_ppp'
    return key[0] == 'aaa_list' and rule.startswith('admin_authentication_login')


class Collector:
    def __init__(self, text, extracted, *, limits):
        self.limits = limits
        records = extracted['records']
        if len(records) > limits.max_captures or sum(len(r['context_lines']) for r in records.values()) > limits.max_context_links:
            raise ProvenanceError('Provenance capture limit exceeded')
        self.document_id = uuid4().hex
        self.source = build_safe_view(text, extracted)
        self.captures = {line: Capture(capture_id=f'{self.document_id}:c{i}', rule_id=r['rule'],
                                       source_line=line, root_line=r['root_line'], context_lines=tuple(r['context_lines']),
                                       ambiguous=line in extracted.get('ambiguous_lines', ()))
                         for i, (line, r) in enumerate(sorted(records.items()), 1)}
        self.fact_ids, self.events, self.active = {}, [], {}
        self.current = None
        self.sidecar = None

    def begin(self, state, record):
        self.current = (_facts(state.c), record, [])

    def bound(self, candidates, line):
        if self.current is not None:
            self.current[2].extend((path, line) for path, _ in candidates)

    def abort(self):
        self.current = None

    def _id(self, key):
        if key not in self.fact_ids:
            self.fact_ids[key] = f'{self.document_id}:f{len(self.fact_ids) + 1}'
        return self.fact_ids[key]

    def _cancel(self, key, status):
        for index in self.active.pop(key, []):
            self.events[index] = self.events[index].model_copy(update={'state': status})

    def _event(self, key, line, role, status, quality):
        if len(self.events) >= self.limits.max_contributions:
            raise ProvenanceError('Provenance contribution limit exceeded')
        item = Contribution(contribution_id=f'{self.document_id}:e{len(self.events) + 1}', fact_id=self._id(key),
                            capture_id=self.captures[line].capture_id, role=role, state=status, quality=quality)
        self.events.append(item)
        if status == State.ACTIVE:
            self.active.setdefault(key, []).append(len(self.events) - 1)

    def commit(self, state):
        before, record, observations = self.current
        self.current = None
        after = _facts(state.c)
        line, rule = record['source_line'], record['rule']
        for key in before.keys() | after.keys():
            previous, current = before.get(key), after.get(key)
            self._id(key)
            changed = previous is None or current is None or type(previous.value) is not type(current.value) or previous.value != current.value
            removed = current is None or current.value is None
            if removed:
                explicit = _supports(rule, key)
                removal = 'remove' in rule or 'default' in rule or rule.endswith('_reset')
                had_value = previous is not None and previous.value is not None
                if changed and had_value or explicit and removal:
                    # An overlap invalidates another range; it is not a source
                    # command explicitly configuring that range's value.
                    target = getattr(state, '_line_target', None)
                    own = (key[0] != 'vty' or
                           target is not None and current is not None and current.pointer.startswith('/' + target.strip('/') + '/') or
                           state.records.get(record['root_line'], {}).get('values', {}).get('name') == key[1])
                    status = State.CANCELLED if explicit and own and removal else State.AMBIGUOUS
                    self._cancel(key, status)
                    if line in self.captures:
                        self._event(key, line, Role.REMOVAL if removal else Role.ASSIGNMENT, status, Quality.PARTIAL)
                continue
            sources = list(dict.fromkeys(source for path, source in observations
                                         if path == current.pointer or path.startswith(current.pointer + '/')
                                         if source in self.captures and _supports(state.records[source]['rule'], key)
                                         and state.eligible(source)))
            if not sources:
                if changed:
                    self._cancel(key, State.AMBIGUOUS)
                continue
            for source in sources:
                capture = self.captures[source]
                existing = self.active.get(key, [])
                if not changed and any(self.events[i].capture_id == capture.capture_id for i in existing):
                    continue  # Rebinding a surviving Syslog item is not a new fact.
                declaration = key[0] == 'aaa_list' or key[0] == 'vty' and key[-1] == 'name'
                reference = key[0] == 'vty' and key[-1] == 'authentication/method_list'
                role = Role.DECLARATION if declaration else Role.REFERENCE if reference else Role.REPLACEMENT if existing else Role.ASSIGNMENT
                if not declaration or changed:
                    self._cancel(key, State.REPLACED)
                quality = Quality.EXACT if not capture.ambiguous and not self.source.lines[source - 1].masked else Quality.PARTIAL
                if key[0] == 'vty' and key[-1] == 'name' and state.records[source]['values'].get('name') != current.value:
                    quality = Quality.CONTEXTUAL  # Derived interval, not a verbatim source header.
                self._event(key, source, role, State.ACTIVE, quality)

    def finalize(self, state, document, projection):
        current = _facts(state.c)

        def translated(pointer):
            if pointer in projection:
                return projection[pointer]
            parts = pointer.split('/')
            for cut in range(len(parts) - 1, -1, -1):
                parent, tail = '/'.join(parts[:cut]), parts[cut:]
                if any(part.isdigit() for part in tail):
                    return None  # Never reuse an index across an unmapped item.
                if parent in projection:
                    return projection[parent] + '/' + '/'.join(tail)
            return pointer if not any(part.isdigit() for part in parts) else None

        entries = []
        for key, fact_id in self.fact_ids.items():
            fact = current.get(key)
            pointer = translated(fact.pointer) if fact else None
            try:
                value = at(document, pointer) if pointer is not None else None
            except (KeyError, IndexError, TypeError, AttributeError, ValueError):
                pointer, value = None, None
            active = self.active.get(key, [])
            expected = list(fact.value) if fact and isinstance(fact.value, tuple) else fact.value if fact else None
            if type(value) is not type(expected) or value != expected:
                self._cancel(key, State.AMBIGUOUS)
                active = []
            if value is None or not active:
                self._cancel(key, State.CANCELLED)
                entries.append(Entry(fact_id=fact_id, json_pointer=pointer, quality=Quality.UNAVAILABLE))
                continue
            ids = tuple(self.events[i].contribution_id for i in active)
            qualities = {self.events[i].quality for i in active}
            quality = (Quality.EXACT if qualities == {Quality.EXACT} else
                       Quality.CONTEXTUAL if qualities <= {Quality.EXACT, Quality.CONTEXTUAL} else Quality.PARTIAL)
            references = []
            if key[0] == 'vty' and key[-1] == 'authentication/method_list':
                targets = [(k, f) for k, f in current.items() if k[0] == 'aaa_list' and f.value == fact.value]
                if len(targets) == 1:
                    target_key, target = targets[0]
                    target_pointer = translated(target.pointer)
                    target_ids = tuple(self.events[i].capture_id for i in self.active.get(target_key, []))
                    if target_pointer is not None and target_ids:
                        references.append(ReferenceLink(status='RESOLVED_DECLARATION', target_pointer=target_pointer,
                                                        target_capture_ids=target_ids, quality=Quality.CONTEXTUAL))
                if not references:
                    references.append(ReferenceLink(status='UNRESOLVED'))
            entries.append(Entry(fact_id=fact_id, json_pointer=pointer, quality=quality,
                                 contribution_ids=ids, references=tuple(references)))
        # Parent containers summarize scope, not a unique command responsible
        # for a collective Finding. No direct contribution/highlight is emitted.
        known = {e.json_pointer for e in entries if e.json_pointer is not None}
        parents = {}
        for entry in entries:
            if entry.json_pointer is None or entry.quality == Quality.UNAVAILABLE:
                continue
            parent = entry.json_pointer.rsplit('/', 1)[0]
            while parent:
                if parent not in known:
                    parents.setdefault(parent, []).append(entry.json_pointer)
                parent = parent.rsplit('/', 1)[0]
        entries.extend(Entry(fact_id=None, json_pointer=p, quality=Quality.CONTEXTUAL,
                             related_pointers=tuple(dict.fromkeys(children))) for p, children in sorted(parents.items()))
        if len(entries) > self.limits.max_entries:
            raise ProvenanceError('Provenance entry limit exceeded')
        result = SourceMap(document_id=self.document_id, source=self.source, captures=tuple(self.captures.values()),
                           contributions=tuple(self.events), entries=tuple(entries))
        result._key = secrets.token_bytes(32)
        result._mac = hmac.digest(result._key, _payload(document), 'sha256')
        result._sidecar_mac = hmac.digest(result._key, result.model_dump_json().encode('utf-8'), 'sha256')
        result.validate_links(document, document_id=self.document_id)
        if len(result.model_dump_json().encode('utf-8')) > self.limits.max_output_bytes:
            raise ProvenanceError('Provenance output limit exceeded')
        self.sidecar = result
