"""One normalization engine: declarations, domain mappings, relations, contract.

Each capture has one owning domain. Declarations establish identities first;
only reference-dependent commands are deferred. Temporary field ownership
prevents constructor defaults from becoming configured facts.
"""
from collections import defaultdict
from copy import deepcopy
from parser.validation import validate_record
from schemas import normalized_config as s
from .common.addresses import flat_official
from .common.contexts import root, address_family, at
from .common.configured import Binding, leaves, select_configured, validate_targets
from .common.validation import validate
from .domains import handler_for, DECLARATIONS
from .domains import policies


class NormalizationEngine:
    def __init__(self, extracted, *, os_family='ios'):
        if os_family not in ('ios', 'iosxe'):
            raise ValueError('Supported OS families: ios, iosxe')
        self.nodes = extracted['nodes']
        self.records = extracted['records']
        self.validation = {line: validate_record(r) for line, r in self.records.items()}
        identities = set()
        for line, record in sorted(self.records.items()):
            duplicate = False
            if record['rule'] in ('if_header', 'policy_header'):
                key = (record['rule'], record['values'].get('name'), record['values'].get('sequence'))
                duplicate = key in identities
                identities.add(key)
            invalid_parent = any(not self.validation.get(n, {'valid': True})['valid'] for n in record['context_lines'])
            if duplicate or invalid_parent or line in extracted.get('ambiguous_lines', set()):
                self.validation[line] = dict(valid=False, invalid_fields=list(record['values']), fields={k: 'invalid' for k in record['values']})
        self.c = s.NormalizedConfig(system=s.System(aaa=s.AAA(), snmp=s.SNMP(), management=s.Management()))
        self.bindings = []
        self.consumed = defaultdict(set)
        self.mapped, self.structural, self.failed, self.ambiguous = set(), set(), set(), set()
        self.entities = {}
        self.pending = {}
        self._before = {}
        official = extracted.get('official', {})
        self.official_interfaces = {r['name']: r for r in flat_official(official.get('interfaces')) if 'name' in r}
        self.official_vrfs = {r['name']: r for r in flat_official(official.get('vrfs')) if 'name' in r}
        self._result = None

    def root(self, record):
        return root(self, record)

    def af(self, record):
        return address_family(self, record)

    def entity(self, line):
        path = self.entities.get(self.nodes[line].root)
        if path is None or isinstance(path, tuple):
            return path
        return at(self.c, path), path

    def bind(self, path, line, fields=None):
        path = '/' + path.strip('/')
        value = at(self.c, path)
        scalar = value == [] or not isinstance(value, (dict, list)) and not hasattr(value, 'model_dump')
        candidates = list(leaves(value, path))
        for pointer, value in candidates:
            if not scalar and pointer in self._before and self._before[pointer] == value:
                continue
            self.bindings[:] = [b for b in self.bindings if b.path != pointer]
            self.bindings.append(Binding(pointer, line))
        values = self.records[line]['values']
        fields = list(values) if fields is None else fields
        self.consumed[line].update(k for k in fields if not (k == 'options' and values.get(k) == 'log-input'))
        self.mapped.add(line)

    def assign(self, obj, field, value, path, line, fields=None):
        setattr(obj, field, value)
        self.bind(path + '/' + field, line, fields)

    def unbind(self, path, *, descendants=True):
        path = '/' + path.strip('/')
        removed = {b.record for b in self.bindings if b.path == path or descendants and b.path.startswith(path + '/')}
        self.bindings[:] = [b for b in self.bindings if not (b.path == path or descendants and b.path.startswith(path + '/'))]
        for line in removed:
            if not any(b.record == line for b in self.bindings):
                self.consumed[line].clear()

    def defer(self, record):
        self.pending[record['source_line']] = record

    def is_complete(self, line):
        record = self.records.get(line)
        validation = self.validation.get(line, {'valid': False})
        return bool(record and validation['valid'] and line not in self.failed and line not in self.ambiguous
            and record['values'] and self.consumed[line] == set(record['values'])
            and all(value == 'validated' for value in validation['fields'].values()))

    def eligible(self, line):
        validation = self.validation.get(line, {'valid': False, 'fields': {}})
        return validation['valid'] and line not in self.failed and line not in self.ambiguous and any(
            validation['fields'].get(key) == 'validated' for key in self.consumed[line])

    def _apply(self, record, handler):
        line = record['source_line']
        if not self.validation[line]['valid']:
            return False
        previous = self.c.model_copy(deep=True)
        old_bindings = list(self.bindings)
        old_consumed = deepcopy(self.consumed)
        old_entities, old_pending = dict(self.entities), dict(self.pending)
        self._before = dict(leaves(self.c.model_dump(mode='json')))
        try:
            return handler(self, record)
        except (ValueError, KeyError, IndexError, StopIteration, TypeError) as exc:
            self.c = previous
            self.bindings = old_bindings
            self.consumed = old_consumed
            self.entities, self.pending = old_entities, old_pending
            self.failed.add(line)
            if 'Duplicate' in str(exc) or 'cannot be guessed' in str(exc):
                self.ambiguous.add(line)
            return False

    def run(self):
        if self._result is not None:
            return self._result
        declarations = set()
        for line, record in sorted(self.records.items()):
            if record['rule'] not in DECLARATIONS:
                continue
            domain = handler_for(record)
            declare = getattr(domain, 'declare', None)
            if declare and self._apply(record, declare):
                declarations.add(line)
        for line, record in sorted(self.records.items()):
            if line not in declarations:
                self._apply(record, handler_for(record).handle)
        for line, record in sorted(self.pending.items()):
            domain = handler_for(record)
            self._apply(record, domain.resolve)
        validate_targets(self.c, self.bindings)
        configured = select_configured(self, policies.blocked_objects(self))
        self._result = validate(configured)
        return self._result


def normalize_captures(extracted, *, os_family='ios'):
    return NormalizationEngine(extracted, os_family=os_family).run()
