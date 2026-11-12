"""One normalization engine: declarations, domain mappings, relations, contract.

Each capture has one owning domain. Declarations establish identities first;
only reference-dependent commands are deferred. Temporary field ownership
prevents constructor defaults from becoming configured facts.
"""
from collections import defaultdict
from copy import deepcopy
from parser.validation import validate_record
from schemas import router_contract_v1 as s
from pydantic import ValidationError
from .common.absence import AbsenceResolver
from .common.addresses import flat_official
from .common.contexts import root, address_family, at
from .common.configured import Binding, leaves, select_configured, validate_targets
from .common.line_intervals import LineIntervals
from .common.validation import validate, validate_preserved_references
from .domains import handler_for, DECLARATIONS
from .domains import policies
from . import lifecycle


class NormalizationEngine:
    def __init__(self, extracted, *, os_family='ios', provenance=None, provenance_errors='raise'):
        if os_family not in ('ios', 'iosxe'):
            raise ValueError('Supported OS families: ios, iosxe')
        self.nodes = extracted['nodes']
        self.records, self.retired, self.lifecycle_events = lifecycle.prepare(extracted['records'])
        self.validation = {line: validate_record(r) for line, r in self.records.items()}
        self.line_intervals = LineIntervals(self.records, self.validation)
        self._line_target = None
        identities = set()
        for line, record in sorted(self.records.items()):
            duplicate = False
            if record['rule'] == 'policy_header':
                key = (record['rule'], record['values'].get('name'), record['values'].get('sequence'))
                duplicate = key in identities
                identities.add(key)
            invalid_parent = any(not self.validation.get(n, {'valid': True})['valid'] for n in record['context_lines'])
            if duplicate or invalid_parent or line in extracted.get('ambiguous_lines', set()):
                self.validation[line] = dict(valid=False, invalid_fields=list(record['values']), fields={k: 'invalid' for k in record['values']})
        self.c = s.RouterContractV1(
            contract_version='1.0.0', device={}, system={}, interfaces=None,
            interface_aggregations=None, network_instances=None, routing={},
            routing_policies={}, security={}, nat={}, vpn={}, qos={}, mpls={},
            multicast={}, pki={}, extensions={})
        self._empty_document = self.c.model_dump(mode='json')
        self.absences = AbsenceResolver()
        self.bindings = []
        self.consumed = defaultdict(set)
        self.mapped, self.structural, self.failed, self.ambiguous = set(), set(), set(), set()
        self.uncertain = set()  # Recognized rewrite with an unresolved semantic effect.
        self.completed_history = set()  # Fully applied captures may later lose ownership.
        self.entities = {}
        self.pending = {}
        self._before = {}
        official = extracted.get('official', {})
        self.official_interfaces = {r['name']: r for r in flat_official(official.get('interfaces')) if 'name' in r}
        self.official_vrfs = {r['name']: r for r in flat_official(official.get('vrfs')) if 'name' in r}
        self._result = None
        self.provenance = provenance
        if provenance_errors not in ('raise', 'unavailable'):
            raise ValueError('Invalid provenance error policy')
        self.provenance_errors = provenance_errors
        self.provenance_error = None

    def _observe(self, method, *args):
        """Only the opt-in tolerant operation may discard failed provenance.

        Never turn an observer error into a business-handler rollback. Business
        mapping/validation exceptions retain their existing behavior.
        """
        if self.provenance is None:
            return
        try:
            getattr(self.provenance, method)(*args)
        except Exception:
            if self.provenance_errors == 'raise':
                raise
            self.provenance = None
            self.provenance_error = 'PROVENANCE_UNAVAILABLE'

    def root(self, record):
        return root(self, record)

    def af(self, record):
        return address_family(self, record)

    def entity(self, line):
        if self._line_target is not None and self.nodes[line].root in self.line_intervals.targets:
            path = self._line_target
            return at(self.c, path), path
        path = self.entities.get(self.nodes[line].root)
        if path is None or isinstance(path, tuple):
            return path
        return at(self.c, path), path

    def bind(self, path, line, fields=None):
        path = '/' + path.strip('/')
        value = at(self.c, path)
        scalar = value == [] or not isinstance(value, (dict, list)) and not hasattr(value, 'model_dump')
        candidates = list(leaves(value, path))
        if self.provenance is not None:
            self._observe('bound', candidates, line)
        for pointer, value in candidates:
            if not scalar and pointer in self._before and self._before[pointer] == value:
                continue
            self.bindings[:] = [b for b in self.bindings if b.path != pointer]
            self.bindings.append(Binding(pointer, line))
            # Also bind parent paths to make list items eligible
            parent = pointer.rsplit('/', 1)[0]
            while parent and parent != '/':
                self.bindings[:] = [b for b in self.bindings if b.path != parent]
                self.bindings.append(Binding(parent, line))
                parent = parent.rsplit('/', 1)[0]
        values = self.records[line]['values']
        fields = list(values) if fields is None else fields
        self.consumed[line].update(fields)
        self.mapped.add(line)

    def assign(self, obj, field, value, path, line, fields=None, *, explicit_empty=False):
        if isinstance(obj, s.ManagementLine):
            # A line setter owns the effective property even for a repeated
            # identical value. Remove superseded structured leaves (e.g. the
            # old AAA method_list when changing to login local).
            prefix = '/' + path.strip('/') + '/' + field
            self.unbind(prefix)
            self._before = {p: v for p, v in self._before.items()
                            if p != prefix and not p.startswith(prefix + '/')}
        if value == [] and explicit_empty:
            self.absences.confirm(path + '/' + field, explicit=True)
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
        # A command retains its source identity but applies independently to
        # every effective segment covered by its captured root declaration.
        targets = self.line_intervals.targets.get(record['root_line'])
        if record['rule'] != 'services_line' and targets is not None:
            if not self.validation[record['root_line']]['valid']:
                return False
            applied = False
            try:
                for span in targets:
                    self._line_target = self.line_intervals.paths[span]
                    applied = self._apply_one(record, handler) or applied
            finally:
                self._line_target = None
            return applied
        return self._apply_one(record, handler)

    def _apply_one(self, record, handler):
        line = record['source_line']
        if not self.validation[line]['valid']:
            return False
        if not self.in_scope(record):
            return False
        previous = self.c.model_copy(deep=True)
        old_absences = set(self.absences.confirmed_empty)
        old_bindings = list(self.bindings)
        old_consumed = deepcopy(self.consumed)
        old_entities, old_pending = dict(self.entities), dict(self.pending)
        self._before = dict(leaves(self.c.model_dump(mode='json')))
        if self.provenance is not None:
            self._observe('begin', self, record)
        try:
            applied = handler(self, record)
        except ValidationError:
            if self.provenance is not None:
                self._observe('abort')
            # A broken canonical mapping must fail the export, never drop its object.
            raise
        except (ValueError, KeyError, IndexError, StopIteration, TypeError) as exc:
            if self.provenance is not None:
                self._observe('abort')
            self.c = previous
            self.absences.confirmed_empty = old_absences
            self.bindings = old_bindings
            self.consumed = old_consumed
            self.entities, self.pending = old_entities, old_pending
            self.failed.add(line)
            if 'Duplicate' in str(exc) or 'cannot be guessed' in str(exc):
                self.ambiguous.add(line)
            return False
        # Provenance errors must never be swallowed as a handler failure or
        # roll back/alter business facts. The opt-in operation fails safely.
        if self.provenance is not None:
            self._observe('commit', self)
        if self.is_complete(line):
            self.completed_history.add(line)
        return applied

    def in_scope(self, record):
        rules = [record] + [self.records[n] for n in record['context_lines'] if n in self.records]
        for item in rules:
            rule = item['rule']
            if rule.startswith(('advanced_l2_', 'advanced_vlan')) or rule in {
                'if_service_instance', 'if_bridge_domain', 'if_encap_untagged',
                'if_switchport', 'if_access_vlan', 'if_native_vlan',
                'if_trunk_vlans', 'if_trunk_modify',
            }:
                return False
            if rule.startswith('bgp_af') and item['values'].get('afi') == 'l2vpn':
                return False
        return True

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
        # A reset is also a first-class fact, alongside its fresh identity.
        for line in self.lifecycle_events:
            if line in declarations or not self.records[line]['rule'].startswith('lifecycle_'):
                self._apply(self.records[line], lifecycle.handle)
        for line, record in sorted(self.pending.items()):
            domain = handler_for(record)
            self._apply(record, domain.resolve)
        validate_targets(self.c, self.bindings)
        projection = {} if self.provenance is not None else None
        configured = select_configured(self, policies.blocked_objects(self), projection=projection)
        # Coverage metadata has inventory provenance, not an invented configured
        # leaf/command binding. Resolvers must retain these uncertainty guards.
        from parser.routing_coverage import issues
        integrity = issues(self)
        if integrity:
            configured['routing']['integrity_issues'] = [issue.model_dump(mode='json') for issue in integrity]
        validate_preserved_references(self.c.model_dump(mode='json'), configured)
        result = validate(configured)
        if self.provenance is not None:
            self._observe('finalize', self, result.model_dump(mode='json'), projection)
        self._result = result
        return self._result


def normalize_captures(extracted, *, os_family='ios'):
    return NormalizationEngine(extracted, os_family=os_family).run()
