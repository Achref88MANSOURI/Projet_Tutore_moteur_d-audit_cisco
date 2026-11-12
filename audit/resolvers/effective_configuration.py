"""Resolve effective Cisco properties after normalization, without parsing CLI.

The routing functions below are the R3.1 implementation.  The generic Level 1
context extends the same provenance vocabulary without creating a second
default engine.  Level 1 defaults additionally require evidence from the live
normalization transaction, because a caller-supplied normalized JSON cannot
prove parser coverage.  Derived absences never receive a synthetic pointer.
"""
from dataclasses import dataclass
from typing import Any

from .routing_common import Authentication, Key, Property, Relation, Scope


@dataclass(frozen=True)
class EffectiveValue:
    """A resolved scalar and the evidence boundary that authorized it."""

    value: Any = None
    origin: str = 'unknown'
    rule: str = 'UNRESOLVED'
    reference_id: str | None = None
    qualification: str | None = None
    source_command_present: bool = False
    inheritance_checked: bool = False
    scope_complete: bool = False


@dataclass(frozen=True)
class EffectiveConfiguration:
    """Qualification context shared by Level 1 evaluators.

    ``configuration_evidence`` is intentionally process-local and sealed by
    :mod:`audit.configuration_facts`; serialized evidence is never trusted.
    """

    input_completeness: str
    platform_family: str
    configuration_evidence: tuple[Any, str] | None = None
    parser_coverage_trusted: bool = False
    incomplete_families: frozenset[str] = frozenset()

    @classmethod
    def build(cls, document, *, input_completeness, platform_family,
              evidence=None, operation_id=None):
        from ..configuration_facts import ConfigurationEvidence

        pair = ((evidence, operation_id)
                if isinstance(evidence, ConfigurationEvidence) else None)
        trusted = bool(pair and evidence.valid_for(document, operation_id=operation_id))
        incomplete = frozenset(
            item.family for item in (evidence.facts.coverage if trusted else ())
            if not item.covered
        )
        return cls(
            input_completeness=input_completeness,
            platform_family=platform_family,
            configuration_evidence=pair,
            parser_coverage_trusted=trusted,
            incomplete_families=incomplete,
        )

    def qualifies(self, *, family=None, platforms=('ios', 'iosxe')):
        return (
            self.input_completeness == 'complete'
            and self.platform_family in platforms
            and self.parser_coverage_trusted
            and (family is None or family not in self.incomplete_families)
        )

    def explicit(self, value, rule='EXPLICIT_CONFIGURATION'):
        return EffectiveValue(
            value=value, origin='explicit', rule=rule,
            source_command_present=True, inheritance_checked=True,
            scope_complete=False,
        )

    def default(self, value, *, rule, reference_id, qualification,
                family=None, platforms=('ios', 'iosxe'), blocked=False):
        if blocked or not self.qualifies(family=family, platforms=platforms):
            return EffectiveValue(
                rule='DEFAULT_NOT_QUALIFIED', reference_id=reference_id,
                qualification=qualification,
            )
        return EffectiveValue(
            value=value, origin='documented_default', rule=rule,
            reference_id=reference_id, qualification=qualification,
            source_command_present=False, inheritance_checked=True,
            scope_complete=True,
        )

    def absent(self, *, rule, reference_id, qualification, family=None,
               platforms=('ios', 'iosxe')):
        if not self.qualifies(family=family, platforms=platforms):
            return EffectiveValue(
                rule='ABSENCE_NOT_QUALIFIED', reference_id=reference_id,
                qualification=qualification,
            )
        return EffectiveValue(
            origin='proven_absent', rule=rule, reference_id=reference_id,
            qualification=qualification, source_command_present=False,
            inheritance_checked=True, scope_complete=True,
        )


def effective_context(value):
    """Return a Level 1 effective context, tolerating legacy direct calls."""
    return value if isinstance(value, EffectiveConfiguration) else None


def configuration_evidence(value):
    """Unwrap the historical sealed-evidence tuple for SNMP/coverage helpers."""
    context = effective_context(value)
    return context.configuration_evidence if context is not None else value


DEFAULTS = {
    'eigrp': {'reference_id': 'C3/C4', 'qualification': 'IOS_IOSXE_EIGRP_IPV4'},
    'ospf': {'reference_id': 'C5', 'qualification': 'IOS_IOSXE_OSPFV2'},
    'rip': {'reference_id': 'C7/C8', 'qualification': 'IOS_IOSXE_RIPV2'},
    'bgp': {'reference_id': 'C9', 'qualification': 'IOS_IOSXE_BGP_TCP_MD5'},
    'key_chain': {'reference_id': 'C2', 'qualification': 'IOS_IOSXE_KEY_CHAIN'},
}


def _eligible(completeness, platform_family):
    return completeness == 'complete' and platform_family in ('ios', 'iosxe')


def documented_default(value, protocol, rule, *, pointers=()):
    meta = DEFAULTS[protocol]
    return Property(
        value=value, status='RESOLVED', origin='documented_default',
        pointers=list(pointers), rule=rule, source_command_present=False,
        inheritance_checked=True, scope_complete=True, **meta,
    )


def proven_absent(protocol, rule, *, value=None, pointers=()):
    meta = DEFAULTS[protocol]
    return Property(
        value=value, status='RESOLVED', origin='proven_absent',
        pointers=list(pointers), rule=rule, source_command_present=False,
        inheritance_checked=True, scope_complete=True, **meta,
    )


def inherited_versions(value, source):
    return Property(
        value=value, status='RESOLVED', origin='inherited',
        pointers=source.pointers, rule='RIP_PROCESS_VERSION_INHERITANCE',
        source_command_present=source.source_command_present,
        inheritance_checked=True, scope_complete=source.scope_complete,
        reference_id=source.reference_id, qualification=source.qualification,
    )


def _complete_key_inventory(auth):
    chain = auth.key_chain
    if chain.status != 'RESOLVED' or chain.value is None or chain.origin == 'proven_absent':
        return auth
    if auth.keys:
        presence = auth.key_presence if auth.key_presence.status == 'RESOLVED' else Property(
            value=True, status='RESOLVED', origin='derived',
            pointers=[auth.keys[0].pointer], rule='DECLARED_KEY_INVENTORY_NONEMPTY',
            source_command_present=True, inheritance_checked=True, scope_complete=True,
            reference_id='C2', qualification='IOS_IOSXE_KEY_CHAIN',
        )
        keys = [key if key.secret_configured is not None else key.model_copy(update={
            'secret_configured': False,
            'secret_origin': 'proven_absent',
            'secret_rule': 'KEY_STRING_PROVEN_ABSENT_IN_COMPLETE_SCOPE; C2',
        }) for key in auth.keys]
        return auth.model_copy(update={'key_presence': presence, 'keys': keys})
    return auth.model_copy(update={
        'key_presence': proven_absent('key_chain', 'KEY_DECLARATION_PROVEN_ABSENT_IN_COMPLETE_CHAIN'),
    })


def _authentication(protocol, auth, completeness, platform_family):
    if not _eligible(completeness, platform_family):
        return auth
    updates = {}
    chain = auth.key_chain
    if protocol in ('eigrp', 'rip'):
        if chain.status == 'UNRESOLVED_REFERENCE' and chain.value is not None:
            chain = proven_absent('key_chain', 'REFERENCED_KEY_CHAIN_PROVEN_ABSENT', value=chain.value, pointers=chain.pointers)
        elif chain.status == 'UNKNOWN' and chain.origin == 'unknown':
            chain = proven_absent(protocol, 'KEY_CHAIN_ASSOCIATION_PROVEN_ABSENT')
        updates['key_chain'] = chain

    mode = auth.mode
    if protocol == 'eigrp' and (mode.status == 'UNKNOWN' or mode.origin == 'removed'):
        updates['mode'] = documented_default('none', 'eigrp', 'EIGRP_AUTHENTICATION_DISABLED_BY_DEFAULT', pointers=mode.pointers)
    elif protocol == 'ospf' and (mode.status == 'UNKNOWN' or mode.origin == 'removed'):
        updates['mode'] = documented_default('none', 'ospf', 'OSPF_AREA_OR_INTERFACE_DEFAULT_NULL', pointers=mode.pointers)
    elif protocol == 'rip' and (mode.status == 'UNKNOWN' or mode.origin == 'removed'):
        has_chain = chain.status == 'RESOLVED' and chain.value is not None and chain.origin != 'proven_absent'
        updates['mode'] = documented_default('plaintext' if has_chain else 'none', 'rip',
            'RIP_AUTHENTICATION_MODE_TEXT_DEFAULT' if has_chain else 'RIP_AUTHENTICATION_DISABLED_WITHOUT_KEY_CHAIN',
            pointers=mode.pointers)
    elif protocol == 'bgp' and (mode.status == 'UNKNOWN' or mode.origin == 'removed'):
        updates['mode'] = documented_default('none', 'bgp', 'BGP_TCP_MD5_DISABLED_BY_DEFAULT', pointers=mode.pointers)

    if protocol in ('eigrp', 'rip'):
        enabled = auth.enabled
        has_chain = chain.status == 'RESOLVED' and chain.value is not None and chain.origin != 'proven_absent'
        if enabled.status == 'UNKNOWN':
            updates['enabled'] = (Property(value=True, status='RESOLVED', origin=chain.origin,
                pointers=chain.pointers, rule='KEY_CHAIN_REFERENCE_ENABLES_AUTHENTICATION',
                source_command_present=True, inheritance_checked=True, scope_complete=True)
                if has_chain else documented_default(False, protocol, 'AUTHENTICATION_DISABLED_WITHOUT_KEY_CHAIN'))
    if protocol == 'bgp' and auth.secret.status == 'UNKNOWN':
        updates['secret'] = documented_default(False, 'bgp', 'BGP_PASSWORD_NOT_CONFIGURED_BY_DEFAULT')

    resolved = auth.model_copy(update=updates)
    return _complete_key_inventory(resolved) if protocol in ('eigrp', 'rip') else resolved


def apply_scope(scope: Scope, completeness, platform_family):
    """Return a scope enriched with effective defaults and applicability."""
    if scope.status != 'RESOLVED':
        return scope.model_copy(update={'applicability': 'APPLICABILITY_UNKNOWN'})
    applicable = 'APPLICABLE' if scope.relations else 'NOT_APPLICABLE'
    send, receive = scope.send_versions, scope.receive_versions
    if scope.protocol == 'rip' and _eligible(completeness, platform_family):
        if send.status == 'UNKNOWN':
            send = documented_default([1], 'rip', 'RIP_DEFAULT_SEND_VERSION_1')
        if receive.status == 'UNKNOWN':
            receive = documented_default([1, 2], 'rip', 'RIP_DEFAULT_RECEIVE_VERSIONS_1_AND_2')
    relations = []
    for relation in scope.relations:
        relation_applicability = 'APPLICABLE' if relation.status == 'RESOLVED' else 'APPLICABILITY_UNKNOWN'
        auth = relation.authentication
        rsend, rreceive = relation.send_versions, relation.receive_versions
        if relation.status == 'RESOLVED':
            auth = _authentication(scope.protocol, auth, completeness, platform_family)
            if scope.protocol == 'rip':
                if rsend.status == 'UNKNOWN' and send.status == 'RESOLVED':
                    rsend = inherited_versions(send.value, send)
                if rreceive.status == 'UNKNOWN' and receive.status == 'RESOLVED':
                    rreceive = inherited_versions(receive.value, receive)
                if rsend.status == 'RESOLVED' and rreceive.status == 'RESOLVED' and 2 not in set(rsend.value + rreceive.value):
                    relation_applicability = 'NOT_APPLICABLE'
        relations.append(relation.model_copy(update={
            'applicability': relation_applicability,
            'authentication': auth,
            'send_versions': rsend,
            'receive_versions': rreceive,
        }))
    return scope.model_copy(update={
        'applicability': applicable,
        'send_versions': send,
        'receive_versions': receive,
        'relations': relations,
    })
