"""CIS Cisco IOS 15 evaluation layer.

Consumes the catalog and a RouterContractV1 document, dispatches to per-control
evaluators, and returns an AuditReport with CIS-specific findings.

This module reuses the existing audit engine's models and status enum.
"""
from __future__ import annotations

from typing import Any, Callable
from pathlib import Path
import json
from copy import deepcopy
from functools import wraps

from .models import AuditReport, AuditStatus, Evidence, Finding, Reference, CISAuditScope
from .catalog.loader import CISIOS15Catalog
from .catalog.execution_scope import automatic_controls, exclusions
from .rules import management, logging, aaa_central, cis_scope, cis_relations, cis_level2_remaining
from . import configuration_facts
from .resolvers.effective_configuration import (
    EffectiveConfiguration, configuration_evidence as _configuration_evidence,
    effective_context as _effective_context,
)


# Type for evaluator functions
Evaluator = Callable[[dict, dict, dict | None], tuple[AuditStatus, list[str], str]]
# Returns (status, evidence_parts, detail)
# evaluator(raw_document, control_metadata, configuration_fact_context)


class _UnknownFact(Exception):
    def __init__(self, path):
        self.path = path


class _Facts(dict):
    """Read barrier: missing facts are not Python defaults or absence proofs.

    False, zero and explicit transport-none remain usable facts. Empty object
    collections have no completeness certificate in V1, so cannot prove absence.
    """
    def __init__(self, data, path=()):
        super().__init__(data)
        self.path = path

    def get(self, key, default=None):
        path = self.path + (str(key),)
        if key not in self or super().get(key) is None:
            raise _UnknownFact(path)
        value = super().get(key)
        if value == [] and path[-1] not in ('allowed_transports', 'transport_output'):
            raise _UnknownFact(path)
        return self.wrap(value, path)

    @staticmethod
    def wrap(value, path):
        if isinstance(value, dict): return _Facts(value, path)
        if isinstance(value, list): return [_Facts.wrap(v, path + (str(i),)) for i, v in enumerate(value)]
        return value


def _guard_unknown(evaluator):
    control_id = evaluator.__name__.removeprefix('_eval_').replace('_', '.')
    @wraps(evaluator)
    def evaluate(raw, control, evidence):
        decisive = cis_scope.before(control_id, raw)
        if decisive is not None:
            return decisive
        try:
            return cis_scope.after(control_id, evaluator(_Facts(raw), control, evidence), raw=raw, evidence=evidence)
        except _UnknownFact as unknown:
            # Phase 5B explicitly requires an explicit positive AUX timeout.
            # Preserve that local policy only for an observed AUX object, never
            # infer that a missing collection proves an AUX port exists.
            if evaluator.__name__ == '_eval_1_2_6' and unknown.path[-1] == 'idle_timeout_seconds':
                status, parts, detail = evaluator(raw, control, evidence)
                return status, parts, detail + ' Local explicit-setting policy for observed AUX; effective platform default is not established.'
            return (AuditStatus.NEEDS_REVIEW, list(unknown.path),
                    'Unknown or omitted normalized fact; V1 does not prove exhaustive absence or platform defaults.')
    return evaluate


class CISEvaluatorRegistry:
    """Registry of CIS control evaluators.

    Maps control_id -> evaluator function.
    Evaluators receive (contract_dict, control_metadata, configuration_fact_context) and return
    (status, evidence_parts, detail).
    """

    def __init__(self):
        self._evaluators: dict[str, Evaluator] = {}

    def register(self, control_id: str, evaluator: Evaluator, *, fact_barrier: bool = True) -> None:
        if control_id in self._evaluators:
            raise ValueError(f"Evaluator for {control_id} already registered")
        self._evaluators[control_id] = _guard_unknown(evaluator) if fact_barrier else evaluator

    def get(self, control_id: str) -> Evaluator | None:
        return self._evaluators.get(control_id)

    def all_registered(self) -> list[str]:
        return list(self._evaluators.keys())


# Sensitive field names that should never appear in evidence or reasons
SENSITIVE_FIELDS = frozenset({
    'password', 'secret', 'private', 'key', 'credential', 'community_string',
    'shared_secret', 'auth_key', 'privacy_key', 'encryption_key', 'hash',
    'token', 'api_key', 'access_key', 'secret_key', 'private_key',
    'ca_password', 'enable_secret', 'enable_password', 'username_secret',
    'tacacs_key', 'radius_key', 'ntp_key', 'snmp_key', 'ike_key', 'ipsec_key',
    'ssh_key', 'rsa_key', 'dsa_key', 'ecdsa_key', 'ed25519_key',
    'pre_shared_key', 'psk', 'wpa_key', 'wep_key',
})


def _sanitize_value(value: Any, seen: set | None = None) -> Any:
    """Recursively sanitize a value by removing sensitive fields.

    Returns a sanitized copy safe for evidence and logging.
    """
    if seen is None:
        seen = set()

    obj_id = id(value)
    if obj_id in seen:
        return "<circular>"
    seen.add(obj_id)

    try:
        if value is None or isinstance(value, (bool, int, str, float)):
            return value
        if isinstance(value, dict):
            sanitized = {}
            for k, v in value.items():
                k_lower = str(k).lower()
                if k_lower == 'community_or_user' and value.get('version') != '3' or any(sensitive in k_lower for sensitive in SENSITIVE_FIELDS):
                    sanitized[k] = "<REDACTED>"
                else:
                    sanitized[k] = _sanitize_value(v, seen)
            return sanitized
        if isinstance(value, (list, tuple, set)):
            return [_sanitize_value(item, seen) for item in value]
        return str(value)
    finally:
        seen.discard(obj_id)


def _scalarize_safe(value: Any) -> Any:
    """Convert a value to a scalar acceptable by Evidence.observed_value.

    Sanitizes sensitive data before serialization.
    """
    sanitized = _sanitize_value(value)
    if sanitized is None or isinstance(sanitized, (bool, int, str)):
        return sanitized
    if isinstance(sanitized, (list, dict)):
        return json.dumps(sanitized, ensure_ascii=False)
    return str(sanitized)


def _lookup(document: dict, parts: list[str]) -> tuple[bool, Any]:
    """Lookup a value in the raw document by JSON pointer parts."""
    value = document
    for part in parts:
        if isinstance(value, list) and part.isdigit():
            index = int(part)
            if index >= len(value):
                return False, None
            value = value[index]
            continue
        if not isinstance(value, dict) or part not in value:
            return False, None
        value = value[part]
    return True, value


def _logging_severity(value: Any) -> int | None:
    """Interpret normalized severity names/numeric aliases, without int(input)."""
    names = ('emergencies', 'alerts', 'critical', 'errors', 'warnings',
             'notifications', 'informational', 'debugging')
    levels = {name: index for index, name in enumerate(names)}
    levels.update({str(index): index for index in range(8)})
    return levels.get(value.lower()) if isinstance(value, str) else None


def _effective_scalar(raw, parts, context, *, default, rule, reference_id,
                      qualification, family=None, platforms=('ios', 'iosxe'),
                      blocked=False):
    """Resolve one scalar without turning a missing JSON member into a fact."""
    exists, value = _lookup(raw, parts)
    if exists and value is not None:
        return value, 'explicit'
    effective = _effective_context(context)
    if effective is None:
        return None, 'unknown'
    resolved = effective.default(
        default, rule=rule, reference_id=reference_id,
        qualification=qualification, family=family, platforms=platforms,
        blocked=blocked)
    return resolved.value, resolved.origin


def _proven_absent(context, *, rule, reference_id, qualification,
                   family=None, platforms=('ios', 'iosxe')):
    effective = _effective_context(context)
    if effective is None:
        return False
    return effective.absent(
        rule=rule, reference_id=reference_id, qualification=qualification,
        family=family, platforms=platforms).origin == 'proven_absent'


def _create_finding(
    check_id: str,
    title: str,
    status: AuditStatus,
    severity: str,
    reason: str,
    evidence_parts: list[str],
    raw_document: dict,
    recommendation: str,
    references: list[dict],
    profile_name: str = "CIS Cisco IOS 15"
) -> Finding:
    """Create a Finding with evidence from the raw document."""
    exists, observed = _lookup(raw_document, evidence_parts)
    evidence = [Evidence(json_pointer='/'+'/'.join(evidence_parts), observed_value=_scalarize_safe(observed))] if exists else []

    return Finding(
        check_id=check_id,
        title=title,
        status=status,
        severity=severity,
        reason=reason,
        evidence=evidence,
        recommendation=recommendation,
        references=[Reference.model_validate(r) for r in references],
    )


def audit_cis_normalized(
    normalized_document: dict | str | Path,
    *,
    profile_level: int = 1,
    include_lower: bool = True,
    evidence: configuration_facts.ConfigurationEvidence | None = None,
    evidence_operation_id: str | None = None,
    input_completeness: str = 'unknown',
    platform_family: str = 'unknown',
) -> AuditReport:
    """Evaluate CIS Cisco IOS 15 benchmark controls against a normalized document.

    Args:
        normalized_document: RouterContractV1 dict, model, or JSON file path
        profile_level: 1 or 2 (Level 2 includes Level 1 by default)
        include_lower: When profile_level=2 and include_lower=False, only Level 2 controls
        evidence: Optional live configuration facts from the producing transaction.
            Imported dicts cannot authorize decisions. Operational outputs are unsupported.
        evidence_operation_id: Expected operation, required for pre-redaction facts.

    Returns:
        AuditReport with CIS-specific findings
    """
    if input_completeness not in ('complete', 'partial', 'unknown'):
        raise ValueError('input_completeness must be complete, partial, or unknown')
    if platform_family not in ('ios', 'iosxe', 'unknown'):
        raise ValueError('platform_family must be ios, iosxe, or unknown')

    # Load the catalog
    catalog = CISIOS15Catalog()
    catalog_controls = catalog.controls_for_profile(profile_level, include_lower=include_lower)
    excluded = exclusions(catalog_controls)
    controls = automatic_controls(catalog_controls)

    # Load raw document (make a deep copy to avoid mutating input)
    if isinstance(normalized_document, (str, Path)):
        raw = json.loads(Path(normalized_document).read_text(encoding='utf-8-sig'))
    elif hasattr(normalized_document, 'model_dump'):
        raw = normalized_document.model_dump(mode='json')
    else:
        raw = deepcopy(normalized_document)

    # Validate with RouterContractV1 (use a copy for validation to avoid mutation issues)
    from schemas.router_contract_v1 import RouterContractV1
    model = RouterContractV1.model_validate(raw)

    # Load reference mappings
    mapping = json.loads((Path(__file__).parent / 'mappings' / 'verified_references.json').read_text(encoding='utf-8'))

    # Get evaluator registry
    registry = _build_evaluator_registry()

    # The Level 1 context shares the R3.1 effective-resolution vocabulary, but
    # additionally requires sealed evidence from this normalization operation.
    effective_configuration = EffectiveConfiguration.build(
        raw, input_completeness=input_completeness,
        platform_family=platform_family, evidence=evidence,
        operation_id=evidence_operation_id)

    # R3 predicates perform their own multi-object three-valued aggregation.
    # The historical first-missing-fact barrier must not mask a later violation.
    from .rules import cis_routing
    routing_context = None
    if any(c['id'] in cis_routing.EVALUATORS for c in controls):
        from .resolvers.routing import resolve_routing
        routing_context = cis_routing.RoutingContext(resolve_routing(
            model, input_completeness=input_completeness, platform_family=platform_family))

    findings: list[Finding] = []
    skipped = 0

    for control in controls:
        control_id = control["id"]
        evaluator = registry.get(control_id)

        if evaluator is None:
            # No evaluator implemented - distinguish from evaluated-but-indeterminate
            finding = Finding(
                check_id=f"CIS-{control_id}",
                title=control["title"],
                status=AuditStatus.NEEDS_REVIEW,
                severity="high",
                reason=(f"Manual assessment required for control {control_id}; configuration alone does not establish applicability or the required interface/security policy."
                        if control.get('assessment')=='Manual' else
                        f"No evaluator implemented for control {control_id}. Catalog status: {control.get('catalogue_integration_status', 'UNKNOWN')}."),
                evidence=[],
                recommendation=("Review the documented applicability and interface policy manually; no automatic certification is asserted."
                                if control.get('assessment')=='Manual' else "Implement CIS evaluator for this control."),
                references=[],
                applicability='APPLICABILITY_UNKNOWN',
                execution_status='MANUAL' if control.get('assessment') == 'Manual' else 'NO_EVALUATOR',
            )
            findings.append(finding)
            skipped += 1
            continue

        # Private configuration facts stay separate from the business document.
        try:
            status, evidence_parts, detail = evaluator(
                raw, control, routing_context if control_id in cis_routing.EVALUATORS else effective_configuration)
        except Exception as e:
            # Log error internally but don't expose raw exception in findings
            detail = "Evaluator error - internal error during evaluation"
            status = AuditStatus.NEEDS_REVIEW
            evidence_parts = []

        # Build finding
        references = mapping.get(f"CIS-{control_id}", mapping.get(control_id, []))

        # Use the evaluator's detail as the reason for all statuses (more precise)
        # Sanitize the detail in case it contains sensitive data
        safe_detail = _sanitize_value(detail) if detail else ""
        reason = safe_detail if safe_detail else (
            "Established normalized fact satisfies the CIS rule." if status == AuditStatus.PASS else
            "Established normalized fact violates the CIS rule." if status == AuditStatus.FAIL else
            "Explicitly excluded by the audit profile." if status == AuditStatus.NOT_APPLICABLE else
            "Insufficient evidence to determine compliance."
        )

        # Build evidence with actual observed values (sanitized and scalarized)
        evidence_list = []
        paths = evidence_parts if evidence_parts and isinstance(evidence_parts[0],list) else [evidence_parts] if evidence_parts else []
        seen=set()
        for parts in paths:
            pointer='/'+'/'.join(parts)
            if pointer in seen:continue
            seen.add(pointer)
            exists, observed = _lookup(raw, parts)
            if exists:
                evidence_list.append(Evidence(json_pointer=pointer, observed_value=_scalarize_safe(observed)))
            # An unsupported contract path is not an observed null value.
            # Keep the finding indeterminate without inventing an Evidence.

        finding = Finding(
            check_id=f"CIS-{control_id}",
            title=control["title"],
            status=status,
            severity="high",
            reason=reason,
            evidence=evidence_list,
            recommendation="Review CIS benchmark for remediation steps.",
            references=[Reference.model_validate(r) for r in references],
            applicability=(cis_routing.applicability(raw, routing_context.graph, control_id)
                           if control_id in cis_routing.EVALUATORS else
                           cis_scope.applicability(control_id, raw, effective_configuration, status)),
            execution_status='EXECUTED',
        )
        findings.append(finding)

    execution_counts = {
        status: sum(f.execution_status == status for f in findings)
        for status in ('EXECUTED', 'NO_EVALUATOR', 'MANUAL')
    }
    cumulative = profile_level == 2 and include_lower
    profile_name = ('CIS Level 1 + Level 2' if cumulative else
                    'CIS Level 2' if profile_level == 2 else 'CIS Level 1')
    return AuditReport(
        engine_version='0.2.0',
        contract_version='1.0.0',
        profile={
            'cis_enabled': True,
            'name': profile_name,
            'level_1_enabled': profile_level == 1 or cumulative,
            'level_2_enabled': profile_level == 2,
            'cumulative': cumulative,
            'eligible_level_1_controls': sum(
                c['profile_level'] == 'Level 1' for c in controls),
            'eligible_level_2_controls': sum(
                c['profile_level'] == 'Level 2' for c in controls),
        },
        findings=findings,
        counts={s.value: sum(f.status == s for f in findings) for s in AuditStatus},
        execution_counts=execution_counts,
        compliance_notice=(
            f'Running-config scope: {len(controls)} of {len(catalog_controls)} catalogue controls eligible; '
            f'{len(excluded)} excluded as NOT_AUDITABLE_FROM_RUNNING_CONFIG. '
            'Eligibility and evaluator registration do not establish semantic certification, '
            'complete inventory or operational compliance.'),
        scope=CISAuditScope(catalog_controls=len(catalog_controls), eligible_controls=len(controls),
                            evaluator_controls=sum(registry.get(c['id']) is not None for c in controls),
                            excluded_controls=excluded,
                            executed_controls=execution_counts['EXECUTED'],
                            unevaluated_automatic_controls=execution_counts['NO_EVALUATOR'],
                            manual_controls=execution_counts['MANUAL'],
                            input_completeness=input_completeness,
                            platform_family=platform_family),
    )


# --- Evaluator implementations ---

def _eval_1_1_1(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """1.1.1 Enable 'aaa new-model' -> /system/aaa/enabled"""
    enabled = raw.get("system", {}).get("aaa", {}).get("enabled")
    detail = 'AAA new-model is explicitly enabled' if enabled is True else 'AAA new-model is explicitly disabled' if enabled is False else 'AAA state is unknown'
    return management.aaa01(enabled), ["system", "aaa", "enabled"], detail


def _eval_1_1_2(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """1.1.2 Enable 'aaa authentication login' -> check authentication_method_lists"""
    return cis_relations.authentication_lists(raw, 'login')


def _eval_1_2_2(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """1.2.2 Set 'transport input ssh' for 'line vty' connections

    All VTY lines must have SSH as the ONLY allowed transport.
    If multiple VTY ranges exist (e.g., vty 0 4 and vty 5 15), ALL must permit only SSH.
    """
    # Read this collection without the generic first-unknown barrier: an
    # established violation in a later group is decisive regardless of order.
    _, lines = _lookup(raw, ["system", "management", "lines"])
    parts = ["system", "management", "lines"]
    if not lines:
        return AuditStatus.NEEDS_REVIEW, parts, 'VTY coverage is unknown; no exhaustive inventory is supplied'
    vty_lines = [line for line in lines if line.get("name", "").startswith("vty")]

    if not vty_lines:
        return AuditStatus.NEEDS_REVIEW, parts, 'No observed VTY group; absence or inapplicability is not established'

    unknown = None
    for line in vty_lines:
        transports = line.get("allowed_transports")
        if transports is None:
            if unknown is None:
                unknown = parts + [str(lines.index(line)), "allowed_transports"]
            continue
        if transports == ['all']:
            return AuditStatus.FAIL, parts, f"VTY line '{line.get('name')}' allows all transports, not SSH only"
        if "ssh" not in transports:
            return AuditStatus.FAIL, ["system", "management", "lines"], f"VTY line '{line.get('name')}' does not allow SSH transport"
        # Check that ONLY ssh is allowed (no telnet, rlogin, or other protocols)
        if len(transports) != 1 or transports[0] != "ssh":
            return AuditStatus.FAIL, ["system", "management", "lines"], f"VTY line '{line.get('name')}' allows non-SSH transports: {transports} (must be SSH only)"

    if unknown is not None:
        return AuditStatus.NEEDS_REVIEW, unknown, 'Observed VTY transport is unknown; no platform default is assumed'
    return AuditStatus.PASS, parts, "All configured VTY groups allow only SSH; parser coverage and input completeness are qualified separately"


def _eval_1_2_6(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """Configured AUX timeout; omitted defaults require separate evidence.

    The local benchmark audit explicitly notes that ten minutes may not be
    printed. Phase5B's historical explicit-setting policy is not a CIS proof
    of failure when V1 contains None (including a reset or unextracted value).
    """
    return cis_relations.line_property(raw, 'aux', 'idle_timeout_seconds', evidence)


def _eval_1_4_1(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """1.4.1 Set 'password' for 'enable secret' -> /system/aaa/enable_secrets"""
    _, enable_secrets = _lookup(raw, ['system', 'aaa', 'enable_secrets'])
    # Check if any enable secret is configured (level 15 is the default for privileged access)
    for secret in enable_secrets or []:
        if secret.get("level") == 15 and secret.get("secret_configured") is True:
            return AuditStatus.PASS, ["system", "aaa", "enable_secrets"], ""
        if secret.get('level') == 15 and secret.get('secret_configured') is False:
            return AuditStatus.FAIL, ["system", "aaa", "enable_secrets"], 'Level-15 enable secret is explicitly removed'
    if _proven_absent(evidence, rule='ENABLE_SECRET_PROVEN_ABSENT',
                      reference_id='C25', qualification='IOS_IOSXE_ENABLE_SECRET',
                      family='enable_secret'):
        return AuditStatus.FAIL, ["system", "aaa", "enable_secrets"], "No level-15 enable secret exists in the qualified complete configuration (proven absence; C25)"
    return AuditStatus.NEEDS_REVIEW, ["system", "aaa", "enable_secrets"], "No observed level-15 enable secret; exhaustive absence is not established"


def _eval_1_4_2(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """1.4.2 Enable 'service password-encryption' -> /system/ip_services/password_encryption_service"""
    parts = ["system", "ip_services", "password_encryption_service"]
    pw_enc, origin = _effective_scalar(
        raw, parts, evidence, default=False,
        rule='PASSWORD_ENCRYPTION_DISABLED_BY_DEFAULT', reference_id='C22',
        qualification='IOS_IOSXE_SERVICE_PASSWORD_ENCRYPTION',
        family='password_encryption')
    if pw_enc is None:
        return AuditStatus.NEEDS_REVIEW, parts, "Password encryption service state is unknown"
    if pw_enc is True:
        return AuditStatus.PASS, parts, "Service password-encryption is explicitly enabled; cryptographic strength is not assessed"
    return AuditStatus.FAIL, parts, ("Service password-encryption is disabled by the documented Cisco default (C22)"
                                    if origin == 'documented_default' else "Password encryption service not enabled")


def _eval_1_5_4(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """1.5.4 Do not set 'RW' for any 'snmp-server community'"""
    _, communities = _lookup(raw, ["system", "snmp", "communities"])
    communities = communities or []
    unresolved = False
    for comm in communities:
        if comm.get("access") == "rw":
            # Never expose community strings or full dict in findings
            return AuditStatus.FAIL, ["system", "snmp", "communities"], "RW community found (community string redacted)"
        if comm.get('access') not in ('ro', 'rw'):
            unresolved = True
    context = _effective_context(evidence)
    qualified = bool(context and context.qualifies(family='snmp_communities'))
    if unresolved and not qualified:
        return AuditStatus.NEEDS_REVIEW, ["system", "snmp", "communities"], "A declared community has unresolved access; implicit RO is not applied without a qualified complete inventory"
    detail = ("No RW community exists in the qualified complete inventory; communities without an access keyword resolve to implicit RO (C12)"
              if qualified else "No RW communities found")
    return AuditStatus.PASS, ["system", "snmp", "communities"], detail


def _eval_1_5_9(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """Configuration-only predicate over normalized facts and declared relations."""
    return cis_relations.snmp_privacy(raw, evidence)


def _eval_2_1_1_2(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """2.1.1.2 SSH version 2 -> /system/management/ssh/version"""
    version = raw.get("system", {}).get("management", {}).get("ssh", {}).get("version")
    detail = 'SSH configuration selects version 2; operational SSH availability is not demonstrated' if version == 2 else 'SSH configuration explicitly selects version 1 instead of version 2' if version == 1 else 'SSH version is unknown'
    return management.ssh01(version), ["system", "management", "ssh", "version"], detail


def _eval_2_1_6(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """2.1.6 Set 'service tcp-keepalives-in'"""
    parts = ["system", "ip_services", "tcp_keepalives_in"]
    tcp_keepalives_in, origin = _effective_scalar(
        raw, parts, evidence, default=False,
        rule='TCP_KEEPALIVES_IN_DISABLED_BY_DEFAULT', reference_id='C15',
        qualification='IOS_IOSXE_TCP_KEEPALIVES', family='tcp_keepalives_in')
    if tcp_keepalives_in is True:
        return AuditStatus.PASS, parts, "TCP keepalives-in is enabled"
    if tcp_keepalives_in is False:
        return AuditStatus.FAIL, parts, ("TCP keepalives-in is disabled by the documented Cisco default (C15)"
                                        if origin == 'documented_default' else "TCP keepalives-in not enabled")
    return AuditStatus.NEEDS_REVIEW, parts, "TCP keepalives-in state is unknown"


def _eval_2_2_4(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """2.2.4 Remote syslog destination -> /system/logging/destinations

    The catalog asks for a demonstrated IP target. LOG-01 deliberately keeps
    its broader declared-host policy (including DNS); delivery is not proved.
    """
    from ipaddress import ip_address
    parts = ["system", "logging", "destinations"]
    _, destinations = _lookup(raw, parts)
    unresolved = None
    for index, destination in enumerate(destinations or []):
        address = destination.get('address')
        try:
            ip_address(address)
        except (ValueError, TypeError):
            if unresolved is None: unresolved = parts + [str(index), 'address']
            continue
        if destination.get('transport') != 'unknown' and cis_relations.literal_remote(raw, address):
            return AuditStatus.PASS, parts + [str(index), 'address'], 'Remote Syslog IP target is declared; delivery, VRF reachability and logging enablement are separate evidence'
    if unresolved is not None:
        return AuditStatus.NEEDS_REVIEW, unresolved, 'Syslog target has no demonstrated literal IP; DNS resolution or operational evidence is required'
    return AuditStatus.NEEDS_REVIEW, parts, 'No remote Syslog IP target is demonstrated; the collection does not prove exhaustive absence'


def _eval_2_3_1_1(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """2.3.1.1 NTP authentication enabled"""
    parts = ["system", "ntp", "authentication_enabled"]
    _, auth_enabled = _lookup(raw, parts)
    if auth_enabled is True:
        return AuditStatus.PASS, parts, ""
    if auth_enabled is False:
        return AuditStatus.FAIL, parts, "NTP authentication is explicitly disabled"
    context = _effective_context(evidence)
    if context and context.qualifies(family='ntp_authenticate'):
        return AuditStatus.FAIL, parts, (
            "NTP authentication is absent from the qualified complete command inventory")
    return AuditStatus.NEEDS_REVIEW, parts, (
        "NTP authentication state is unknown because absence is not qualified")


def _eval_3_1_1(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """3.1.1 Set 'no ip source-route'"""
    ip_services = raw.get("system", {}).get("ip_services", {})
    source_routing = ip_services.get("source_routing")
    if source_routing is False:
        return AuditStatus.PASS, ["system", "ip_services", "source_routing"], ""
    return AuditStatus.FAIL, ["system", "ip_services", "source_routing"], "IP source routing enabled"


# --- Groupe 1: BanniÃƒÆ’Ã‚Â¨res F03 ---

def _banner_presence(raw: dict, kind: str, context=None) -> tuple[AuditStatus, list[str], str]:
    """Scoped presence only; another banner is not proof of target absence."""
    parts = ["system", "identity", "banners"]
    _, banners = _lookup(raw, parts)
    banners = banners or []
    for item in banners:
        if item.get("type") == kind:
            present = item.get("text_present")
            if present is True:
                return AuditStatus.PASS, parts, f"{kind.upper()} banner has explicitly configured text; legal approval and effective display are not established"
            if present is False:
                return AuditStatus.FAIL, parts, f"{kind.upper()} banner is explicitly empty"
            return AuditStatus.NEEDS_REVIEW, parts, "Banner text presence is unknown"
    if _proven_absent(
            context, rule=f'{kind.upper()}_BANNER_PROVEN_ABSENT',
            reference_id='C19', qualification='IOS_IOSXE_BANNER_DEFINITION',
            family=f'banner_{kind}'):
        return AuditStatus.FAIL, parts, f"No {kind.upper()} banner is defined in the qualified complete configuration (proven absence; C19)"
    return AuditStatus.NEEDS_REVIEW, parts, f"No {kind.upper()} banner observed; partial configuration does not prove its exhaustive absence"


def _eval_1_3_1(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """1.3.1 Set 'banner exec' text

    Verifies that an EXEC banner is configured with non-empty text.
    """
    return _banner_presence(raw, "exec", evidence)


def _eval_1_3_2(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """1.3.2 Set 'banner login' text

    Verifies that a LOGIN banner is configured with non-empty text.
    """
    return _banner_presence(raw, "login", evidence)


def _eval_1_3_3(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """1.3.3 Set 'banner motd' text

    Verifies that a MOTD banner is configured with non-empty text.
    """
    return _banner_presence(raw, "motd", evidence)


# --- Groupe 2: Utilisateurs locaux F01/F02/F04 ---

def _eval_1_2_1(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """1.2.1 Set 'privilege 1' for local users

    Verifies that all local users have privilege level 1.
    """
    local_users = raw.get("system", {}).get("aaa", {}).get("local_users", [])
    if not local_users:
        return AuditStatus.FAIL, ["system", "aaa", "local_users"], "No local users configured"

    for user in local_users:
        priv = user.get("privilege_level")
        if priv is None or priv != 1:
            return AuditStatus.FAIL, ["system", "aaa", "local_users"], f"User '{user.get('username')}' has privilege level {priv}, expected 1"
    return AuditStatus.PASS, ["system", "aaa", "local_users"], "All local users have privilege level 1"


def _eval_1_4_3(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """1.4.3 Set 'username secret' for all local users

    Verifies that all local users have a secret (type 5/8/9) configured, not a password.
    """
    local_users = raw.get("system", {}).get("aaa", {}).get("local_users", [])
    if not local_users:
        return AuditStatus.FAIL, ["system", "aaa", "local_users"], "No local users configured"

    for user in local_users:
        cred_type = user.get("credential_type")
        cred_configured = user.get("credential_configured")
        if not cred_configured:
            return AuditStatus.FAIL, ["system", "aaa", "local_users"], f"User '{user.get('username')}' has no credential configured"
        if cred_type.partition(':')[0] not in ("secret", "8", "9", "5"):
            return AuditStatus.FAIL, ["system", "aaa", "local_users"], f"User '{user.get('username')}' uses credential type '{cred_type}', expected secret (type 5/8/9)"
    return AuditStatus.PASS, ["system", "aaa", "local_users"], "All local users have secret credentials configured"


# --- Groupe 3: Services globaux F07 ---

def _eval_2_1_2(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """2.1.2 Disable CDP (no cdp run)

    Verifies that CDP is disabled globally.
    """
    ip_services = raw.get("system", {}).get("ip_services", {})
    cdp_enabled = ip_services.get("cdp_enabled")
    if cdp_enabled is None:
        return AuditStatus.NEEDS_REVIEW, ["system", "ip_services", "cdp_enabled"], "Global CDP state is unknown"
    if cdp_enabled is False:
        return AuditStatus.PASS, ["system", "ip_services", "cdp_enabled"], "CDP is disabled"
    return AuditStatus.FAIL, ["system", "ip_services", "cdp_enabled"], "CDP is enabled (should be disabled with 'no cdp run')"


def _eval_2_1_3(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """2.1.3 Disable BOOTP server (no ip bootp server)

    Verifies that BOOTP server is disabled.
    """
    ip_services = raw.get("system", {}).get("ip_services", {})
    bootp_enabled = ip_services.get("bootp_server_enabled")
    if bootp_enabled is False:
        return AuditStatus.PASS, ["system", "ip_services", "bootp_server_enabled"], "BOOTP server is disabled"
    return AuditStatus.FAIL, ["system", "ip_services", "bootp_server_enabled"], "BOOTP server is enabled (should be disabled with 'no ip bootp server')"


def _eval_2_1_4(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """2.1.4 Disable DHCP service (no service dhcp)

    Verifies that DHCP service is disabled.
    """
    parts = ["system", "ip_services", "dhcp_service_enabled"]
    dhcp_enabled, origin = _effective_scalar(
        raw, parts, evidence, default=True,
        rule='DHCP_SERVICE_ENABLED_BY_DEFAULT', reference_id='C17',
        qualification='IOS_IOSXE_DHCP_SERVICE', family='dhcp_service')
    if dhcp_enabled is False:
        return AuditStatus.PASS, parts, "DHCP service is disabled"
    if dhcp_enabled is True:
        detail = ("DHCP service is enabled by the documented default (C17); this does not assert that a server is running or port 67 is open"
                  if origin == 'documented_default' else "DHCP service is enabled (should be disabled with 'no service dhcp')")
        return AuditStatus.FAIL, parts, detail
    return AuditStatus.NEEDS_REVIEW, parts, "DHCP service state is unknown"


def _eval_2_1_5(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """2.1.5 Disable Ident service (no ip identd)

    Verifies that Ident service is disabled.
    """
    parts = ["system", "ip_services", "ident_enabled"]
    ident_enabled, origin = _effective_scalar(
        raw, parts, evidence, default=False,
        rule='IDENTD_DISABLED_BY_DEFAULT', reference_id='C10',
        qualification='IOS_IOSXE_IDENTD', family='identd')
    if ident_enabled is False:
        return AuditStatus.PASS, parts, ("Ident service is disabled by the documented Cisco default (C10)"
                                         if origin == 'documented_default' else "Ident service is disabled")
    if ident_enabled is True:
        return AuditStatus.FAIL, parts, "Ident service is enabled (should be disabled with 'no ip identd')"
    return AuditStatus.NEEDS_REVIEW, parts, "Ident service state is unknown"


def _eval_2_1_7(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """2.1.7 Enable TCP keepalives-out (service tcp-keepalives-out)

    Verifies that TCP keepalives-out is enabled.
    """
    parts = ["system", "ip_services", "tcp_keepalives_out"]
    keepalives_out, origin = _effective_scalar(
        raw, parts, evidence, default=False,
        rule='TCP_KEEPALIVES_OUT_DISABLED_BY_DEFAULT', reference_id='C15',
        qualification='IOS_IOSXE_TCP_KEEPALIVES', family='tcp_keepalives_out')
    if keepalives_out is True:
        return AuditStatus.PASS, parts, "TCP keepalives-out is enabled"
    if keepalives_out is False:
        return AuditStatus.FAIL, parts, ("TCP keepalives-out is disabled by the documented Cisco default (C15)"
                                        if origin == 'documented_default' else "TCP keepalives-out is not enabled")
    return AuditStatus.NEEDS_REVIEW, parts, "TCP keepalives-out state is unknown"


def _eval_2_1_8(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """2.1.8 Disable PAD service (no service pad)

    Verifies that PAD service is disabled.
    """
    parts = ["system", "ip_services", "pad_enabled"]
    pad_enabled, origin = _effective_scalar(
        raw, parts, evidence, default=True,
        rule='CLASSIC_PAD_ENABLED_BY_DEFAULT', reference_id='C16',
        qualification='IOS_IOSXE_CLASSIC_PAD', family='classic_pad')
    if pad_enabled is False:
        return AuditStatus.PASS, parts, "PAD service is disabled"
    if pad_enabled is True:
        return AuditStatus.FAIL, parts, ("Classic PAD is enabled by the documented Cisco default (C16); XOT/CMNS are outside this conclusion"
                                        if origin == 'documented_default' else "PAD service is enabled (should be disabled with 'no service pad')")
    return AuditStatus.NEEDS_REVIEW, parts, "PAD service state is unknown"


# --- Groupe 4: Syslog F08 ---

def _eval_2_2_1(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """2.2.1 Enable logging (logging on)

    Verifies that logging is enabled globally.
    """
    logging = raw.get("system", {}).get("logging", {})
    enabled = logging.get("enabled")
    if enabled is True:
        return AuditStatus.PASS, ["system", "logging", "enabled"], "Logging is enabled"
    return AuditStatus.FAIL, ["system", "logging", "enabled"], "Logging is not enabled (should be enabled with 'logging on')"


def _eval_2_2_2(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """2.2.2 Set logging buffered size

    Verifies that logging buffered is configured with a size.
    """
    logging = raw.get("system", {}).get("logging", {})
    buffered_size = logging.get("buffered_size")
    if buffered_size is not None and buffered_size > 0:
        return AuditStatus.PASS, ["system", "logging", "buffered_size"], f"Logging buffered size set to {buffered_size}"
    return AuditStatus.FAIL, ["system", "logging", "buffered_size"], "Logging buffered size not configured"


def _eval_2_2_3(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """2.2.3 Set logging console critical

    Verifies that console logging includes critical-severity events.
    """
    _, logging = _lookup(raw, ["system", "logging"])
    logging = logging or {}
    # An explicit negative witness must precede the unknown severity guard.
    # dict.get inspects only this optional flag, without inventing its default.
    if dict.get(logging, "console_logging") is False:
        return AuditStatus.FAIL, ["system", "logging", "console_logging"], "Console logging is explicitly disabled; the scoped catalogue predicate requires enabled console logging at the critical threshold"
    console_severity, origin = _effective_scalar(
        raw, ["system", "logging", "console_severity"], evidence,
        default='debugging', rule='CONSOLE_SEVERITY_DEBUGGING_BY_DEFAULT',
        reference_id='C07', qualification='IOS_15_MT_SYSLOG',
        family='logging_console', platforms=('ios',))
    console_logging, console_origin = _effective_scalar(
        raw, ["system", "logging", "console_logging"], evidence,
        default=True, rule='CONSOLE_LOGGING_ENABLED_BY_DEFAULT',
        reference_id='C07', qualification='IOS_15_MT_SYSLOG',
        family='logging_console', platforms=('ios',))
    # Valid severity levels (lower number = more severe): emergencies(0), alerts(1), critical(2), errors(3), warnings(4), notifications(5), informational(6), debugging(7)
    level = _logging_severity(console_severity)
    if console_severity is not None:
        sev = console_severity.lower()
        if level is None:
            return AuditStatus.NEEDS_REVIEW, ["system", "logging", "console_severity"], "Unknown console logging severity"
        if level < 2:
            return AuditStatus.FAIL, ["system", "logging", "console_severity"], (
                f"Console logging severity is {sev} (level {level}); this threshold excludes critical level 2 events required by the control")
        if level == 2:
            if console_logging is not True:
                return AuditStatus.NEEDS_REVIEW, ["system", "logging", "console_logging"], "Console severity is configured but console activation is unknown; the enabled-and-severity predicate is not established"
            return AuditStatus.PASS, ["system", "logging", "console_severity"], f"Console logging severity is {sev} (critical level 2)"
        suffix = ' from the documented IOS 15M&T default (C07)' if origin == 'documented_default' else ''
        return AuditStatus.FAIL, ["system", "logging", "console_severity"], f"Console logging severity is {sev}{suffix}; expected critical level 2, without admitting less-severe events"
    return AuditStatus.NEEDS_REVIEW, ["system", "logging", "console_severity"], "Console logging severity is unknown"


def _eval_2_2_5(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """2.2.5 Set logging trap informational

    Verifies informational (6) or debugging (7), per catalogue rationale.
    """
    trap_severity, origin = _effective_scalar(
        raw, ["system", "logging", "trap_severity"], evidence,
        default='informational', rule='TRAP_SEVERITY_INFORMATIONAL_BY_DEFAULT',
        reference_id='C07', qualification='IOS_15_MT_SYSLOG',
        family='logging_trap', platforms=('ios',))
    numeric = _logging_severity(trap_severity)
    if trap_severity is not None:
        sev = trap_severity.lower()
        if numeric in (6, 7):
            suffix = ' by the documented IOS 15M&T default (C07)' if origin == 'documented_default' else ''
            return AuditStatus.PASS, ["system", "logging", "trap_severity"], f"Logging trap severity is {sev}{suffix}; a remote destination is evaluated separately"
        if numeric in range(6):
            return AuditStatus.FAIL, ["system", "logging", "trap_severity"], f"Logging trap severity is {sev}; catalogue requires informational (6) or debugging (7)"
        return AuditStatus.NEEDS_REVIEW, ["system", "logging", "trap_severity"], "Unknown logging trap severity"
    return AuditStatus.NEEDS_REVIEW, ["system", "logging", "trap_severity"], "Logging trap severity is unknown"


def _eval_2_2_6(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """2.2.6 Set service timestamps

    Verifies that service timestamps are configured for logging.
    """
    return cis_relations.debug_timestamps(raw, evidence)


def _eval_2_2_7(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """2.2.7 Set logging source-interface

    Verifies that logging source-interface is configured.
    """
    return cis_relations.logging_source(raw, evidence)


# --- Groupe 5: NTP F09 ---

def _eval_2_3_1_2(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """2.3.1.2 Set NTP authentication key

    Verifies that an NTP authentication key is defined.
    """
    parts = ["system", "ntp", "authentication_keys"]
    _, auth_keys = _lookup(raw, parts)
    if auth_keys:
        return AuditStatus.PASS, parts, f"NTP authentication key(s) configured ({len(auth_keys)} key(s))"
    context = _effective_context(evidence)
    if context and context.qualifies(family='ntp_authentication_keys'):
        return AuditStatus.FAIL, parts, (
            "No NTP authentication key exists in the qualified complete command inventory")
    return AuditStatus.NEEDS_REVIEW, parts, (
        "No NTP authentication key is observed, but exhaustive absence is not qualified")


def _eval_2_3_1_3(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """2.3.1.3 Set NTP trusted key

    Verifies that NTP trusted key(s) are configured.
    """
    parts = ["system", "ntp", "trusted_keys"]
    _, trusted_keys = _lookup(raw, parts)
    if trusted_keys:
        return AuditStatus.PASS, parts, f"NTP trusted key(s) configured ({len(trusted_keys)} key(s))"
    context = _effective_context(evidence)
    if context and context.qualifies(family='ntp_trusted_keys'):
        return AuditStatus.FAIL, parts, (
            "No NTP trusted key exists in the qualified complete command inventory")
    return AuditStatus.NEEDS_REVIEW, parts, (
        "No NTP trusted key is observed, but exhaustive absence is not qualified")


def _eval_2_3_1_4(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """Configuration-only predicate over normalized facts and declared relations."""
    return cis_relations.ntp_server_keys(raw, evidence)


def _eval_2_3_2(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """2.3.2 Set 'ip address' for 'ntp server'

    Verifies that at least one NTP server address is configured.
    """
    from ipaddress import ip_address
    parts = ['system', 'ntp', 'servers']
    _, servers = _lookup(raw, parts)
    for index, server in enumerate(servers or []):
        try:
            ip_address(server.get('address'))
        except (ValueError, TypeError):
            continue
        if server.get('association_type') == 'server' and cis_relations.literal_remote(raw, server['address']):
            return AuditStatus.PASS, parts + [str(index), 'address'], 'Remote NTP server IP is declared; synchronization and external trust require operational evidence'
    if _proven_absent(evidence, rule='NTP_SERVER_PROVEN_ABSENT',
                      reference_id='CIS-2.3.2', qualification='IOS_IOSXE_NTP_SERVER',
                      family='ntp_servers'):
        return AuditStatus.FAIL, parts, 'No NTP server declaration exists in the qualified complete configuration; Cisco configures no remote server by default'
    return AuditStatus.NEEDS_REVIEW, parts, 'No observed remote NTP server IP; exhaustive server-command absence is not established'


# --- New AAA evaluators (Group A) ---

def _eval_1_1_3(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """1.1.3 Enable 'aaa authentication enable default'

    Checks for the DEFAULT authentication method list with service='enable'.
    Only the 'default' list satisfies this control (named lists don't apply to enable).
    Normalizer places this in authentication_method_lists (not authentication_enable field).
    """
    return cis_relations.authentication_lists(raw, 'enable')


def _eval_1_1_4(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """1.1.4 Set 'login authentication' for 'line con 0'

    Checks that console line uses AAA authentication (not local/line password).
    """
    return cis_relations.authentication_lines(raw, 'con', evidence)


def _eval_1_1_5(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """1.1.5 Set 'login authentication' for 'line tty'

    Checks that TTY lines use AAA authentication.
    """
    return cis_relations.authentication_lines(raw, 'tty', evidence)


def _eval_1_1_6(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """1.1.6 Set 'login authentication' for 'line vty'

    Checks that VTY lines use AAA authentication.
    Note: This is related to 1.2.2 which checks SSH transport on VTY.
    """
    return cis_relations.authentication_lines(raw, 'vty', evidence)


def _eval_1_1_7(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """Configuration-only predicate over normalized facts and declared relations."""
    return cis_relations.accounting_lists(raw, 'commands', 15, evidence)


def _eval_1_1_8(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """Configuration-only predicate over normalized facts and declared relations."""
    return cis_relations.accounting_lists(raw, 'connection', context=evidence)


def _eval_1_1_9(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """Configuration-only predicate over normalized facts and declared relations."""
    return cis_relations.accounting_lists(raw, 'exec', context=evidence)


def _eval_1_1_10(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """Configuration-only predicate over normalized facts and declared relations."""
    return cis_relations.accounting_lists(raw, 'network', context=evidence)


def _eval_1_1_11(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """Configuration-only predicate over normalized facts and declared relations."""
    return cis_relations.accounting_lists(raw, 'system', context=evidence)


# --- New Lines/Access evaluators (Group B) ---

def _eval_1_2_3(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """1.2.3 Set 'no exec' for 'line aux 0'

    Disables EXEC process on AUX port.
    """
    return cis_relations.line_property(raw, 'aux', 'exec_disabled', evidence)


def _eval_1_2_5(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """1.2.5 Set 'access-class' for 'line vty'

    Checks that all VTY lines have an access-class (ACL) applied inbound.
    """
    return cis_relations.line_acls(raw, context=evidence)


def _eval_1_2_7(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """1.2.7 Set 'exec-timeout' <= 10 minutes for 'line console 0'

    Same logic as 1.2.6 but for console line.
    """
    return cis_relations.line_property(raw, 'con', 'idle_timeout_seconds', evidence)


def _eval_1_2_8(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """1.2.8 Set 'exec-timeout' <= 10 minutes for 'line tty'

    Applies to all TTY lines.
    """
    return cis_relations.line_property(raw, 'tty', 'idle_timeout_seconds', evidence)


def _eval_1_2_9(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """1.2.9 Set 'exec-timeout' <= 10 minutes for 'line vty'

    Applies to all VTY lines. Note: 1.2.10 appears to be a duplicate in the benchmark.
    """
    return cis_relations.line_property(raw, 'vty', 'idle_timeout_seconds', evidence)


def _eval_1_2_10(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """1.2.10 Set 'exec-timeout' <= 10 minutes for 'line vty' (duplicate of 1.2.9)

    CIS benchmark appears to have a duplicate control. This evaluator mirrors 1.2.9.
    """
    return _eval_1_2_9(raw, control, evidence)


# --- New SSH evaluators (Group C) ---

def _eval_2_1_1_1_1(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """2.1.1.1.1 Set 'hostname' for SSH key generation"""
    hostname = raw.get("system", {}).get("identity", {}).get("hostname")
    if hostname and hostname.strip():
        return AuditStatus.PASS, ["system", "identity", "hostname"], ""
    return AuditStatus.FAIL, ["system", "identity", "hostname"], "No hostname configured"


def _eval_2_1_1_1_2(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """2.1.1.1.2 Set 'ip domain-name' for SSH key generation"""
    domain = raw.get("system", {}).get("identity", {}).get("domain_name")
    if domain and domain.strip():
        return AuditStatus.PASS, ["system", "identity", "domain_name"], ""
    return AuditStatus.FAIL, ["system", "identity", "domain_name"], "No domain-name configured"


def _eval_2_1_1_1_3(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """A configuration or generation command cannot prove a present key's size."""
    return AuditStatus.NEEDS_REVIEW, [], (
        'Effective RSA key size is not demonstrated by configuration-only data; '
        'a key name or generation history is insufficient')


def _eval_2_1_1_1_4(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """Keep the catalogue's 60/120-second normative conflict visible."""
    parts = ["system", "management", "ssh", "timeout_seconds"]
    _, timeout = _lookup(raw, parts)
    if timeout is not None and 0 < timeout <= 60:
        return AuditStatus.PASS, parts, "Explicit SSH timeout is at or below the 60-second remediation example"
    if timeout is not None and 60 < timeout <= 120:
        return AuditStatus.NEEDS_REVIEW, parts, "The catalogue remediation shows 60 seconds while its additional information only establishes a 120-second CLI maximum; the compliance threshold is not normatively stabilized"
    if timeout == 0:
        return AuditStatus.NEEDS_REVIEW, parts, "Explicit SSH timeout 0 is in the documented CLI domain; its compliance and operational meaning are not established by the available benchmark text"
    if timeout is None:
        effective = _effective_context(evidence)
        if effective is not None and 'ssh_timeout' in effective.incomplete_families:
            return AuditStatus.NEEDS_REVIEW, parts, (
                "A relevant SSH timeout command was encountered but was not accepted as a valid 0-120 second fact; "
                "the Cisco default must not replace an explicit out-of-domain or unsupported command")
        return AuditStatus.NEEDS_REVIEW, parts, "SSH timeout is not explicitly observed; the Cisco default does not resolve the catalogue's 60/120-second normative conflict"
    return AuditStatus.FAIL, parts, "SSH timeout exceeds the documented 120-second maximum"


def _eval_2_1_1_1_5(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """2.1.1.1.5 Set 'ip ssh authentication-retries' <= 3"""
    parts = ["system", "management", "ssh", "authentication_retries"]
    retries, origin = _effective_scalar(
        raw, parts, evidence, default=3,
        rule='SSH_AUTHENTICATION_RETRIES_DEFAULT_3', reference_id='C03',
        qualification='IOS_IOSXE_SSH', family='ssh_authentication_retries')
    if retries is not None and 0 <= retries <= 3:
        detail = ("SSH authentication-retries resolves to the documented default of 3 (C03)"
                  if origin == 'documented_default' else "SSH authentication-retries is explicitly within the maximum of 3")
        return AuditStatus.PASS, parts, detail
    if retries is None:
        return AuditStatus.NEEDS_REVIEW, parts, "SSH authentication-retries is unknown; the documented default is not qualified for this input"
    return AuditStatus.FAIL, parts, "SSH authentication-retries is greater than 3"


# --- New SNMP Level 1 evaluators ---

def _eval_1_2_4(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """1.2.4 Create 'access-list' for use with 'line vty'

    Verifies that an access-list exists AND is referenced by VTY lines via access-class.
    Per CIS: The ACL must be created for use with VTY access-class.
    The actual binding (access-class applied inbound) is checked in 1.2.5.
    This control validates the ACL exists and is of a type suitable for VTY.
    """
    return cis_relations.line_acls(raw, same_acl=True, context=evidence)


def _eval_1_2_11(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """1.2.11 Set 'transport input none' for 'line aux 0'

    Verifies that transport input is disabled on AUX line.
    """
    return cis_relations.line_property(raw, 'aux', 'allowed_transports')


def _eval_1_5_1(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """Running configuration cannot establish business usage or applicability."""
    return AuditStatus.NEEDS_REVIEW, [], (
        'SNMP configuration does not establish business usage; applicability remains unknown')


def _eval_1_5_2(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """Consume only sealed, nonsecret facts from validated configuration captures."""
    return configuration_facts.evaluate_forbidden_community(
        "1.5.2", raw, evidence)


def _eval_1_5_3(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """Consume only sealed, nonsecret facts from validated configuration captures."""
    return configuration_facts.evaluate_forbidden_community(
        "1.5.3", raw, evidence)


def _eval_1_5_5(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """1.5.5 Set the ACL for each 'snmp-server community'

    Verifies that each SNMP community has an ACL configured AND the ACL exists.
    """
    return cis_relations.snmp_acl(raw, context=evidence)


def _eval_1_5_6(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """1.5.6 Create an 'access-list' for use with SNMP

    Verifies resolved community-to-ACL associations while preserving the catalogue's
    title-versus-rationale ambiguity for partial or unrelated ACL coverage.
    """
    return cis_relations.snmp_acl(raw, existential=True, context=evidence)


def _eval_1_5_7(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """1.5.7 Set 'snmp-server host' when using SNMP

    Verifies that SNMP trap destinations are configured when SNMP is used.
    """
    return cis_relations.snmp_hosts(raw)


def _eval_1_5_8(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """1.5.8 Set 'snmp-server enable traps snmp'

    Verifies that SNMP traps are enabled with appropriate types.
    """
    return cis_relations.traps(raw, evidence)


def _eval_1_5_10(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """Partial negative evaluation; running-config cannot prove all persistent SNMPv3 users."""
    return cis_level2_remaining.snmpv3_user_aes(raw, evidence)


def _eval_2_4_1(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    return cis_level2_remaining.single_loopback(raw, evidence)


def _eval_2_4_2(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    return cis_level2_remaining.aaa_source_interfaces(raw, evidence)


def _eval_2_4_3(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    return cis_level2_remaining.ntp_source_interface(raw, evidence)


def _eval_2_4_4(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    return cis_level2_remaining.tftp_source_interface(raw, evidence)


def _eval_3_1_3(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    return cis_level2_remaining.no_tunnel_interfaces(raw, evidence)


def _eval_3_1_4(raw: dict, control: dict, evidence: dict | None) -> tuple[AuditStatus, list[str], str]:
    """Partial universal proof; target topology is not guessed from interface names or addresses."""
    return cis_level2_remaining.strict_urpf(raw, evidence)


def _build_evaluator_registry() -> CISEvaluatorRegistry:
    """Build the registry of implemented CIS evaluators."""
    registry = CISEvaluatorRegistry()

    # AAA controls
    registry.register("1.1.1", _eval_1_1_1)
    registry.register("1.1.2", _eval_1_1_2)
    registry.register("1.1.3", _eval_1_1_3)
    registry.register("1.1.4", _eval_1_1_4)
    registry.register("1.1.5", _eval_1_1_5)
    registry.register("1.1.6", _eval_1_1_6)
    registry.register("1.1.7", _eval_1_1_7)
    registry.register("1.1.8", _eval_1_1_8)
    registry.register("1.1.9", _eval_1_1_9)
    registry.register("1.1.10", _eval_1_1_10)
    registry.register("1.1.11", _eval_1_1_11)
    registry.register("1.2.1", _eval_1_2_1)
    registry.register("1.2.2", _eval_1_2_2)
    registry.register("1.2.3", _eval_1_2_3)
    registry.register("1.2.4", _eval_1_2_4)
    registry.register("1.2.5", _eval_1_2_5)
    registry.register("1.2.6", _eval_1_2_6)
    registry.register("1.2.7", _eval_1_2_7)
    registry.register("1.2.8", _eval_1_2_8)
    registry.register("1.2.9", _eval_1_2_9)
    registry.register("1.2.10", _eval_1_2_10)
    registry.register("1.2.11", _eval_1_2_11)
    registry.register("1.3.1", _eval_1_3_1)
    registry.register("1.3.2", _eval_1_3_2)
    registry.register("1.3.3", _eval_1_3_3)
    registry.register("1.4.1", _eval_1_4_1)
    registry.register("1.4.2", _eval_1_4_2)
    registry.register("1.4.3", _eval_1_4_3)

    # SNMP controls
    registry.register("1.5.1", _eval_1_5_1)
    registry.register("1.5.2", _eval_1_5_2)
    registry.register("1.5.3", _eval_1_5_3)
    registry.register("1.5.4", _eval_1_5_4)
    registry.register("1.5.5", _eval_1_5_5)
    registry.register("1.5.6", _eval_1_5_6)
    registry.register("1.5.7", _eval_1_5_7)
    registry.register("1.5.8", _eval_1_5_8)
    registry.register("1.5.9", _eval_1_5_9)
    registry.register("1.5.10", _eval_1_5_10)

    # SSH controls
    registry.register("2.1.1.1.1", _eval_2_1_1_1_1)
    registry.register("2.1.1.1.2", _eval_2_1_1_1_2)
    registry.register("2.1.1.1.3", _eval_2_1_1_1_3)
    registry.register("2.1.1.1.4", _eval_2_1_1_1_4)
    registry.register("2.1.1.1.5", _eval_2_1_1_1_5)
    registry.register("2.1.1.2", _eval_2_1_1_2)
    registry.register("2.1.2", _eval_2_1_2)
    registry.register("2.1.3", _eval_2_1_3)
    registry.register("2.1.4", _eval_2_1_4)
    registry.register("2.1.5", _eval_2_1_5)
    registry.register("2.1.6", _eval_2_1_6)
    registry.register("2.1.7", _eval_2_1_7)
    registry.register("2.1.8", _eval_2_1_8)

    # Logging controls
    registry.register("2.2.1", _eval_2_2_1)
    registry.register("2.2.2", _eval_2_2_2)
    registry.register("2.2.3", _eval_2_2_3)
    registry.register("2.2.4", _eval_2_2_4)
    registry.register("2.2.5", _eval_2_2_5)
    registry.register("2.2.6", _eval_2_2_6)
    registry.register("2.2.7", _eval_2_2_7)

    # NTP controls
    registry.register("2.3.1.1", _eval_2_3_1_1)
    registry.register("2.3.1.2", _eval_2_3_1_2)
    registry.register("2.3.1.3", _eval_2_3_1_3)
    registry.register("2.3.1.4", _eval_2_3_1_4)
    registry.register("2.3.2", _eval_2_3_2)

    # Level 2 source-interface and configured-interface controls
    registry.register("2.4.1", _eval_2_4_1)
    registry.register("2.4.2", _eval_2_4_2)
    registry.register("2.4.3", _eval_2_4_3)
    registry.register("2.4.4", _eval_2_4_4)

    # IP Security controls
    registry.register("3.1.1", _eval_3_1_1)
    registry.register("3.1.3", _eval_3_1_3)
    registry.register("3.1.4", _eval_3_1_4)

    from .rules.cis_routing import EVALUATORS
    for cid, evaluator in EVALUATORS.items():
        registry.register(cid, evaluator, fact_barrier=False)

    return registry
