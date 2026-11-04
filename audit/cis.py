"""CIS Cisco IOS 15 evaluation layer.

Consumes the catalog and a RouterContractV1 document, dispatches to per-control
evaluators, and returns an AuditReport with CIS-specific findings.

This module reuses the existing audit engine's models and status enum.
"""
from __future__ import annotations

from typing import Any, Callable
from pathlib import Path
import json

from .models import AuditReport, AuditStatus, Evidence, Finding, Reference
from .catalog.loader import CISIOS15Catalog
from .rules import management, logging, aaa_central


# Type for evaluator functions
Evaluator = Callable[[dict, dict], tuple[AuditStatus, list[tuple[str, Any]], str]]
# Returns (status, evidence_parts, detail)


class CISEvaluatorRegistry:
    """Registry of CIS control evaluators.

    Maps control_id -> evaluator function.
    Evaluators receive (contract_dict, control_metadata) and return
    (status, evidence_parts, detail).
    """

    def __init__(self):
        self._evaluators: dict[str, Evaluator] = {}

    def register(self, control_id: str, evaluator: Evaluator) -> None:
        if control_id in self._evaluators:
            raise ValueError(f"Evaluator for {control_id} already registered")
        self._evaluators[control_id] = evaluator

    def get(self, control_id: str) -> Evaluator | None:
        return self._evaluators.get(control_id)

    def all_registered(self) -> list[str]:
        return list(self._evaluators.keys())


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
    evidence = [Evidence(json_pointer='/'+'/'.join(evidence_parts), observed_value=observed)] if exists else []

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
    evidence: dict | None = None,
) -> AuditReport:
    """Evaluate CIS Cisco IOS 15 benchmark controls against a normalized document.

    Args:
        normalized_document: RouterContractV1 dict, model, or JSON file path
        profile_level: 1 or 2 (Level 2 includes Level 1 by default)
        include_lower: When profile_level=2 and include_lower=False, only Level 2 controls
        evidence: Optional dict of operational evidence (show command outputs)

    Returns:
        AuditReport with CIS-specific findings
    """
    # Load the catalog
    catalog = CISIOS15Catalog()
    controls = catalog.controls_for_profile(profile_level, include_lower=include_lower)

    # Load raw document
    if isinstance(normalized_document, (str, Path)):
        raw = json.loads(Path(normalized_document).read_text(encoding='utf-8-sig'))
    elif hasattr(normalized_document, 'model_dump'):
        raw = normalized_document.model_dump(mode='json')
    else:
        raw = normalized_document

    # Validate with RouterContractV1
    from schemas.router_contract_v1 import RouterContractV1
    model = RouterContractV1.model_validate(raw)

    # Load reference mappings
    mapping = json.loads((Path(__file__).parent / 'mappings' / 'verified_references.json').read_text(encoding='utf-8'))

    # Get evaluator registry
    registry = _build_evaluator_registry()

    findings: list[Finding] = []
    skipped = 0

    for control in controls:
        control_id = control["id"]
        evaluator = registry.get(control_id)

        if evaluator is None:
            # No evaluator implemented - skip with NOT_APPLICABLE or NEEDS_REVIEW
            # We use NEEDS_REVIEW to signal the control exists but isn't evaluated
            finding = Finding(
                check_id=f"CIS-{control_id}",
                title=control["title"],
                status=AuditStatus.NEEDS_REVIEW,
                severity="high",
                reason=f"No evaluator implemented for control {control_id}. Catalog status: {control.get('catalogue_integration_status', 'UNKNOWN')}.",
                evidence=[],
                recommendation="Implement CIS evaluator for this control.",
                references=[],
            )
            findings.append(finding)
            skipped += 1
            continue

        # Run evaluator
        try:
            status, evidence_parts, detail = evaluator(raw, control)
        except Exception as e:
            status = AuditStatus.NEEDS_REVIEW
            evidence_parts = []
            detail = f"Evaluator error: {e}"

        # Build finding
        references = mapping.get(f"CIS-{control_id}", mapping.get(control_id, []))

        reason = (
            detail if status == AuditStatus.NEEDS_REVIEW else
            "Established normalized fact satisfies the CIS rule." if status == AuditStatus.PASS else
            "Established normalized fact violates the CIS rule." if status == AuditStatus.FAIL else
            "Explicitly excluded by the audit profile."
        )

        finding = Finding(
            check_id=f"CIS-{control_id}",
            title=control["title"],
            status=status,
            severity="high",
            reason=reason,
            evidence=[Evidence(json_pointer='/'+'/'.join(evidence_parts), observed_value=None)] if evidence_parts else [],
            recommendation="Review CIS benchmark for remediation steps.",
            references=[Reference.model_validate(r) for r in references],
        )
        findings.append(finding)

    # Add existing audit rules if requested (AAA-01, AAA-02, SSH-01, LOG-01)
    # These are already covered by audit_normalized() - we can optionally include them
    # For now, we focus on the CIS catalog controls

    return AuditReport(
        engine_version='0.2.0',
        contract_version='1.0.0',
        profile={'cis_enabled': True},
        findings=findings,
        counts={s.value: sum(f.status == s for f in findings) for s in AuditStatus},
        compliance_notice='Technical checks only; references do not establish global or certified compliance.'
    )


# --- Evaluator implementations ---

def _eval_1_1_1(raw: dict, control: dict) -> tuple[AuditStatus, list[str], str]:
    """1.1.1 Enable 'aaa new-model' -> /system/aaa/enabled"""
    return management.aaa01(raw.get("system", {}).get("aaa", {}).get("enabled")), ["system", "aaa", "enabled"], ""


def _eval_1_1_2(raw: dict, control: dict) -> tuple[AuditStatus, list[str], str]:
    """1.1.2 Enable 'aaa authentication login' -> check authentication_method_lists"""
    aaa = raw.get("system", {}).get("aaa", {})
    method_lists = aaa.get("authentication_method_lists", [])
    if not method_lists:
        return AuditStatus.FAIL, ["system", "aaa", "authentication_method_lists"], "No AAA authentication method lists declared"
    # Check if any login list exists with methods
    for ml in method_lists:
        if ml.get("service") == "login" and ml.get("methods"):
            return AuditStatus.PASS, ["system", "aaa", "authentication_method_lists"], ""
    return AuditStatus.FAIL, ["system", "aaa", "authentication_method_lists"], "No login authentication method list with methods"


def _eval_1_2_2(raw: dict, control: dict) -> tuple[AuditStatus, list[str], str]:
    """1.2.2 Set 'transport input ssh' for 'line vty' connections"""
    lines = raw.get("system", {}).get("management", {}).get("lines", [])
    for line in lines:
        if line.get("name", "").startswith("vty"):
            transports = line.get("allowed_transports")
            if transports is not None and "ssh" in transports:
                return AuditStatus.PASS, ["system", "management", "lines"], ""
    return AuditStatus.FAIL, ["system", "management", "lines"], "No VTY line with SSH transport"


def _eval_1_2_6(raw: dict, control: dict) -> tuple[AuditStatus, list[str], str]:
    """1.2.6 Set 'exec-timeout' <= 10 minutes for 'line aux 0'"""
    lines = raw.get("system", {}).get("management", {}).get("lines", []) or []
    for line in lines:
        if line.get("name", "") == "aux 0":
            timeout = line.get("idle_timeout_seconds")
            if timeout is not None and timeout <= 600:
                return AuditStatus.PASS, ["system", "management", "lines"], ""
    return AuditStatus.FAIL, ["system", "management", "lines"], "No 'line aux 0' with exec-timeout <= 10 minutes"


def _eval_1_4_1(raw: dict, control: dict) -> tuple[AuditStatus, list[str], str]:
    """1.4.1 Set 'password' for 'enable secret'"""
    aaa = raw.get("system", {}).get("aaa", {})
    enable_secret = aaa.get("enable_secret")
    if enable_secret and enable_secret.get("configured") is True:
        return AuditStatus.PASS, ["system", "aaa", "enable_secret"], ""
    return AuditStatus.FAIL, ["system", "aaa", "enable_secret"], "No enable secret configured"


def _eval_1_4_2(raw: dict, control: dict) -> tuple[AuditStatus, list[str], str]:
    """1.4.2 Enable 'service password-encryption'"""
    system = raw.get("system", {})
    ip_services = system.get("ip_services", {})
    # Check for password encryption service
    pw_enc = system.get("password_encryption_service")
    if pw_enc is True:
        return AuditStatus.PASS, ["system", "password_encryption_service"], ""
    return AuditStatus.FAIL, ["system", "password_encryption_service"], "Password encryption service not enabled"


def _eval_1_5_4(raw: dict, control: dict) -> tuple[AuditStatus, list[str], str]:
    """1.5.4 Do not set 'RW' for any 'snmp-server community'"""
    snmp = raw.get("system", {}).get("snmp", {})
    communities = snmp.get("communities", [])
    for comm in communities:
        if comm.get("access") == "rw":
            return AuditStatus.FAIL, ["system", "snmp", "communities"], f"RW community found: {comm}"
    return AuditStatus.PASS, ["system", "snmp", "communities"], "No RW communities found"


def _eval_1_5_9(raw: dict, control: dict) -> tuple[AuditStatus, list[str], str]:
    """1.5.9 Set 'priv' for each 'snmp-server group' using SNMPv3"""
    snmp = raw.get("system", {}).get("snmp", {})
    groups = snmp.get("groups", [])
    for group in groups:
        if group.get("version") == "v3" and group.get("security_level") != "priv":
            return AuditStatus.FAIL, ["system", "snmp", "groups"], f"SNMPv3 group {group.get('name')} lacks priv"
    return AuditStatus.PASS, ["system", "snmp", "groups"], "All SNMPv3 groups use priv"


def _eval_2_1_1_2(raw: dict, control: dict) -> tuple[AuditStatus, list[str], str]:
    """2.1.1.2 SSH version 2 -> /system/management/ssh/version"""
    version = raw.get("system", {}).get("management", {}).get("ssh", {}).get("version")
    return management.ssh01(version), ["system", "management", "ssh", "version"], ""


def _eval_2_1_6(raw: dict, control: dict) -> tuple[AuditStatus, list[str], str]:
    """2.1.6 Set 'service tcp-keepalives-in'"""
    ip_services = raw.get("system", {}).get("ip_services", {})
    tcp_keepalives_in = ip_services.get("tcp_keepalives_in")
    if tcp_keepalives_in is True:
        return AuditStatus.PASS, ["system", "ip_services", "tcp_keepalives_in"], ""
    return AuditStatus.FAIL, ["system", "ip_services", "tcp_keepalives_in"], "TCP keepalives-in not enabled"


def _eval_2_2_4(raw: dict, control: dict) -> tuple[AuditStatus, list[str], str]:
    """2.2.4 Remote syslog destination -> /system/logging/destinations"""
    destinations = raw.get("system", {}).get("logging", {}).get("destinations", [])
    return logging.log01(destinations)


def _eval_2_3_1_1(raw: dict, control: dict) -> tuple[AuditStatus, list[str], str]:
    """2.3.1.1 NTP authentication enabled"""
    ntp = raw.get("system", {}).get("ntp", {})
    auth_enabled = ntp.get("authentication_enabled")
    if auth_enabled is True:
        return AuditStatus.PASS, ["system", "ntp", "authentication_enabled"], ""
    return AuditStatus.FAIL, ["system", "ntp", "authentication_enabled"], "NTP authentication not enabled"


def _eval_3_1_1(raw: dict, control: dict) -> tuple[AuditStatus, list[str], str]:
    """3.1.1 Set 'no ip source-route'"""
    ip_services = raw.get("system", {}).get("ip_services", {})
    source_routing = ip_services.get("source_routing")
    if source_routing is False:
        return AuditStatus.PASS, ["system", "ip_services", "source_routing"], ""
    return AuditStatus.FAIL, ["system", "ip_services", "source_routing"], "IP source routing enabled"


def _build_evaluator_registry() -> CISEvaluatorRegistry:
    """Build the registry of implemented CIS evaluators."""
    registry = CISEvaluatorRegistry()

    # AAA controls
    registry.register("1.1.1", _eval_1_1_1)
    registry.register("1.1.2", _eval_1_1_2)
    registry.register("1.2.2", _eval_1_2_2)
    registry.register("1.2.6", _eval_1_2_6)
    registry.register("1.4.1", _eval_1_4_1)
    registry.register("1.4.2", _eval_1_4_2)

    # SNMP controls
    registry.register("1.5.4", _eval_1_5_4)
    registry.register("1.5.9", _eval_1_5_9)

    # SSH controls
    registry.register("2.1.1.2", _eval_2_1_1_2)
    registry.register("2.1.6", _eval_2_1_6)

    # Logging controls
    registry.register("2.2.4", _eval_2_2_4)

    # NTP controls
    registry.register("2.3.1.1", _eval_2_3_1_1)

    # IP Security controls
    registry.register("3.1.1", _eval_3_1_1)

    return registry