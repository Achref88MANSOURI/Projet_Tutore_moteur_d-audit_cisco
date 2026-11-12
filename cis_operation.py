"""Configuration-only analysis. No supplementary artifacts or router access."""
import contextlib
import io
from datetime import datetime, timezone
from threading import RLock
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict
from audit.models import AuditReport
from audit.configuration_facts import ConfigurationEvidence, ConfigurationFacts
from audit.resolvers.routing_common import RoutingResolution

_OPERATION_LOCK = RLock()
CUMULATIVE_PROFILE_LEVEL = 2
CUMULATIVE_INCLUDE_LOWER = True
CUMULATIVE_PROFILE_NAME = 'CIS Level 1 + Level 2'


class ConfigurationAnalysis(BaseModel):
    model_config = ConfigDict(extra='forbid')
    normalized: dict
    audit: AuditReport
    provenance: dict
    configuration_evidence: ConfigurationEvidence
    proof_basis: dict[str, Literal['PROVEN_BY_CONFIG', 'NOT_DEMONSTRATED']]
    routing_resolution: RoutingResolution | None = None


def _audit_live_result(result, facts, *, os_family, profile_level=2, include_lower=True,
                       input_completeness='unknown'):
    """Trusted producers only: seal facts from the same normalization operation.

    No serialized fact or sidecar is accepted by either HTTP request schema.
    A degraded SourceMap does not change the normalized configuration facts.
    """
    from audit.cis import audit_cis_normalized
    context = ConfigurationEvidence._create(
        result.normalized, operation_id=result.document_id or uuid4().hex,
        declared_os_family=os_family, received_at=datetime.now(timezone.utc),
        facts=ConfigurationFacts(**facts))
    # The historical arguments remain accepted for callers, but every
    # application transaction is intentionally cumulative.
    report = audit_cis_normalized(
        result.normalized, profile_level=CUMULATIVE_PROFILE_LEVEL,
        include_lower=CUMULATIVE_INCLUDE_LOWER,
        evidence=context, evidence_operation_id=context.operation_id,
        input_completeness=input_completeness, platform_family=os_family)
    return report, context


def analyze(text, *, os_family='ios', official=True, profile_level=2, include_lower=True,
            input_completeness='unknown'):
    if (type(profile_level) is not int or profile_level not in (1, 2) or type(include_lower) is not bool
            or input_completeness not in ('complete', 'partial', 'unknown')):
        raise ValueError('Invalid audit profile')
    from cli import normalize_with_provenance
    from audit.cis import audit_cis_normalized
    from audit.provenance import enrich_findings
    from audit.resolvers.routing import resolve_routing

    try:
        # Match the trusted worker's policy: library diagnostics never publish CLI.
        with _OPERATION_LOCK, contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            facts = {}
            result = normalize_with_provenance(
                text, os_family=os_family, official=official, _evidence_sink=facts)
            report, context = _audit_live_result(result, facts, os_family=os_family,
                                                 profile_level=CUMULATIVE_PROFILE_LEVEL,
                                                 include_lower=CUMULATIVE_INCLUDE_LOWER,
                                                 input_completeness=input_completeness)
            enriched = enrich_findings(result, report, document_id=result.document_id)
            basis = {cid: 'NOT_DEMONSTRATED' for cid in ('1.5.2', '1.5.3')}
            for finding in report.findings:
                cid = finding.check_id.removeprefix('CIS-')
                if cid in ('1.5.2', '1.5.3') and finding.status.value == 'FAIL':
                    basis[cid] = 'PROVEN_BY_CONFIG'
            return ConfigurationAnalysis(
                normalized=result.normalized, audit=report,
                provenance=enriched.model_dump(mode='json'),
                configuration_evidence=context, proof_basis=basis,
                routing_resolution=resolve_routing(result.normalized, input_completeness=input_completeness,
                                                   platform_family=os_family))
    except Exception:
        raise ValueError('Configuration analysis failed') from None
