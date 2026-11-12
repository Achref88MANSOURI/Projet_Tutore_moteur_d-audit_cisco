"""One trusted analysis transaction; stdout carries only the public response.

No imported SourceMap/document is accepted. Seals remain in this process and
are verified before enrichment, not reconstructed from the stdout JSON.
"""
import contextlib
import json
import os
import sys
from typing import Literal

from pydantic import BaseModel, ConfigDict, StrictBool, StrictInt, StrictStr
from audit.models import AuditReport
from audit.provenance import PublicProvenance, enrich_findings
from web_analysis_limits import MAX_REQUEST_BYTES, MAX_CONFIG_BYTES, MAX_RESPONSE_BYTES
from audit.resolvers.routing_common import RoutingResolution

OUTPUT_LIMIT_EXIT = 3


class AnalysisInputError(ValueError):
    pass


class AnalysisInputTooLarge(AnalysisInputError):
    pass


class AnalysisOutputTooLarge(ValueError):
    pass


class AnalysisRequest(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)
    configuration: StrictStr
    os_family: Literal['ios', 'iosxe'] = 'ios'
    profile_level: StrictInt = 2
    include_lower: StrictBool = True
    input_completeness: Literal['complete', 'partial', 'unknown'] = 'unknown'


class AnalysisResponse(BaseModel):
    model_config = ConfigDict(extra='forbid')
    normalized: dict
    audit: AuditReport
    provenance: PublicProvenance
    routing_resolution: RoutingResolution | None = None


def decode_request(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise AnalysisInputError('Invalid analysis request')
            result[key] = value
        return result
    def constant(_):
        raise AnalysisInputError('Invalid analysis request')
    try:
        return json.loads(data, object_pairs_hook=pairs, parse_constant=constant)
    except Exception:
        raise AnalysisInputError('Invalid analysis request') from None


def validate_request(payload):
    try:
        request = AnalysisRequest.model_validate(payload)
        if request.profile_level not in (1, 2) or not request.configuration.strip() or '\x00' in request.configuration:
            raise AnalysisInputError('Invalid analysis request')
        configuration = request.configuration.removeprefix('\ufeff')
        if not configuration.strip():
            raise AnalysisInputError('Invalid analysis request')
        size = len(configuration.encode('utf-8'))
    except Exception:
        raise AnalysisInputError('Invalid analysis request') from None
    if size > MAX_CONFIG_BYTES:
        raise AnalysisInputTooLarge('Analysis input limit exceeded')
    from cis_operation import CUMULATIVE_INCLUDE_LOWER, CUMULATIVE_PROFILE_LEVEL
    return request.model_copy(update={
        'configuration': configuration,
        'profile_level': CUMULATIVE_PROFILE_LEVEL,
        'include_lower': CUMULATIVE_INCLUDE_LOWER,
    })


def validate_public_response(response):
    """Structural checks on the authorized child's DTO, not MAC rehydration."""
    from schemas.router_contract_v1 import RouterContractV1
    from normalizer.common.contexts import at
    from normalizer.provenance import Quality
    if response.routing_resolution is not None:
        from audit.resolvers.routing import resolve_routing
        if response.routing_resolution != resolve_routing(
                response.normalized,
                input_completeness=response.routing_resolution.input_completeness,
                platform_family=response.routing_resolution.platform_family):
            raise ValueError('Inconsistent routing resolution')
    if RouterContractV1.model_validate(response.normalized).model_dump(mode='json') != response.normalized:
        raise ValueError('Noncanonical analysis response')
    scope = response.audit.scope
    if response.audit.profile.get('cis_enabled'):
        from cis_operation import CUMULATIVE_PROFILE_NAME
        if scope is None:
            raise ValueError('Missing configuration audit scope')
        if (response.audit.profile.get('name') != CUMULATIVE_PROFILE_NAME
                or response.audit.profile.get('cumulative') is not True
                or response.audit.profile.get('level_1_enabled') is not True
                or response.audit.profile.get('level_2_enabled') is not True
                or response.audit.profile.get('eligible_level_1_controls') != 51
                or response.audit.profile.get('eligible_level_2_controls') != 37
                or scope.catalog_controls != 90 or scope.eligible_controls != 88):
            raise ValueError('Non-cumulative CIS audit profile')
        excluded_ids = {'CIS-' + c.control_id for c in scope.excluded_controls}
        if (scope.catalog_controls != scope.eligible_controls + len(excluded_ids)
                or scope.eligible_controls != len(response.audit.findings)
                or not 0 <= scope.evaluator_controls <= scope.eligible_controls
                or any(f.check_id in excluded_ids for f in response.audit.findings)
                or len(excluded_ids) != len(scope.excluded_controls)
                or scope.executed_controls != response.audit.execution_counts.get('EXECUTED', 0)
                or scope.unevaluated_automatic_controls != response.audit.execution_counts.get('NO_EVALUATOR', 0)
                or scope.manual_controls != response.audit.execution_counts.get('MANUAL', 0)
                or any(response.audit.counts.get(s) != sum(f.status.value == s for f in response.audit.findings)
                       for s in ('PASS','FAIL','NEEDS_REVIEW','NOT_APPLICABLE'))):
            raise ValueError('Inconsistent configuration audit scope')
        if (response.routing_resolution is not None and
                (scope.input_completeness != response.routing_resolution.input_completeness or
                 scope.platform_family != response.routing_resolution.platform_family)):
            raise ValueError('Inconsistent routing audit qualification')
    proof = response.provenance
    if len(proof.findings) != len(response.audit.findings):
        raise ValueError('Invalid public evidence association')
    if proof.state == 'DEGRADED' and (proof.source_lines or proof.document_id is not None):
        raise ValueError('Invalid degraded provenance')
    if proof.state == 'AVAILABLE' and not proof.document_id:
        raise ValueError('Missing operation identity')
    if any(line.number != i for i, line in enumerate(proof.source_lines, 1)):
        raise ValueError('Invalid source positions')
    for trace, finding in zip(proof.findings, response.audit.findings):
        if trace.check_id != finding.check_id or len(trace.evidence) != len(finding.evidence):
            raise ValueError('Invalid public finding association')
        for i, (origin, evidence) in enumerate(zip(trace.evidence, finding.evidence)):
            if origin.evidence_index != i or origin.json_pointer != evidence.json_pointer:
                raise ValueError('Invalid public evidence pointer')
            if origin.quality == Quality.CONTEXTUAL and origin.commands:
                raise ValueError('Collective evidence cannot highlight commands')
            for link in (origin, *origin.related):
                if link.quality == Quality.EXACT and (not link.commands or at(response.normalized, link.json_pointer) is None):
                    raise ValueError('Invalid public exact evidence')
                for command in link.commands:
                    if (not 1 <= command.source_line <= len(proof.source_lines)
                            or proof.source_lines[command.source_line - 1].masked
                            or any(not 1 <= n < command.source_line for n in command.context_lines)):
                        raise ValueError('Invalid public command origin')


def analyze_request(payload, *, official=True, provenance_limits=None, provenance_max_bytes=None):
    """Internal worker function; test quota overrides are never HTTP options."""
    from cli import normalize_with_provenance
    from cis_operation import _audit_live_result
    from audit.resolvers.routing import resolve_routing
    request = validate_request(payload)
    facts = {}
    result = normalize_with_provenance(request.configuration, os_family=request.os_family, official=official,
                                       limits=provenance_limits, on_provenance_error='unavailable',
                                       _evidence_sink=facts)
    document_id = result.document_id
    report, _ = _audit_live_result(result, facts, os_family=request.os_family,
                                  profile_level=request.profile_level, include_lower=request.include_lower,
                                  input_completeness=request.input_completeness)
    kwargs = {} if provenance_max_bytes is None else {'max_bytes': provenance_max_bytes}
    proof = enrich_findings(result, report, document_id=document_id, **kwargs)
    return AnalysisResponse(normalized=result.normalized, audit=report, provenance=proof,
                            routing_resolution=resolve_routing(
                                result.normalized, input_completeness=request.input_completeness,
                                platform_family=request.os_family))


def main():
    try:
        raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        if len(raw) > MAX_REQUEST_BYTES:
            return OUTPUT_LIMIT_EXIT
        payload = decode_request(raw.decode('utf-8'))
        # Library diagnostics must not corrupt stdout or disclose source data.
        # os.devnull is a device, not persistent storage of imported configs.
        with open(os.devnull, 'w', encoding='utf-8') as sink:
            with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
                response = analyze_request(payload)
        encoded = response.model_dump_json().encode('utf-8')
        if len(encoded) > MAX_RESPONSE_BYTES:
            return OUTPUT_LIMIT_EXIT
        sys.stdout.buffer.write(encoded)
        return 0
    except Exception:
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
