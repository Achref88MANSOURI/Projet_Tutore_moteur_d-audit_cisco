"""Serializable audit results. No raw configuration or credential fields."""
from enum import Enum
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr


class AuditStatus(str, Enum):
    PASS = 'PASS'
    FAIL = 'FAIL'
    NOT_APPLICABLE = 'NOT_APPLICABLE'
    NEEDS_REVIEW = 'NEEDS_REVIEW'


class AuditModel(BaseModel):
    model_config = ConfigDict(extra='forbid')


class Evidence(AuditModel):
    json_pointer: str
    observed_value: StrictBool | StrictInt | StrictStr | None


class Reference(AuditModel):
    framework: str
    platform: str
    version: str
    control_id: str
    relationship: Literal['direct', 'supporting']
    source: str
    provenance: str
    verification_status: Literal['upstream_claim_only']
    limitation: str


class Finding(AuditModel):
    check_id: str
    title: str
    status: AuditStatus
    severity: Literal['critical','high']
    reason: str
    evidence: list[Evidence] = Field(default_factory=list)
    references: list[Reference] = Field(default_factory=list)
    recommendation: str
    applicability: Literal['APPLICABLE', 'NOT_APPLICABLE', 'APPLICABILITY_UNKNOWN'] = 'APPLICABILITY_UNKNOWN'
    execution_status: Literal['EXECUTED', 'NO_EVALUATOR', 'MANUAL'] = 'EXECUTED'


class ExcludedControl(AuditModel):
    control_id: str
    title: str
    status: Literal['NOT_AUDITABLE_FROM_RUNNING_CONFIG']
    reason: str


class CISAuditScope(AuditModel):
    version: Literal['1.0.0'] = '1.0.0'
    scope_id: Literal['CIS_IOS15_V4_1_1_RUNNING_CONFIG'] = 'CIS_IOS15_V4_1_1_RUNNING_CONFIG'
    catalog_controls: int
    eligible_controls: int
    evaluator_controls: int
    excluded_controls: list[ExcludedControl]
    executed_controls: int = 0
    unevaluated_automatic_controls: int = 0
    manual_controls: int = 0
    input_completeness: Literal['complete', 'partial', 'unknown'] = 'unknown'
    platform_family: Literal['ios', 'iosxe', 'unknown'] = 'unknown'


class AuditReport(AuditModel):
    engine_version: str = '0.2.0'
    contract_version: str = '1.0.0'
    profile: dict[str, StrictBool | StrictInt | StrictStr]
    findings: list[Finding]
    counts: dict[str, int]
    execution_counts: dict[str, int] = Field(default_factory=dict)
    compliance_notice: str = 'Technical checks only; references do not establish global or certified compliance.'
    # Additive CIS-only metadata; historical four-rule reports keep their shape.
    scope: CISAuditScope | None = Field(default=None, exclude_if=lambda value: value is None)
