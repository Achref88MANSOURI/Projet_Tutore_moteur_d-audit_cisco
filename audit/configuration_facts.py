"""Private, operation-bound facts extracted before configuration redaction.

No operational output is accepted. Serialized facts cannot authorize a verdict.
"""
from datetime import datetime
import hmac
import json
import secrets
import time
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, StrictBool, StrictInt, StrictStr, model_validator
from .models import AuditStatus


class FamilyCoverage(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)
    family: StrictStr
    relevant: StrictInt = Field(ge=0)
    recognized: StrictInt = Field(ge=0)

    @model_validator(mode='after')
    def bounded_counts(self):
        if self.recognized > self.relevant:raise ValueError('Invalid command coverage counts')
        return self

    @property
    def covered(self):
        return self.relevant > 0 and self.recognized == self.relevant


class ConfigurationFacts(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)
    forbidden_152_active: StrictBool | None = None
    forbidden_153_active: StrictBool | None = None
    forbidden_152_removed: StrictBool = False
    forbidden_153_removed: StrictBool = False
    exhaustive: Literal[False] = False
    coverage: tuple[FamilyCoverage, ...] = ()


class ConfigurationEvidence(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)
    version: Literal['0.2.0'] = '0.2.0'
    operation_id: str = Field(pattern=r'^[0-9a-f]{32}$')
    source: Literal['SUPPLIED_CONFIGURATION_ONLY'] = 'SUPPLIED_CONFIGURATION_ONLY'
    origin_authenticated: Literal[False] = False
    declared_os_family: Literal['ios', 'iosxe']
    received_at: datetime
    facts: ConfigurationFacts
    limitations: tuple[str, ...] = (
        'NO_ORIGIN_AUTHENTICATION', 'NO_EXHAUSTIVE_INVENTORY',
        'NO_OPERATIONAL_STATE_CLAIM',
    )
    _key: bytes = PrivateAttr(default=b'')
    _mac: bytes = PrivateAttr(default=b'')
    _expires: float = PrivateAttr(default=0)

    def _payload(self, document):
        return json.dumps([document, self.model_dump(mode='json')], sort_keys=True,
                          separators=(',', ':'), ensure_ascii=True).encode()

    @classmethod
    def _create(cls, document, **kwargs):
        result = cls(**kwargs)
        result._key = secrets.token_bytes(32)
        result._expires = time.monotonic() + 300
        result._mac = hmac.digest(result._key, result._payload(document), 'sha256')
        return result

    def valid_for(self, document, *, operation_id):
        try:
            return bool(self._key and operation_id == self.operation_id
                        and time.monotonic() <= self._expires
                        and hmac.compare_digest(
                            self._mac, hmac.digest(self._key, self._payload(document), 'sha256')))
        except Exception:
            return False


def evaluate_forbidden_community(control_id, document, context):
    """Decide from a positive witness or a qualified sealed inventory.

    Community values never cross this boundary. A negative result is authorized
    only for a complete input whose relevant command coverage is intact.
    """
    if control_id not in ('1.5.2', '1.5.3'):
        raise ValueError('Unsupported configuration fact')
    unknown = ('No active forbidden-community category is demonstrated after redaction; '
               'no exhaustive absence of a forbidden community is inferred')
    from .resolvers.effective_configuration import effective_context
    effective = effective_context(context)
    evidence = effective.configuration_evidence if effective is not None else None
    if not (isinstance(evidence, tuple) and len(evidence) == 2
            and isinstance(evidence[0], ConfigurationEvidence)
            and evidence[0].valid_for(document, operation_id=evidence[1])):
        return AuditStatus.NEEDS_REVIEW, [], unknown
    suffix = '152' if control_id == '1.5.2' else '153'
    if getattr(evidence[0].facts, 'forbidden_' + suffix + '_active') is True:
        return AuditStatus.FAIL, [], (
            'An active forbidden-community category is demonstrated by validated '
            'configuration captures; value withheld')
    if effective.qualifies(family='snmp_communities'):
        return AuditStatus.PASS, [], (
            'The forbidden community category is absent from the qualified, '
            'complete and sealed community inventory; values remain withheld')
    return AuditStatus.NEEDS_REVIEW, [], unknown


def relevant_coverage_gap(document, evidence, family):
    """Only a live producing transaction can report rejected command coverage.

    Covered syntax does NOT authorize a universal PASS or infer device defaults.
    Imported counts have no trust; no verdict can be supplied by the caller.
    """
    if not (isinstance(evidence, tuple) and len(evidence)==2
            and isinstance(evidence[0], ConfigurationEvidence)
            and evidence[0].valid_for(document, operation_id=evidence[1])):
        return False
    return any(c.family==family and not c.covered for c in evidence[0].facts.coverage)
