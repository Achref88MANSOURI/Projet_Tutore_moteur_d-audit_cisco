"""Validate normalized inputs, evaluate pure rules, attach minimal evidence."""
import json
from pathlib import Path
from schemas.router_contract_v1 import RouterContractV1
from .models import AuditStatus, AuditReport, Evidence, Finding, Reference
from .rules import management, logging, aaa_central


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON member')
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError('Non-finite JSON number')


def _lookup(document, parts):
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



def _aaa02_finding(model, raw, mapping, required):
    """AAA-02 proof is verified against the supplied document before publication."""
    status, proof, detail = (aaa_central.aaa02(model.system.aaa, model.system.management.lines)
                             if required else (AuditStatus.NOT_APPLICABLE, [], ''))
    evidence = []
    for parts, expected in proof:
        exists, observed = _lookup(raw, list(parts))
        if not exists or observed != expected or type(observed) is not type(expected):
            raise ValueError('AAA-02 proof does not match the supplied document')
        evidence.append(Evidence(json_pointer='/'+'/'.join(parts), observed_value=observed))
    if not required:
        reason = 'Explicitly excluded by the audit profile.'
    elif status == AuditStatus.PASS:
        reason = ('A declared centralized AAA login chain is established for at least one observed '
                  'VTY range: VTY association, login method list, prioritized group method, server '
                  'group and declared member server. Exhaustive VTY coverage, server reachability, '
                  'shared-secret validity, fallback behaviour and effective authentication are not '
                  'checked. Document origin is not authenticated.')
    elif status == AuditStatus.FAIL:
        reason = ('AAA is explicitly disabled, so no VTY range can use a centralized AAA login '
                  'chain. This is the only negative the rule establishes from a non-exhaustive '
                  'document.')
    else:
        reason = (detail + ' Missing, null, invalidated or ambiguous data do not prove exhaustive '
                  'absence; V1 exports no verifiable completeness proof. '
                  'Document origin is not authenticated.')
    return Finding(check_id='AAA-02',
                   title='Centralized AAA login chain declared for an observed VTY range',
                   status=status, severity='high', reason=reason, evidence=evidence,
                   recommendation=('Reference a declared login method list from the VTY range whose '
                       'first method is a named RADIUS/TACACS+ server group with declared member '
                       'servers; separately verify reachability, shared-secret validity and '
                       'fallback operationally.'),
                   references=[Reference.model_validate(r) for r in mapping.get('AAA-02',[])])


def audit_normalized(normalized_document, *, require_aaa=True, require_ssh=True, require_syslog=True,
                     require_aaa02=True):
    """Accept a contract dict, RouterContractV1, or JSON file path.

    Omitted optional facts are unknown, never N/A. N/A requires explicit profile
    exclusion. The function never mutates input or reads raw Cisco configuration.
    AAA-02 has its own profile switch: disabling AAA-01 does not disable it.
    """
    if any(type(value) is not bool for value in (require_aaa, require_ssh, require_syslog, require_aaa02)):
        raise TypeError('Profile requirements must be booleans')
    if isinstance(normalized_document, (str, Path)):
        raw = json.loads(Path(normalized_document).read_text(encoding='utf-8-sig'),
                         object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    elif isinstance(normalized_document, RouterContractV1):
        raw = normalized_document.model_dump(mode='json')
    else:
        raw = normalized_document
    # Literal[1,2] may coerce bool/float/string inputs: enforce the original fact.
    present, version = _lookup(raw, ['system','management','ssh','version'])
    if present and version is not None and type(version) is not int:
        raise ValueError('SSH version requires an integer fact')
    model = RouterContractV1.model_validate(raw)
    ssh = model.system.management.ssh
    if ssh.version_setting == 'removed' and ssh.version is not None:
        raise ValueError('Removed SSH version cannot carry a configured version')
    mapping = json.loads((Path(__file__).parent/'mappings'/'verified_references.json').read_text(encoding='utf-8'))
    findings = []
    specs = [
        ('AAA-01','AAA framework enabled','critical',['system','aaa','enabled'],model.system.aaa.enabled,require_aaa,management.aaa01,
         'Enable AAA using the approved management access policy.'),
        ('SSH-01','SSH version 2 configured','high',['system','management','ssh','version'],ssh.version,require_ssh,management.ssh01,
         'Explicitly configure SSH version 2 when SSH is required.'),
        ('LOG-01','Remote syslog destination declared','high',['system','logging','destinations'],model.system.logging.destinations,require_syslog,logging.log01,
         'Configure an approved remote syslog destination using the platform-supported logging host command; separately verify delivery operationally.'),
    ]
    for check_id,title,severity,parts,value,required,evaluator,recommendation in specs:
        index = None
        if check_id == 'LOG-01':
            status, index = evaluator(value) if required else (AuditStatus.NOT_APPLICABLE, None)
            if status == AuditStatus.PASS:
                if type(index) is not int or value is None or not 0 <= index < len(value):
                    raise ValueError('LOG-01 proof index is invalid')
                parts = parts + [str(index), 'address']
        else:
            status = evaluator(value) if required else AuditStatus.NOT_APPLICABLE
        exists, observed = _lookup(raw, parts)
        if check_id == 'LOG-01' and status == AuditStatus.PASS:
            if not exists or not isinstance(observed, str) or observed != value[index].address:
                raise ValueError('LOG-01 proof does not match the supplied document')
        admissible = exists and (check_id != 'LOG-01' or required and (index is not None or observed is None))
        evidence = [Evidence(json_pointer='/'+'/'.join(parts),observed_value=observed)] if admissible else []
        reason = ('Explicitly excluded by the audit profile.' if not required else
                  'Fact unknown or omitted; configuration defaults are not inferred.' if status == AuditStatus.NEEDS_REVIEW else
                  'Established normalized fact satisfies the rule.' if status == AuditStatus.PASS else
                  'Established normalized fact violates the rule.')
        if check_id == 'LOG-01' and required:
            reason = ('An interpretable remote syslog destination is declared in the normalized document. '
                      'Document origin is not authenticated; delivery is not checked.' if status == AuditStatus.PASS else
                      'No interpretable remote destination can be established. Missing, null, empty or ambiguous '
                      'data do not prove exhaustive absence; V1 exports no verifiable completeness proof. '
                      'Document origin is not authenticated.')
        findings.append(Finding(check_id=check_id,title=title,status=status,severity=severity,
                        reason=reason,evidence=evidence,recommendation=recommendation,
                        references=[Reference.model_validate(r) for r in mapping.get(check_id,[])]))
    findings.append(_aaa02_finding(model, raw, mapping, require_aaa02))
    return AuditReport(profile={'require_aaa':require_aaa,'require_ssh':require_ssh,'require_syslog':require_syslog,
                                'require_aaa02':require_aaa02},findings=findings,
                       counts={s.value:sum(f.status==s for f in findings) for s in AuditStatus})
