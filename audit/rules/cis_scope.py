"""Configuration proof boundaries shared by Level 1 evaluators.

Only normalized values are inspected. A partial inventory may prove a negative
witness, but cannot prove a universal positive or the absence of a target.
"""
from ..models import AuditStatus as S
import re

UNIVERSAL = frozenset({
    '1.1.4', '1.1.5', '1.1.6', '1.2.1', '1.2.2', '1.2.5',
    '1.2.8', '1.2.9', '1.2.10', '1.4.3', '1.5.2', '1.5.3',
    '1.5.4', '1.5.5',
})

LINE_TARGETS = {
    '1.1.4': 'con', '1.1.5': 'tty', '1.1.6': 'vty', '1.2.2': 'vty',
    '1.2.3': 'aux', '1.2.5': 'vty', '1.2.6': 'aux', '1.2.7': 'con',
    '1.2.8': 'tty', '1.2.9': 'vty', '1.2.10': 'vty', '1.2.11': 'aux',
}


def target_lines(raw,kind):
    """Validate normalized native identities; never infer a device inventory."""
    system=dict.get(raw,'system') or {}
    management=dict.get(system,'management') or {}
    result=[]
    for i,line in enumerate(dict.get(management,'lines') or []):
        name=line.get('name') or ''
        match=re.fullmatch(r'(con|console|aux|tty|vty) ([0-9]+)(?: ([0-9]+))?',name)
        if not match or match[1] not in ({'con','console'} if kind=='con' else {kind}):continue
        if kind in ('con','aux'):
            if match[2]!='0' or match[3] is not None:continue
        else:
            first=match[2].lstrip('0') or '0';last=(match[3] or match[2]).lstrip('0') or '0'
            if (len(first),first)>(len(last),last):continue
        result.append((i,line))
    return result


def applicability(control_id, raw, context, status):
    """Classify Level-1 scope independently from compliance.

    A known IOS/IOS-XE global benchmark scope is applicable even when its
    predicate is indeterminate. Hardware-backed line targets remain unknown
    when they are not observed. SNMP community controls can be not applicable
    only after a qualified negative community inventory.
    """
    if status == S.NOT_APPLICABLE:
        return 'NOT_APPLICABLE'
    if control_id in LINE_TARGETS:
        return ('APPLICABLE' if target_lines(raw, LINE_TARGETS[control_id])
                else 'APPLICABILITY_UNKNOWN')
    if control_id == '1.5.1':
        return 'APPLICABILITY_UNKNOWN'
    if control_id == '1.5.10':
        users=((raw.get('system') or {}).get('snmp') or {}).get('users') or []
        return ('APPLICABLE' if any(user.get('version') == '3' for user in users)
                else 'APPLICABILITY_UNKNOWN')
    if control_id == '3.1.4' and status == S.NEEDS_REVIEW:
        # The configuration exposes per-interface uRPF mode, not the business
        # classification "external or high risk" used by this control.
        return 'APPLICABILITY_UNKNOWN'
    if control_id.startswith('1.5.'):
        snmp=((raw.get('system') or {}).get('snmp') or {})
        observed=any(snmp.get(field) for field in
                     ('communities','groups','users','hosts','views','trap_config'))
        if observed:
            return 'APPLICABLE'
        effective=context if hasattr(context,'qualifies') else None
        if control_id in ('1.5.2','1.5.3','1.5.4','1.5.5','1.5.6') and effective and effective.qualifies(family='snmp_communities'):
            return 'NOT_APPLICABLE'
        return 'APPLICABILITY_UNKNOWN'
    return ('APPLICABLE' if getattr(context,'platform_family',None) in ('ios','iosxe')
            else 'APPLICABILITY_UNKNOWN')


def before(control_id, raw):
    system = raw.get('system') or {}
    parts = ['system', 'management', 'lines']
    if control_id in LINE_TARGETS:
        target = LINE_TARGETS[control_id]
        observed = target_lines(raw,target)
        if not observed:
            return S.NEEDS_REVIEW, parts, 'No observed target line; absence and inapplicability are not established'
        for index, line in observed:
            # Keep collective VTY evidence contextual; no unique responsibility
            # is inferred from a collection's JSON Pointer.
            if control_id in ('1.1.4', '1.1.5', '1.1.6'):
                method = (line.get('authentication') or {}).get('method')
                if method is not None and method != 'aaa':
                    return S.FAIL, parts, 'An observed management line explicitly uses non-AAA authentication'
            if control_id in ('1.2.6', '1.2.7', '1.2.8', '1.2.9', '1.2.10'):
                timeout = line.get('idle_timeout_seconds')
                if timeout is not None and (timeout == 0 or timeout > 600):
                    return S.FAIL, parts, 'An observed management line explicitly disables the idle timeout or exceeds 600 seconds'
    if control_id in ('1.2.1', '1.4.3'):
        users = (system.get('aaa') or {}).get('local_users') or []
        for index, user in enumerate(users):
            path = ['system', 'aaa', 'local_users', str(index)]
            if control_id == '1.2.1':
                privilege = user.get('privilege_level')
                if privilege is not None and privilege != 1:
                    return S.FAIL, path + ['privilege_level'], 'An observed local user has explicit privilege different from 1'
            else:
                category = (user.get('credential_type') or '').partition(':')[0]
                if category == 'password' or user.get('nopassword') is True or user.get('credential_configured') is False:
                    key = 'credential_type' if category == 'password' else 'nopassword' if user.get('nopassword') is True else 'credential_configured'
                    return S.FAIL, path + [key], 'An observed local user explicitly lacks a secret credential'
    if control_id == '1.5.4':
        for index, community in enumerate((system.get('snmp') or {}).get('communities') or []):
            if community.get('access') == 'rw':
                return S.FAIL, ['system', 'snmp', 'communities', str(index), 'access'], 'RW community found (community string redacted)'
    return None


def after(control_id, result, *, raw=None, evidence=None):
    status, parts, detail = result
    family={'1.1.2':'aaa_login','1.1.3':'aaa_enable','1.2.1':'local_users','1.4.3':'local_users',
            '1.5.4':'snmp_communities','1.5.8':'snmp_notifications','2.2.7':'logging_source'}.get(control_id)
    if control_id in LINE_TARGETS:
        # Coverage is property-specific: unrelated ACL syntax must not revoke
        # an explicit AUX no-exec/input-none fact. EXEC has no coverage family.
        prop=('auth' if control_id.startswith('1.1.') else
              'timeout' if control_id in ('1.2.6','1.2.7','1.2.8','1.2.9','1.2.10') else
              'transport' if control_id in ('1.2.2','1.2.11') else
              'acl' if control_id=='1.2.5' else None)
        family=f'line_{LINE_TARGETS[control_id]}_{prop}' if prop else None
    if status == S.PASS and family is not None and raw is not None:
        from ..configuration_facts import relevant_coverage_gap
        from ..resolvers.effective_configuration import configuration_evidence
        if relevant_coverage_gap(raw,configuration_evidence(evidence),family):
            return S.NEEDS_REVIEW,parts,'Relevant configuration command coverage is incomplete; an unrecognized or semantically unresolved command prevents a positive claim. '+detail
    if control_id in ('1.1.5', '1.2.8') and status == S.PASS:
        return S.NEEDS_REVIEW, parts, (
            'Observed TTY ranges satisfy the configured predicate, but a complete running-config does not establish the physical TTY inventory; '
            'hardware inventory or show line evidence is required for a universal positive result. ' + detail)
    if control_id in UNIVERSAL and status == S.PASS:
        from ..resolvers.effective_configuration import effective_context
        context=effective_context(evidence)
        if context is not None and context.qualifies(family=family):
            return result
        return S.NEEDS_REVIEW, parts, ('Observed values satisfy the configured predicate, but the complete target inventory is unknown; '
                                      'a universal PASS is not established. ' + detail)
    return result
