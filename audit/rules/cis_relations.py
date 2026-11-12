"""Configuration-only relational predicates over canonical V1 facts.

No CLI recognition, new trust flags, or completeness inference is performed.
Negative witnesses precede unknown facts; complete inventories remain external.
"""
from schemas.router_contract_v1 import AAA
from ..models import AuditStatus as S
from .aaa_central import resolve_group
from collections import Counter
from ipaddress import ip_address, ip_interface


def section(raw,*path):
    value=raw
    for key in path:value=dict.get(value,key) if isinstance(value,dict) else None
    return value


def accounting_lists(raw,service,level=None,context=None):
    """Declared default accounting chain, not receipt or complete application."""
    aaa=AAA.model_validate(section(raw,'system','aaa') or {})
    active=['system','aaa','enabled'];base=['system','aaa','accounting_method_lists']
    if aaa.enabled is False:
        return S.FAIL,active,'AAA is explicitly disabled; dependent accounting is not established'
    candidates=[(i,m) for i,m in enumerate(aaa.accounting_method_lists or [])
                if m.service==service and m.privilege_level==level]
    for i,item in candidates:
        if item.name=='default' and item.local_setting!='removed' and item.accounting_mode=='none':
            return S.FAIL,base+[str(i),'accounting_mode'],'Default accounting is explicitly disabled with none'
    if aaa.enabled is not True:
        return S.NEEDS_REVIEW,active,'AAA activation is unknown; no platform default is inferred'
    if any(m.name!='default' and m.local_setting!='removed' for _,m in candidates):
        return S.NEEDS_REVIEW,base,'Named accounting-list application and overrides are not fully established'
    for li,line in enumerate(section(raw,'system','management','lines') or []):
        for bi,binding in enumerate(line.get('accounting_'+service) or []):
            if service=='commands' and binding.get('privilege_level') not in (None,level):
                continue
            if binding.get('method_list')!='default':
                pointer=['system','management','lines',str(li),'accounting_'+service,str(bi),'method_list']
                return S.NEEDS_REVIEW,pointer,'An observed line accounting override is not established by the default list'
    defaults=[(i,m) for i,m in candidates if m.name=='default']
    if len(defaults)!=1:
        from ..resolvers.effective_configuration import effective_context
        effective=effective_context(context)
        if not defaults and effective is not None and effective.qualifies(
                family='aaa_accounting_'+service):
            return S.FAIL,base,(
                f'No default {service} accounting list exists in the qualified '
                'complete accounting-command inventory')
        return S.NEEDS_REVIEW,base,'A unique configured default accounting list is not established'
    index,item=defaults[0];path=base+[str(index)]
    if item.local_setting=='removed':
        return S.FAIL,path,'The required default accounting list is explicitly removed'
    if item.accounting_mode not in ('start-stop','stop-only') or not item.methods:
        return S.NEEDS_REVIEW,path,'Accounting list content is unknown or outside the verified modes'
    proof=[active,path+['accounting_mode']]
    for i,method in enumerate(item.methods):
        if method.method!='group':
            return S.NEEDS_REVIEW,path+['methods',str(i)],'Accounting method has no verified remote recording dependency'
        resolved,reason=resolve_group(aaa,method,allow_generic=True)
        if resolved is None:return S.NEEDS_REVIEW,path+['methods',str(i)],reason
        gi,mi,si=resolved
        proof.extend([path+['methods',str(i),'method'],['system','aaa','servers',str(si),'address']])
        if gi is not None:proof.append(['system','aaa','server_groups',str(gi),'name'])
    return S.PASS,proof,'Default accounting mode and declared server references are configured; full override coverage and receipt of records are not certified'


def snmp_privacy(raw,context=None):
    base=['system','snmp','groups'];groups=section(raw,*base) or []
    v3=[]
    for i,group in enumerate(groups):
        if group.get('version')!='v3':continue
        v3.append(i)
        if group.get('security_level') in ('auth','noauth'):
            return S.FAIL,base+[str(i),'security_level'],'An observed SNMPv3 group explicitly omits privacy'
        if group.get('security_level')!='priv':
            return S.NEEDS_REVIEW,base+[str(i),'security_level'],'An observed SNMPv3 group has an unresolved security level'
    from ..resolvers.effective_configuration import effective_context
    effective=effective_context(context)
    if v3 and effective is not None and effective.qualifies(family='snmp_groups'):
        return S.PASS,[base+[str(i),'security_level'] for i in v3],(
            'Every SNMPv3 group in the qualified complete group-command inventory '
            'explicitly uses privacy; user availability and operational SNMP state are not certified')
    if v3:
        return S.NEEDS_REVIEW,[base+[str(i),'security_level'] for i in v3],(
            'Observed SNMPv3 groups use privacy, but complete group-command coverage is not established')
    if effective is not None and effective.qualifies(family='snmp_groups'):
        return S.NOT_APPLICABLE,base,(
            'No SNMPv3 group exists in the qualified complete group-command inventory; '
            'this per-group privacy control has no target and no vacuous PASS is claimed')
    return S.NEEDS_REVIEW,base,(
        'No SNMPv3 group is observed; absence does not establish applicability or a vacuous positive result')


def ntp_server_keys(raw,context=None):
    base=['system','ntp'];ntp=section(raw,*base) or {}
    servers=[(i,s) for i,s in enumerate(ntp.get('servers') or []) if s.get('association_type')=='server']
    from ..resolvers.effective_configuration import effective_context
    effective=effective_context(context)
    qualified=bool(effective and effective.qualifies(family='ntp_servers'))
    if not servers:
        if qualified:
            return S.NOT_APPLICABLE,base+['servers'],(
                'No NTP server exists in the qualified complete server-command inventory; '
                'this per-server key-association control has no target. CIS 2.3.2 separately '
                'evaluates the requirement to configure an NTP server')
        return S.NEEDS_REVIEW,base+['servers'],'No established server association inventory; peer is a different association type'
    proof=[]
    for i,server in servers:
        pointer=base+['servers',str(i),'key_id'];identifier=server.get('key_id')
        if identifier is None:
            return (S.FAIL if qualified else S.NEEDS_REVIEW),pointer,(
                'An NTP server in the qualified complete server-command inventory has no key association'
                if qualified else
                'Server key association is not established and complete server-command coverage is unavailable')
        proof.append(pointer)
    if qualified:
        return S.PASS,proof,(
            'Every declared NTP server in the qualified complete server-command inventory '
            'contains a key identifier; key definition and trusted-key status are evaluated '
            'by the separate CIS 2.3.1.2 and 2.3.1.3 predicates')
    return S.NEEDS_REVIEW,proof,(
        'Observed NTP servers contain key identifiers, but complete server-command coverage '
        'is not established; key definition and trust are separate predicates')


def assess_method_list(aaa,item,service,index):
    base=['system','aaa','authentication_method_lists',str(index)]
    if item.local_setting=='removed' or not item.methods:return S.NEEDS_REVIEW,[base],'Method-list content is removed or unknown'
    paths=[base]
    for i,m in enumerate(item.methods):
        if m.method=='none':return S.FAIL,[base+['methods',str(i),'method']],'Declared authentication permits unauthenticated access via none'
    groups=[(i,m) for i,m in enumerate(item.methods) if m.method=='group']
    fallback='local' if service=='login' else 'enable'
    if groups:
        if any(m.method in ('local','local-case') for m in item.methods[:groups[0][0]]):
            return S.NEEDS_REVIEW,paths,'Local-first network fallback policy is not established by the available benchmark text'
        if not any(m.method==fallback for m in item.methods[groups[-1][0]+1:]):
            return S.FAIL,paths,'The declared centralized chain lacks the fallback required by the scoped catalogue predicate'
        for i,m in groups:
            resolved,missing=resolve_group(aaa,m,allow_generic=True)
            if resolved is None:return S.NEEDS_REVIEW,paths,missing
            gi,mi,si=resolved
            paths.extend([base+['methods',str(i),'method'],['system','aaa','servers',str(si),'address']])
            if gi is not None:paths.extend([['system','aaa','server_groups',str(gi),'name'],['system','aaa','server_groups',str(gi),'servers',str(mi),'name']])
    elif not any(m.method in (('local','local-case') if service=='login' else ('enable',)) for m in item.methods):
        return S.NEEDS_REVIEW,paths,'Declared method requires an unverified authentication dependency'
    return S.PASS,paths,'Declared authentication methods and references are established; effective authentication, credentials and reachability are not certified'


def authentication_lists(raw,service):
    aaa=AAA.model_validate(section(raw,'system','aaa') or {})
    active=['system','aaa','enabled'];base=['system','aaa','authentication_method_lists']
    if aaa.enabled is False:return S.FAIL,active,'AAA new-model is explicitly disabled; dependent authentication is not enabled'
    candidates=[(i,item) for i,item in enumerate(aaa.authentication_method_lists or []) if item.service==service and (service!='enable' or item.name=='default')]
    referenced={(line.get('authentication') or {}).get('method_list') for line in section(raw,'system','management','lines') or []}
    positives=[];unknown=[]
    identities=Counter((m.name,m.service,m.privilege_level) for _,m in candidates)
    for i,item in candidates:
        if identities[(item.name,item.service,item.privilege_level)]!=1:
            unknown.append(([[*base,str(i)]],'Method-list identity is ambiguous; no unique current declaration is established'))
            continue
        status,paths,reason=assess_method_list(aaa,item,service,i)
        if status==S.FAIL and (item.name=='default' or item.name in referenced):return status,paths,reason
        if status==S.PASS:positives.append((paths,reason))
        else:unknown.append((paths,reason))
    if aaa.enabled is not True:return S.NEEDS_REVIEW,active,'AAA activation is unknown; a list declaration alone cannot establish dependent authentication'
    if positives:
        paths,reason=positives[0];return S.PASS,paths+[active],reason
    if unknown:return S.NEEDS_REVIEW,unknown[0][0],unknown[0][1]
    return S.NEEDS_REVIEW,base,'No usable declared authentication list is established; absence is not exhaustive'


def authentication_lines(raw,kind,context=None):
    from .cis_scope import target_lines
    lines=target_lines(raw,kind)
    base=['system','management','lines']
    if not lines:return S.NEEDS_REVIEW,base,'Target management-line inventory is unknown'
    aaa=AAA.model_validate(section(raw,'system','aaa') or {})
    unknown=False;proof=[];inherited_default=False
    for i,line in lines:
        p=base+[str(i)];auth=line.get('authentication') or {}
        if line.get('login_disabled') is True:return S.FAIL,p+['login_disabled'],'An observed line explicitly disables login authentication'
        if auth.get('method') is not None and auth.get('method')!='aaa':return S.FAIL,p+['authentication','method'],'An observed line explicitly uses non-AAA login authentication'
        if aaa.enabled is False:return S.FAIL,['system','aaa','enabled'],'AAA is explicitly disabled for the observed line association'
        if auth.get('method')!='aaa' or not auth.get('method_list'):
            defaults=[(j,m) for j,m in enumerate(aaa.authentication_method_lists or [])
                      if m.name=='default' and m.service=='login' and m.privilege_level is None]
            if aaa.enabled is True and len(defaults)==1:
                status,paths,reason=assess_method_list(aaa,defaults[0][1],'login',defaults[0][0])
                if status==S.FAIL:return status,[p]+paths,reason
                if status==S.PASS:
                    inherited_default=True;proof.extend([p]+paths)
            unknown=True;continue
        hits=[(j,m) for j,m in enumerate(aaa.authentication_method_lists or []) if m.name==auth['method_list'] and m.service=='login' and m.privilege_level is None]
        if len(hits)!=1:unknown=True;continue
        status,paths,reason=assess_method_list(aaa,hits[0][1],'login',hits[0][0])
        if status==S.FAIL:return status,[p+['authentication','method_list']]+paths,reason
        if status!=S.PASS or aaa.enabled is not True:unknown=True
        proof.extend([p+['authentication','method_list']]+paths)
    if inherited_default:
        return S.NEEDS_REVIEW,proof or base,('The AAA default login list is effectively inherited by an observed line, but the local catalogue may require a literal line command; normative arbitration is required')
    if unknown:
        return S.NEEDS_REVIEW,proof or base,'An observed line association or dependency is unknown'
    return S.PASS,proof or base,('Every observed target line has an explicit AAA login association whose method-list dependencies resolve; '
                                 'server reachability and credentials are not certified')


def line_property(raw,kind,field,context=None):
    from .cis_scope import target_lines
    base=['system','management','lines'];observed=target_lines(raw,kind)
    unresolved=[];resolved=[]
    for i,line in observed:
        value=dict.get(line,field);path=base+[str(i),field]
        origin='explicit'
        if value is None and field=='idle_timeout_seconds':
            from ..resolvers.effective_configuration import effective_context
            effective=effective_context(context)
            setting=dict.get(line,'timeout_setting')
            default=(effective.default(600, rule='EXEC_TIMEOUT_DEFAULT_600_SECONDS',
                     reference_id='C02', qualification='IOS_IOSXE_LINE_EXEC_TIMEOUT',
                     family=f'line_{kind}_timeout', blocked=setting=='removed')
                     if effective is not None else None)
            if default is not None:
                value=default.value;origin=default.origin
        elif value is None and field=='exec_disabled':
            from ..resolvers.effective_configuration import effective_context
            effective=effective_context(context)
            default=(effective.default(False, rule='EXEC_ENABLED_BY_DEFAULT_ON_LINES',
                     reference_id='C21', qualification='IOS_IOSXE_LINE_EXEC',
                     family=f'line_{kind}_exec') if effective is not None else None)
            if default is not None:
                value=default.value;origin=default.origin
        if value is None:
            unresolved.append(path);continue
        if field=='exec_disabled':good=value is True
        elif field=='allowed_transports':good=value==[]
        else:good=0<value<=600
        if not good:
            detail=('The documented Cisco default violates the predicate'
                    if origin=='documented_default' else 'An observed target explicitly violates the configured predicate')
            return S.FAIL,path,detail
        resolved.append((path,origin))
    if unresolved:return S.NEEDS_REVIEW,unresolved[0],'The target property remains unknown; a reset, parser gap, or unqualified scope prevents use of a default'
    if resolved:
        defaults=any(origin=='documented_default' for _,origin in resolved)
        return S.PASS,resolved[0][0],('Every observed target resolves to 600 seconds or less, including documented default values (C02)'
                                     if defaults else 'Every observed target satisfies the configured predicate')
    return S.NEEDS_REVIEW,base,'The target property or its inventory is unknown'


def line_acls(raw,same_acl=False,context=None):
    from .cis_scope import target_lines
    base=['system','management','lines'];lines=target_lines(raw,'vty')
    refs=[];proof=[];acls=section(raw,'security','acls') or [];missing=[];unresolved=[]
    if not lines:
        return S.NEEDS_REVIEW,base,'No observed VTY target; target applicability is unknown'
    for i,line in lines:
        p=base+[str(i)]
        # Incoming and outgoing ACLs are independent. A projected outgoing
        # relation does not establish that incoming protection is absent.
        relations=dict.get(line,'access_classes')
        if relations is None:
            relations=[dict(family='ipv4',direction=dict.get(line,'access_list_direction'),name=dict.get(line,'access_list'),setting='configured')]
        incoming=[]
        for ri,relation in enumerate(relations):
            name=dict.get(relation,'name');family=dict.get(relation,'family')
            if not name or dict.get(relation,'setting')!='configured' or dict.get(relation,'direction')!='in':continue
            incoming.append((family,name))
            refs.append((family,name))
            hits=[(j,a) for j,a in enumerate(acls) if dict.get(a,'name')==name and dict.get(a,'family')==family and dict.get(a,'entries')]
            path=p+['access_classes',str(ri),'name'] if dict.get(line,'access_classes') is not None else p+['access_list']
            if len(hits)==1:proof.extend([path,['security','acls',str(hits[0][0]),'name']])
            else:unresolved.append(path)
        if not incoming:missing.append(p+['access_classes'])
    if same_acl and any(len({n for f,n in refs if f==family})>1 for family in ('ipv4','ipv6')):
        return S.FAIL,base,'Observed VTY groups explicitly use different inbound ACLs of the same address family; the catalogue rationale requires the same ACL'
    from ..resolvers.effective_configuration import effective_context
    effective=effective_context(context)
    qualified=bool(effective and effective.qualifies(family='line_vty_acl'))
    if missing:
        if not same_acl and qualified:
            return S.FAIL,missing[0],'An observed VTY target has no configured inbound access-class in the qualified complete configuration'
        return S.NEEDS_REVIEW,missing[0],('No inbound VTY association is observed; control 1.2.4 wording about creating an ACL versus using it remains normatively ambiguous'
                                         if same_acl else 'Inbound access-class absence is not proven for a complete qualified VTY scope')
    if unresolved:
        return S.NEEDS_REVIEW,unresolved[0],'The referenced inbound VTY ACL is absent, empty, duplicated or has the wrong address family'
    if any(not str(name).isdigit() for _,name in refs):
        return S.NEEDS_REVIEW,proof or base,'Inbound named ACL relations resolve, but named VTY access-class support depends on the unqualified IOS train'
    if proof and qualified:
        return S.PASS,proof,'Every observed VTY target references a unique populated inbound numbered ACL of the matching address family'
    return S.NEEDS_REVIEW,proof or base,'Resolved VTY ACL relations are observed, but complete qualified VTY command coverage is not established'


def snmp_acl(raw,existential=False,context=None):
    base=['system','snmp','communities'];communities=section(raw,*base) or [];acls=section(raw,'security','acls') or []
    from ..resolvers.effective_configuration import effective_context
    effective=effective_context(context)
    qualified=bool(effective and effective.qualifies(family='snmp_communities'))
    if not communities:
        if qualified:
            return S.NOT_APPLICABLE,base,'No v1/v2c community exists in the qualified complete inventory; SNMPv3 group ACLs are a distinct scope'
        return S.NEEDS_REVIEW,base,'No community is observed, but exhaustive v1/v2c community absence is not established'
    if not existential:
        for i,comm in enumerate(communities):
            if dict.get(comm,'acl_restriction')=='absent':
                return S.FAIL,base+[str(i),'acl_restriction'],'A complete recognized community declaration explicitly has no source ACL restriction; community value withheld'
    resolved=[];unresolved=[];missing=[]
    for i,comm in enumerate(communities):
        matched=False
        for field,family in (('access_list','ipv4'),('access_list_v6','ipv6')):
            ref=dict.get(comm,field)
            hits=[(j,a) for j,a in enumerate(acls) if dict.get(a,'name')==ref and dict.get(a,'family')==family]
            if ref and len(hits)==1 and any(dict.get(e,'action') in ('permit','deny') for e in dict.get(hits[0][1],'entries') or []):
                matched=True
                resolved.extend([base+[str(i),field],['security','acls',str(hits[0][0]),'name'],['security','acls',str(hits[0][0]),'family']])
        if not matched:
            target=base+[str(i),'acl_restriction']
            if dict.get(comm,'acl_restriction')=='absent':missing.append(target)
            else:unresolved.append(target)
    if existential and missing:
        if resolved:
            return S.NEEDS_REVIEW,missing[0],(
                'A populated ACL is associated with only part of the community inventory; '
                'the CIS audit title checks ACL creation while its rationale expects application to every community')
        return S.NEEDS_REVIEW,missing[0],(
            'No declared community is associated with a populated ACL; an unrelated ACL definition is not SNMP protection, '
            'but the CIS audit title and universal rationale require normative arbitration')
    if unresolved:
        return S.NEEDS_REVIEW,unresolved[0],'A community ACL reference or matching populated definition is unresolved'
    if resolved and qualified:
        return S.PASS,resolved,'Every declared community references a unique populated ACL of the matching address family'
    return S.NEEDS_REVIEW,resolved or base,'Community-to-ACL relations resolve, but complete qualified community inventory is not established'


def literal_remote(raw,address):
    """Configured literal witness, excluding known local interface addresses."""
    from .logging import _remote_address
    try:target=ip_address(address)
    except (ValueError,TypeError):return False
    if not _remote_address(str(target)):return False
    for interface in section(raw,'interfaces') or []:
        for family in ('ipv4','ipv6'):
            for item in section(interface,family,'addresses') or []:
                try:local=ip_interface(dict.get(item,'address')).ip
                except (ValueError,TypeError):continue
                if local==target:return False
    return True


def snmp_hosts(raw):
    base=['system','snmp','hosts'];snmp=section(raw,'system','snmp') or {}
    literal=[];dependencies=[]
    for i,host in enumerate(dict.get(snmp,'hosts') or []):
        if not literal_remote(raw,dict.get(host,'destination')):continue
        literal.append(i)
        identity=dict.get(host,'community_or_user');version=dict.get(host,'version')
        if not identity:
            dependencies.append((i,'notification identity is absent or redacted without a resolvable category'));continue
        proof=[base+[str(i),'destination'],base+[str(i),'type'],base+[str(i),'version']]
        if version=='3':
            requested=dict.get(host,'security_level')
            if requested not in ('noauth','auth','priv'):
                dependencies.append((i,'the declared SNMPv3 destination security level is unresolved'));continue
            proof.append(base+[str(i),'security_level'])
        elif version not in ('1','2c'):
            dependencies.append((i,'the notification version is unresolved'));continue
        # CIS 1.5.7 asks for a configured snmp-server host.  IOS can omit
        # SNMPv3 users from running-config, so a user/group/secret chain is
        # operational evidence, not a prerequisite for proving this command.
        # The identity value is deliberately not returned as evidence because
        # it can be a sensitive community in v1/v2c forms.
        return S.PASS,proof,('A literal traps/informs notification destination, version and declared identity are configured; '
                             'SNMPv3 user availability, authorization, reachability and delivery are not certified')
    if literal:
        index,reason=dependencies[0] if dependencies else (literal[0],'its notification identity dependency is unresolved')
        return S.NEEDS_REVIEW,base+[str(index),'destination'],f'A literal notification destination is declared, but {reason}; delivery is not certified'
    return S.NEEDS_REVIEW,base,'No resolved literal notification destination is established; omissions do not prove SNMP disabled or absent'


def traps(raw,context=None):
    base=['system','snmp','trap_config'];config=section(raw,*base) or {}
    enabled=dict.get(config,'enabled')
    if enabled is False:return S.FAIL,base+['enabled'],'SNMP notifications are explicitly disabled globally'
    negative=dict.get(config,'disabled_notification_types') or []
    types=set(dict.get(config,'notification_types') or [])
    generic=types & {'authentication','linkup','linkdown','coldstart','warmstart'}
    if enabled is True and generic:
        disabled=set(negative) & {'authentication','linkup','linkdown','coldstart','warmstart'}
        detail=('At least one generic SNMP notification type is explicitly enabled; '
                'other types are explicitly disabled, but the CIS audit procedure checks for configured notification values'
                if disabled else
                'At least one generic SNMP notification type is explicitly enabled as required by the CIS audit procedure')
        return S.PASS,base,detail+'; destination reachability and delivery are not certified'
    from ..resolvers.effective_configuration import effective_context
    effective=effective_context(context)
    if effective is not None and effective.qualifies(family='snmp_notifications'):
        return S.FAIL,base,('No positive snmp-server enable traps snmp declaration exists in the qualified complete configuration; '
                            'Cisco disables SNMP notifications by default')
    if negative:
        return S.NEEDS_REVIEW,base+['disabled_notification_types','0'],('A generic notification type is explicitly disabled, but complete positive notification '
                                                                       'coverage is not established for this input')
    return S.NEEDS_REVIEW,base,'No positive generic SNMP notification declaration is established'


def debug_timestamps(raw,context=None):
    base=['system','logging','timestamps']
    disabled = section(raw,'system','logging','timestamps_disabled') or []
    if 'debug' in disabled:
        return S.FAIL,['system','logging','timestamps_disabled',str(disabled.index('debug'))], 'Debug timestamps are explicitly disabled; no platform default is assumed'
    for i,item in enumerate(section(raw,*base) or []):
        if dict.get(item,'category')!='debug':continue
        if dict.get(item,'format')=='uptime':return S.FAIL,base+[str(i),'format'],'Debug timestamps explicitly use uptime instead of datetime'
        if dict.get(item,'format')=='datetime':
            return S.PASS,base+[str(i)],('Debug timestamps explicitly use datetime; msec, localtime and show-timezone are optional '
                                         'operands in the benchmark remediation rather than additional audit prerequisites')
    from ..resolvers.effective_configuration import effective_context
    effective=effective_context(context)
    if effective is not None:
        default=effective.default('uptime', rule='DEBUG_TIMESTAMP_UPTIME_BY_DEFAULT',
            reference_id='C09', qualification='IOS_IOSXE_DEBUG_TIMESTAMPS',
            family='timestamps_debug')
        if default.origin=='documented_default':
            return S.FAIL,base,'Debug timestamps use uptime rather than required datetime by documented default (C09)'
    return S.NEEDS_REVIEW,base,'Debug datetime is not established'


def logging_source(raw,context=None):
    base=['system','logging'];name=section(raw,*base,'source_interface');vrf=section(raw,*base,'source_vrf')
    matches=[(i,item) for i,item in enumerate(section(raw,'interfaces') or []) if dict.get(item,'name')==name]
    if len(matches)!=1:
        from ..resolvers.effective_configuration import effective_context
        effective=effective_context(context)
        if name is None and effective is not None:
            absent=effective.absent(rule='LOGGING_SOURCE_INTERFACE_PROVEN_ABSENT',
                reference_id='C07', qualification='IOS_IOSXE_SYSLOG_SOURCE',
                family='logging_source')
            if absent.origin=='proven_absent':
                return S.FAIL,base+['source_interface'],'Logging source-interface is absent in the qualified complete configuration (proven absence; C07)'
        return S.NEEDS_REVIEW,base+['source_interface'],'Logging source-interface is absent or not uniquely resolved'
    i,item=matches[0];proof=[base+['source_interface'],['interfaces',str(i),'kind']]
    kind=dict.get(item,'kind')
    if kind not in (None,'unknown','other','loopback'):return S.FAIL,proof,'The declared logging source is not a loopback as required by the scoped remediation'
    actual_vrf=dict.get(item,'vrf')
    if vrf is not None and actual_vrf is not None and vrf!=actual_vrf:return S.FAIL,[base+['source_vrf'],['interfaces',str(i),'vrf']],'Explicit logging and interface VRF identities conflict'
    if actual_vrf is not None and vrf is None:
        return S.NEEDS_REVIEW,proof+[base+['source_vrf'],['interfaces',str(i),'vrf']],'Logging VRF scope is unspecified for an explicitly VRF-bound source interface'
    if kind=='loopback' and (vrf is None or actual_vrf==vrf):
        for family in ('ipv4','ipv6'):
            for index,address in enumerate(section(item,family,'addresses') or []):
                try:parsed=ip_address(dict.get(address,'address'))
                except (ValueError,TypeError):continue
                if parsed.is_unspecified or parsed.is_multicast or parsed.is_loopback or parsed.is_link_local:continue
                if family=='ipv4' and dict.get(address,'secondary') is not False:continue
                return S.PASS,proof+[['interfaces',str(i),family,'addresses',str(index),'address']],'A usable fixed-address loopback is declared consistently; operational stability and delivery are not established'
    return S.NEEDS_REVIEW,proof,'A fixed-address loopback and compatible VRF are not fully established'
