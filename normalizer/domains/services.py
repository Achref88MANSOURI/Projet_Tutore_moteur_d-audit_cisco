"""Identity, AAA, management lines, NTP, syslog and system services."""
from ipaddress import ip_address
from schemas import normalized_config as s
from normalizer.common.validation import boolean


def handle(state,r):
    rule, v, line = (r['rule'], r['values'], r['source_line'])
    if rule in ('services_ntp_source','services_logging_trap'):
        state.defer(r)
        return
    system = state.c.system
    if rule == 'services_hostname':
        state.assign(system, 'hostname', v['hostname'], 'system', line)
    elif rule == 'services_version':
        state.structural.add(line)
    elif rule in ('services_domain', 'services_domain_alt'):
        state.assign(system, 'domain_name', v['domain'], 'system', line)
    elif rule == 'services_dns':
        values = [str(ip_address(value)) for value in v['addresses'].split()]
        for value in values:
            system.dns_servers.append(value)
            state.bind(f'system/dns_servers/{len(system.dns_servers) - 1}', line)
    elif rule.startswith('services_ntp') and rule != 'services_ntp_source':
        system.ntp_servers.append(s.NTPServer(address=v['address'], prefer=True if rule.endswith('prefer') else None, network_instance=v.get('vrf')))
        state.bind(f'system/ntp_servers/{len(system.ntp_servers) - 1}', line)
    elif rule in ('services_logging', 'services_logging_legacy'):
        system.syslog_destinations.append(s.SyslogDestination(address=v['address']))
        state.bind(f'system/syslog_destinations/{len(system.syslog_destinations) - 1}', line)
    elif rule in ('services_aaa_on', 'services_aaa_off'):
        state.assign(system.aaa, 'enabled', boolean(v['enabled']), 'system/aaa', line)
    elif rule.startswith('services_user') and v['credential_type'] in ('secret', 'password'):
        system.aaa.local_users.append(s.UserAccount(username=v['username'], privilege_level=v.get('privilege'), credential_configured=True, credential_type=v['credential_type'] + ':' + v['credential_format']))
        state.bind(f'system/aaa/local_users/{len(system.aaa.local_users) - 1}', line)
    elif rule.startswith('services_snmp_community') and v['access'].lower() in ('ro', 'rw'):
        system.snmp.communities.append(s.SNMPCommunity(name='[REDACTED]', access=v['access'].lower(), access_list=v.get('acl')))
        state.bind(f'system/snmp/communities/{len(system.snmp.communities) - 1}', line)
    elif rule in ('services_snmp_location', 'services_snmp_contact'):
        state.assign(system.snmp, 'location' if rule.endswith('location') else 'contact', v['value'], 'system/snmp', line)
    elif rule == 'services_ssh_version':
        state.assign(system.management, 'ssh_version', v['version'], 'system/management', line)
    elif rule in ('services_http_on', 'services_http_off', 'services_https_on', 'services_https_off'):
        state.assign(system.management, 'https_enabled' if 'https' in rule else 'http_enabled', boolean(v['enabled']), 'system/management', line)
    elif rule in ('services_transport', 'services_timeout', 'services_timeout_minutes', 'services_access_class', 'services_login', 'services_login_plain'):
        entry = state.entity(line)
        if not entry or not isinstance(entry[0], s.ManagementLine):
            return
        item, path = entry
        if rule == 'services_transport':
            tokens = v['transports'].split()
            if any((x not in ('ssh', 'telnet', 'none', 'all') for x in tokens)):
                return
            if ('all' in tokens or 'none' in tokens) and len(tokens) != 1:
                return
            state.assign(item, 'allowed_transports', [] if tokens == ['none'] else tokens, path, line)
        elif rule.startswith('services_timeout'):
            seconds = v.get('seconds', 0)
            if not 0 <= seconds <= 59:
                raise ValueError('Invalid timeout')
            state.assign(item, 'idle_timeout_seconds', v['minutes'] * 60 + seconds, path, line)
        elif rule == 'services_access_class' and v['direction'] == 'in':
            state.assign(item, 'access_list', v['acl'], path, line)
        elif rule == 'services_login':
            state.assign(item, 'authentication', authentication(v['method']), path, line)
        elif rule == 'services_login_plain':
            state.assign(item, 'authentication', s.Authentication(method='line_password'), path, line)
    elif rule in ('services_auth_address', 'services_auth_ports'):
        entry = state.entity(line)
        if not entry or entry[0] is not None:
            return
        _, protocol = entry
        system.aaa.servers.append(s.AuthServer(protocol=protocol, address=v['address'], port=v.get('auth_port')))
        state.bind(f'system/aaa/servers/{len(system.aaa.servers) - 1}', line)
        if 'acct_port' in v:
            state.mapped.discard(line)
            state.consumed[line].clear()
    else:
        pass
    fields = {'services_login_logging': ('login_success_logging', 'enabled'), 'services_logging_source': ('syslog_source_interface', 'interface'), 'services_console_off': ('console_logging', 'enabled'), 'services_source_route_off': ('source_routing', 'enabled'), 'services_lookup_off': ('dns_lookup_enabled', 'enabled'), 'services_password_encryption_off': ('password_encryption_service', 'enabled'), 'services_ipv6_routing': ('ipv6_unicast_routing', 'enabled')}
    if r['rule'] in fields:
        field, key = fields[r['rule']]
        state.assign(state.c.system, field, r['values'][key], 'system', r['source_line'], list(r['values']))
    v = r['values']
    line = r['source_line']
    rule = r['rule']
    if rule.startswith('services_timestamp'):
        obj = s.TimestampPolicy(category=v['category'], format=v['format'], options=v.get('options', '').split())
        state.c.system.timestamps.append(obj)
        if 'options' in v:
            state.validation[line]['fields']['options'] = 'validated'
        state.bind('system/timestamps', line, list(v))
    elif rule == 'services_banner':
        state.c.system.banners.append(s.Banner(type=v['type']))
        state.bind('system/banners', line, list(v))
    elif rule == 'services_http_auth':
        state.assign(state.c.system, 'http_authentication', v['method'], 'system', line, list(v))
    elif rule.startswith('services_line_'):
        root = state.root(r)
        if root is None or root['rule'] != 'services_line':
            return
        obj = next((o for o in state.c.system.management.lines if o.name == root['values']['name']))
        path = f'system/management/lines/{state.c.system.management.lines.index(obj)}'
        pair = {'services_line_synchronous': ('logging_synchronous', 'enabled'), 'services_line_privilege': ('privilege_level', 'level'), 'services_line_stopbits': ('stopbits', 'bits'), 'services_line_length': ('screen_length', 'length')}.get(rule)
        if pair:
            state.assign(obj, pair[0], v[pair[1]], path, line, list(v))
        elif rule == 'services_line_preferred':
            tokens = v['transports'].split()
            if any((t not in ('none', 'all', 'ssh', 'telnet') for t in tokens)):
                raise ValueError('Transport protocol')
            state.assign(obj, 'preferred_transports', tokens, path, line, list(v))
    elif rule == 'services_community_expanded':
        obj = next((c for c in state.c.cisco.community_lists if c.name == v['name']), None)
        if obj is None:
            obj = s.CommunityList(name=v['name'],dialect='cisco_expanded_regex')
            state.c.cisco.community_lists.append(obj)
        obj.entries.append(s.CommunityListEntry(action=v['action'], expression=v['expression']))
        state.bind(f'cisco/community_lists/{state.c.cisco.community_lists.index(obj)}', line, list(v))
    elif rule == 'services_flow_source':
        state.assign(state.c.system.flow_export, 'source_interface', v['interface'], 'system/flow_export', line, list(v))
    elif rule == 'services_flow_version':
        state.c.system.flow_export.version = v['version']
        state.c.system.flow_export.as_mode = v['as_mode']
        state.bind('system/flow_export', line, list(v))
    elif rule == 'services_flow_timeout':
        field = {'active': 'cache_timeout_active_minutes', 'inactive': 'cache_timeout_inactive_seconds'}.get(v['type'])
        if field is None:
            raise ValueError('Flow timeout mode')
        state.assign(state.c.system.flow_export, field, v['timeout'], 'system/flow_export', line, list(v))



def declare(state,r):
    rule,v,line=r['rule'],r['values'],r['source_line']
    if rule == 'services_line':
        item = s.ManagementLine(name=v['name'])
        state.c.system.management.lines.append(item)
        path = f'system/management/lines/{len(state.c.system.management.lines) - 1}'
        state.entities[line] = path
        state.bind(path + '/name', line)
        return True
    if rule in ('services_tacacs', 'services_radius'):
        state.entities[line] = (None, 'tacacs' if rule == 'services_tacacs' else 'radius')
        return True
    return False


def authentication(value):
    if value=='local':return s.Authentication(method='local')
    if value.startswith('authentication '):return s.Authentication(method='aaa',method_list=value[len('authentication '):])
    return None


def resolve(state,r):
    line=r['source_line'];v=r['values']
    if r['rule']=='services_ntp_source':
        for i,obj in enumerate(state.c.system.ntp_servers):
            state.assign(obj,'source_interface',v['source'],f'system/ntp_servers/{i}',line)
    elif r['rule']=='services_logging_trap':
        for i,obj in enumerate(state.c.system.syslog_destinations):
            state.assign(obj,'severity',v['severity'],f'system/syslog_destinations/{i}',line)
