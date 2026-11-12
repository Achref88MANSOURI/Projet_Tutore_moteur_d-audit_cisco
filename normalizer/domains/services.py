"""Identity, AAA, management lines, NTP, syslog and system services."""
from ipaddress import ip_address
from schemas import router_contract_v1 as s
from normalizer.common.collections import collection, owned_entries, publish_entries
from normalizer.common.validation import boolean
from . import aaa_administration, global_scalars


def handle(state, r):
    if r['rule'].startswith('services_ntp_trusted_key'):
        from normalizer.common.ntp_trust import update
        update(state, r)
        return
    rule, v, line = (r['rule'], r['values'], r['source_line'])
    if rule.startswith('services_snmp_community'):
        return snmp_community(state, r)
    if rule.startswith('services_snmp'):
        state.defer(r)
        return
    if rule == 'services_scalar_default':
        return global_scalars.reset(state, r)
    if rule.startswith('services_enable_secret'):
        return aaa_administration.enable_secret(state, r)
    if rule.startswith('services_enable_password'):
        return aaa_administration.enable_password(state, r)
    if rule.startswith('admin_') or rule in (
        'services_radius','services_tacacs',
        'services_tacacs_legacy_host', 'services_tacacs_legacy_host_key',
        'services_tacacs_legacy_host_key_format', 'services_tacacs_legacy_host_remove',
        'services_radius_source', 'services_radius_source_remove',
        'services_tacacs_source', 'services_tacacs_source_remove',
        'services_aaa_authentication_enable_remove',
        'services_ssh_version', 'services_auth_address', 'services_auth_ports',
        'services_ssh_timeout', 'services_ssh_timeout_remove',
        'services_ssh_version_remove', 'services_ssh_rsa_keypair',
        'services_ssh_version_default',
        'services_ssh_rsa_keypair_remove', 'services_ssh_source',
        'services_ssh_source_remove', 'services_ssh_pubkey_chain',
        'services_ssh_pubkey_chain_remove',
        'services_user', 'services_user_simple', 'services_user_no_format', 'services_user_privilege_no_format',
        'services_user_privilege', 'services_user_remove', 'services_user_algorithm', 'services_user_nopassword'):
        return aaa_administration.handle(state, r)

    if rule.startswith('services_transport') or rule.startswith('services_login') or rule.startswith('services_access_class') or rule.startswith('services_line_password') or rule in ('services_exec_on', 'services_exec_off', 'services_exec_default', 'services_line_preferred', 'services_line_synchronous', 'services_line_privilege', 'services_line_stopbits', 'services_line_length'):
        state.defer(r)
        return

    if rule in (
        'services_ntp_global_source', 'services_ntp_global_source_remove', 'services_logging_trap', 'services_logging_trap_remove',
        'services_ntp_authenticate', 'services_ntp_authenticate_remove',
        'services_ntp_auth_key', 'services_ntp_auth_key_format', 'services_ntp_auth_key_remove',
        'services_ntp_trusted_key', 'services_ntp_trusted_key_single', 'services_ntp_trusted_key_remove',
        'services_ntp_master', 'services_ntp_master_no_stratum', 'services_ntp_master_remove',
        'services_login_block', 'services_login_block_remove',
        'services_domain_lookup', 'services_domain_lookup_remove',
        'services_accounting_commands', 'services_accounting_connection', 'services_accounting_exec',
        'services_accounting_network', 'services_accounting_system',
        'services_line_accounting_commands', 'services_line_accounting_connection',
        'services_line_accounting_exec', 'services_line_accounting_system',
        'services_snmp_group_v3', 'services_snmp_group_v1_v2c', 'services_snmp_group_remove',
        'services_snmp_user_v3', 'services_snmp_user_v3_remote', 'services_snmp_user_remove',
        'services_snmp_host_v3', 'services_snmp_host_v3_vrf', 'services_snmp_host_traps', 'services_snmp_host_traps_vrf', 'services_snmp_host_traps_simple',
        'services_snmp_host_traps_v2c', 'services_snmp_host_informs_v2c',
        'services_snmp_host_implicit_v1', 'services_snmp_host_implicit_v1_vrf',
        'services_snmp_host_implicit_v1_vrf_alt', 'services_snmp_host_implicit_v1_udp_vrf',
        'services_snmp_host_implicit_version', 'services_snmp_host_implicit_version_vrf',
        'services_snmp_host_implicit_version_vrf_alt', 'services_snmp_host_implicit_version_udp_vrf',
        'services_snmp_host_traps_implicit', 'services_snmp_host_traps_implicit_vrf',
        'services_snmp_host_implicit_traps', 'services_snmp_host_implicit_traps_vrf',
        'services_snmp_host_informs', 'services_snmp_host_informs_vrf', 'services_snmp_host_informs_simple',
        'services_snmp_host_informs_implicit', 'services_snmp_host_informs_implicit_vrf',
        'services_snmp_host_informs_implicit_vrf_alt', 'services_snmp_host_informs_implicit_udp_vrf',
        'services_snmp_host_remove',
        'services_snmp_enable_traps', 'services_snmp_enable_traps_remove',
        'services_snmp_engineid', 'services_snmp_engineid_remove',
        'services_snmp_view', 'services_snmp_view_remove',
        'services_snmp_source_interface', 'services_snmp_source_interface_remove',
        'services_snmp_trap_source', 'services_snmp_trap_source_vrf', 'services_snmp_trap_source_remove',
        'services_snmp_server_enable', 'services_snmp_server_disable',
        'services_snmp_community_view_acl', 'services_snmp_community_view_acl_simple',
        'services_login', 'services_login_plain',
        'services_login_authentication_remove', 'services_login_authentication_remove_args',
        'services_banner', 'services_banner_remove',
        'services_banner_incoming', 'services_banner_incoming_remove',
        'services_line_exec_banner', 'services_line_exec_banner_remove',
        'services_line_motd_banner', 'services_line_motd_banner_remove',
        'services_source_route_on', 'services_source_route_off', 'services_source_route_reset',
        'services_ipv6_urpf_rx', 'services_ipv6_urpf_rx_params',
        'services_ipv6_urpf_any', 'services_ipv6_urpf_any_params',
        'services_ipv6_urpf_off', 'services_ipv6_urpf_reset',
        'services_cdp_run', 'services_cdp_run_off', 'services_cdp_run_default', 'services_cdp_enable', 'services_cdp_enable_off',
        'services_bootp_server', 'services_bootp_server_off', 'services_dhcp_bootp_ignore', 'services_dhcp_bootp_ignore_off',
        'services_dhcp', 'services_dhcp_off', 'services_ident', 'services_ident_off',
        'services_finger', 'services_finger_off', 'services_pad', 'services_pad_off',
        'services_tcp_keepalives_in', 'services_tcp_keepalives_in_off', 'services_tcp_keepalives_out', 'services_tcp_keepalives_out_off',
        'services_timeout', 'services_timeout_minutes', 'services_timeout_remove', 'services_timeout_default',
        'services_http_on', 'services_http_off', 'services_https_on', 'services_https_off'):
        state.defer(r)
        return

    system = state.c.system
    resets = {
        'services_aaa_default': (system.aaa, 'enabled', 'system/aaa'),
        'services_password_encryption_default': (system.ip_services, 'password_encryption_service', 'system/ip_services'),
    }
    if rule in resets:
        obj, field, path = resets[rule]
        setattr(obj, field, None)
        state.unbind(path + '/' + field)
        return  # A reset invalidates the explicit fact; it does not prove a default.
    global_fields = {
        'services_lookup_off': (system.dns, 'lookup_enabled', 'system/dns', 'enabled'),
        'services_ipv6_routing': (system.ip_services, 'ipv6_unicast_routing', 'system/ip_services', 'enabled'),
        'services_http_auth': (system.management.http, 'authentication', 'system/management/http', 'method'),
    }
    if rule in global_fields:
        if not r['context_lines']:
            obj, field, path, key = global_fields[rule]
            state.assign(obj, field, v[key], path, line)
        return
    if rule == 'services_community_expanded':
        if r['context_lines']:
            return
        items = collection(state.c.routing_policies, 'community_lists')
        obj = next((x for x in items if x.name == v['name']), None)
        if obj is None:
            obj = s.CommunityList(name=v['name'], dialect='cisco_expanded_regex')
            items.append(obj)
        collection(obj, 'entries').append(s.CommunityListEntry(action=v['action'], expression=v['expression']))
        state.validation[line]['fields']['expression'] = 'validated'
        state.bind(f'routing_policies/community_lists/{items.index(obj)}', line)
        return
    if rule in ('services_flow_source', 'services_flow_version', 'services_flow_timeout'):
        if r['context_lines']:
            return
        obj = system.flow_monitoring.export
        if obj is None:
            obj = s.FlowExport()
            system.flow_monitoring.export = obj
        path = 'system/flow_monitoring/export'
        if rule == 'services_flow_source':
            state.assign(obj, 'source_interface', v['interface'], path, line)
        elif rule == 'services_flow_version':
            # Validate the entire declaration before publishing either operand.
            candidate = s.FlowExport(version=v['version'], as_mode=v['as_mode'])
            state.assign(obj, 'version', candidate.version, path, line)
            state.assign(obj, 'as_mode', candidate.as_mode, path, line)
        else:
            field = {'active': 'cache_timeout_active_minutes', 'inactive': 'cache_timeout_inactive_seconds'}.get(v['type'])
            if field and v['timeout'] >= 1:
                state.assign(obj, field, v['timeout'], path, line)
        return
    if rule == 'services_hostname':
        state.assign(system.identity, 'hostname', v['hostname'], 'system/identity', line)
    elif rule in ('services_hostname_remove', 'services_domain_remove', 'services_domain_alt_remove'):
        field = 'hostname' if rule == 'services_hostname_remove' else 'domain_name'
        setattr(system.identity, field, None)
        state.unbind('system/identity/' + field)
    elif rule == 'services_version':
        state.assign(state.c.device, 'software_version', v['version'], 'device', line)
    elif rule in ('services_timestamp', 'services_timestamp_plain', 'services_timestamp_remove', 'services_timestamp_remove_all', 'services_timestamp_bare'):
        timestamp(state, r)
    elif rule in ('services_domain', 'services_domain_alt'):
        state.assign(system.identity, 'domain_name', v['domain'], 'system/identity', line)
    elif rule == 'services_dns':
        values = [str(ip_address(value)) for value in v['addresses'].split()]
        for value in values:
            collection(system.dns, 'servers').append(value)
            state.bind(f'system/dns/servers/{len((system.dns.servers or [])) - 1}', line)
    elif rule.startswith('services_ntp') and 'address' in v:
        ntp_association(state, r)
    elif rule in ('services_logging', 'services_logging_legacy', 'services_logging_update', 'services_logging_remove', 'services_logging_legacy_remove',
                  'services_logging_vrf', 'services_logging_vrf_transport', 'services_logging_transport',
                  'services_logging_port', 'services_logging_vrf_port'):
        syslog_destination(state, r)
    elif rule in ('services_logging_on', 'services_logging_off'):
        state.assign(system.logging, 'enabled', v['enabled'], 'system/logging', line, list(v))
    elif rule in ('services_password_encryption_on', 'services_password_encryption_off'):
        state.assign(system.ip_services, 'password_encryption_service', v['enabled'], 'system/ip_services', line)
    elif rule in ('services_aaa_on', 'services_aaa_off'):
        state.assign(system.aaa, 'enabled', v['enabled'], 'system/aaa', line, list(v))
    elif rule == 'services_logging_buffered_size':
        if 4096 <= v['size'] <= 2147483647:
            state.assign(system.logging, 'buffered_size', v['size'], 'system/logging', line)
    elif rule in ('services_logging_buffered', 'services_logging_buffered_severity', 'services_logging_buffered_discriminator'):
        logging = system.logging
        if rule == 'services_logging_buffered':
            logging.buffered_size = v['size']
            logging.buffered_severity = v['severity']
        elif rule == 'services_logging_buffered_severity':
            logging.buffered_severity = v['severity']
        elif rule == 'services_logging_buffered_discriminator':
            logging.buffered_discriminator = v['name']
            logging.buffered_severity = v['severity']
        state.bind('system/logging/buffered_size', line, list(v))
        state.bind('system/logging/buffered_severity', line, list(v))
        state.bind('system/logging/buffered_discriminator', line, list(v))
    elif rule == 'services_logging_buffered_remove':
        logging = system.logging
        logging.buffered_size = None
        logging.buffered_severity = None
        logging.buffered_discriminator = None
        state.unbind('system/logging/buffered_size')
        state.unbind('system/logging/buffered_severity')
        state.unbind('system/logging/buffered_discriminator')
    elif rule in ('services_logging_console',):
        system.logging.console_severity = v['severity']
        system.logging.console_logging = True
        state.bind('system/logging/console_severity', line, list(v))
        state.bind('system/logging/console_logging', line, list(v))
    elif rule in ('services_logging_console_remove', 'services_console_off'):
        system.logging.console_severity = None
        system.logging.console_logging = False
        state.unbind('system/logging/console_severity')
        state.bind('system/logging/console_logging', line, list(v))
    elif rule == 'services_logging_source_remove':
        system.logging.source_interface = None
        system.logging.source_vrf = None
        state.unbind('system/logging/source_interface')
        state.unbind('system/logging/source_vrf')
    elif rule in ('services_logging_source', 'services_logging_source_vrf'):
        state.assign(system.logging, 'source_interface', v['interface'], 'system/logging', line)
        if 'vrf' in v:
            state.assign(system.logging, 'source_vrf', v['vrf'], 'system/logging', line)
        else:
            system.logging.source_vrf = None
            state.unbind('system/logging/source_vrf')
    elif rule in ('services_crypto_key_generate_rsa', 'services_crypto_key_generate_rsa_general', 'services_crypto_key_generate_rsa_usage', 'services_crypto_key_generate_rsa_label'):
        crypto = system.management.ssh
        if crypto.rsa_keys is None:
            crypto.rsa_keys = []
        key = s.RSAKey(
            label=v.get('name'),
            modulus=v['modulus'],
            usage=v.get('usage', 'general')
        )
        crypto.rsa_keys.append(key)
        state.bind(f'system/management/ssh/rsa_keys/{len(crypto.rsa_keys) - 1}', line, list(v))
    elif rule in ('services_crypto_key_zeroize_rsa', 'services_crypto_key_zeroize_rsa_label'):
        crypto = system.management.ssh
        if crypto.rsa_keys:
            if rule == 'services_crypto_key_zeroize_rsa':
                crypto.rsa_keys = []
            else:
                name = v['name']
                crypto.rsa_keys = [k for k in crypto.rsa_keys if k.label != name]
    elif rule in ('services_ssh_rsa_keypair', 'services_ssh_rsa_keypair_remove'):
        if rule == 'services_ssh_rsa_keypair':
            system.management.ssh.rsa_keypair_name = v['name']
        else:
            system.management.ssh.rsa_keypair_name = None
    elif rule == 'services_source_route_on':
        system.ip_services.source_routing = True
        state.bind('system/ip_services/source_routing', line, list(v))
    elif rule == 'services_source_route_off':
        system.ip_services.source_routing = False
        state.bind('system/ip_services/source_routing', line, list(v))
    elif rule == 'services_source_route_reset':
        system.ip_services.source_routing = None
        state.unbind('system/ip_services/source_routing')
    # F07 Global Services
    elif rule in ('services_cdp_run', 'services_cdp_run_off'):
        system.ip_services.cdp_enabled = v['enabled']
        state.bind('system/ip_services/cdp_enabled', line, list(v))
    elif rule in ('services_cdp_enable', 'services_cdp_enable_off'):
        # Per-interface CDP handled in interfaces.py via if_cdp_off
        pass
    elif rule in ('services_bootp_server', 'services_bootp_server_off'):
        system.ip_services.bootp_server_enabled = v['enabled']
        state.bind('system/ip_services/bootp_server_enabled', line, list(v))
    elif rule in ('services_dhcp_bootp_ignore', 'services_dhcp_bootp_ignore_off'):
        if rule == 'services_dhcp_bootp_ignore':
            system.ip_services.dhcp_bootp_ignore = True
        else:
            system.ip_services.dhcp_bootp_ignore = None
        state.bind('system/ip_services/dhcp_bootp_ignore', line, list(v))
    elif rule in ('services_dhcp', 'services_dhcp_off'):
        system.ip_services.dhcp_service_enabled = v['enabled']
        state.bind('system/ip_services/dhcp_service_enabled', line, list(v))
    elif rule in ('services_ident', 'services_ident_off'):
        system.ip_services.ident_enabled = v['enabled']
        state.bind('system/ip_services/ident_enabled', line, list(v))
    elif rule in ('services_finger', 'services_finger_off'):
        system.ip_services.finger_enabled = v['enabled']
        state.bind('system/ip_services/finger_enabled', line, list(v))
    elif rule in ('services_pad', 'services_pad_off'):
        system.ip_services.pad_enabled = v['enabled']
        state.bind('system/ip_services/pad_enabled', line, list(v))
    elif rule in ('services_tcp_keepalives_in', 'services_tcp_keepalives_in_off'):
        system.ip_services.tcp_keepalives_in = v['enabled']
        state.bind('system/ip_services/tcp_keepalives_in', line, list(v))
    elif rule in ('services_tcp_keepalives_out', 'services_tcp_keepalives_out_off'):
        system.ip_services.tcp_keepalives_out = v['enabled']
        state.bind('system/ip_services/tcp_keepalives_out', line, list(v))
    elif rule in ('services_ssh_source', 'services_ssh_source_remove'):
        if rule == 'services_ssh_source':
            system.management.ssh.source_interface = v['interface']
        else:
            system.management.ssh.source_interface = None
    elif rule in ('services_ssh_pubkey_chain', 'services_ssh_pubkey_chain_remove'):
        if rule == 'services_ssh_pubkey_chain':
            system.management.ssh.pubkey_chain_enabled = True
        else:
            system.management.ssh.pubkey_chain_enabled = False
    elif rule in ('services_login_block', 'services_login_block_remove'):
        if rule == 'services_login_block':
            state.assign(system.management.ssh, 'login_block_for', s.LoginBlockFor(
                seconds=v['seconds'],
                attempts=v['attempts'],
                within_seconds=v['within']
            ), 'system/management/ssh', line)
        else:
            system.management.ssh.login_block_for = None
            state.unbind('system/management/ssh/login_block_for')
    elif rule.startswith('services_snmp_community') and v['access'].lower() in ('ro', 'rw'):
        community = s.SNMPCommunity(identifier_redacted=True, access=v['access'].lower(), access_list=v.get('acl'))
        if 'view' in v:
            community.view = v['view']
        collection(system.snmp, 'communities').append(community)
        state.bind(f'system/snmp/communities/{len((system.snmp.communities or [])) - 1}', line)
    elif rule in ('services_snmp_location', 'services_snmp_contact'):
        state.assign(system.snmp, 'location' if rule.endswith('location') else 'contact', v['value'], 'system/snmp', line)
    elif rule in ('services_snmp_group_v3', 'services_snmp_group_v3_plain', 'services_snmp_group_v1_v2c'):
        group = s.SNMPGroup(name=v['name'])
        if 'params' in v:
            parts = v['params'].split()
            i = 0
            while i < len(parts):
                if parts[i].lower() == 'read' and i + 1 < len(parts):
                    group.read_view = parts[i + 1]
                    i += 2
                elif parts[i].lower() == 'write' and i + 1 < len(parts):
                    group.write_view = parts[i + 1]
                    i += 2
                elif parts[i].lower() == 'notify' and i + 1 < len(parts):
                    group.notify_view = parts[i + 1]
                    i += 2
                elif parts[i].lower() == 'access' and i + 1 < len(parts):
                    group.access_list = parts[i + 1]
                    i += 2
                else:
                    i += 1
        else:
            if 'read' in v:
                group.read_view = v['read']
            if 'write' in v:
                group.write_view = v['write']
            if 'notify' in v:
                group.notify_view = v['notify']
            if 'access' in v:
                group.access_list = v['access']
        if rule in ('services_snmp_group_v3', 'services_snmp_group_v3_plain'):
            group.version = 'v3'
        elif 'version' in v:
            group.version = v['version']
        if 'sec_level' in v:
            group.security_level = v['sec_level']
        replace_owned(state, system.snmp, 'groups', 'system/snmp/groups', lambda g: (g.name,g.version)==(group.name,group.version), group, line)
    elif rule == 'services_snmp_group_remove':
        replace_owned(state, system.snmp, 'groups', 'system/snmp/groups',
                      lambda g: g.name == v['name'] and (v.get('version') is None or g.version == v['version']), None, line)


def declare(state, r):
    rule, v, line = r['rule'], r['values'], r['source_line']
    if rule == 'services_line':
        items = collection(state.c.system.management, 'lines')
        for span in state.line_intervals.targets.get(line, ()):
            path = state.line_intervals.paths.get(span)
            if path is None:
                items.append(s.ManagementLine(name=state.line_intervals.names[span]))
                path = f'system/management/lines/{len(items) - 1}'
                state.line_intervals.paths[span] = path
            state.entities.setdefault(line, path)
            state.bind(path + '/name', line)
        return True
    if rule in ('services_tacacs', 'services_radius') or (
            rule.startswith('services_tacacs_legacy_host')
            and rule != 'services_tacacs_legacy_host_remove'):
        return aaa_administration.server_declare(state, r)
    if rule == 'admin_aaa_group':
        return aaa_administration.group_declare(state, r)
    return False


def resolve(state, r):
    line, v = r['source_line'], r['values']
    rule = r['rule']
    system = state.c.system
    if rule.startswith('services_snmp_host_v3'):
        return snmp_v3_host(state, r)
    if rule.startswith('services_access_class'):
        return line_access_class(state, r)
    if rule.startswith('services_snmp_traps_default'):
        return snmp_traps(state, r)
    if rule == 'services_scalar_default':
        return global_scalars.reset(state, r, resolving=True)
    if rule in ('services_exec_on', 'services_exec_off', 'services_exec_default'):
        entry = state.entity(line)
        if entry and isinstance(entry[0], s.ManagementLine) and len(r['context_lines']) == 1:
            item, path = entry
            if rule == 'services_exec_default':
                for field in ('exec_shell_enabled', 'exec_disabled'):
                    setattr(item, field, None)
                    state.unbind(path + '/' + field)
            else:
                state.assign(item, 'exec_shell_enabled', v['exec_shell_enabled'], path, line)
                state.assign(item, 'exec_disabled', not v['exec_shell_enabled'], path, line)
        return
    if rule == 'services_cdp_run_default':
        system.ip_services.cdp_enabled = None
        state.unbind('system/ip_services/cdp_enabled')
        return
    line_fields = {'services_line_synchronous': ('logging_synchronous', 'enabled'),
                   'services_line_privilege': ('privilege_level', 'level'),
                   'services_line_stopbits': ('stopbits', 'bits'),
                   'services_line_length': ('screen_length', 'length')}
    if rule in line_fields:
        entry = state.entity(line)
        if entry and isinstance(entry[0], s.ManagementLine) and len(r['context_lines']) == 1:
            item, path = entry
            field, key = line_fields[rule]
            state.assign(item, field, v[key], path, line)
        return
    if rule == 'services_line_preferred':
        entry = state.entity(line)
        if entry and isinstance(entry[0], s.ManagementLine) and len(r['context_lines']) == 1:
            item, path = entry
            tokens = v['transports'].split()
            if tokens == ['none'] or tokens and all(t in ('ssh', 'telnet') for t in tokens):
                state.unbind(path + '/preferred_transports')
                state.assign(item, 'preferred_transports', [] if tokens == ['none'] else tokens, path, line, explicit_empty=tokens == ['none'])
        return
    if rule.startswith('services_transport') or rule.startswith('services_line_password') or rule in ('services_login', 'services_login_plain', 'services_login_authentication_remove', 'services_login_authentication_remove_args', 'services_login_authentication_default'):
        entry = state.entity(line)
        if not entry or not isinstance(entry[0], s.ManagementLine) or len(r['context_lines']) != 1:
            return
        item, path = entry
        if rule.startswith('services_transport'):
            output = rule.startswith('services_transport_output')
            field = 'transport_output' if output else 'allowed_transports'
            tokens = v.get('transports', '').split()
            valid = rule in ('services_transport', 'services_transport_output') and bool(tokens) and (
                tokens in (['none'], ['all']) or all(t in ('ssh', 'telnet') for t in tokens))
            if output and tokens == ['all']:
                valid = False  # V1 output transports cannot represent 'all'.
            if valid:
                value = [] if tokens == ['none'] else list(dict.fromkeys(tokens))
                state.unbind(path + '/' + field)
                pointer = '/' + path + '/' + field
                state._before = {k: v for k, v in state._before.items() if k != pointer and not k.startswith(pointer + '/')}
                state.assign(item, field, value, path, line, explicit_empty=value == [])
            else:
                setattr(item, field, None)
                state.unbind(path + '/' + field)
                state.absences.confirmed_empty.discard('/' + path + '/' + field)
            if not output:
                setting = 'configured' if valid else 'default' if 'default' in rule else 'removed' if 'remove' in rule else None
                item.transport_input_setting = None
                state.unbind(path + '/transport_input_setting')
                if setting is not None:state.assign(item, 'transport_input_setting', setting, path, line)
            return
    if rule == 'services_timeout':
        seconds = v.get('seconds', 0)
        if not 0 <= seconds <= 59:
            raise ValueError('Invalid timeout')
        entry = state.entity(line)
        if not entry or not isinstance(entry[0], s.ManagementLine):
            return
        item, path = entry
        state.assign(item, 'idle_timeout_seconds', v['minutes'] * 60 + seconds, path, line)
        state.assign(item, 'timeout_setting', 'configured', path, line)
        return

    if rule in ('services_accounting_commands', 'services_accounting_connection', 'services_accounting_exec', 'services_accounting_network', 'services_accounting_system', 'services_line_accounting_commands', 'services_line_accounting_connection', 'services_line_accounting_exec', 'services_line_accounting_system'):
        entry = state.entity(line)
        if not entry or not isinstance(entry[0], s.ManagementLine):
            return
        item, path = entry
        service_map = {
            'services_accounting_commands': 'commands',
            'services_accounting_connection': 'connection',
            'services_accounting_exec': 'exec',
            'services_accounting_system': 'system',
            'services_line_accounting_commands': 'commands',
            'services_line_accounting_connection': 'connection',
            'services_line_accounting_exec': 'exec',
            'services_line_accounting_system': 'system',
        }
        service = service_map[rule]
        privilege = v.get('privilege')
        method_list = v.get('method_list')
        acc = s.AAAAccountingLine(
            privilege_level=privilege,
            method_list=method_list,
            service=service
        )
        collection(item, f'accounting_{service}').append(acc)
        state.bind(f'{path}/accounting_{service}/{len(getattr(item, f"accounting_{service}", [])) - 1}', line, list(v))
    elif rule == 'services_ntp_global_source':
        state.assign(system.ntp, 'source_interface', v['source'], 'system/ntp', line)
    elif rule == 'services_ntp_global_source_remove':
        state.unbind('system/ntp/source_interface')
    elif rule == 'services_logging_trap':
        state.assign(system.logging, 'trap_severity', v['severity'], 'system/logging', line)
    elif rule == 'services_logging_trap_remove':
        system.logging.trap_severity = None
        state.unbind('system/logging/trap_severity')
    elif rule in ('services_ntp_authenticate', 'services_ntp_authenticate_remove'):
        state.assign(system.ntp, 'authentication_enabled', not v.get('removed', False), 'system/ntp', line)
    elif rule in ('services_ntp_auth_key', 'services_ntp_auth_key_format'):
        ntp = system.ntp
        identifier = v['identifier']
        credential_format = v.get('credential_format')
        existing = next((k for k in (ntp.authentication_keys or []) if k.identifier == identifier), None)
        if existing:
            idx = (ntp.authentication_keys or []).index(existing)
        else:
            idx = len(ntp.authentication_keys or [])
            collection(ntp, 'authentication_keys').append(s.NTPAuthKey(identifier=identifier))
            existing = ntp.authentication_keys[idx]
        existing.algorithm = 'md5'
        existing.secret_configured = True
        existing.credential_format = credential_format
        state.bind(f'system/ntp/authentication_keys/{idx}/identifier', line)
        state.bind(f'system/ntp/authentication_keys/{idx}/algorithm', line)
        state.bind(f'system/ntp/authentication_keys/{idx}/credential_format', line)
    elif rule == 'services_ntp_auth_key_remove':
        ntp = system.ntp
        identifier = v['identifier']
        path='system/ntp/authentication_keys'
        publish_entries(state,ntp,'authentication_keys',path,
            [(item,owners) for item,owners in owned_entries(state,ntp,'authentication_keys',path) if item.identifier!=identifier])
    elif rule in ('services_ntp_master', 'services_ntp_master_no_stratum', 'services_ntp_master_remove'):
        state.assign(system.ntp, 'master', v.get('enabled', True), 'system/ntp', line)
    elif rule in ('services_login_block', 'services_login_block_remove'):
        if rule == 'services_login_block':
            state.assign(system.management.ssh, 'login_block_for', s.LoginBlockFor(
                seconds=v['seconds'],
                attempts=v['attempts'],
                within_seconds=v['within']
            ), 'system/management/ssh', line)
        else:
            system.management.ssh.login_block_for = None
            state.unbind('system/management/ssh/login_block_for')
    elif rule in ('services_snmp_user_v3', 'services_snmp_user_v3_remote', 'services_snmp_user_v3_plain'):
        params = v.get('params', '')
        from parser.admin_secrets import MARKER
        if params == MARKER:
            # Unsupported opaque rewrite: revoke the previous user facts.
            # A safe marker is neither an algorithm nor a credential proof.
            replace_owned(state,system.snmp,'users','system/snmp/users',lambda user:user.username==v['username'] and user.group_reference==v['group'] and (str(user.remote_ip) if user.remote_ip is not None else None)==v.get('remote_ip'),None,line)
            return
        parts = params.split()
        auth_alg = None
        priv_alg = None
        i = 0
        while i < len(parts):
            if parts[i].lower() == 'auth' and i + 1 < len(parts):
                auth_alg = parts[i + 1]
                i += 2
            elif parts[i].lower() == 'priv' and i + 1 < len(parts):
                priv_alg = parts[i + 1]
                if priv_alg.lower()=='aes' and i+2<len(parts) and parts[i+2] in ('128','192','256'):
                    priv_alg='aes'+parts[i+2]
                i += 2
            else:
                i += 1
        user = s.SNMPUser(username=v['username'], group_reference=v['group'], version='3')
        if auth_alg:
            user.authentication_algorithm = auth_alg
            user.authentication_secret_configured = True
        if priv_alg:
            user.privacy_algorithm = priv_alg
            user.privacy_secret_configured = True
        if 'remote_ip' in v:
            user.remote_ip = v['remote_ip']
        replace_owned(state, system.snmp, 'users', 'system/snmp/users', lambda u: (u.username,u.group_reference,u.remote_ip)==(user.username,user.group_reference,user.remote_ip), user, line)
    elif rule.startswith('services_snmp_user_remove'):
        replace_owned(state, system.snmp, 'users', 'system/snmp/users',
                      lambda u: u.username == v['username'] and u.group_reference == v['group']
                      and (str(u.remote_ip) if u.remote_ip is not None else None) == v.get('remote_ip')
                      and (v.get('version') is None or u.version == v['version'].removeprefix('v')), None, line)
    elif rule in ('services_snmp_community_view_acl', 'services_snmp_community_view_acl_simple'):
        community = s.SNMPCommunity(identifier_redacted=True, access=v['access'].lower(), view=v['view'], access_list=v.get('acl'))
        collection(system.snmp, 'communities').append(community)
        state.bind(f'system/snmp/communities/{len((system.snmp.communities or [])) - 1}', line)
    elif rule in ('services_snmp_community_view', 'services_snmp_community_view_simple'):
        community = s.SNMPCommunity(identifier_redacted=True, access=v['access'].lower(), view=v['view'], access_list=v.get('acl'))
        collection(system.snmp, 'communities').append(community)
        state.bind(f'system/snmp/communities/{len((system.snmp.communities or [])) - 1}', line)
    elif rule in ('services_snmp_community_acl', 'services_snmp_community_acl6', 'services_snmp_community_no_acl'):
        access = v['access'].lower() if 'access' in v else ('ro' if rule.endswith('no_acl') else 'ro')
        community = s.SNMPCommunity(identifier_redacted=True, access=access, access_list=v.get('acl'))
        collection(system.snmp, 'communities').append(community)
        state.bind(f'system/snmp/communities/{len((system.snmp.communities or [])) - 1}', line)
    elif rule in ('services_snmp_group_v3', 'services_snmp_group_v3_plain', 'services_snmp_group_v1_v2c'):
        group = s.SNMPGroup(name=v['name'])
        if 'params' in v:
            parts = v['params'].split()
            i = 0
            while i < len(parts):
                if parts[i].lower() == 'read' and i + 1 < len(parts):
                    group.read_view = parts[i + 1]
                    i += 2
                elif parts[i].lower() == 'write' and i + 1 < len(parts):
                    group.write_view = parts[i + 1]
                    i += 2
                elif parts[i].lower() == 'notify' and i + 1 < len(parts):
                    group.notify_view = parts[i + 1]
                    i += 2
                elif parts[i].lower() == 'access' and i + 1 < len(parts):
                    group.access_list = parts[i + 1]
                    i += 2
                else:
                    i += 1
        else:
            if 'read' in v:
                group.read_view = v['read']
            if 'write' in v:
                group.write_view = v['write']
            if 'notify' in v:
                group.notify_view = v['notify']
            if 'access' in v:
                group.access_list = v['access']
        if rule in ('services_snmp_group_v3', 'services_snmp_group_v3_plain'):
            group.version = 'v3'
        elif 'version' in v:
            group.version = v['version']
        if 'sec_level' in v:
            group.security_level = v['sec_level']
        replace_owned(state, system.snmp, 'groups', 'system/snmp/groups', lambda g: (g.name,g.version)==(group.name,group.version), group, line)
    elif rule == 'services_snmp_group_remove':
        replace_owned(state, system.snmp, 'groups', 'system/snmp/groups',
                      lambda g: g.name == v['name'] and (v.get('version') is None or g.version == v['version']), None, line)
    elif rule in (
        'services_snmp_host_v3', 'services_snmp_host_v3_vrf', 'services_snmp_host_traps', 'services_snmp_host_traps_vrf', 'services_snmp_host_traps_simple',
        'services_snmp_host_traps_v2c', 'services_snmp_host_informs_v2c',
        'services_snmp_host_implicit_v1', 'services_snmp_host_implicit_v1_vrf',
        'services_snmp_host_implicit_v1_vrf_alt', 'services_snmp_host_implicit_v1_udp_vrf',
        'services_snmp_host_implicit_version', 'services_snmp_host_implicit_version_vrf',
        'services_snmp_host_implicit_version_vrf_alt', 'services_snmp_host_implicit_version_udp_vrf',
        'services_snmp_host_traps_implicit', 'services_snmp_host_traps_implicit_vrf',
        'services_snmp_host_implicit_traps', 'services_snmp_host_implicit_traps_vrf',
        'services_snmp_host_informs', 'services_snmp_host_informs_vrf', 'services_snmp_host_informs_simple',
        'services_snmp_host_informs_implicit', 'services_snmp_host_informs_implicit_vrf',
        'services_snmp_host_informs_implicit_vrf_alt', 'services_snmp_host_informs_implicit_udp_vrf'):
        host_type = 'traps' if 'traps' in rule or 'implicit_v1' in rule or 'implicit_version' in rule or rule.startswith('services_snmp_host_v3') else 'informs'
        host = s.SNMPHost(destination=v['destination'], type=host_type)
        if rule.startswith('services_snmp_host_v3'):
            host.version = '3'
        if rule.endswith('_v2c'):
            host.version = '2c'
        if 'implicit_v1' in rule:
            host.version = '1'
        if 'vrf' in v:
            host.vrf = v['vrf']
        if 'version' in v:
            host.version = v['version']
        if 'community_user' in v:
            host.community_or_user = v['community_user']
        rest = v.get('rest', '')
        if rest:
            parts = rest.split()
            i = 0
            while i < len(parts):
                if parts[i] == 'udp-port' and i + 1 < len(parts):
                    host.udp_port = int(parts[i + 1])
                    i += 2
                elif parts[i] == 'version' and i + 1 < len(parts):
                    host.version = parts[i + 1]
                    i += 2
                else:
                    i += 1
        if 'vrf' in v:
            host.vrf = v['vrf']
        if 'version' in v and not host.version:
            host.version = v['version']
        if 'community_user' in v:
            host.community_or_user = v['community_user']
        if 'udp_port' in v and not host.udp_port:
            host.udp_port = int(v['udp_port'])
        if 'types' in v:
            host.notification_types = v['types'].split()
        replace_owned(state, system.snmp, 'hosts', 'system/snmp/hosts', lambda h: (h.destination,h.vrf,h.type)==(host.destination,host.vrf,host.type), host, line)
    elif rule == 'services_snmp_host_remove':
        replace_owned(state,system.snmp,'hosts','system/snmp/hosts',lambda h:h.destination==v['destination'] and h.vrf==v.get('vrf'),None,line)
    elif rule in ('services_snmp_enable_traps','services_snmp_enable_traps_remove','services_snmp_enable_traps_remove_all'):
        snmp_traps(state,r)
    elif rule in ('services_snmp_engineid', 'services_snmp_engineid_remove'):
        if rule == 'services_snmp_engineid':
            system.snmp.engine_id = v['id']
        else:
            system.snmp.engine_id = None
        state.bind('system/snmp/engine_id', line, list(v))
    elif rule in ('services_snmp_view', 'services_snmp_view_remove'):
        view = None if v.get('removed') else s.SNMPView(name=v['name'], oid=v['oid'], included=v.get('included', 'included').lower() == 'included')
        replace_owned(state, system.snmp, 'views', 'system/snmp/views',
                      lambda item: (item.name, item.oid) == (v['name'], v['oid']), view, line)
    elif rule in ('services_snmp_source_interface', 'services_snmp_source_interface_remove'):
        if rule == 'services_snmp_source_interface':
            system.snmp.trap_source_interface = v['interface']
        else:
            system.snmp.trap_source_interface = None
        state.bind('system/snmp/trap_source_interface', line, list(v))
    elif rule in ('services_snmp_trap_source', 'services_snmp_trap_source_vrf', 'services_snmp_trap_source_remove'):
        if rule == 'services_snmp_trap_source_remove':
            system.snmp.trap_source_interface = None
            system.snmp.trap_source_vrf = None
        else:
            system.snmp.trap_source_interface = v['interface']
            if 'vrf' in v:
                system.snmp.trap_source_vrf = v['vrf']
        state.bind('system/snmp/trap_source_interface', line, list(v))
        state.bind('system/snmp/trap_source_vrf', line, list(v))
    elif rule in ('services_snmp_server_enable', 'services_snmp_server_disable'):
        system.snmp.enabled = v['enabled']
        state.bind('system/snmp/enabled', line, list(v))
    elif rule in ('services_snmp_location', 'services_snmp_contact'):
        state.assign(system.snmp, 'location' if rule.endswith('location') else 'contact', v['value'], 'system/snmp', line)
    elif rule in ('services_banner', 'services_banner_remove', 'services_banner_incoming', 'services_banner_incoming_remove'):
        return global_scalars.banner(state, r, removed=rule.endswith('_remove'))
    elif rule in ('services_line_exec_banner', 'services_line_exec_banner_remove',
                  'services_line_motd_banner', 'services_line_motd_banner_remove'):
        entry = state.entity(line)
        if not entry or not isinstance(entry[0], s.ManagementLine):
            return
        item, path = entry
        if rule == 'services_line_exec_banner':
            state.assign(item, 'exec_banner', True, path, line, list(v))
        elif rule == 'services_line_exec_banner_remove':
            state.assign(item, 'exec_banner', False, path, line, list(v))
        elif rule == 'services_line_motd_banner':
            state.assign(item, 'motd_banner', True, path, line, list(v))
        elif rule == 'services_line_motd_banner_remove':
            state.assign(item, 'motd_banner', False, path, line, list(v))
    elif rule in ('services_http_on', 'services_http_off', 'services_https_on', 'services_https_off'):
        service = 'https' if 'https' in rule else 'http'
        state.assign(getattr(system.management, service), 'enabled', boolean(v['enabled']), 'system/management/' + service, line)
    elif rule.startswith('services_line_password') or rule in ('services_transport_output', 'services_transport_output_remove', 'services_access_class', 'services_access_class_vrf', 'services_access_class_out', 'services_access_class_remove', 'services_access_class_remove_all', 'services_exec_on', 'services_exec_off', 'services_exec_default', 'services_login_off', 'services_timeout_minutes', 'services_timeout_remove', 'services_timeout_default', 'services_login', 'services_login_plain', 'services_login_authentication_remove', 'services_login_authentication_remove_args', 'services_login_authentication_default'):
        entry = state.entity(line)
        if not entry or not isinstance(entry[0], s.ManagementLine):
            return
        item, path = entry
        if rule == 'services_transport_output':
            tokens = v['transports'].split()
            if any(t not in ('ssh', 'telnet') for t in tokens):
                raise ValueError('Transport protocol')
            state.assign(item, 'allowed_transports', [] if tokens == ['none'] else tokens, path, line, list(v), explicit_empty=tokens == ['none'])
        elif rule == 'services_transport_output_remove':
            item.allowed_transports = None
            state.unbind(path + '/allowed_transports')
        elif rule == 'services_access_class':
            item.access_list_vrf = None
            state.unbind(path + '/access_list_vrf')
            state.assign(item, 'access_list', v['acl'], path, line)
            state.assign(item, 'access_list_direction', 'in', path, line)
        elif rule == 'services_access_class_vrf':
            state.assign(item, 'access_list', v['acl'], path, line)
            state.assign(item, 'access_list_vrf', True, path, line)
            state.assign(item, 'access_list_direction', 'in', path, line)
        elif rule == 'services_access_class_out':
            # V1 exposes one directional relation. Preserve a known inbound
            # relation: an independent outgoing ACL cannot replace it. Full
            # bidirectional inventory is not representable by this V1 field.
            if item.access_list_direction == 'in':
                return
            item.access_list_vrf = None
            state.unbind(path + '/access_list_vrf')
            state.assign(item, 'access_list', v['acl'], path, line)
            state.assign(item, 'access_list_direction', 'out', path, line)
        elif rule == 'services_access_class_remove':
            if item.access_list_direction != v.get('direction'):
                return
            item.access_list = None
            item.access_list_vrf = None
            item.access_list_direction = None
            state.unbind(path + '/access_list')
            state.unbind(path + '/access_list_vrf')
            state.unbind(path + '/access_list_direction')
        elif rule == 'services_access_class_remove_all':
            item.access_list = None
            item.access_list_vrf = None
            item.access_list_direction = None
            state.unbind(path + '/access_list')
            state.unbind(path + '/access_list_vrf')
            state.unbind(path + '/access_list_direction')
        elif rule == 'services_exec_on':
            item.exec_disabled = False
            state.bind(path + '/exec_disabled', line, list(v))
        elif rule == 'services_exec_off':
            item.exec_disabled = True
            state.bind(path + '/exec_disabled', line, list(v))
        elif rule == 'services_exec_default':
            item.exec_disabled = None
            state.unbind(path + '/exec_disabled')
        elif rule == 'services_login_off':
            item.login_disabled = v.get('login_disabled', True)
            state.bind(path + '/login_disabled', line, list(v))
        elif rule == 'services_timeout':
            seconds = v.get('seconds', 0)
            if not 0 <= seconds <= 59:
                raise ValueError('Invalid timeout')
            entry = state.entity(line)
            if not entry or not isinstance(entry[0], s.ManagementLine):
                return
            item, path = entry
            state.assign(item, 'idle_timeout_seconds', v['minutes'] * 60 + seconds, path, line)
            state.assign(item, 'timeout_setting', 'configured', path, line)
            return
        elif rule == 'services_timeout_minutes':
            state.assign(item, 'idle_timeout_seconds', v['minutes'] * 60, path, line)
            state.assign(item, 'timeout_setting', 'configured', path, line)
        elif rule in ('services_timeout_remove', 'services_timeout_default'):
            item.idle_timeout_seconds = None
            state.unbind(path + '/idle_timeout_seconds')
            state.assign(item, 'timeout_setting', 'default' if rule.endswith('_default') else 'removed', path, line)
        elif rule == 'services_login':
            state.assign(item, 'authentication', authentication(v['method']), path, line)
            state.assign(item, 'authentication_setting', 'configured', path, line)
            if item.authentication is not None:
                state.assign(item, 'login_disabled', False, path, line)
        elif rule == 'services_login_plain':
            state.assign(item, 'authentication', s.Authentication(method='line_password'), path, line)
            state.assign(item, 'authentication_setting', 'configured', path, line)
            state.assign(item, 'login_disabled', False, path, line)
        elif rule.startswith('services_line_password'):
            removed = rule.endswith('_remove')
            state.assign(item, 'line_password_configured', not removed, path, line)
            if removed:
                item.line_password_format = None
                state.unbind(path + '/line_password_format')
            else:
                state.assign(item, 'line_password_format', v.get('credential_format'), path, line)
        elif rule in ('services_login_authentication_remove', 'services_login_authentication_remove_args', 'services_login_authentication_default'):
            item.authentication = None
            state.unbind(path + '/authentication')
            state.assign(item, 'authentication_setting', 'default' if rule.endswith('_default') else 'removed', path, line)
        elif rule == 'services_login_off':
            item.login_disabled = v.get('login_disabled', True)
            state.bind(path + '/login_disabled', line, list(v))
    elif rule in ('services_crypto_key_generate_rsa', 'services_crypto_key_generate_rsa_general', 'services_crypto_key_generate_rsa_usage', 'services_crypto_key_generate_rsa_label'):
        crypto = system.management.ssh
        if crypto.rsa_keys is None:
            crypto.rsa_keys = []
        key = s.RSAKey(
            label=v.get('name'),
            modulus=v['modulus'],
            usage=v.get('usage', 'general')
        )
        crypto.rsa_keys.append(key)
        state.bind(f'system/management/ssh/rsa_keys/{len(crypto.rsa_keys) - 1}', line, list(v))
    elif rule in ('services_crypto_key_zeroize_rsa', 'services_crypto_key_zeroize_rsa_label'):
        crypto = system.management.ssh
        if crypto.rsa_keys:
            if rule == 'services_crypto_key_zeroize_rsa':
                crypto.rsa_keys = []
            else:
                name = v['name']
                crypto.rsa_keys = [k for k in crypto.rsa_keys if k.label != name]
    elif rule in ('services_ssh_rsa_keypair', 'services_ssh_rsa_keypair_remove'):
        if rule == 'services_ssh_rsa_keypair':
            system.management.ssh.rsa_keypair_name = v['name']
        else:
            system.management.ssh.rsa_keypair_name = None
    elif rule == 'services_source_route_on':
        system.ip_services.source_routing = True
        state.bind('system/ip_services/source_routing', line, list(v))
    elif rule == 'services_source_route_off':
        system.ip_services.source_routing = False
        state.bind('system/ip_services/source_routing', line, list(v))
    elif rule == 'services_source_route_reset':
        system.ip_services.source_routing = None
        state.unbind('system/ip_services/source_routing')
    # F07 Global Services
    elif rule in ('services_cdp_run', 'services_cdp_run_off'):
        system.ip_services.cdp_enabled = v['enabled']
        state.bind('system/ip_services/cdp_enabled', line, list(v))
    elif rule in ('services_cdp_enable', 'services_cdp_enable_off'):
        # Per-interface CDP handled in interfaces.py via if_cdp_off
        pass
    elif rule in ('services_bootp_server', 'services_bootp_server_off'):
        system.ip_services.bootp_server_enabled = v['enabled']
        state.bind('system/ip_services/bootp_server_enabled', line, list(v))
    elif rule in ('services_dhcp_bootp_ignore', 'services_dhcp_bootp_ignore_off'):
        state.assign(system.ip_services, 'dhcp_bootp_ignore', rule == 'services_dhcp_bootp_ignore', 'system/ip_services', line, list(v))
    elif rule in ('services_dhcp', 'services_dhcp_off'):
        system.ip_services.dhcp_service_enabled = v['enabled']
        state.bind('system/ip_services/dhcp_service_enabled', line, list(v))
    elif rule in ('services_ident', 'services_ident_off'):
        system.ip_services.ident_enabled = v['enabled']
        state.bind('system/ip_services/ident_enabled', line, list(v))
    elif rule in ('services_finger', 'services_finger_off'):
        system.ip_services.finger_enabled = v['enabled']
        state.bind('system/ip_services/finger_enabled', line, list(v))
    elif rule in ('services_pad', 'services_pad_off'):
        system.ip_services.pad_enabled = v['enabled']
        state.bind('system/ip_services/pad_enabled', line, list(v))
    elif rule in ('services_tcp_keepalives_in', 'services_tcp_keepalives_in_off'):
        system.ip_services.tcp_keepalives_in = v['enabled']
        state.bind('system/ip_services/tcp_keepalives_in', line, list(v))
    elif rule in ('services_tcp_keepalives_out', 'services_tcp_keepalives_out_off'):
        system.ip_services.tcp_keepalives_out = v['enabled']
        state.bind('system/ip_services/tcp_keepalives_out', line, list(v))
    elif rule in ('services_ssh_source', 'services_ssh_source_remove'):
        if rule == 'services_ssh_source':
            system.management.ssh.source_interface = v['interface']
        else:
            system.management.ssh.source_interface = None
    elif rule in ('services_ssh_pubkey_chain', 'services_ssh_pubkey_chain_remove'):
        if rule == 'services_ssh_pubkey_chain':
            system.management.ssh.pubkey_chain_enabled = True
        else:
            system.management.ssh.pubkey_chain_enabled = False
    elif rule in ('services_login_block', 'services_login_block_remove'):
        if rule == 'services_login_block':
            state.assign(system.management.ssh, 'login_block_for', s.LoginBlockFor(
                seconds=v['seconds'],
                attempts=v['attempts'],
                within_seconds=v['within']
            ), 'system/management/ssh', line)
        else:
            system.management.ssh.login_block_for = None
            state.unbind('system/management/ssh/login_block_for')


def authentication(value):
    if value == 'local':
        return s.Authentication(method='local')
    if value.startswith('authentication '):
        return s.Authentication(method='aaa', method_list=value[len('authentication '):])
    return None


def replace_owned(state, owner, field, path, predicate, item, line):
    entries=[entry for entry in owned_entries(state,owner,field,path) if not predicate(entry[0])]
    publish_entries(state,owner,field,path,entries)
    if item is not None:
        collection(owner,field).append(item)
        state.bind(f'{path}/{len(getattr(owner,field))-1}',line)


def line_access_class(state, record):
    """One relation per captured family/direction, replayed on effective spans."""
    entry = state.entity(record['source_line'])
    if not entry or not isinstance(entry[0], s.ManagementLine) or len(record['context_lines']) != 1:
        return
    item, path = entry
    rule, v, line = record['rule'], record['values'], record['source_line']
    family = 'ipv6' if '_ipv6' in rule else 'ipv4'
    setting = 'default' if 'default' in rule else 'removed' if 'remove' in rule else 'configured'
    directions = [v['direction']] if 'direction' in v else ['out'] if rule.endswith('_out') else ['in']
    if setting != 'configured' and 'direction' not in v:
        directions = ['in', 'out']
    entries = owned_entries(state, item, 'access_classes', path + '/access_classes')
    entries = [(a, owners) for a, owners in entries if not (a.family == family and a.direction in directions)]
    for direction in directions:
        relation = s.LineAccessClass(family=family, direction=direction, setting=setting,
            name=v.get('acl') if setting == 'configured' else None,
            vrf_also=True if rule == 'services_access_class_vrf' else None)
        from normalizer.common.configured import leaves
        entries.append((relation, {p.lstrip('/'): line for p, _ in leaves(relation)}))
    entries.sort(key=lambda pair: (pair[0].family, pair[0].direction))
    publish_entries(state, item, 'access_classes', path + '/access_classes', entries)
    # Compatibility projection only; canonical consumers use access_classes.
    active = [(a, owners) for a, owners in entries if a.family == 'ipv4' and a.setting == 'configured']
    selected = next((pair for pair in active if pair[0].direction == 'in'), active[0] if active else None)
    for field in ('access_list', 'access_list_direction', 'access_list_vrf'):
        setattr(item, field, None)
        state.unbind(path + '/' + field)
    if selected:
        a, owners = selected
        source = owners['name']
        for field, value in [('access_list', a.name), ('access_list_direction', a.direction), ('access_list_vrf', a.vrf_also)]:
            if value is not None:
                state.assign(item, field, value, path, source)


def snmp_v3_host(state, record):
    """Interpret already captured v3 operands, never raw CLI in an evaluator."""
    v = record['values']
    if v.get('sec_level') not in ('noauth', 'auth', 'priv'):
        raise ValueError('Unsupported SNMP host security level')
    values = dict(destination=v['destination'], version='3',
                  community_or_user=v['community_user'], vrf=v.get('vrf'),
                  type=v.get('notification', 'traps'), security_level=v['sec_level'])
    tokens = v.get('options', '').split()
    types = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in ('udp-port', 'vrf'):
            if index + 1 >= len(tokens):
                raise ValueError('Incomplete SNMP host option')
            operand = tokens[index + 1]
            if token == 'udp-port':
                if not operand.isascii() or not operand.isdigit() or len(operand) > 5 or not 1 <= int(operand) <= 65535:
                    raise ValueError('Invalid SNMP notification port')
                values['udp_port'] = int(operand)
            else:
                if values.get('vrf') not in (None, operand):
                    raise ValueError('Conflicting SNMP notification VRF')
                values['vrf'] = operand
            index += 2
        elif token in {'snmp', 'authentication', 'linkup', 'linkdown', 'coldstart', 'warmstart',
                       'config', 'syslog', 'entity', 'cpu', 'memory', 'envmon', 'bgp'}:
            types.append(token)
            index += 1
        else:
            raise ValueError('Unsupported SNMP notification option')
    if types:
        values['notification_types'] = list(dict.fromkeys(types))
    host = s.SNMPHost(**values)
    replace_owned(state, state.c.system.snmp, 'hosts', 'system/snmp/hosts',
                  lambda h: (h.destination, h.vrf, h.type) == (host.destination, host.vrf, host.type),
                  None if v.get('removed') else host, record['source_line'])


def snmp_community(state, record):
    """Reconcile identities retained only as per-operation redaction ordinals."""
    v=record['values'];identity=record.get('identity_ref')
    if not identity:return  # Imported captures without private identity cannot assert replacement.
    owner=state.c.system.snmp;path='system/snmp/communities'
    # Store positions, not model object references: the engine can roll back
    # an unrelated malformed capture by replacing its model with a deep copy.
    identities=dict(getattr(state,'_community_positions',{}))
    previous=identities.pop(identity,None)
    entries=[entry for i,entry in enumerate(owned_entries(state,owner,'communities',path)) if i!=previous]
    publish_entries(state,owner,'communities',path,entries)
    if previous is not None:identities={key:position-(position>previous) for key,position in identities.items()}
    if not v.get('removed'):
        access=v.get('access','').lower()
        if access not in ('ro','rw'):return
        ipv6 = 'acl6' in record['rule']
        obj=s.SNMPCommunity(identifier_redacted=True,access=access,access_list=None if ipv6 else v.get('acl'),
                             access_list_v6=v.get('acl') if ipv6 else None,view=v.get('view'),
                             acl_restriction='present' if v.get('acl') else 'absent')
        collection(owner,'communities').append(obj)
        identities[identity]=len(owner.communities)-1
        state.bind(f'{path}/{len(owner.communities)-1}',record['source_line'])
    else:identities.pop(identity,None)
    state._community_positions=identities


def ntp_association(state,record):
    v=record['values'];rule=record['rule'];owner=state.c.system.ntp
    association='peer' if 'peer' in rule else 'server'
    identity=(v['address'],v.get('vrf'),association)
    match=lambda item:(item.address,item.network_instance,item.association_type)==identity
    item=None if v.get('removed') else s.NTPServer(address=v['address'],network_instance=v.get('vrf'),association_type=association,prefer=True if v.get('prefer') else None,source_interface=v.get('source'),key_id=v.get('key_id'),version=v.get('version'))
    replace_owned(state,owner,'servers','system/ntp/servers',match,item,record['source_line'])


def snmp_traps(state,record):
    """Preserve positive/negative generic trap facts with original leaf owners."""
    owner=state.c.system.snmp;path='system/snmp/trap_config'
    v=record['values'];line=record['source_line'];rule=record['rule']
    old=owner.trap_config or s.SNMPTrapConfig()
    bindings={b.path:b.record for b in state.bindings}
    def owners(field):
        return {token:bindings.get(f'/{path}/{field}/{i}',line)
                for i,token in enumerate(getattr(old,field) or [])}
    positive=owners('notification_types');negative=owners('disabled_notification_types')
    enabled=old.enabled;enabled_owner=bindings.get('/'+path+'/enabled')
    known=['authentication','linkup','linkdown','coldstart','warmstart']
    tokens=v.get('types','').lower().split();reset=rule.startswith('services_snmp_traps_default')
    if rule=='services_snmp_enable_traps_remove_all':
        positive={};negative={t:line for t in known};enabled=False;enabled_owner=line
    elif reset and not tokens:
        positive={};negative={};enabled=None;enabled_owner=None
    else:
        if not tokens or tokens[0]!='snmp':return
        selected=tokens[1:] or known
        if any(t not in known for t in selected):
            state.uncertain.add(line)
            return
        if reset:
            for token in selected:positive.pop(token,None);negative.pop(token,None)
            enabled=None;enabled_owner=None
        elif v.get('removed'):
            for token in selected:positive.pop(token,None);negative[token]=line
        else:
            for token in selected:negative.pop(token,None);positive[token]=line
            enabled=True;enabled_owner=line
    state.unbind(path)
    prefix='/'+path
    state._before={p:v for p,v in state._before.items() if p!=prefix and not p.startswith(prefix+'/')}
    owner.trap_config=s.SNMPTrapConfig(enabled=enabled,
        notification_types=list(positive) or None,
        disabled_notification_types=list(negative) or None)
    if enabled is not None and enabled_owner is not None:state.bind(path+'/enabled',enabled_owner)
    for field,values in [('notification_types',positive),('disabled_notification_types',negative)]:
        for i,token in enumerate(values):state.bind(f'{path}/{field}/{i}',values[token])


def syslog_destination(state, r):
    """Apply source-ordered normalized capture events, scoped by address and VRF."""
    v, line = r['values'], r['source_line']
    address = v.get('address')
    if not address:
        return
    vrf = v.get('vrf')
    path = 'system/logging/destinations'
    owner = state.c.system.logging
    entries, previous = [], None
    for index, destination in enumerate(owner.destinations or []):
        source = next(b.record for b in state.bindings if b.path == f'/{path}/{index}/address')
        if (destination.address, destination.vrf) == (address, vrf):
            previous = destination
        else:
            entries.append((destination, source))
    if not r['rule'].endswith('_remove') and v.get('supported', False):
        transport, port = v.get('transport'), v.get('port')
        if previous and (previous.transport, previous.port) != (transport, port):
            # V1 has one entry per target; distinct declared sessions cannot be
            # collapsed into a guessed effective transport/port.
            transport = port = None
        entries.append((s.SyslogDestination(address=address, transport=transport, port=port, vrf=vrf), line))
    state.unbind(path)
    state.absences.confirmed_empty.discard('/' + path)
    pointer = '/' + path
    state._before = {k: val for k, val in state._before.items() if k != pointer and not k.startswith(pointer + '/')}
    owner.destinations = [item for item, _ in entries] or None
    for index, (destination, source) in enumerate(entries):
        state.bind(f'{path}/{index}', source)


def timestamp(state, record, *, reset=False, reset_category=None):
    """Replace one explicit category and rebuild bindings after list changes."""
    values, line = record['values'], record['source_line']
    if record['rule'] == 'services_timestamp_bare':
        # Documented meaning of this explicit command, not an absent platform default.
        values = {'category': 'debug', 'format': 'uptime'}
    category = reset_category if reset else values.get('category')
    if category is not None and category not in ('debug', 'log'):
        return
    path = 'system/logging/timestamps'
    owner = state.c.system.logging
    disabled_path = 'system/logging/timestamps_disabled'
    disabled = {kind: next(b.record for b in state.bindings if b.path == f'/{disabled_path}/{i}')
                for i, kind in enumerate(owner.timestamps_disabled or [])}
    targets = {'debug', 'log'} if category is None else {category}
    positive = record['rule'] in ('services_timestamp', 'services_timestamp_plain', 'services_timestamp_bare')
    if reset or positive:
        for kind in targets:
            disabled.pop(kind, None)
    else:
        disabled.update({kind: line for kind in targets})
    entries = []
    target_index = None
    for index, item in enumerate(owner.timestamps or []):
        source = next(b.record for b in state.bindings if b.path == f'/{path}/{index}/category')
        if category is None or item.category == category:
            target_index = len(entries)
        else:
            entries.append((item, source))
    if positive:
        options = values.get('options', '').split()
        valid = values['format'] in ('datetime', 'uptime') and (not options or values['format'] == 'datetime' and all(x in ('msec','localtime','show-timezone','year') for x in options))
        if valid:
            # The complete validated command establishes its option set, even
            # when empty. None remains reserved for an unknown option set.
            item = s.TimestampPolicy(category=category, format=values['format'], options=list(dict.fromkeys(options)))
            if record['rule'] == 'services_timestamp_bare':
                item.format_basis = 'COMMAND_IMPLIED'
            entries.insert(len(entries) if target_index is None else target_index, (item, line))
            if 'options' in values:
                state.validation[line]['fields']['options'] = 'validated'
    state.unbind(path)
    state.absences.confirmed_empty.discard('/' + path)
    state.absences.confirmed_empty.difference_update(
        p for p in tuple(state.absences.confirmed_empty) if p.startswith('/' + path + '/'))
    pointer = '/' + path
    state._before = {k: v for k, v in state._before.items() if k != pointer and not k.startswith(pointer + '/')}
    # Clear the two old representations before installing their coherent new
    # state; assignment validation must never observe a transient contradiction.
    owner.timestamps = None
    owner.timestamps_disabled = None
    owner.timestamps = [item for item, _ in entries] or None
    state.unbind(disabled_path)
    disabled_pointer = '/' + disabled_path
    state._before = {k: v for k, v in state._before.items()
                     if k != disabled_pointer and not k.startswith(disabled_pointer + '/')}
    owner.timestamps_disabled = sorted(disabled) or None
    for i, kind in enumerate(owner.timestamps_disabled or []):
        state.bind(f'{disabled_path}/{i}', disabled[kind])
    for index, (item, source) in enumerate(entries):
        if item.options == []:
            state.absences.confirm(f'{path}/{index}/options', explicit=True)
        state.bind(f'{path}/{index}', source)
