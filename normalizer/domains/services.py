"""Identity, AAA, management lines, NTP, syslog and system services."""
from ipaddress import ip_address
from schemas import router_contract_v1 as s
from normalizer.common.collections import collection
from normalizer.common.validation import boolean
from . import aaa_administration


def handle(state, r):
    rule, v, line = (r['rule'], r['values'], r['source_line'])
    if rule.startswith('admin_') or rule in (
        'services_ssh_version', 'services_auth_address', 'services_auth_ports',
        'services_ssh_timeout', 'services_ssh_timeout_remove',
        'services_ssh_version_remove', 'services_ssh_rsa_keypair',
        'services_ssh_rsa_keypair_remove', 'services_ssh_source',
        'services_ssh_source_remove', 'services_ssh_pubkey_chain',
        'services_ssh_pubkey_chain_remove',
        'services_user', 'services_user_simple', 'services_user_no_format'):
        return aaa_administration.handle(state, r)

    if rule in (
        'services_ntp_global_source', 'services_ntp_global_source_remove', 'services_logging_trap',
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
        'services_snmp_host_traps', 'services_snmp_host_traps_vrf', 'services_snmp_host_traps_simple',
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
        'services_cdp_run', 'services_cdp_run_off', 'services_cdp_enable', 'services_cdp_enable_off',
        'services_bootp_server', 'services_bootp_server_off', 'services_dhcp_bootp_ignore', 'services_dhcp_bootp_ignore_off',
        'services_dhcp', 'services_dhcp_off', 'services_ident', 'services_ident_off',
        'services_finger', 'services_finger_off', 'services_pad', 'services_pad_off',
        'services_tcp_keepalives_in', 'services_tcp_keepalives_in_off', 'services_tcp_keepalives_out', 'services_tcp_keepalives_out_off'):
        state.defer(r)
        return

    system = state.c.system
    if rule == 'services_hostname':
        state.assign(system.identity, 'hostname', v['hostname'], 'system/identity', line)
    elif rule == 'services_version':
        state.assign(state.c.device, 'software_version', v['version'], 'device', line)
    elif rule in ('services_domain', 'services_domain_alt'):
        state.assign(system.identity, 'domain_name', v['domain'], 'system/identity', line)
    elif rule == 'services_dns':
        values = [str(ip_address(value)) for value in v['addresses'].split()]
        for value in values:
            collection(system.dns, 'servers').append(value)
            state.bind(f'system/dns/servers/{len((system.dns.servers or [])) - 1}', line)
    elif rule.startswith('services_ntp') and rule != 'services_ntp_global_source':
        is_peer = 'peer' in rule
        has_source = 'source' in rule and 'global' not in rule
        has_key = 'key' in rule
        is_remove = rule.endswith('_remove')
        source_interface = v.get('source') if has_source else None
        if is_remove:
            state.unbind('system/ntp/source_interface')
        else:
            collection(system.ntp, 'servers').append(s.NTPServer(
                address=v['address'],
                prefer=True if rule.endswith('prefer') else None,
                network_instance=v.get('vrf'),
                source_interface=source_interface,
                association_type='peer' if is_peer else 'server',
                key_id=v.get('key_id') if has_key else None,
                version=v.get('version') if 'version' in v else None
            ))
            state.bind(f'system/ntp/servers/{len((system.ntp.servers or [])) - 1}', line)
    elif rule in ('services_logging', 'services_logging_legacy', 'services_logging_update', 'services_logging_remove', 'services_logging_legacy_remove',
                  'services_logging_vrf', 'services_logging_vrf_transport', 'services_logging_transport',
                  'services_logging_port', 'services_logging_vrf_port'):
        syslog_destination(state, r)
    elif rule in ('services_logging_on', 'services_logging_off'):
        state.assign(system.logging, 'enabled', v['enabled'], 'system/logging', line, list(v))
    elif rule in ('services_aaa_on', 'services_aaa_off'):
        state.assign(system.aaa, 'enabled', v['enabled'], 'system/aaa', line, list(v))
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
    elif rule in ('services_logging_source', 'services_logging_source_vrf'):
        if 'vrf' in v:
            state.assign(system.logging, 'source_vrf', v['vrf'], 'system/logging', line)
        else:
            state.assign(system.logging, 'source_interface', v['interface'], 'system/logging', line)
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
        # default ip source-route restores the default (enabled on Cisco IOS)
        system.ip_services.source_routing = True
        state.bind('system/ip_services/source_routing', line, list(v))
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
    elif rule in ('services_snmp_group_v3', 'services_snmp_group_v1_v2c'):
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
        if rule == 'services_snmp_group_v3':
            group.version = 'v3'
        elif 'version' in v:
            group.version = v['version']
        if 'sec_level' in v:
            group.security_level = v['sec_level']
        collection(system.snmp, 'groups').append(group)
        state.bind(f'system/snmp/groups/{len((system.snmp.groups or [])) - 1}', line)
    elif rule == 'services_snmp_group_remove':
        name = v['name']
        version = v.get('version')
        groups = system.snmp.groups or []
        for i, g in enumerate(groups):
            if g.name == name and (version is None or g.version == version):
                groups.pop(i)
                state.unbind(f'system/snmp/groups/{i}')
                break


def declare(state, r):
    rule, v, line = r['rule'], r['values'], r['source_line']
    if rule == 'services_line':
        items = collection(state.c.system.management, 'lines')
        item = next((item for item in items if item.name == v['name']), None)
        if item is None:
            item = s.ManagementLine(name=v['name'])
            items.append(item)
        path = f'system/management/lines/{items.index(item)}'
        state.entities[line] = path
        state.bind(path + '/name', line)
        state.bind(path, line)
        return True
    if rule in ('services_tacacs', 'services_radius'):
        return aaa_administration.server_declare(state, r)
    if rule == 'admin_aaa_group':
        return aaa_administration.group_declare(state, r)
    return False


def resolve(state, r):
    line, v = r['source_line'], r['values']
    rule = r['rule']
    system = state.c.system

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
    elif rule in ('services_ntp_authenticate', 'services_ntp_authenticate_remove'):
        state.assign(system.ntp, 'authentication_enabled', v.get('enabled', True), 'system/ntp', line)
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
        existing = next((k for k in (ntp.authentication_keys or []) if k.identifier == identifier), None)
        if existing:
            idx = (ntp.authentication_keys or []).index(existing)
            state.unbind(f'system/ntp/authentication_keys/{idx}')
            ntp.authentication_keys.remove(existing)
    elif rule in ('services_ntp_trusted_key', 'services_ntp_trusted_key_single'):
        ntp = system.ntp
        start = v['start'] if 'start' in v else v['identifier']
        end = v.get('end')
        existing = next((tk for tk in (ntp.trusted_keys or []) if tk.identifier == start), None)
        if existing:
            if end and end > start:
                existing.range_end = end
            state.bind(f'system/ntp/trusted_keys/{(ntp.trusted_keys or []).index(existing)}/identifier', line)
            if end:
                state.bind(f'system/ntp/trusted_keys/{(ntp.trusted_keys or []).index(existing)}/range_end', line)
        else:
            idx = len(ntp.trusted_keys or [])
            collection(ntp, 'trusted_keys').append(s.NTPTrustedKey(identifier=start, range_end=end))
            state.bind(f'system/ntp/trusted_keys/{idx}/identifier', line)
            if end:
                state.bind(f'system/ntp/trusted_keys/{idx}/range_end', line)
    elif rule == 'services_ntp_trusted_key_remove':
        ntp = system.ntp
        identifier = v['identifier']
        existing = next((tk for tk in (ntp.trusted_keys or []) if tk.identifier == identifier), None)
        if existing:
            ntp.trusted_keys.remove(existing)
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
    elif rule in ('services_snmp_user_v3', 'services_snmp_user_v3_remote'):
        params = v.get('params', '')
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
        users_list = collection(system.snmp, 'users')
        users_list.append(user)
        state.bind(f'system/snmp/users/{len(users_list) - 1}', line)
    elif rule == 'services_snmp_user_remove':
        username = v['username']
        group = v['group']
        users = system.snmp.users or []
        for i, u in enumerate(users):
            if u.username == username and u.group_reference == group:
                users.pop(i)
                state.unbind(f'system/snmp/users/{i}')
                break
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
    elif rule in ('services_snmp_group_v3', 'services_snmp_group_v1_v2c'):
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
        if rule == 'services_snmp_group_v3':
            group.version = 'v3'
        elif 'version' in v:
            group.version = v['version']
        if 'sec_level' in v:
            group.security_level = v['sec_level']
        collection(system.snmp, 'groups').append(group)
        state.bind(f'system/snmp/groups/{len((system.snmp.groups or [])) - 1}', line)
    elif rule == 'services_snmp_group_remove':
        name = v['name']
        version = v.get('version')
        groups = system.snmp.groups or []
        for i, g in enumerate(groups):
            if g.name == name and (version is None or g.version == version):
                groups.pop(i)
                state.unbind(f'system/snmp/groups/{i}')
                break
    elif rule in (
        'services_snmp_host_traps', 'services_snmp_host_traps_vrf', 'services_snmp_host_traps_simple',
        'services_snmp_host_implicit_v1', 'services_snmp_host_implicit_v1_vrf',
        'services_snmp_host_implicit_v1_vrf_alt', 'services_snmp_host_implicit_v1_udp_vrf',
        'services_snmp_host_implicit_version', 'services_snmp_host_implicit_version_vrf',
        'services_snmp_host_implicit_version_vrf_alt', 'services_snmp_host_implicit_version_udp_vrf',
        'services_snmp_host_traps_implicit', 'services_snmp_host_traps_implicit_vrf',
        'services_snmp_host_implicit_traps', 'services_snmp_host_implicit_traps_vrf',
        'services_snmp_host_informs', 'services_snmp_host_informs_vrf', 'services_snmp_host_informs_simple',
        'services_snmp_host_informs_implicit', 'services_snmp_host_informs_implicit_vrf',
        'services_snmp_host_informs_implicit_vrf_alt', 'services_snmp_host_informs_implicit_udp_vrf'):
        host_type = 'traps' if 'traps' in rule or 'implicit_v1' in rule or 'implicit_version' in rule else 'informs'
        host = s.SNMPHost(destination=v['destination'], type=host_type)
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
        collection(system.snmp, 'hosts').append(host)
        state.bind(f'system/snmp/hosts/{len((system.snmp.hosts or [])) - 1}', line)
    elif rule == 'services_snmp_host_remove':
        destination = v['destination']
        hosts = system.snmp.hosts or []
        for i, h in enumerate(hosts):
            if h.destination == destination:
                hosts.pop(i)
                state.unbind(f'system/snmp/hosts/{i}')
                break
    elif rule in ('services_snmp_enable_traps', 'services_snmp_enable_traps_remove'):
        if system.snmp.trap_config is None:
            system.snmp.trap_config = s.SNMPTrapConfig()
        state.unbind('system/snmp/trap_config')
        if rule == 'services_snmp_enable_traps':
            system.snmp.trap_config.enabled = True
            system.snmp.trap_config.notification_types = v['types'].split()
            state.bind('system/snmp/trap_config', line, list(v))
        else:
            system.snmp.trap_config.enabled = False
            types_to_remove = v['types'].split()
            if system.snmp.trap_config.notification_types:
                system.snmp.trap_config.notification_types = [t for t in system.snmp.trap_config.notification_types if t not in types_to_remove]
            state.bind('system/snmp/trap_config', line, list(v))
    elif rule in ('services_snmp_engineid', 'services_snmp_engineid_remove'):
        if rule == 'services_snmp_engineid':
            system.snmp.engine_id = v['id']
        else:
            system.snmp.engine_id = None
        state.bind('system/snmp/engine_id', line, list(v))
    elif rule in ('services_snmp_view', 'services_snmp_view_remove'):
        if rule == 'services_snmp_view':
            included = v.get('included', 'included')
            if isinstance(included, str):
                included = included.lower() == 'included'
            view = s.SNMPView(name=v['name'], oid=v['oid'], included=included)
            collection(system.snmp, 'views').append(view)
            state.bind(f'system/snmp/views/{len((system.snmp.views or [])) - 1}', line)
        else:
            name = v['name']
            oid = v['oid']
            views = system.snmp.views or []
            for i, vi in enumerate(views):
                if vi.name == name and vi.oid == oid:
                    views.pop(i)
                    state.unbind(f'system/snmp/views/{i}')
                    break
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
    elif rule in ('services_banner', 'services_banner_remove'):
        if rule == 'services_banner_remove':
            name = v['type']
            banners = system.identity.banners or []
            for i, b in enumerate(banners):
                if b.type == name:
                    # Unbind the specific banner
                    state.unbind(f'system/identity/banners/{i}')
                    # Remove from list
                    banners.pop(i)
                    # Rebind subsequent banners to update their indices
                    for j in range(i, len(banners)):
                        banner = banners[j]
                        state.bind(f'system/identity/banners/{j}', line, ['type', 'text_present'])
                    break
        else:
            # Banner body is opaque; inventory provides text_present
            node = state.nodes.get(line)
            text_present = getattr(node, 'text_present', True) if node else True
            collection(system.identity, 'banners').append(s.Banner(type=v['type'], text_present=text_present))
            state.bind(f'system/identity/banners/{len((system.identity.banners or [])) - 1}', line, list(v))
    elif rule in ('services_banner_incoming', 'services_banner_incoming_remove'):
        if rule == 'services_banner_incoming_remove':
            name = 'incoming'
            banners = system.identity.banners or []
            for i, b in enumerate(banners):
                if b.type == 'incoming':
                    banners.pop(i)
                    state.unbind(f'system/identity/banners/{i}')
                    break
        else:
            # Banner body is opaque; inventory provides text_present
            node = state.nodes.get(line)
            text_present = getattr(node, 'text_present', True) if node else True
            collection(system.identity, 'banners').append(s.Banner(type='incoming', text_present=text_present))
            state.bind(f'system/identity/banners/{len((system.identity.banners or [])) - 1}', line, list(v))
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
    elif rule in ('services_transport_output', 'services_transport_output_remove', 'services_access_class', 'services_access_class_vrf', 'services_access_class_out', 'services_access_class_remove', 'services_access_class_remove_all', 'services_exec_on', 'services_exec_off', 'services_exec_default', 'services_login_off', 'services_timeout', 'services_timeout_minutes', 'services_timeout_remove', 'services_timeout_default', 'services_login', 'services_login_plain', 'services_login_authentication_remove', 'services_login_authentication_remove_args'):
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
            state.assign(item, 'access_list', v['acl'], path, line)
            state.assign(item, 'access_list_direction', 'in', path, line)
        elif rule == 'services_access_class_vrf':
            state.assign(item, 'access_list', v['acl'], path, line)
            state.assign(item, 'access_list_vrf', True, path, line)
        elif rule == 'services_access_class_out':
            state.assign(item, 'access_list', v['acl'], path, line)
            state.assign(item, 'access_list_direction', 'out', path, line)
        elif rule == 'services_access_class_remove':
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
            state.assign(item, 'idle_timeout_seconds', v['minutes'] * 60 + seconds, path, line)
        elif rule == 'services_timeout_minutes':
            state.assign(item, 'idle_timeout_seconds', v['minutes'] * 60, path, line)
        elif rule in ('services_timeout_remove', 'services_timeout_default'):
            item.idle_timeout_seconds = None
            state.unbind(path + '/idle_timeout_seconds')
        elif rule == 'services_login':
            state.assign(item, 'authentication', authentication(v['method']), path, line)
        elif rule == 'services_login_plain':
            state.assign(item, 'authentication', s.Authentication(method='line_password'), path, line)
        elif rule in ('services_login_authentication_remove', 'services_login_authentication_remove_args'):
            item.authentication = None
            state.unbind(path + '/authentication')
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
        # default ip source-route restores the default (enabled on Cisco IOS)
        system.ip_services.source_routing = True
        state.bind('system/ip_services/source_routing', line, list(v))
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


def authentication(value):
    if value == 'local':
        return s.Authentication(method='local')
    if value.startswith('authentication '):
        return s.Authentication(method='aaa', method_list=value[len('authentication '):])
    return None


def syslog_destination(state, r):
    rule, v, line = r['rule'], r['values'], r['source_line']
    is_remove = rule.endswith('_remove')
    is_legacy = 'legacy' in rule
    is_vrf = 'vrf' in rule
    has_transport = 'transport' in rule
    has_port = 'port' in rule

    if is_remove:
        address = v.get('address') or v.get('target')
        vrf = v.get('vrf')
        path = 'system/logging/destinations'
        owner = state.c.system.logging
        entries = []
        previous = None
        for index, destination in enumerate(owner.destinations or []):
            source = next(b.record for b in state.bindings if b.path == f'/{path}/{index}/address')
            if destination.address == address and destination.vrf == vrf:
                previous = destination
            else:
                entries.append((destination, source))

        state.unbind(path)
        state.absences.confirmed_empty.discard('/' + path)
        owner.destinations = [entry for entry, _ in entries] or None
        for index, (destination, source) in enumerate(entries):
            for field in ('address', 'port', 'transport', 'vrf'):
                if getattr(destination, field) is not None:
                    state.bind(f'{path}/{index}/{field}', source)
        return

    if is_vrf:
        address, vrf, transport, port = _logging_target_vrf(v)
    else:
        address, vrf, transport, port = _logging_target(v)

    removed = False
    supported = True

    if rule in ('services_logging', 'services_logging_legacy'):
        address = v.get('address') or v.get('target')

    owner = state.c.system.logging
    path = 'system/logging/destinations'
    entries = []
    previous = None
    for index, destination in enumerate(owner.destinations or []):
        source = next(b.record for b in state.bindings if b.path == f'/{path}/{index}/address')
        if destination.address == address and destination.vrf == vrf:
            previous = destination
        else:
            entries.append((destination, source))

    if not removed and supported:
        if previous and (previous.transport, previous.port, previous.vrf) != (transport, port, vrf):
            transport = port = vrf = None
        entries.append((s.SyslogDestination(address=address, transport=transport, port=port, vrf=vrf, severity=None), line))

    state.unbind(path)
    state.absences.confirmed_empty.discard('/' + path)
    owner.destinations = [entry for entry, _ in entries] or None
    for index, (destination, source) in enumerate(entries):
        for field in ('address', 'port', 'transport', 'vrf'):
            if getattr(destination, field) is not None:
                state.bind(f'{path}/{index}/{field}', source)


def _logging_target(values):
    target = values.get('target', '')
    address = values.get('address', '')
    vrf = values.get('vrf')
    transport = values.get('transport')
    port = values.get('port')

    if address and (vrf or transport or port):
        return address, vrf, transport, port

    if target:
        tokens = target.split()
        if tokens:
            address = tokens[0]
            i = 1
            while i < len(tokens):
                if tokens[i] == 'vrf' and i + 1 < len(tokens):
                    vrf = tokens[i + 1]
                    i += 2
                elif tokens[i] == 'transport' and i + 1 < len(tokens):
                    transport = tokens[i + 1]
                    i += 2
                elif tokens[i] == 'port' and i + 1 < len(tokens):
                    try:
                        port = int(tokens[i + 1])
                    except ValueError:
                        pass
                    i += 2
                else:
                    i += 1
    return address, vrf, transport, port


def _logging_target_vrf(values):
    target = values.get('target', '')
    address = values.get('address', '')
    vrf = values.get('vrf')
    transport = values.get('transport')
    port = values.get('port')

    if address and (vrf or transport or port):
        return address, vrf, transport, port

    if target:
        tokens = target.split()
        if tokens:
            address = tokens[0]
            i = 1
            while i < len(tokens):
                if tokens[i] == 'vrf' and i + 1 < len(tokens):
                    vrf = tokens[i + 1]
                    i += 2
                elif tokens[i] == 'transport' and i + 1 < len(tokens):
                    transport = tokens[i + 1]
                    i += 2
                elif tokens[i] == 'port' and i + 1 < len(tokens):
                    try:
                        port = int(tokens[i + 1])
                    except ValueError:
                        pass
                    i += 2
                else:
                    i += 1
    return address, vrf, transport, port