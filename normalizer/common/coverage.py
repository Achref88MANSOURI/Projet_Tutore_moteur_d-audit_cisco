"""Internal coverage of relevant inventory nodes, not another CLI interpreter.

Only family prefixes are classified. TTP and existing handlers remain the sole
producers of configuration facts. This never attests hardware, defaults or the
origin/completeness of a file; no source text leaves this module.
"""


def summary(engine):
    counts={}
    for line,node in engine.nodes.items():
        if node.kind!='command':continue
        tokens=node.text.lower().split()
        if not tokens:continue
        action=tokens[0] if tokens[0] in ('no','default') else None
        words=tokens[1:] if action else tokens
        families=[]
        if words[:1]==['username']:families=['local_users']
        elif words[:2]==['enable','secret']:families=['enable_secret']
        elif words[:2]==['enable','password']:families=['enable_password']
        elif words[:2]==['service','password-encryption']:families=['password_encryption']
        elif words[:3] in (['ip','ssh','time-out'],['ip','ssh','timeout']):families=['ssh_timeout']
        elif words[:3]==['ip','ssh','authentication-retries']:families=['ssh_authentication_retries']
        elif words[:2]==['service','dhcp']:families=['dhcp_service']
        elif words[:2]==['ip','identd']:families=['identd']
        elif words[:2]==['service','tcp-keepalives-in']:families=['tcp_keepalives_in']
        elif words[:2]==['service','tcp-keepalives-out']:families=['tcp_keepalives_out']
        elif words[:2]==['service','pad']:families=['classic_pad']
        elif words[:2]==['logging','console']:families=['logging_console']
        elif words[:2]==['logging','trap']:families=['logging_trap']
        elif words[:3]==['service','timestamps','debug']:families=['timestamps_debug']
        elif words[:2] in (['banner','exec'],['banner','login'],['banner','motd']):families=['banner_'+words[1]]
        elif words[:2]==['snmp-server','community']:
            families=['snmp_communities','snmp_community_access','snmp_community_acl']
        elif words[:2]==['snmp-server','group']:families=['snmp_groups']
        elif words[:2]==['snmp-server','user']:families=['snmp_users']
        elif words[:2]==['snmp-server','host']:
            families=['snmp_hosts']
            # A notification-host credential is not a community declaration.
            # Keep its coverage independent from the configured access inventory.
        elif words[:2]==['ntp','authenticate']:families=['ntp_authenticate']
        elif words[:2]==['ntp','authentication-key']:families=['ntp_authentication_keys']
        elif words[:2]==['ntp','trusted-key']:families=['ntp_trusted_keys']
        elif words[:2]==['ntp','server']:
            families=['ntp_servers'] + (['ntp_source'] if 'source' in words[2:] else [])
        elif words[:2]==['ntp','peer']:
            families=['ntp_servers'] + (['ntp_source'] if 'source' in words[2:] else [])
        elif words[:2]==['ntp','source']:families=['ntp_source']
        elif words[:3] in (['ip','radius','source-interface'],['ip','tacacs','source-interface']):
            families=['aaa_source_interface']
        elif words[:3]==['ip','tftp','source-interface']:families=['tftp_source']
        elif words[:2] in (['tacacs-server','host'],['tacacs','server'],['radius-server','host'],['radius','server']):
            families=['aaa_servers']
        elif words[:3] in (['aaa','authentication','login'],['aaa','authentication','enable']):
            families=['aaa_'+words[2]]
        elif words[:2]==['aaa','accounting'] and len(words)>2:
            families=['aaa_accounting_'+words[2]]
        elif words[:2]==['aaa','new-model']:families=['aaa_login','aaa_enable']
        elif words[:2]==['logging','source-interface']:families=['logging_source']
        elif words[:3]==['snmp-server','enable','traps'] and (len(words)==3 or words[3]=='snmp'):
            families=['snmp_notifications']
        root=engine.nodes.get(node.root)
        header=(root.text.lower().split() if root else [])
        if header[:1]==['line'] and len(header)>1:
            kind='con' if header[1]=='console' else header[1]
            if kind in ('con','aux','tty','vty'):
                if line==node.root:families=[f'line_{kind}_{p}' for p in ('auth','transport','timeout','acl','exec')]
                elif words[:1]==['login']:families=[f'line_{kind}_auth']
                elif words[:2]==['transport','input']:families=[f'line_{kind}_transport']
                elif words[:1]==['exec-timeout']:families=[f'line_{kind}_timeout']
                elif words[:1]==['exec']:families=[f'line_{kind}_exec']
                elif words[:1]==['access-class'] or words[:2]==['ipv6','access-class']:families=[f'line_{kind}_acl']
        if header[:1]==['interface'] and words[:5]==['ip','verify','unicast','source','reachable-via']:
            families=['interface_urpf']
        if not families:continue
        record=engine.records.get(line);validation=engine.validation.get(line,{})
        known=bool(record and validation.get('valid') and line not in engine.failed
                   and line not in engine.ambiguous and line not in getattr(engine,'uncertain',set())
                   and all(v=='validated' for v in validation.get('fields',{}).values()))
        if known and node.parent is not None and families[0] in ('local_users','snmp_communities','aaa_login','aaa_enable','aaa_servers','logging_source','snmp_notifications','ntp_servers'):
            known=False
        if known and 'local_users' in families:
            known=record['rule'] in {'services_user','services_user_simple','services_user_no_format',
                'services_user_privilege_no_format','services_user_privilege','services_user_remove',
                'services_user_algorithm','services_user_nopassword'}
        for family in families:
            value=counts.setdefault(family,[0,0]);value[0]+=1;value[1]+=int(known)
    return [dict(family=f,relevant=n,recognized=k) for f,(n,k) in sorted(counts.items())]
