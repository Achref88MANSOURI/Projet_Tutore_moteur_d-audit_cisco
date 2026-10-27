"""v0.2 semantic mapping with per-parameter accounting and conservative statuses."""
from collections import defaultdict
from copy import deepcopy
from ipaddress import ip_address,ip_network,IPv4Address
import re
from schemas import normalizedconfig_v02 as s
from schemas.normalizedconfig import Evidence,UnknownCommand,Diagnostic
from .mapping import Mapper,asn,prefix_length
from parser.inventory import redacted
from parser.validation import validate_record

# Explicitly reviewed base mappings. Free-form policy expressions are NOT
# automatically complete simply because the old mapper attached a proof.
BASE_RULES={'if_header','if_description','if_mtu','if_vrf','if_legacy_vrf','if_shutdown','if_no_shutdown','if_ipv4','if_ipv4_secondary','if_ipv6','if_no_ipv4',
 'if_acl4','if_acl6','if_switchport','if_routed','if_access_vlan','if_native_vlan','if_trunk_vlans','if_trunk_modify','if_lag','if_service_policy','if_ospf2',
 'if_tunnel_source','if_tunnel_destination','bgp_header','bgp_router_id','bgp_remote_as','bgp_description','bgp_group_member','bgp_group_definition','bgp_shutdown','bgp_no_shutdown','bgp_route_map',
 'ospf_header','ospf_header_vrf','ospf_router_id','ospf_network','ospf_passive','vrf_header','vrf_legacy_header','vrf_rd','vrf_target','policy_header','policy_set_localpref','policy_set_metric','policy_set_weight',
 'services_hostname','services_domain','services_domain_alt','services_dns','services_ntp','services_ntp_prefer','services_ntp_vrf','services_ntp_vrf_prefer','services_ntp_source','services_logging','services_logging_legacy','services_logging_trap',
 'services_aaa_on','services_aaa_off','services_user','services_user_simple','services_snmp_community','services_snmp_community_simple','services_snmp_location','services_snmp_contact','services_ssh_version',
 'services_http_on','services_http_off','services_https_on','services_https_off','services_line','services_transport','services_timeout','services_timeout_minutes','services_access_class','services_login','services_login_plain',
 'services_auth_address','services_nat_static','advanced_vlan','advanced_vlan_name','advanced_qos_policymap'}


class SemanticMapper:
    def __init__(self,x,text,source,os_family,raw_hash):
        self.x=x;self.nodes=x['nodes'];self.records=x['records'];self.validation={line:validate_record(r) for line,r in self.records.items()}
        for line,choice in x.get('selection',{}).items():
            if choice['ambiguous']:
                self.validation[line]['valid']=False
                self.validation[line]['invalid_fields']=list(self.records[line]['values'])
                self.validation[line]['fields']={k:'invalid' for k in self.records[line]['values']}
        identities=set()
        for line,r in sorted(self.records.items()):
            if r['rule'] not in ('if_header','policy_header'):continue
            key=(r['rule'],r['values'].get('name'),r['values'].get('sequence'))
            if key in identities:
                self.validation[line]['valid']=False
                self.validation[line]['invalid_fields']=list(r['values'])
                self.validation[line]['fields']={k:'invalid' for k in r['values']}
            identities.add(key)
        for line,r in self.records.items():
            if any(not self.validation.get(n,{'valid':True})['valid'] for n in r['context_lines']):
                self.validation[line]['valid']=False
                self.validation[line]['invalid_fields']=list(r['values'])
                self.validation[line]['fields']={k:'invalid' for k in r['values']}
        valid=dict(x);valid['records']={k:v for k,v in self.records.items() if self.validation[k]['valid']}
        self.base=Mapper(valid,text,source,os_family,raw_hash)
        self.result=s.migrate_v01(self.base.run().model_dump(mode='json'))
        self.c=self.result.configuration;self.evidence=self.result.evidence
        self.consumed=defaultdict(dict);self.extra_invalid={};self.partial_notes={};self.ambiguous=set()
        for line in self.base.mapped:
            r=self.records[line];rule=r['rule'];values=r['values']
            complete=rule in BASE_RULES or rule.startswith('route_') or rule.startswith('acl_')
            if complete:
                paths=[e.path for e in self.evidence if e.status=='explicit' and e.line_start==line]
                for key in values:
                    if key=='options' and values[key]=='log-input':continue
                    if paths:self.consumed[line][key]=paths

    def prove(self,path,line,fields):
        pointer='/configuration/'+path
        node=self.nodes[line]
        self.evidence.append(Evidence(path=pointer,status='explicit',source_file=self.result.metadata.source_file,line_start=line,line_end=line,
            raw_command=redacted(node.text),parser_rule='ttp:'+self.records[line]['rule'],confidence=1))
        for field in fields:self.consumed[line][field]=[pointer]

    def assign(self,obj,field,value,path,line,keys):
        setattr(obj,field,value);self.prove(path+'/'+field,line,keys)

    def root(self,r):return self.records.get(r['root_line'])

    def af(self,r):
        af=next((self.records[n] for n in reversed(r['context_lines']) if self.records.get(n,{}).get('rule','').startswith('bgp_af') and 'afi' in self.records[n]['values']),None)
        return af['values'] if af else None

    def process(self,r):
        a=r['values'] if r['rule'].startswith('bgp_af') and 'afi' in r['values'] else self.af(r)
        vrf=a.get('vrf') if a else None
        local=asn(self.root(r)['values']['local_as'])
        proc=next((p for p in self.c.routing.bgp if p.local_as==local and p.network_instance==vrf),None)
        if proc is None:proc=s.BGPProcess(local_as=local,network_instance=vrf);self.c.routing.bgp.append(proc)
        return proc,'routing/bgp/'+str(self.c.routing.bgp.index(proc)),a

    def interface(self,r):
        root=self.root(r)
        if r['rule']=='if_service_instance' or any(self.records.get(n,{}).get('rule')=='if_service_instance' for n in r['context_lines']):
            return self.ethernet_service(r)
        if not root or root['rule']!='if_header' or len(r['context_lines'])!=1:return
        obj=next(i for i in self.c.interfaces if i.name==root['values']['name']);path=f'interfaces/{self.c.interfaces.index(obj)}'
        rule,v,line=r['rule'],r['values'],r['source_line']
        direct={'if_duplex':('ethernet.duplex','duplex'),'if_negotiation':('ethernet.negotiation','negotiation'),'if_media':('ethernet.media','media'),
            'if_proxyarp':('proxy_arp','enabled'),'if_redirects':('redirects','enabled'),'if_keepalive_off':('keepalive_enabled','enabled'),
            'if_ipv6_enable':('ipv6_enabled','enabled'),'if_unnumbered':('unnumbered_interface','interface'),'if_mss':('tcp_mss','mss'),
            'if_mpls':('mpls_enabled','enabled'),'if_pim':('pim_mode','mode'),'if_isis':('isis_process','process'),'if_isis_network':('isis_network_type','network_type'),
            'if_ospf_network':('ospf_network_type','network_type'),'if_cdp_off':('cdp_enabled','enabled')}
        if rule in direct:
            target,key=direct[rule];fields=target.split('.');owner=obj.ethernet if len(fields)>1 else obj
            self.assign(owner,fields[-1],v[key],path+('/ethernet' if len(fields)>1 else ''),line,[key])
        elif rule=='if_speed':
            fields=obj.ethernet.model_dump()
            fields.update(speed_mode='auto' if v['speed']=='auto' else 'fixed',speed_bps=None if v['speed']=='auto' else int(v['speed'])*1000000)
            obj.ethernet=s.Ethernet(**fields)
            self.prove(path+'/ethernet',line,['speed'])
        elif rule in ('if_dot1q','if_dot1q_lower','if_qinq'):
            obj.encapsulation=s.Encapsulation(kind='qinq' if 'inner_vlan' in v else 'dot1q',outer_vlan=v['vlan'],inner_vlan=v.get('inner_vlan'))
            self.prove(path+'/encapsulation',line,list(v))
        elif rule=='if_flow':
            if v['direction'] not in ('ingress','egress'):raise ValueError('Flow direction')
            obj.flow_directions.append(v['direction']);self.prove(path+'/flow_directions',line,['direction'])
        elif rule=='if_ospf3':
            obj.ospf_bindings.append(s.OSPFBinding(version=3,process=v['process'],area=v['area']))
            self.prove(path+'/ospf_bindings',line,list(v))
        elif rule=='if_mop_off':
            field={'enabled':'mop_enabled','sysid':'mop_sysid'}.get(v['feature'])
            if field is None:raise ValueError('MOP option')
            self.assign(obj,field,False,path,line,list(v))

    def bgp(self,r):
        proc,path,af=self.process(r);v=r['values'];rule=r['rule'];line=r['source_line']
        if rule.startswith('bgp_af') and 'afi' in v:
            self.family(proc,v);self.prove(path+'/family_options',line,list(v));return
        options=self.family(proc,af) if af else proc
        option_path=path+f'/family_options/{proc.family_options.index(options)}' if af else path
        process_flags={'bgp_log_changes':'log_neighbor_changes','bgp_compare_med':'compare_med','bgp_deterministic_med':'deterministic_med',
            'bgp_no_default_ipv4':'default_ipv4_unicast','bgp_no_sync':'synchronization','bgp_no_auto_summary':'auto_summary','bgp_no_enforce_first_as':'enforce_first_as'}
        if rule in process_flags:self.assign(proc,process_flags[rule],v['enabled'],path,line,list(v));return
        if rule=='bgp_dampening':self.assign(options,'dampening',v['enabled'],option_path,line,list(v));return
        if rule=='bgp_additional_select':self.assign(options,'additional_paths_selection',v['selection'],option_path,line,list(v));return
        if rule=='bgp_additional_send':
            if {v['send'],v['receive']}!={'send','receive'}:raise ValueError('Additional paths flags')
            options.additional_paths_send=True;options.additional_paths_receive=True;self.prove(option_path+'/additional_paths_send',line,list(v));self.prove(option_path+'/additional_paths_receive',line,list(v));return
        if rule=='bgp_maximum_paths':
            options.maximum_paths.append(s.MaximumPaths(type=v['type'],count=v['count']));self.prove(option_path+'/maximum_paths',line,list(v));return
        if rule=='bgp_aggregate':
            prefix=ip_network(v['prefix']+'/'+str(prefix_length(v['mask'])),strict=False)
            proc.aggregates.append(s.Aggregate(prefix=prefix,options=v['option'].split(),afi=af.get('afi') if af else None,safi=af.get('safi') if af else None))
            self.validation[line]['fields']['option']='validated';self.prove(path+'/aggregates',line,list(v));return
        if rule.startswith('bgp_redistribute'):
            proc.redistributions.append(s.Redistribution(protocol=v['protocol'],process=v.get('process'),route_map=v.get('policy'),afi=af.get('afi') if af else None,safi=af.get('safi') if af else None))
            self.prove(path+'/redistributions',line,list(v));return
        if rule in ('bgp_network','bgp_network4'):
            if 'mask' not in v and '/' not in v['prefix']:raise ValueError('No explicit prefix length; classful defaults are not inferred')
            p=ip_network(v['prefix']+'/'+str(prefix_length(v['mask'])),strict=False) if 'mask' in v else ip_network(v['prefix'],strict=False)
            proc.networks.append(s.BGPNetwork(prefix=p,afi=af.get('afi') if af else None,safi=af.get('safi') if af else None))
            self.prove(path+'/networks',line,list(v));return
        if rule not in ('bgp_remote_as','bgp_update_source','bgp_route_map','bgp_activate','bgp_deactivate','bgp_send_community','bgp_send_community_option','bgp_reflector','bgp_next_hop','bgp_group_member'):return
        peer=v['peer']
        try:peer=str(ip_address(peer));kind='neighbor'
        except ValueError:
            if peer not in proc.peer_groups:raise ValueError('A native peer identity cannot be guessed to be a group')
            kind='group'
        if af:
            family=self.family(proc,af);items=family.peers
            basepath=path+f'/family_options/{proc.family_options.index(family)}/peers'
        else:items=proc.peer_options;basepath=path+'/peer_options'
        obj=next((p for p in items if p.peer==peer and p.kind==kind),None)
        if obj is None:obj=s.BGPPeerOptions(peer=peer,kind=kind);items.append(obj)
        fields={'bgp_remote_as':('remote_as',asn(v['remote_as']))} if rule=='bgp_remote_as' else {}
        if rule=='bgp_update_source':fields={'update_source':v['source']}
        if rule in ('bgp_activate','bgp_deactivate'):fields={'active':v['enabled']}
        if rule=='bgp_reflector':fields={'route_reflector_client':v['enabled']}
        if rule=='bgp_next_hop':fields={'next_hop_self':v['enabled']}
        if rule=='bgp_group_member':fields={'inherited_group':v['group']}
        if rule in ('bgp_send_community','bgp_send_community_option'):
            mode='command_without_option' if v['option']=='unspecified' else v['option']
            fields={'send_community':mode}
        if rule=='bgp_route_map':
            if v['direction'] not in ('in','out'):raise ValueError('Policy direction')
            fields={'import_policies' if v['direction']=='in' else 'export_policies':[v['policy']]}
        for key,value in fields.items():setattr(obj,key,value)
        self.prove(basepath+'/'+str(items.index(obj)),line,list(v))

    @staticmethod
    def family(proc,v):
        obj=next((a for a in proc.family_options if a.afi==v['afi'] and a.safi==v.get('safi')),None)
        if obj is None:obj=s.BGPAddressFamily(afi=v['afi'],safi=v.get('safi'));proc.family_options.append(obj)
        return obj

    def ospf(self,r):
        root=self.root(r)
        if not root or root['rule'] not in ('ospf_header','ospf_header_vrf','ospf3_header'):return
        version=3 if root['rule']=='ospf3_header' else 2;rv=root['values'];v=r['values'];line=r['source_line'];rule=r['rule']
        proc=next((p for p in self.c.routing.ospf if p.identifier==rv['process'] and p.version==version and p.network_instance==rv.get('vrf')),None)
        if proc is None:proc=s.OSPFProcess(identifier=rv['process'],version=version,network_instance=rv.get('vrf'));self.c.routing.ospf.append(proc)
        path=f'routing/ospf/{self.c.routing.ospf.index(proc)}'
        if rule in ('ospf_header','ospf_header_vrf','ospf3_header'):self.prove(path,line,list(v))
        elif rule=='ospf_router_id':self.assign(proc,'router_id',IPv4Address(v['router_id']),path,line,list(v))
        elif rule=='ospf_log':self.assign(proc,'log_adjacency_changes',v['enabled'],path,line,list(v))
        elif rule=='ospf_area':
            if v['type'] not in ('stub','nssa','normal'):raise ValueError('Area type')
            area=str(IPv4Address(int(v['area']))) if v['area'].isdigit() else str(IPv4Address(v['area']))
            obj=next((a for a in proc.areas if a.area_id==area),None)
            if obj is None:obj=s.OSPFArea(area_id=area);proc.areas.append(obj)
            obj.type=v['type'];self.prove(path+'/areas',line,list(v))
        elif rule=='ospf_virtual_link':
            proc.virtual_links.append(s.VirtualLink(area=v['area'],peer_router_id=v['peer']));self.prove(path+'/virtual_links',line,list(v))
        elif rule in ('ospf_redistribute','ospf_redistribute_simple'):
            options=v.get('options','').split();process=None;subnets=None;route_map=None
            if options and options[0].isdigit():process=options.pop(0)
            if 'subnets' in options:subnets=True;options.remove('subnets')
            if len(options)==2 and options[0]=='route-map':route_map=options[1];options=[]
            if options:raise ValueError('Unparsed redistribution qualifier')
            proc.redistributions.append(s.Redistribution(protocol=v['protocol'],process=process,subnets=subnets,route_map=route_map))
            if 'options' in v:self.validation[line]['fields']['options']='validated'
            self.prove(path+'/redistributions',line,list(v))
        elif rule=='ospf_default':
            if v['options']!='always':raise ValueError('Unparsed default origination option')
            proc.default_origination=s.DefaultOrigination(enabled=True,always=True)
            self.validation[line]['fields']['options']='validated';self.prove(path+'/default_origination',line,list(v))

    def prefix(self,r):
        v=r['values'];family='ipv6' if r['rule'].startswith('prefix_ipv6') else 'ipv4'
        # Validate the entry BEFORE mutating the collection.
        entry=s.PrefixListEntry(sequence=v.get('sequence'),action=v['action'],prefix=ip_network(v['prefix'],strict=False),ge=v.get('ge'),le=v.get('le'))
        obj=next((p for p in self.c.routing.prefix_lists if p.name==v['name'] and p.family==family),None)
        if obj is None:obj=s.PrefixList(name=v['name'],family=family);self.c.routing.prefix_lists.append(obj)
        if entry.sequence is not None and any(e.sequence==entry.sequence for e in obj.entries):raise ValueError('Duplicate prefix sequence')
        obj.entries.append(entry);s.PrefixList.model_validate(obj.model_dump(mode='json'))
        self.prove(f'routing/prefix_lists/{self.c.routing.prefix_lists.index(obj)}',r['source_line'],list(v))

    def qos(self,r):
        rule=r['rule'];v=r['values'];line=r['source_line'];root=self.root(r)
        if root is None:return
        if root['rule']=='advanced_qos_classmap':
            name=root['values']['name'];obj=next((m for m in self.c.qos.class_maps if m.name==name),None)
            if obj is None:obj=s.ClassMap(name=name,match_mode=root['values']['mode']);self.c.qos.class_maps.append(obj)
            path=f'qos/class_maps/{self.c.qos.class_maps.index(obj)}'
            if rule=='advanced_qos_classmap':self.prove(path,line,list(v));return
            kind={'advanced_qos_match_dscp':('dscp','dscp'),'advanced_qos_match_protocol':('protocol','protocol'),
                'advanced_qos_match_precedence':('precedence','precedence'),'advanced_qos_match_acl':('acl','acl')}.get(rule)
            if kind:obj.matches.append(s.QoSMatch(kind=kind[0],value=str(v[kind[1]])));self.prove(path+'/matches',line,list(v))
        elif root['rule']=='advanced_qos_policymap':
            name=root['values']['name'];obj=next((m for m in self.c.qos.policy_maps if m.name==name),None)
            if obj is None:obj=s.PolicyMap(name=name);self.c.qos.policy_maps.append(obj)
            path=f'qos/policy_maps/{self.c.qos.policy_maps.index(obj)}'
            if rule=='advanced_qos_policymap':self.prove(path,line,list(v));return
            class_record=r if rule=='advanced_qos_class' else next((self.records[n] for n in reversed(r['context_lines']) if self.records.get(n,{}).get('rule')=='advanced_qos_class'),None)
            if class_record is None:return
            name=class_record['values']['name'];cl=next((c for c in obj.classes if c.name==name),None)
            if cl is None:cl=s.PolicyClass(name=name);obj.classes.append(cl)
            if rule=='advanced_qos_class':self.prove(path+'/classes',line,list(v));return
            action={'advanced_qos_set_dscp':('set_dscp','dscp'),'advanced_qos_set_precedence':('set_precedence','precedence'),
                'advanced_qos_priority':('priority_percent','percent'),'advanced_qos_fair':('fair_queue','enabled')}.get(rule)
            if action:cl.actions.append(s.QoSAction(kind=action[0],value=v[action[1]]));self.prove(path+'/classes',line,list(v))

    def pki(self,r):
        root=self.root(r);rule=r['rule'];v=r['values'];line=r['source_line']
        if root is None:return
        pki=self.c.cisco.pki
        if root['rule']=='advanced_pki_trust':
            name=root['values']['name'];obj=next((t for t in pki.trustpoints if t.name==name),None)
            if obj is None:obj=s.Trustpoint(name=name);pki.trustpoints.append(obj)
            path=f'cisco/pki/trustpoints/{pki.trustpoints.index(obj)}'
            if rule=='advanced_pki_trust':self.prove(path,line,list(v));return
            field={'advanced_pki_enrollment':('enrollment','method'),'advanced_pki_revocation':('revocation_check','method'),
                'advanced_pki_subject':('subject_name','subject'),'advanced_pki_keypair':('keypair_reference','name')}.get(rule)
            if field:self.assign(obj,field[0],v[field[1]],path,line,list(v))
        elif root['rule']=='advanced_pki_chain':
            name=root['values']['name'];obj=next((c for c in pki.chains if c.name==name),None)
            if obj is None:obj=s.CertificateChain(name=name);pki.chains.append(obj)
            path=f'cisco/pki/chains/{pki.chains.index(obj)}'
            if rule=='advanced_pki_chain':self.prove(path,line,list(v))
            elif rule=='advanced_pki_certificate':
                obj.certificates.append(s.Certificate(type=v['type'],identifier=v['identifier'],source_line=line));self.prove(path+'/certificates',line,list(v))

    def services(self,r):
        fields={'services_login_logging':('login_success_logging','enabled'),'services_logging_source':('syslog_source_interface','interface'),
            'services_console_off':('console_logging','enabled'),'services_source_route_off':('source_routing','enabled'),
            'services_lookup_off':('dns_lookup_enabled','enabled'),'services_password_encryption_off':('password_encryption_service','enabled'),
            'services_ipv6_routing':('ipv6_unicast_routing','enabled')}
        if r['rule'] in fields:
            field,key=fields[r['rule']];self.assign(self.c.system,field,r['values'][key],'system',r['source_line'],list(r['values']))
        v=r['values'];line=r['source_line'];rule=r['rule']
        if rule.startswith('services_timestamp'):
            obj=s.TimestampPolicy(category=v['category'],format=v['format'],options=v.get('options','').split())
            self.c.system.timestamps.append(obj)
            if 'options' in v:self.validation[line]['fields']['options']='validated'
            self.prove('system/timestamps',line,list(v))
        elif rule=='services_banner':
            self.c.system.banners.append(s.Banner(type=v['type'],delimiter=v['delimiter'],source_line=line));self.prove('system/banners',line,list(v))
        elif rule=='services_http_auth':self.assign(self.c.system,'http_authentication',v['method'],'system',line,list(v))
        elif rule.startswith('services_line_'):
            root=self.root(r)
            if root is None or root['rule']!='services_line':return
            obj=next(o for o in self.c.system.management.lines if o.name==root['values']['name'])
            path=f'system/management/lines/{self.c.system.management.lines.index(obj)}'
            pair={'services_line_synchronous':('logging_synchronous','enabled'),'services_line_privilege':('privilege_level','level'),
                'services_line_stopbits':('stopbits','bits'),'services_line_length':('screen_length','length')}.get(rule)
            if pair:self.assign(obj,pair[0],v[pair[1]],path,line,list(v))
            elif rule=='services_line_preferred':
                tokens=v['transports'].split()
                if any(t not in ('none','all','ssh','telnet') for t in tokens):raise ValueError('Transport protocol')
                self.assign(obj,'preferred_transports',tokens,path,line,list(v))
        elif rule=='services_community_expanded':
            obj=next((c for c in self.c.cisco.community_lists if c.name==v['name']),None)
            if obj is None:obj=s.CommunityList(name=v['name']);self.c.cisco.community_lists.append(obj)
            obj.entries.append(s.CommunityListEntry(action=v['action'],expression=v['expression']))
            self.prove(f'cisco/community_lists/{self.c.cisco.community_lists.index(obj)}',line,list(v))
        elif rule=='services_flow_source':self.assign(self.c.system.flow_export,'source_interface',v['interface'],'system/flow_export',line,list(v))
        elif rule=='services_flow_version':
            self.c.system.flow_export.version=v['version'];self.c.system.flow_export.as_mode=v['as_mode'];self.prove('system/flow_export',line,list(v))
        elif rule=='services_flow_timeout':
            field={'active':'cache_timeout_active_minutes','inactive':'cache_timeout_inactive_seconds'}.get(v['type'])
            if field is None:raise ValueError('Flow timeout mode')
            self.assign(self.c.system.flow_export,field,v['timeout'],'system/flow_export',line,list(v))

    def ethernet_service(self,r):
        root=self.root(r)
        if root is None or root['rule']!='if_header':return
        header=r if r['rule']=='if_service_instance' else next((self.records[n] for n in reversed(r['context_lines']) if self.records.get(n,{}).get('rule')=='if_service_instance'),None)
        if header is None:return
        interface=root['values']['name'];instance=header['values']['instance'];items=self.c.cisco.ethernet_services
        obj=next((o for o in items if o.interface==interface and o.instance==instance),None)
        if obj is None:obj=s.EthernetService(interface=interface,instance=instance);items.append(obj)
        path=f'cisco/ethernet_services/{items.index(obj)}';v=r['values'];line=r['source_line'];rule=r['rule']
        if rule=='if_service_instance':self.prove(path,line,list(v))
        elif rule in ('if_dot1q_lower','if_dot1q','if_qinq'):
            obj.encapsulation=s.Encapsulation(kind='qinq' if 'inner_vlan' in v else 'dot1q',outer_vlan=v['vlan'],inner_vlan=v.get('inner_vlan'));self.prove(path+'/encapsulation',line,list(v))
        elif rule=='if_encap_untagged':obj.encapsulation=s.Encapsulation(kind='untagged');self.prove(path+'/encapsulation',line,list(v))
        elif rule=='if_bridge_domain':self.assign(obj,'bridge_domain',v['domain'],path,line,list(v))

    def advanced(self,r):
        rule=r['rule'];root=self.root(r);v=r['values'];line=r['source_line']
        if root is None:return
        if root['rule']=='advanced_isis':
            items=self.c.cisco.isis;name=root['values']['process'];obj=next((o for o in items if o.name==name),None)
            if obj is None:obj=s.IsisProcess(name=name);items.append(obj)
            path=f'cisco/isis/{items.index(obj)}'
            if rule=='advanced_isis':self.prove(path,line,list(v))
            elif rule=='advanced_isis_net':self.assign(obj,'net',v['net'],path,line,list(v))
            elif rule=='advanced_isis_passive':obj.passive_interfaces.append(v['interface']);self.prove(path+'/passive_interfaces',line,list(v))
        elif rule=='advanced_multicast':self.assign(self.c.cisco.multicast,'routing_enabled',v['enabled'],'cisco/multicast',line,list(v))
        elif rule=='advanced_pim_rp':
            self.c.cisco.multicast.rendezvous_points.append(ip_address(v['address']));self.prove('cisco/multicast/rendezvous_points',line,list(v))
        elif rule.startswith('advanced_l2_'):
            obj=self.c.cisco.l2vpn
            if rule=='advanced_l2_evpn_global':self.assign(obj,'evpn_declared',v['declaration'],'cisco/l2vpn',line,list(v))
            elif rule=='advanced_l2_replication' and root['rule']=='advanced_l2_evpn_global':self.assign(obj,'replication_type',v['type'],'cisco/l2vpn',line,list(v))
            elif rule=='advanced_l2_rid' and root['rule']=='advanced_l2_evpn_global':self.assign(obj,'router_id_interface',v['interface'],'cisco/l2vpn',line,list(v))
            elif rule=='advanced_l2_evpn':
                obj.evpn_instances.append(s.EVI(identifier=v['instance'],type=v['type']));self.prove('cisco/l2vpn/evpn_instances',line,list(v))
            elif root['rule']=='advanced_l2_bridge':
                identifier=root['values']['domain'];bd=next((b for b in obj.bridge_domains if b.identifier==identifier),None)
                if bd is None:bd=s.BridgeDomain(identifier=identifier);obj.bridge_domains.append(bd)
                path=f'cisco/l2vpn/bridge_domains/{obj.bridge_domains.index(bd)}'
                if rule=='advanced_l2_bridge':self.prove(path,line,list(v))
                elif rule=='advanced_l2_member':
                    match=re.fullmatch(r'(\S+) service-instance (\d+)',v['member'])
                    if match:member=s.BridgeMember(kind='interface_service',interface=match[1],service_instance=int(match[2]))
                    else:
                        match=re.fullmatch(r'evpn-instance (\d+) ethernet-tag (\d+)',v['member'])
                        if match is None:raise ValueError('Unsupported bridge member syntax')
                        member=s.BridgeMember(kind='evpn',evpn_instance=int(match[1]),ethernet_tag=int(match[2]))
                    bd.members.append(member);self.validation[line]['fields']['member']='validated';self.prove(path+'/members',line,list(v))
            elif root['rule']=='advanced_l2_vfi':
                identifier=root['values']['vfi'];vf=next((o for o in obj.vfis if o.identifier==identifier),None)
                if vf is None:vf=s.VFI(identifier=identifier,mode=root['values']['mode']);obj.vfis.append(vf)
                path=f'cisco/l2vpn/vfis/{obj.vfis.index(vf)}'
                if rule=='advanced_l2_vfi':self.prove(path,line,list(v))
                elif rule=='advanced_l2_vpnid':self.assign(vf,'vpn_id',v['vpn_id'],path,line,list(v))
                elif rule=='advanced_l2_neighbor':vf.neighbors.append(s.VFINeighbor(address=v['address'],encapsulation=v['encapsulation']));self.prove(path+'/neighbors',line,list(v))

    def run(self):
        for line,r in sorted(self.records.items()):
            if not self.validation[line]['valid']:continue
            # Mutations on failed rule mappings are rolled back as a transaction.
            backup=self.c.model_copy(deep=True);old_evidence=len(self.evidence);old_consumed=deepcopy(self.consumed)
            try:
                family=r['family']
                if family=='interfaces':self.interface(r)
                elif family=='bgp':self.bgp(r)
                elif family=='ospf':self.ospf(r)
                elif family=='prefix':self.prefix(r)
                elif family=='vrf' and r['rule']=='vrf_description':
                    root=self.root(r);obj=next(v for v in self.c.network_instances if v.name==root['values']['name'])
                    self.assign(obj,'description',r['values']['description'],f'network_instances/{self.c.network_instances.index(obj)}',line,['description'])
                elif family=='services':self.services(r)
                elif r['rule'].startswith('advanced_qos'):self.qos(r)
                elif r['rule'].startswith('advanced_pki'):self.pki(r)
                elif r['rule']=='advanced_mpls_label':self.assign(self.c.cisco.mpls,'label_protocol',r['values']['protocol'],'cisco/mpls',line,list(r['values']))
                elif r['rule'].startswith('advanced_mpls_ldp'):
                    option=r['values'].get('option')
                    if option not in (None,'force'):raise ValueError('LDP option')
                    self.c.cisco.mpls.ldp.router_id_interface=r['values']['interface']
                    self.c.cisco.mpls.ldp.force=True if option=='force' else None
                    self.prove('cisco/mpls/ldp',line,list(r['values']))
                elif r['rule'].startswith('advanced_'):self.advanced(r)
            except (ValueError,KeyError,StopIteration,TypeError) as exc:
                self.c=backup;self.result.configuration=backup;del self.evidence[old_evidence:];self.consumed=old_consumed
                self.extra_invalid[line]='Unsupported or invalid semantic variant; no value guessed.'
                if 'Duplicate' in str(exc) or 'cannot be guessed' in str(exc):self.ambiguous.add(line)
        # Retain native properties without presenting them as a common semantic
        # model or complete mapping. Every record's remaining parameters are visible.
        for line,r in sorted(self.records.items()):
            remaining=[(k,v) for k,v in r['values'].items() if k not in self.consumed[line]]
            if not remaining:continue
            prefix=r['rule'].split('_')[0];domain={'if':'interface','advanced':'services','services':'services','route':'routing','policy':'policy','acl':'acl','prefix':'prefix'}.get(prefix,prefix)
            for marker in ('qos','pki','mpls','pim','isis','l2'):
                if marker in r['rule']:domain={'pim':'multicast','l2':'l2vpn'}.get(marker,marker)
            if domain not in s.CiscoObservation.model_fields['domain'].annotation.__args__:domain='services'
            scope=s.Scope(root_line=r['root_line'],root_command=redacted(self.nodes[r['root_line']].text),
                ancestors=[redacted(self.nodes[n].text) for n in r['context_lines']],ancestor_lines=r['context_lines'])
            self.c.cisco.observations.append(s.CiscoObservation(domain=domain,rule=r['rule'],source_line=line,scope=scope,
                parameters=[s.NativeParameter(name=k,value=v,validation='validated' if self.validation[line]['fields'][k]=='validated' else 'unvalidated') for k,v in remaining],
                justification='Native Cisco parameters preserved because their complete common-model semantics or relation handling is not implemented. Not credited as fully normalized.'))
        for n in self.nodes.values():
            if n.kind.startswith('opaque'):
                self.c.cisco.opaque_blocks.append(s.OpaqueBlock(kind='certificate' if n.kind=='opaque_pki' else 'banner',line_start=n.line,line_end=n.end_line,parent_line=n.parent,sha256=n.opaque_sha256))
        remaining={line for line,r in self.records.items() if set(self.consumed[line])!=set(r['values']) or not self.validation[line]['valid'] or line in self.extra_invalid}
        unknown=[]
        for n in self.nodes.values():
            if n.kind=='command' and (n.line not in self.records or n.line in remaining):
                unknown.append(UnknownCommand(line_start=n.line,line_end=n.end_line,raw_text=redacted(n.text),
                    parent_context=redacted(self.nodes[n.parent].text) if n.parent else None,reason='unsupported_semantics' if n.line in self.records else 'not_implemented'))
        self.result.parsing.unknown_commands=unknown;self.result.parsing.parser_version='0.3.0'
        # Validate relations without silently deleting or repairing references.
        for message in self.result.semantic_warnings():
            if not any(d.message==message for d in self.result.parsing.diagnostics):self.result.parsing.diagnostics.append(Diagnostic(severity='warning',code='UNRESOLVED_REFERENCE',message=message))
        return s.NormalizedConfig.model_validate(self.result.model_dump(mode='json'))
