"""Validate captured domains before any semantic mapping; retain raw records."""
from ipaddress import ip_address,ip_network
import re
from normalizer.common.addresses import asn,prefix_length
from .eigrp_commands import validate as validate_eigrp

PROTOCOLS={'ip','ipv6','tcp','udp','icmp','icmp6','icmpv6','gre','esp','ahp','ospf','eigrp','igmp','pim','sctp','ipinip'}
OPAQUE_FIELDS={'options','member','subject','value','method','expression'}


def dscp(value):
    return str(value) in ('default','ef') or bool(re.fullmatch(r'cs[0-7]|af[1-4][1-3]',str(value))) or (str(value).isdigit() and 0<=int(value)<=63)


def validate_record(record):
    rule=record['rule'];v=record['values'];fields={};errors=[]
    for key,value in v.items():
        state='validated'
        try:
            if isinstance(value,str) and (not value or '\n' in value or '\r' in value):raise ValueError('Empty or multiline scalar')
            if key in ('local_as','remote_as'):asn(value)
            if key in ('address','inside','outside','router_id') and rule not in ('advanced_l2_rid',):
                try:ip_address(str(value))
                except ValueError:
                    if not rule.startswith(('services_ntp','services_logging')) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9.-]*',str(value)):raise
            if key=='mask':prefix_length(value)
            if key in ('vlan','inner_vlan','native_vlan','access_vlan'):
                if not 1<=int(value)<=4094:raise ValueError('VLAN range')
            if key=='mss' and not 1<=int(value)<=65535:raise ValueError('MSS range')
            if key=='mtu' and not 64<=int(value)<=65535:raise ValueError('MTU range')
            if key=='percent' and not 0<=int(value)<=100:raise ValueError('Percentage')
            if key=='direction' and str(value) not in ('in','out','input','output','ingress','egress','import','export','both'):raise ValueError('Direction')
            if key=='direction':
                choices={'bgp_route_map':{'in','out'},'if_acl4':{'in','out'},'if_acl6':{'in','out'},'services_access_class':{'in','out'},'if_service_policy':{'input','output'}}.get(rule)
                if choices is not None and value not in choices:raise ValueError('Direction for this CLI concept')
            if key=='action' and value not in ('permit','deny'):raise ValueError('Action')
            if key=='protocol' and rule.startswith('acl_'):
                if value not in PROTOCOLS and not (str(value).isdigit() and 0<=int(value)<=255):raise ValueError('IP protocol')
            if key=='duplex' and value not in ('auto','half','full'):raise ValueError('Duplex')
            if key=='media' and value not in ('rj45','gbic','sfp','auto'):raise ValueError('Media type not supported')
            if key=='negotiation' and value!='auto':raise ValueError('Negotiation')
            if key=='speed' and value!='auto' and (not str(value).isdigit() or int(value)<=0 or int(value)>1000000):raise ValueError('Speed')
            if key=='dscp' and not dscp(value):raise ValueError('DSCP')
            if key=='precedence' and (not str(value).isdigit() or not 0<=int(value)<=7):raise ValueError('Precedence')
            if key=='afi' and value not in ('ipv4','ipv6','vpnv4','vpnv6','l2vpn'):raise ValueError('AFI')
            if key=='net':
                compact=str(value).replace('.','')
                if not re.fullmatch('[0-9a-fA-F]+',compact) or len(compact)%2 or not 16<=len(compact)<=40:raise ValueError('IS-IS NET')
            if key=='protocol' and rule=='advanced_qos_match_protocol' and value not in ('dns','vofr','icmp','ftp','http','sip','rtp','tcp','udp'):state='unvalidated'
            if key=='prefix' and rule.startswith('prefix_'):ip_network(value,strict=False)
            if key=='peer' and ':' in str(value):ip_address(value)
            if key=='key_id' and rule.startswith('auth_if_ospf_md5') and not 1 <= value <= 255:raise ValueError('OSPF key ID range')
            if key in OPAQUE_FIELDS:state='unvalidated'
            if key=='value' and (not isinstance(value,str) or rule=='if_description' or rule in ('services_snmp_location','services_snmp_contact')):state='validated'
            if key=='options' and rule.startswith('acl_') and value=='log':state='validated'
            if key=='method' and rule=='services_login' and (value in ('local','authentication default') or value.startswith('authentication ')):state='validated'
            if key=='method' and rule=='services_http_auth' and value in ('local','aaa','enable'):state='validated'
            if key=='method' and rule=='advanced_pki_enrollment' and value in ('selfsigned','terminal','pkcs12'):state='validated'
            if key=='method' and rule=='advanced_pki_revocation' and value in ('none','crl','ocsp'):state='validated'
            if key=='subject' and '=' in str(value):state='validated'
            if key=='enabled' and rule in ('services_console_off', 'services_aaa_on', 'services_aaa_off', 'services_password_encryption_on', 'services_password_encryption_off', 'services_ipv6_routing', 'services_lookup_off', 'services_source_route_off', 'services_login_logging', 'services_logging_on', 'services_logging_off'):state='validated'
        except (ValueError,TypeError):
            state='invalid';errors.append(key)
        fields[key]=state
    try:
        validate_eigrp(rule, v)
    except (ValueError, TypeError, KeyError):
        fields = {key: 'invalid' for key in v}
        errors = list(v)
    return dict(valid=not errors,fields=fields,invalid_fields=errors)
