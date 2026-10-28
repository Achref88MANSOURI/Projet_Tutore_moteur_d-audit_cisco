"""Handwritten source scan for the documented static-interface test subset."""
from ipaddress import IPv4Address, IPv6Address
import re


def expected(text):
    interfaces,ipv4,ipv6={},[],[]
    current=None;hostname=None;asns=set()
    for raw in text.splitlines():
        s=raw.strip()
        if not s or s.startswith('!'): continue
        if not raw[0].isspace():
            current=None
            if m:=re.fullmatch(r'hostname (\S+)',s): hostname=m[1]
            if m:=re.fullmatch(r'interface (\S+)',s): current=m[1];interfaces[current]=None
            if m:=re.fullmatch(r'router bgp (\d+(?:\.\d+)?)',s):
                parts=m[1].split('.');asns.add(int(parts[0]) if len(parts)==1 else int(parts[0])*65536+int(parts[1]))
            continue
        if current is None: continue
        if s in ('shutdown','no shutdown'): interfaces[current]=s=='no shutdown'
        if m:=re.fullmatch(r'ip address (\S+) (\S+)( secondary)?',s):
            mask=int(IPv4Address(m[2]));inverse=mask^0xffffffff
            assert not inverse & (inverse+1)
            ipv4.append((current,str(IPv4Address(m[1])),32-inverse.bit_length(),bool(m[3])))
        if m:=re.fullmatch(r'ipv6 address ([\da-fA-F:]+)/(\d+)',s):
            ipv6.append((current,str(IPv6Address(m[1])),int(m[2])))
    return {'hostname':hostname,'interfaces':interfaces,'ipv4':sorted(ipv4),'ipv6':sorted(ipv6),'asns':sorted(asns)}


def check_result(result, source, manifest):
    truth=expected(source);c=result
    actual4=sorted((i.name,str(a.address),a.prefix_length,bool(a.secondary)) for i in c.interfaces for a in i.ipv4_addresses)
    actual6=sorted((i.name,str(a.address),a.prefix_length) for i in c.interfaces for a in i.ipv6_addresses)
    return {
        'hostname_source_and_description':c.system.hostname==truth['hostname']==manifest['hostname_description'],
        'interfaces_source_and_description':len(c.interfaces)==manifest['description_interface_count'] and {i.name for i in c.interfaces}==set(truth['interfaces']),
        'explicit_admin_states_no_template_defaults':{i.name:i.admin_enabled for i in c.interfaces}==truth['interfaces'],
        'all_static_ipv4_values':actual4==truth['ipv4'],
        'all_unqualified_static_ipv6_values':actual6==truth['ipv6'],
        'bgp_local_as':sorted({p.local_as for p in c.routing.bgp})==truth['asns'],
    }
