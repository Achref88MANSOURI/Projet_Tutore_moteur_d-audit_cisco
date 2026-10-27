"""Consume TTP captures, never the old parser's objects or parsing code."""
from __future__ import annotations
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_interface, ip_network
import hashlib

from schemas.normalizedconfig import (
    AAA, ACLAddressMatch, ACLAttachment, ACLEntry, ACLSet, AuthServer, BGPNeighbor,
    BGPProcess, Configuration, Diagnostic, Evidence, Interface, IPv4InterfaceAddress,
    IPv6InterfaceAddress, LAG, Management, ManagementLine, Metadata, NetworkInstance,
    NormalizedConfig, NTPServer, NATRule, OSPFArea, OSPFNetworkStatement, OSPFProcess,
    Parsing, FeatureCoverage, PortMatch, PrefixSet, QoSAttachment, RoutingPolicy,
    RoutingPolicyAction, RoutingPolicyMatch, RoutingPolicyStatement, SNMP,
    SNMPCommunity, StaticRoute, SyslogDestination, UnknownCommand, UserAccount, VLAN, VPNTunnel,
)
from parser.inventory import ancestors, redacted


def asn(value):
    parts = str(value).split('.')
    number = int(parts[0]) if len(parts) == 1 else int(parts[0]) * 65536 + int(parts[1])
    if len(parts) > 2 or not 1 <= number <= 4294967295 or (len(parts) == 2 and any(not 0 <= int(x) <= 65535 for x in parts)):
        raise ValueError('Invalid ASN')
    return number


def prefix_length(mask):
    number = int(IPv4Address(mask))
    inverse = number ^ 0xffffffff
    if inverse & (inverse + 1):
        raise ValueError('Non-contiguous subnet mask')
    return 32 - inverse.bit_length()


def vlan_set(expression):
    if expression == 'all': return list(range(1, 4095))
    if expression == 'none': return []
    result = set()
    for part in expression.split(','):
        ends = part.split('-')
        if len(ends) > 2: raise ValueError('Invalid VLAN range')
        low, high = int(ends[0]), int(ends[-1])
        if not 1 <= low <= high <= 4094: raise ValueError('Invalid VLAN range')
        result.update(range(low, high + 1))
    return sorted(result)


def flat_official(value):
    if isinstance(value, list):
        for child in value: yield from flat_official(child)
    elif isinstance(value, dict):
        yield value


class Mapper:
    def __init__(self, extracted, text, source_file, os_family, raw_hash=None):
        if os_family not in ('ios', 'iosxe'): raise ValueError('Supported OS families: ios, iosxe')
        self.x, self.text, self.source_file = extracted, text, str(source_file)
        self.nodes, self.records = extracted['nodes'], extracted['records']
        self.c = Configuration(system={'aaa': AAA(), 'snmp': SNMP(), 'management': Management()})
        self.evidence, self.diagnostics = [], []
        self.mapped, self.structural, self.failed = set(), set(), set()
        self.entities, self.bgp, self.official_usage = {}, {}, []
        self.official_interfaces = {r['name']: r for r in flat_official(extracted['official'].get('interfaces')) if 'name' in r}
        self.official_vrfs = {r['name']: r for r in flat_official(extracted['official'].get('vrfs')) if 'name' in r}
        self.metadata = Metadata(vendor='cisco', os_family=os_family, source_file=self.source_file,
            source_sha256=raw_hash or hashlib.sha256(text.encode()).hexdigest(), input_format='cisco-running',
            completeness='unknown', source_kind='unknown', os_detection_method='explicit', redacted_secrets=True)

    def prove(self, path, line, rule=None):
        node = self.nodes[line]
        self.evidence.append(Evidence(path='/configuration/' + path, status='explicit',
            source_file=self.source_file, line_start=line, line_end=line,
            raw_command=redacted(node.text), parser_rule='ttp:' + (rule or self.records[line]['rule']), confidence=1))
        self.mapped.add(line)

    def assign(self, obj, field, value, path, line):
        setattr(obj, field, value)
        full = '/configuration/' + path + '/' + field
        self.evidence[:] = [e for e in self.evidence if e.path != full]
        self.prove(path + '/' + field, line)

    def entity(self, line):
        return self.entities.get(self.nodes[line].root)

    def bgp_context(self, record):
        vrf, af = None, None
        for line in record['context_lines']:
            parent = self.records.get(line)
            if parent and parent['rule'].startswith('bgp_af') and 'afi' in parent['values']:
                v = parent['values']
                vrf = v.get('vrf')
                af = v['afi'] + (' ' + v['safi'] if v.get('safi') else ' unicast' if v['afi'] in ('ipv4', 'ipv6') else '')
        key = (record['root_line'], vrf)
        if key not in self.bgp:
            header = self.records[record['root_line']]
            item = BGPProcess(local_as=asn(header['values']['local_as']), network_instance=vrf)
            self.c.routing.bgp.append(item)
            path = f'routing/bgp/{len(self.c.routing.bgp)-1}'
            self.bgp[key] = (item, path)
            self.prove(path + '/local_as', header['source_line'])
            if vrf:
                af_source = next(line for line in record['context_lines'] if self.records.get(line, {}).get('values', {}).get('vrf') == vrf)
                self.prove(path + '/network_instance', af_source)
        return *self.bgp[key], af

    def headers(self):
        for line, r in sorted(self.records.items()):
            rule, v = r['rule'], r['values']
            if rule == 'if_header':
                name = v['name']
                lower = name.lower()
                kind = ('subinterface' if '.' in name else 'loopback' if lower.startswith('loopback') else
                    'svi' if lower.startswith(('vlan', 'bvi')) else 'lag' if lower.startswith('port-channel') else
                    'tunnel' if lower.startswith('tunnel') else 'physical')
                item = Interface(name=name, kind=kind)
                if kind == 'subinterface':
                    item.parent_interface, suffix = name.rsplit('.', 1)
                    item.subinterface_index = int(suffix)
                self.c.interfaces.append(item)
                path = f'interfaces/{len(self.c.interfaces)-1}'
                self.entities[line] = item, path
                self.prove(path + '/name', line); self.prove(path + '/kind', line)
                if item.parent_interface:
                    self.prove(path + '/parent_interface', line); self.prove(path + '/subinterface_index', line)
            elif rule in ('vrf_header', 'vrf_legacy_header'):
                item = NetworkInstance(name=v['name'], kind='L3VRF')
                self.c.network_instances.append(item)
                path = f'network_instances/{len(self.c.network_instances)-1}'
                self.entities[line] = item, path
                self.prove(path + '/name', line); self.prove(path + '/kind', line)
            elif rule in ('ospf_header', 'ospf_header_vrf'):
                item = OSPFProcess(identifier=v['process'], network_instance=v.get('vrf'))
                self.c.routing.ospf.append(item)
                path = f'routing/ospf/{len(self.c.routing.ospf)-1}'
                self.entities[line] = item, path
                self.prove(path + '/identifier', line)
                if item.network_instance: self.prove(path + '/network_instance', line)
            elif rule == 'bgp_header':
                self.bgp_context(r)
            elif rule == 'policy_header':
                item = next((p for p in self.c.routing.routing_policies if p.name == v['name']), None)
                if item is None:
                    item = RoutingPolicy(name=v['name'])
                    self.c.routing.routing_policies.append(item)
                statement = RoutingPolicyStatement(identifier=str(v['sequence']), decision='accept' if v['action'] == 'permit' else 'reject')
                item.statements.append(statement)
                path = f'routing/routing_policies/{self.c.routing.routing_policies.index(item)}'
                self.prove(path + '/name', line)
                path += f'/statements/{len(item.statements)-1}'
                self.entities[line] = statement, path
                self.prove(path + '/identifier', line); self.prove(path + '/decision', line)
            elif rule == 'services_line':
                item = ManagementLine(name=v['name'])
                self.c.system.management.lines.append(item)
                path = f'system/management/lines/{len(self.c.system.management.lines)-1}'
                self.entities[line] = item, path
                self.prove(path + '/name', line)
            elif rule in ('services_tacacs', 'services_radius'):
                self.entities[line] = None, 'tacacs' if rule == 'services_tacacs' else 'radius'
            elif rule == 'advanced_qos_policymap':
                self.c.qos.policy_names.append(v['name'])
                self.prove(f'qos/policy_names/{len(self.c.qos.policy_names)-1}', line)
            elif rule == 'advanced_vlan':
                for identifier in vlan_set(v['vlan']):
                    item = VLAN(vlan_id=identifier)
                    self.c.layer2.vlans.append(item)
                    path = f'layer2/vlans/{len(self.c.layer2.vlans)-1}'
                    self.entities[line] = item, path
                    self.prove(path + '/vlan_id', line)

    def interface(self, r):
        if len(r['context_lines']) != 1: return  # nested service-instance is not the physical interface
        entry = self.entity(r['source_line'])
        if not entry: return
        item, path = entry
        rule, v, line = r['rule'], r['values'], r['source_line']
        fields = {'if_description': ('description', 'value'), 'if_mtu': ('mtu', 'mtu'),
                  'if_vrf': ('vrf', 'vrf'), 'if_legacy_vrf': ('vrf', 'vrf')}
        if rule in fields:
            field, key = fields[rule]; self.assign(item, field, v[key], path, line)
        elif rule in ('if_shutdown', 'if_no_shutdown'):
            self.assign(item, 'admin_enabled', rule == 'if_no_shutdown', path, line)
        elif rule in ('if_ipv4', 'if_ipv4_secondary'):
            self.evidence[:]=[e for e in self.evidence if e.path!='/configuration/'+path+'/ipv4_addresses']
            length = prefix_length(v['mask'])
            address = str(IPv4Address(v['address']))
            cidr = f'{address}/{length}'
            official = self.official_interfaces.get(item.name, {})
            match = next((a for a in official.get('ipv4_addresses', []) if a.get('ip') == cidr), None)
            if match:
                parsed = ip_interface(match['ip'])
                address, length = str(parsed.ip), parsed.network.prefixlen
                self.official_usage.append({'line': line, 'template': 'interfaces', 'field': 'ipv4_addresses.ip'})
            item.ipv4_addresses.append(IPv4InterfaceAddress(address=address, prefix_length=length,
                secondary=True if rule == 'if_ipv4_secondary' else None))
            self.prove(path + f'/ipv4_addresses/{len(item.ipv4_addresses)-1}', line)
        elif rule == 'if_ipv6':
            item.ipv6_addresses.append(IPv6InterfaceAddress(address=v['address'], prefix_length=v['prefix_length']))
            self.prove(path + f'/ipv6_addresses/{len(item.ipv6_addresses)-1}', line)
        elif rule in ('if_acl4', 'if_acl6') and v['direction'] in ('in', 'out'):
            field = 'acl_ingress' if v['direction'] == 'in' else 'acl_egress'
            getattr(item, field).append(v['acl'])
            self.prove(path + f'/{field}/{len(getattr(item, field))-1}', line)
            self.c.security.acl_attachments.append(ACLAttachment(acl_name=v['acl'], interface_name=item.name,
                direction='ingress' if v['direction'] == 'in' else 'egress'))
            self.prove(f'security/acl_attachments/{len(self.c.security.acl_attachments)-1}', line)
        elif rule in ('if_switchport', 'if_routed'):
            self.assign(item, 'switchport_mode', 'routed' if rule == 'if_routed' else v['mode'], path, line)
        elif rule in ('if_access_vlan', 'if_native_vlan'):
            self.assign(item, 'access_vlan' if rule == 'if_access_vlan' else 'native_vlan', v['vlan'], path, line)
        elif rule in ('if_trunk_vlans', 'if_trunk_modify'):
            values = set(vlan_set(v['vlans']))
            op = v.get('operation')
            if op in ('add', 'remove'):
                if item.trunk_allowed_vlans is None: return
                current = set(item.trunk_allowed_vlans)
                item.trunk_allowed_vlans = sorted(current | values if op == 'add' else current - values)
                self.prove(path + '/trunk_allowed_vlans', line)
            elif op in (None, 'except'):
                self.assign(item, 'trunk_allowed_vlans', sorted(values if op is None else set(range(1,4095)) - values), path, line)
        elif rule == 'if_lag':
            name = 'Port-channel' + str(v['lag_id'])
            lag = next((x for x in self.c.layer2.lags if x.name == name), None)
            if lag is None:
                lag = LAG(name=name, lacp_mode=v['mode']); self.c.layer2.lags.append(lag)
            if lag.lacp_mode != v['mode']: return
            lag.members.append(item.name)
            self.assign(item, 'lag', name, path, line)
            self.prove(f'layer2/lags/{self.c.layer2.lags.index(lag)}', line)
        elif rule == 'if_service_policy' and v['direction'] in ('input', 'output'):
            self.c.qos.attachments.append(QoSAttachment(policy_name=v['policy'], interface_name=item.name,
                direction='ingress' if v['direction'] == 'input' else 'egress'))
            self.prove(f'qos/attachments/{len(self.c.qos.attachments)-1}', line)
        elif rule == 'if_ospf2':
            process = next((p for p in self.c.routing.ospf if p.identifier == v['process'] and p.network_instance == item.vrf), None)
            if process is None:
                process = OSPFProcess(identifier=v['process'], network_instance=item.vrf)
                self.c.routing.ospf.append(process)
                self.prove(f'routing/ospf/{len(self.c.routing.ospf)-1}/identifier', line)
            area = str(IPv4Address(int(v['area']))) if v['area'].isdigit() else str(IPv4Address(v['area']))
            group = next((a for a in process.areas if a.area_id == area), None)
            if group is None: group = OSPFArea(area_id=area); process.areas.append(group)
            group.interfaces.append(item.name)
            self.prove(f'routing/ospf/{self.c.routing.ospf.index(process)}/areas/{process.areas.index(group)}', line)
        elif rule == 'if_no_ipv4':
            prefix='/configuration/'+path+'/ipv4_addresses'
            self.evidence[:]=[e for e in self.evidence if e.path!=prefix and not e.path.startswith(prefix+'/')]
            item.ipv4_addresses=[]
            self.prove(path+'/ipv4_addresses',line)
        elif rule == 'if_tunnel_destination' and item.kind=='tunnel':
            endpoint=str(ip_address(v['destination']))
            tunnel=self.ensure_tunnel(item,line)
            self.assign(tunnel,'remote_endpoint',endpoint,f'vpn_tunnels/{self.c.vpn_tunnels.index(tunnel)}',line)

    def ensure_tunnel(self, interface, line):
        tunnel=next((t for t in self.c.vpn_tunnels if t.identifier==interface.name),None)
        if tunnel is None:
            tunnel=VPNTunnel(identifier=interface.name,tunnel_interface=interface.name,technology='unknown',network_instance=interface.vrf)
            self.c.vpn_tunnels.append(tunnel)
            path=f'vpn_tunnels/{len(self.c.vpn_tunnels)-1}'
            self.prove(path+'/identifier',self.nodes[line].root)
            self.prove(path+'/tunnel_interface',self.nodes[line].root)
        return tunnel

    def routing_bgp(self, r):
        rule, v, line = r['rule'], r['values'], r['source_line']
        item, path, af = self.bgp_context(r)
        if rule == 'bgp_router_id':
            self.assign(item, 'router_id', IPv4Address(v['router_id']), path, line)
        elif rule.startswith('bgp_af'):
            if 'afi' not in v:
                self.structural.add(line); return
            name = v['afi'] + (' ' + v['safi'] if v.get('safi') else ' unicast' if v['afi'] in ('ipv4', 'ipv6') else '')
            if v.get('vrf'):
                self.bgp_context({'root_line': r['root_line'], 'context_lines': [line]})
                item, path = self.bgp[(r['root_line'], v['vrf'])]
            if name not in item.address_families: item.address_families.append(name)
            self.prove(path + f'/address_families/{item.address_families.index(name)}', line)
        elif rule == 'bgp_group_definition':
            if v['peer'] not in item.peer_groups: item.peer_groups.append(v['peer'])
            self.prove(path + f'/peer_groups/{item.peer_groups.index(v["peer"])}', line)
        elif rule in ('bgp_remote_as', 'bgp_description', 'bgp_group_member', 'bgp_shutdown', 'bgp_no_shutdown', 'bgp_route_map'):
            if rule=='bgp_route_map' and v['direction'] not in ('in','out'):
                self.failed.add(line);return
            if rule == 'bgp_route_map' and af is not None: return
            if rule in ('bgp_shutdown', 'bgp_no_shutdown') and af is not None: return
            try: peer = str(ip_address(v['peer']))
            except ValueError: return
            neighbor = next((n for n in item.neighbors if n.peer == peer), None)
            if neighbor is None: neighbor = BGPNeighbor(peer=peer); item.neighbors.append(neighbor)
            np = path + f'/neighbors/{item.neighbors.index(neighbor)}'
            self.prove(np + '/peer', line)
            if rule == 'bgp_remote_as': self.assign(neighbor, 'remote_as', asn(v['remote_as']), np, line)
            elif rule == 'bgp_description': self.assign(neighbor, 'description', v['description'], np, line)
            elif rule == 'bgp_group_member': self.assign(neighbor, 'peer_group', v['group'], np, line)
            elif rule in ('bgp_shutdown', 'bgp_no_shutdown'): self.assign(neighbor, 'enabled', rule == 'bgp_no_shutdown', np, line)
            elif rule == 'bgp_route_map' and v['direction'] in ('in', 'out'):
                self.assign(neighbor, 'import_policies' if v['direction'] == 'in' else 'export_policies', [v['policy']], np, line)

    def routing_ospf(self, r):
        entry = self.entity(r['source_line'])
        if not entry: return  # OSPFv3 has no version discriminator in this contract
        item, path = entry
        rule, v, line = r['rule'], r['values'], r['source_line']
        if rule == 'ospf_router_id': self.assign(item, 'router_id', IPv4Address(v['router_id']), path, line)
        elif rule == 'ospf_network':
            mask = str(IPv4Address(int(IPv4Address(v['wildcard'])) ^ 0xffffffff))
            prefix = str(IPv4Network(v['address'] + '/' + str(prefix_length(mask)), strict=False))
            area = str(IPv4Address(int(v['area']))) if v['area'].isdigit() else str(IPv4Address(v['area']))
            item.network_statements.append(OSPFNetworkStatement(prefix=prefix, area=area))
            self.prove(path + f'/network_statements/{len(item.network_statements)-1}', line)
        elif rule == 'ospf_passive' and v['interface'] != 'default':
            item.passive_interfaces.append(v['interface']); self.prove(path + f'/passive_interfaces/{len(item.passive_interfaces)-1}', line)

    def routes(self, r):
        v, line = r['values'], r['source_line']
        ipv6 = r['rule'].startswith('route_ipv6')
        if ipv6:
            destination = ip_network(v['destination'], strict=False)
            if destination.version != 6: raise ValueError('Wrong route family')
        else:
            destination = IPv4Network(v['destination'] + '/' + str(prefix_length(v['mask'])), strict=False)
        interface, hop = v.get('interface'), v['hop']
        try: hop = str(ip_address(hop))
        except ValueError:
            if interface is not None or not any(c.isdigit() for c in hop): raise ValueError('Invalid route next-hop')
            interface, hop = hop, None
        route = StaticRoute(destination=destination, next_hop=hop, outgoing_interface=interface,
            network_instance=v.get('vrf'), admin_distance=v.get('distance'), description=v.get('name'))
        self.c.routing.static_routes.append(route)
        self.prove(f'routing/static_routes/{len(self.c.routing.static_routes)-1}', line)

    def vrf(self, r):
        entry = self.entity(r['source_line'])
        if not entry: return
        item, path = entry
        rule, v, line = r['rule'], r['values'], r['source_line']
        if rule == 'vrf_rd':
            value = v['rd']
            official = self.official_vrfs.get(item.name, {})
            if official.get('rd') == value:
                value = official['rd']; self.official_usage.append({'line': line, 'template': 'vrfs', 'field': 'rd'})
            self.assign(item, 'route_distinguisher', value, path, line)
        elif rule == 'vrf_target' and v['direction'] in ('import', 'export', 'both'):
            for direction in ('import', 'export') if v['direction'] == 'both' else (v['direction'],):
                field = 'route_targets_' + direction
                if v['target'] not in getattr(item, field): getattr(item, field).append(v['target'])
                self.prove(path + f'/{field}/{getattr(item, field).index(v["target"])}', line)
        elif rule in ('vrf_af', 'vrf_af_exit'): self.structural.add(line)

    @staticmethod
    def acl_address(value):
        t = value.split()
        if t[0] in ('any', 'any4', 'any6'): return ACLAddressMatch(kind='any')
        if t[0] == 'host': return ACLAddressMatch(kind='host', value=str(ip_address(t[1])))
        if t[0] == 'object-group': return ACLAddressMatch(kind='object_group', value=t[1])
        if len(t) == 2:
            mask = str(IPv4Address(int(IPv4Address(t[1])) ^ 0xffffffff))
            try: value = str(IPv4Network(t[0] + '/' + str(prefix_length(mask)), strict=False))
            except ValueError: return ACLAddressMatch(kind='wildcard', value=value)
            return ACLAddressMatch(kind='prefix', value=value)
        if '/' in value: return ACLAddressMatch(kind='prefix', value=str(ip_network(value, strict=False)))
        return ACLAddressMatch(kind='host', value=str(ip_address(value)))

    @staticmethod
    def acl_port(value):
        if not value: return None
        t = value.split(); aliases = {'ssh':22,'telnet':23,'www':80,'http':80,'https':443,'domain':53,'bgp':179,'snmp':161,'snmptrap':162,'ntp':123}
        def number(token): return int(token) if token.isdigit() else aliases[token]
        return PortMatch(operator=t[0], start=number(t[1]), end=number(t[2]) if t[0] == 'range' else None)

    def acl(self, r):
        v, line = r['values'], r['source_line']
        root = self.records.get(r['root_line'])
        name = v.get('name') or v.get('acl_name') or (root or {}).get('values', {}).get('name')
        if not name: return
        family = 'ipv6' if root and root['rule'] == 'acl_header_ipv6' else 'ipv4'
        item = next((a for a in self.c.security.acl_sets if a.name == name and a.family == family), None)
        if item is None: item = ACLSet(name=name, family=family); self.c.security.acl_sets.append(item)
        path = f'security/acl_sets/{self.c.security.acl_sets.index(item)}'
        if r['rule'].startswith('acl_header'):
            self.prove(path + '/name', line); self.prove(path + '/family', line); return
        options = v.get('options')
        if options not in (None, 'log', 'log-input'):
            return
        entry = ACLEntry(sequence=v.get('sequence'), action=v['action'], protocol=v.get('protocol'),
            source=self.acl_address(v['source']), destination=self.acl_address(v['destination']) if v.get('destination') else None,
            source_port=self.acl_port(v.get('source_port')), destination_port=self.acl_port(v.get('destination_port')),
            log=True if options else None)
        if entry.sequence is not None and any(e.sequence == entry.sequence for e in item.entries): raise ValueError('Duplicate ACL sequence')
        item.entries.append(entry)
        self.prove(path + f'/entries/{len(item.entries)-1}', line)

    def policies(self, r):
        entry = self.entity(r['source_line'])
        if not entry: return
        item, path = entry
        rule, v, line = r['rule'], r['values'], r['source_line']
        if rule.startswith('policy_match_'):
            kind = {'prefix4':'prefix_set_ipv4','prefix6':'prefix_set_ipv6','acl':'acl','interface':'interface','community':'community','aspath':'as_path','tag':'tag'}[rule[len('policy_match_'):]]
            item.matches.append(RoutingPolicyMatch(kind=kind, value=v['value']))
            self.prove(path + f'/matches/{len(item.matches)-1}', line)
        elif rule.startswith('policy_set_'):
            kind = {'aspath':'as_path_prepend','localpref':'local_preference','metric':'metric','weight':'cisco_weight','community':'community'}[rule[len('policy_set_'):]]
            item.actions.append(RoutingPolicyAction(kind=kind, value=str(v['value'])))
            self.prove(path + f'/actions/{len(item.actions)-1}', line)

    def services(self, r):
        rule, v, line = r['rule'], r['values'], r['source_line']
        s = self.c.system
        if rule == 'services_hostname': self.assign(s, 'hostname', v['hostname'], 'system', line)
        elif rule == 'services_version': self.metadata.os_version = v['version']; self.structural.add(line)
        elif rule in ('services_domain', 'services_domain_alt'): self.assign(s, 'domain_name', v['domain'], 'system', line)
        elif rule == 'services_dns':
            values = [str(ip_address(value)) for value in v['addresses'].split()]
            for value in values: s.dns_servers.append(value); self.prove(f'system/dns_servers/{len(s.dns_servers)-1}', line)
        elif rule.startswith('services_ntp') and rule != 'services_ntp_source':
            s.ntp_servers.append(NTPServer(address=v['address'], prefer=True if rule.endswith('prefer') else None, network_instance=v.get('vrf')))
            self.prove(f'system/ntp_servers/{len(s.ntp_servers)-1}', line)
        elif rule in ('services_logging', 'services_logging_legacy'):
            s.syslog_destinations.append(SyslogDestination(address=v['address']))
            self.prove(f'system/syslog_destinations/{len(s.syslog_destinations)-1}', line)
        elif rule in ('services_aaa_on', 'services_aaa_off'):
            self.assign(s.aaa, 'enabled', rule == 'services_aaa_on', 'system/aaa', line)
        elif rule == 'services_aaa_method' and v['category'] in ('authentication', 'authorization', 'accounting'):
            s.aaa.method_lists.append('aaa ' + v['category'] + ' ' + v['method'])
            self.prove(f'system/aaa/method_lists/{len(s.aaa.method_lists)-1}', line)
        elif rule.startswith('services_user') and v['credential_type'] in ('secret', 'password'):
            s.aaa.local_users.append(UserAccount(username=v['username'], privilege_level=v.get('privilege'),
                credential_configured=True, credential_type=v['credential_type'] + ':' + v['credential_format']))
            self.prove(f'system/aaa/local_users/{len(s.aaa.local_users)-1}', line)
        elif rule.startswith('services_snmp_community') and v['access'].lower() in ('ro', 'rw'):
            s.snmp.communities.append(SNMPCommunity(name='[REDACTED]', access=v['access'].lower(), access_list=v.get('acl')))
            self.prove(f'system/snmp/communities/{len(s.snmp.communities)-1}', line)
        elif rule in ('services_snmp_location', 'services_snmp_contact'):
            self.assign(s.snmp, 'location' if rule.endswith('location') else 'contact', v['value'], 'system/snmp', line)
        elif rule == 'services_ssh_version': self.assign(s.management, 'ssh_version', v['version'], 'system/management', line)
        elif rule in ('services_http_on','services_http_off','services_https_on','services_https_off'):
            self.assign(s.management, 'https_enabled' if 'https' in rule else 'http_enabled', rule.endswith('_on'), 'system/management', line)
        elif rule == 'services_banner' and v['type'] in ('login', 'motd'):
            self.assign(s, 'login_banner_present', True, 'system', line)
        elif rule in ('services_transport','services_timeout','services_timeout_minutes','services_access_class','services_login','services_login_plain'):
            entry = self.entity(line)
            if not entry or not isinstance(entry[0], ManagementLine): return
            item, path = entry
            if rule == 'services_transport':
                tokens = v['transports'].split()
                if any(x not in ('ssh','telnet','none','all') for x in tokens): return
                if ('all' in tokens or 'none' in tokens) and len(tokens)!=1:return
                self.assign(item, 'allowed_transports', [] if tokens == ['none'] else tokens, path, line)
            elif rule.startswith('services_timeout'):
                seconds = v.get('seconds',0)
                if not 0 <= seconds <= 59: raise ValueError('Invalid timeout')
                self.assign(item,'idle_timeout_seconds',v['minutes']*60+seconds,path,line)
            elif rule == 'services_access_class' and v['direction'] == 'in': self.assign(item,'access_list',v['acl'],path,line)
            elif rule == 'services_login': self.assign(item,'authentication','login '+v['method'],path,line)
            elif rule == 'services_login_plain': self.assign(item,'authentication','login',path,line)
        elif rule in ('services_auth_address', 'services_auth_ports'):
            entry = self.entity(line)
            if not entry or entry[0] is not None: return
            _, protocol = entry
            s.aaa.servers.append(AuthServer(protocol=protocol,address=v['address'],port=v.get('auth_port')))
            self.prove(f'system/aaa/servers/{len(s.aaa.servers)-1}',line)
            if 'acct_port' in v:
                self.mapped.discard(line)  # account port is not represented: partial record
        elif rule == 'services_nat_static':
            self.c.nat.append(NATRule(identifier=f'line-{line}',type='static',
                source_match=str(IPv4Address(v['inside'])),translated_source=str(IPv4Address(v['outside']))))
            self.prove(f'nat/{len(self.c.nat)-1}',line)

    def finish_links(self):
        for r in self.records.values():
            if r['rule']!='if_tunnel_source' or len(r['context_lines'])!=1:continue
            entry=self.entity(r['source_line'])
            if not entry or entry[0].kind!='tunnel':continue
            interface=entry[0];value=r['values']['source'];address_line=None
            try:value=str(ip_address(value))
            except ValueError:
                source=next((i for i in self.c.interfaces if i.name==value and i.vrf==interface.vrf),None)
                if source is None or len(source.ipv4_addresses)!=1:continue
                value=str(source.ipv4_addresses[0].address)
                proof=next((e for e in self.evidence if e.path==f'/configuration/interfaces/{self.c.interfaces.index(source)}/ipv4_addresses/0' and e.status=='explicit'),None)
                if proof is None:continue
                address_line=proof.line_start
            tunnel=self.ensure_tunnel(interface,r['source_line'])
            path=f'vpn_tunnels/{self.c.vpn_tunnels.index(tunnel)}'
            self.assign(tunnel,'local_endpoint',value,path,r['source_line'])
            if address_line:self.prove(path+'/local_endpoint',address_line,'tunnel.explicit_source_interface_address')
        # Only exact-permit lists can be represented faithfully by PrefixSet.
        prefix_groups = {}
        for r in self.records.values():
            if r['family']=='prefix': prefix_groups.setdefault(r['values']['name'],[]).append(r)
        for name, records in prefix_groups.items():
            if any(r['values']['action']!='permit' or 'ge' in r['values'] or 'le' in r['values'] for r in records): continue
            item=PrefixSet(name=name,prefixes=[str(ip_network(r['values']['prefix'],strict=False)) for r in records])
            self.c.routing.prefix_sets.append(item)
            path=f'routing/prefix_sets/{len(self.c.routing.prefix_sets)-1}'
            for i,r in enumerate(records): self.prove(path+f'/prefixes/{i}',r['source_line'])
        for r in self.records.values():
            if r['rule']=='services_ntp_source':
                for i,item in enumerate(self.c.system.ntp_servers):
                    self.assign(item,'source_interface',r['values']['source'],f'system/ntp_servers/{i}',r['source_line'])
            elif r['rule']=='services_logging_trap':
                for i,item in enumerate(self.c.system.syslog_destinations):
                    self.assign(item,'severity',r['values']['severity'],f'system/syslog_destinations/{i}',r['source_line'])
        for i, interface in enumerate(self.c.interfaces):
            if interface.vrf:
                vrf = next((v for v in self.c.network_instances if v.name == interface.vrf), None)
                if vrf:
                    vrf.interface_names.append(interface.name)
                    proof = next(e for e in self.evidence if e.path == f'/configuration/interfaces/{i}/vrf')
                    self.prove(f'network_instances/{self.c.network_instances.index(vrf)}/interface_names/{len(vrf.interface_names)-1}', proof.line_start)
        # Explicit one-level peer-group inheritance, never an OS default.
        for key, (process, path) in self.bgp.items():
            for i, neighbor in enumerate(process.neighbors):
                if neighbor.remote_as is not None or not neighbor.peer_group: continue
                candidates = []
                for record in self.records.values():
                    if record['rule'] == 'bgp_remote_as' and record['root_line'] == key[0] and record['values']['peer'] == neighbor.peer_group:
                        af_nodes = [self.records.get(n) for n in record['context_lines'] if self.records.get(n,{}).get('rule','').startswith('bgp_af')]
                        scope_vrf = af_nodes[-1]['values'].get('vrf') if af_nodes else None
                        if scope_vrf == key[1]: candidates.append(record)
                if len(candidates) == 1:
                    value = candidates[0]
                    neighbor.remote_as = asn(value['values']['remote_as'])
                    self.prove(path + f'/neighbors/{i}/remote_as', value['source_line'], 'bgp.explicit_peer_group_inheritance')
                    member = next((r for r in self.records.values() if r['root_line'] == key[0] and r['rule'] == 'bgp_group_member' and r['values']['peer'] == neighbor.peer),None)
                    if member: self.prove(path + f'/neighbors/{i}/remote_as', member['source_line'], 'bgp.explicit_peer_group_membership')

    def run(self):
        self.headers()
        headers = {'if_header','vrf_header','vrf_legacy_header','ospf_header','ospf_header_vrf','bgp_header','policy_header',
                   'services_line','services_tacacs','services_radius','advanced_qos_policymap','advanced_vlan'}
        handlers = {'interfaces':self.interface,'bgp':self.routing_bgp,'ospf':self.routing_ospf,'routes':self.routes,
                    'vrf':self.vrf,'acl_standard':self.acl,'acl_extended':self.acl,'policies':self.policies,'services':self.services}
        for line, r in sorted(self.records.items()):
            if r['rule'] in headers: continue
            try:
                handler = handlers.get(r['family'])
                if handler: handler(r)
                elif r['rule'] == 'advanced_vlan_name' and self.entity(line):
                    item,path=self.entity(line); self.assign(item,'name',r['values']['name'],path,line)
            except (ValueError, KeyError, IndexError, TypeError):
                self.failed.add(line)
                self.diagnostics.append(Diagnostic(severity='error',code='INVALID_CAPTURE_VALUE',
                    message='Captured values cannot be normalized; original command preserved.',source_line=line))
        self.finish_links()
        for i, interface in enumerate(self.c.interfaces):
            if interface.admin_enabled is None:
                self.evidence.append(Evidence(path=f'/configuration/interfaces/{i}/admin_enabled',status='unknown',
                    confidence=0,basis='No explicit shutdown command; defaults from official templates are not adopted.'))
        for path in ('system/management/ssh_enabled','system/management/telnet_enabled','system/ntp_enabled','system/snmp/enabled'):
            self.evidence.append(Evidence(path='/configuration/'+path,status='unknown',confidence=0,basis='No explicit supported global activation command.'))
        unknown = []
        for node in self.nodes.values():
            if node.kind == 'command' and node.line not in self.mapped or node.line in self.failed:
                unknown.append(UnknownCommand(line_start=node.line, raw_text=redacted(node.text),
                    parent_context=redacted(self.nodes[node.parent].text) if node.parent else None,
                    reason='unsupported_semantics' if node.line in self.records else 'not_implemented'))
        for family in ('bgp','ospf','policies','prefix','acl_standard','acl_extended','advanced'):
            rest = [n for n in self.nodes.values() if n.family==family and n.kind=='command' and n.line not in self.mapped]
            if rest:
                path = 'routing' if family in ('bgp','ospf','policies','prefix') else 'security' if family.startswith('acl') else 'qos'
                self.evidence.append(Evidence(path='/configuration/'+path,status='unsupported',source_file=self.source_file,
                    line_start=rest[0].line,raw_command=redacted(rest[0].text),basis='Captured or preserved commands have unrepresented semantics.',confidence=0))
                if family in ('policies','prefix','acl_standard','acl_extended'):
                    self.diagnostics.append(Diagnostic(severity='warning',code='PARTIAL_POLICY_DOMAIN',
                        message='Unrepresented policy commands remain; normalized subset is not deployable as a full policy.',source_line=rest[0].line))
        parsed = Parsing(parser_name='TTP official templates + source-numbered project extensions',parser_version='0.2.0',
            unknown_commands=sorted(unknown,key=lambda x:x.line_start),diagnostics=self.diagnostics,
            total_source_lines=len(self.text.splitlines()),recognized_source_lines=len(self.mapped-self.failed),
            feature_coverage=[FeatureCoverage(feature=family,status='partial',note='See coverage_report.json for per-command status.') for family in sorted({n.family for n in self.nodes.values() if n.kind=='command'})])
        result=NormalizedConfig(metadata=self.metadata,configuration=self.c,evidence=self.evidence,parsing=parsed)
        result=NormalizedConfig.model_validate(result.model_dump(mode='json'))
        for message in result.semantic_warnings():
            result.parsing.diagnostics.append(Diagnostic(severity='warning',code='UNRESOLVED_REFERENCE',message=message))
        return result
