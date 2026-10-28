"""Single active business contract for configured network facts.

OpenConfig-aligned vocabulary with explicit Cisco extensions. No version
inheritance, parsing reports, source metadata, or migration models.
"""
from __future__ import annotations
from functools import lru_cache
from copy import deepcopy
from ipaddress import IPv4Address,IPv6Address,ip_network
from typing import Annotated,Literal
from pydantic import BaseModel,ConfigDict,Field,IPvAnyAddress,IPvAnyNetwork,StrictStr,StrictInt,StrictBool,model_validator

class Contract(BaseModel):
    model_config = ConfigDict(extra='forbid', validate_assignment=True, use_enum_values=True)

class IPv4InterfaceAddress(Contract):
    address: IPv4Address
    prefix_length: int = Field(ge=0, le=32)
    secondary: bool | None = None

class IPv6InterfaceAddress(Contract):
    address: IPv6Address
    prefix_length: int = Field(ge=0, le=128)

class VLAN(Contract):
    vlan_id: int = Field(ge=1, le=4094)
    name: str | None = None
    admin_status: Literal['active', 'suspended', 'unknown'] | None = None
    tagged_interfaces: list[str] = Field(default_factory=list)
    untagged_interfaces: list[str] = Field(default_factory=list)

class LAG(Contract):
    name: str = Field(min_length=1)
    members: list[str] = Field(default_factory=list)
    lacp_mode: Literal['active', 'passive', 'on', 'unknown'] | None = None

class SpanningTree(Contract):
    mode: str | None = None
    bpdu_guard_default: bool | None = None
    portfast_default: bool | None = None

class Layer2(Contract):
    vlans: list[VLAN] = Field(default_factory=list)
    lags: list[LAG] = Field(default_factory=list)
    spanning_tree: SpanningTree | None = None

class NetworkInstance(Contract):
    name: str = Field(min_length=1)
    kind: Literal['DEFAULT_INSTANCE', 'L3VRF', 'L2VSI', 'L2L3', 'OTHER', 'UNKNOWN'] = 'UNKNOWN'
    route_distinguisher: str | None = None
    route_targets_import: list[str] = Field(default_factory=list)
    route_targets_export: list[str] = Field(default_factory=list)
    description: str | None = None

class NTPServer(Contract):
    address: str = Field(min_length=1)
    prefer: bool | None = None
    source_interface: str | None = None
    network_instance: str | None = None

class SyslogDestination(Contract):
    address: str = Field(min_length=1)
    port: int | None = Field(default=None, ge=1, le=65535)
    transport: Literal['udp', 'tcp', 'tls', 'unknown'] | None = None
    severity: str | None = None

class UserAccount(Contract):
    username: str = Field(min_length=1)
    privilege_level: int | None = Field(default=None, ge=0, le=15)
    credential_configured: bool | None = None
    credential_type: str | None = None

class AuthServer(Contract):
    protocol: Literal['radius', 'tacacs', 'other']
    address: str = Field(min_length=1)
    port: int | None = Field(default=None, ge=1, le=65535)

class SNMPCommunity(Contract):
    name: str = Field(min_length=1)
    access: Literal['ro', 'rw', 'unknown'] = 'unknown'
    access_list: str | None = None

class SNMP(Contract):
    enabled: bool | None = None
    communities: list[SNMPCommunity] = Field(default_factory=list)
    version: list[str] = Field(default_factory=list)
    location: str | None = None
    contact: str | None = None

class StaticRoute(Contract):
    destination: IPvAnyNetwork
    next_hop: IPvAnyAddress | None = None
    outgoing_interface: str | None = None
    network_instance: str | None = None
    admin_distance: int | None = Field(default=None, ge=1, le=255)
    description: str | None = None

    @model_validator(mode='after')
    def nexthop_present(self):
        if self.next_hop is None and self.outgoing_interface is None:
            raise ValueError('A static route needs next_hop or outgoing_interface')
        if self.next_hop is not None and self.destination.version != self.next_hop.version:
            raise ValueError('Static route next_hop family differs from destination')
        return self

class OSPFNetworkStatement(Contract):
    prefix: IPvAnyNetwork
    area: str = Field(min_length=1)

class OSPFArea(Contract):
    area_id: str = Field(min_length=1)
    interfaces: list[str] = Field(default_factory=list)
    type: Literal['stub', 'nssa', 'normal'] | None = None

class PortMatch(Contract):
    operator: Literal['eq', 'neq', 'lt', 'gt', 'range']
    start: int = Field(ge=0, le=65535)
    end: int | None = Field(default=None, ge=0, le=65535)

    @model_validator(mode='after')
    def valid_range(self):
        if self.operator == 'range':
            if self.end is None or self.end < self.start:
                raise ValueError('range requires end >= start')
        elif self.end is not None:
            raise ValueError('only range permits end')
        return self

class ACLAttachment(Contract):
    acl_name: str = Field(min_length=1)
    interface_name: str = Field(min_length=1)
    direction: Literal['ingress', 'egress']

class NATRule(Contract):
    identifier: str | None = Field(default=None, min_length=1)
    type: Literal['static', 'dynamic', 'pat', 'other', 'unknown'] = 'unknown'
    source_match: str | None = None
    translated_source: str | None = None
    destination_match: str | None = None
    translated_destination: str | None = None
    ingress_interface: str | None = None
    egress_interface: str | None = None
    network_instance: str | None = None

class VPNTunnel(Contract):
    identifier: str = Field(min_length=1)
    technology: Literal['ipsec', 'gre', 'wireguard', 'ssl', 'other', 'unknown'] = 'unknown'
    local_endpoint: str | None = None
    remote_endpoint: str | None = None
    tunnel_interface: str | None = None
    network_instance: str | None = None

class QoSAttachment(Contract):
    policy_name: str = Field(min_length=1)
    interface_name: str = Field(min_length=1)
    direction: Literal['ingress', 'egress']

class AllowASIn(Contract):
    enabled: bool
    configured_max_occurrences: int | None = Field(default=None, ge=1, le=10)

class PasswordPolicy(Contract):
    minimum_length: int | None = Field(default=None, ge=0)

class ConfigLogging(Contract):
    declared: bool | None = None
    hidekeys: bool | None = None

class ConfigArchive(Contract):
    declared: bool | None = None
    config_logging: ConfigLogging = Field(default_factory=ConfigLogging)

class CallHomeProfile(Contract):
    name: str = Field(min_length=1)
    active: bool | None = None
    transport_methods: list[Literal['http', 'email']] = Field(default_factory=list)

class CallHome(Contract):
    declared: bool | None = None
    enabled: bool | None = None
    profiles: list[CallHomeProfile] = Field(default_factory=list)

class BroadcastForwarding(Contract):
    protocol: Literal['nd']
    enabled: bool

class IPServices(Contract):
    cef_ipv4_enabled: bool | None = None
    cef_ipv6_enabled: bool | None = None
    icmp_unreachable_rate_limit_enabled: bool | None = None
    tcp_synwait_seconds: int | None = Field(default=None, ge=5, le=300)
    broadcast_forwarding_protocols: list[BroadcastForwarding] = Field(default_factory=list)

class DNSView(Contract):
    name: str = Field(min_length=1)
    network_instance: str = Field(min_length=1)
    declared: bool

class DNS(Contract):
    lookup_source_interface: str | None = None
    views: list[DNSView] = Field(default_factory=list)

class TFTPClient(Contract):
    source_interface: str | None = None

class FileTransfer(Contract):
    tftp: TFTPClient = Field(default_factory=TFTPClient)

class Collector(Contract):
    address: IPvAnyAddress
    port: int = Field(ge=1, le=65535)

class AggregationCache(Contract):
    aggregation: Literal['as']
    destinations: list[Collector] = Field(default_factory=list)

class NetFlow(Contract):
    aggregation_caches: list[AggregationCache] = Field(default_factory=list)

class AutoRP(Contract):
    listener_configured: bool | None = None
    discovery_scope: int | None = Field(default=None, ge=1, le=255)

class BSRCandidate(Contract):
    source_interface: str = Field(min_length=1)
    hash_mask_length: int = Field(ge=0, le=32)

class RPCandidate(Contract):
    source_interface: str = Field(min_length=1)

class SSM(Contract):
    range_selector: Literal['default'] | None = None

class MSDPPeer(Contract):
    address: IPv4Address
    connect_source_interface: str = Field(min_length=1)

class MSDP(Contract):
    peers: list[MSDPPeer] = Field(default_factory=list)

class RIPRedistribution(Contract):
    protocol: Literal['bgp']
    source_bgp_as: int = Field(ge=1, le=4294967295)
    metric: int = Field(ge=0, le=16)

class RIPScope(Contract):
    network_statements: list[IPv4Address] = Field(default_factory=list)
    auto_summary: bool | None = None
    redistributions: list[RIPRedistribution] = Field(default_factory=list)

class RIPFamily(RIPScope):
    afi: Literal['ipv4']
    network_instance: str = Field(min_length=1)

class RIPProcess(RIPScope):
    declared: bool
    address_families: list[RIPFamily] = Field(default_factory=list)

class VirtualService(Contract):
    name: str = Field(min_length=1)
    declared: bool

class Boot(Contract):
    configuration_register: str | None = Field(default=None, pattern='^0x[0-9A-Fa-f]{1,4}$')

class Ethernet(Contract):
    speed_mode: Literal['auto', 'fixed'] | None = None
    speed_bps: int | None = Field(default=None, gt=0)
    duplex: Literal['auto', 'half', 'full'] | None = None
    negotiation: Literal['auto'] | None = None
    media: str | None = None

    @model_validator(mode='after')
    def speed_consistency(self):
        if self.speed_mode == 'auto' and self.speed_bps is not None:
            raise ValueError('Auto speed has no configured numeric rate')
        if self.speed_mode == 'fixed' and self.speed_bps is None:
            raise ValueError('Fixed speed needs a rate')
        return self

class Encapsulation(Contract):
    kind: Literal['dot1q', 'qinq', 'untagged']
    outer_vlan: int | None = Field(default=None, ge=1, le=4094)
    inner_vlan: int | None = Field(default=None, ge=1, le=4094)

    @model_validator(mode='after')
    def coherent(self):
        if self.kind in ('dot1q', 'qinq') and self.outer_vlan is None:
            raise ValueError('Tagged encapsulation needs outer VLAN')
        if self.kind == 'qinq' and self.inner_vlan is None:
            raise ValueError('QinQ needs inner VLAN')
        return self

class OSPFBinding(Contract):
    version: Literal[2, 3]
    process: str
    area: str

class BGPNetwork(Contract):
    prefix: IPvAnyNetwork
    afi: str | None = None
    safi: str | None = None

class MaximumPaths(Contract):
    type: Literal['ibgp', 'ebgp', 'eibgp']
    count: int = Field(ge=1, le=512)

class Aggregate(Contract):
    prefix: IPvAnyNetwork
    options: list[Literal['summary-only', 'as-set']]
    afi: str | None = None
    safi: str | None = None

class Redistribution(Contract):
    protocol: Literal['connected', 'static', 'bgp', 'ospf', 'ospfv3', 'isis', 'eigrp', 'rip']
    process: str | None = None
    subnets: bool | None = None
    route_map: str | None = None
    afi: str | None = None
    safi: str | None = None

class DefaultOrigination(Contract):
    enabled: bool
    always: bool | None = None

class VirtualLink(Contract):
    area: str
    peer_router_id: IPv4Address

class PrefixListEntry(Contract):
    sequence: int | None = Field(default=None, ge=0)
    action: Literal['permit', 'deny']
    prefix: IPvAnyNetwork
    ge: int | None = Field(default=None, ge=0, le=128)
    le: int | None = Field(default=None, ge=0, le=128)

    @model_validator(mode='after')
    def lengths(self):
        p = ip_network(self.prefix)
        limit = p.max_prefixlen
        for bound in (self.ge, self.le):
            if bound is not None and (not p.prefixlen <= bound <= limit):
                raise ValueError('Invalid prefix length bound')
        if self.ge is not None and self.le is not None and (self.ge > self.le):
            raise ValueError('ge exceeds le')
        return self

class PrefixList(Contract):
    name: str
    family: Literal['ipv4', 'ipv6']
    entries: list[PrefixListEntry] = Field(default_factory=list)

    @model_validator(mode='after')
    def identities(self):
        seq = [x.sequence for x in self.entries if x.sequence is not None]
        if len(seq) != len(set(seq)):
            raise ValueError('Duplicate prefix sequence')
        if any((ip_network(x.prefix).version != (4 if self.family == 'ipv4' else 6) for x in self.entries)):
            raise ValueError('Mixed prefix family')
        return self

class TimestampPolicy(Contract):
    category: Literal['debug', 'log']
    format: Literal['datetime', 'uptime']
    options: list[Literal['msec', 'localtime', 'show-timezone', 'year']] = Field(default_factory=list)

class CommunityListEntry(Contract):
    action: Literal['permit', 'deny']
    expression: str

class CommunityList(Contract):
    name: str
    dialect: Literal['cisco_expanded_regex'] = 'cisco_expanded_regex'
    entries: list[CommunityListEntry] = Field(default_factory=list)

class Banner(Contract):
    type: Literal['login', 'motd', 'exec', 'incoming']

class FlowExport(Contract):
    source_interface: str | None = None
    version: int | None = Field(default=None, ge=1, le=10)
    as_mode: Literal['origin-as', 'peer-as'] | None = None
    cache_timeout_active_minutes: int | None = Field(default=None, ge=1)
    cache_timeout_inactive_seconds: int | None = Field(default=None, ge=1)

class QoSMatch(Contract):
    kind: Literal['dscp', 'precedence', 'protocol', 'acl']
    value: str

class QoSAction(Contract):
    kind: Literal['set_dscp', 'set_precedence', 'priority_percent', 'fair_queue']
    value: StrictStr | StrictInt | StrictBool

    @model_validator(mode='after')
    def constraints(self):
        if self.kind == 'priority_percent' and (type(self.value) is not int or not 0 <= self.value <= 100):
            raise ValueError('Invalid QoS percentage')
        if self.kind == 'fair_queue' and type(self.value) is not bool:
            raise ValueError('Queue flag must be boolean')
        return self

class ClassMap(Contract):
    name: str
    match_mode: Literal['match-any', 'match-all']
    matches: list[QoSMatch] = Field(default_factory=list)

class PolicyClass(Contract):
    name: str
    actions: list[QoSAction] = Field(default_factory=list)

class PolicyMap(Contract):
    name: str
    classes: list[PolicyClass] = Field(default_factory=list)

class Trustpoint(Contract):
    name: str
    enrollment: Literal['selfsigned', 'terminal', 'pkcs12'] | None = None
    revocation_check: Literal['none', 'crl', 'ocsp'] | None = None
    subject_name: str | None = None
    keypair_reference: str | None = None

class Certificate(Contract):
    type: Literal['ca', 'self-signed']
    identifier: str = Field(pattern='^[0-9a-fA-F]+$')

class CertificateChain(Contract):
    name: str
    certificates: list[Certificate] = Field(default_factory=list)

class LDP(Contract):
    router_id_interface: str | None = None
    force: bool | None = None

class MPLS(Contract):
    label_protocol: Literal['ldp', 'tdp'] | None = None
    ldp: LDP = Field(default_factory=LDP)

class PKI(Contract):
    trustpoints: list[Trustpoint] = Field(default_factory=list)
    chains: list[CertificateChain] = Field(default_factory=list)

class IsisProcess(Contract):
    name: str
    net: str | None = Field(default=None, pattern='^[0-9A-Fa-f.]+$')
    passive_interfaces: list[str] = Field(default_factory=list)

class Multicast(Contract):
    auto_rp: AutoRP = Field(default_factory=AutoRP)
    bsr_candidates: list[BSRCandidate] = Field(default_factory=list)
    rp_candidates: list[RPCandidate] = Field(default_factory=list)
    ssm: SSM = Field(default_factory=SSM)
    msdp: MSDP = Field(default_factory=MSDP)
    routing_enabled: bool | None = None
    rendezvous_points: list[IPvAnyAddress] = Field(default_factory=list)

class EthernetService(Contract):
    interface: str
    instance: int = Field(ge=1)
    encapsulation: Encapsulation | None = None
    bridge_domain: int | None = Field(default=None, ge=1, le=16777215)

class BridgeMember(Contract):
    kind: Literal['interface_service', 'evpn']
    interface: str | None = None
    service_instance: int | None = Field(default=None, ge=1)
    evpn_instance: int | None = Field(default=None, ge=1)
    ethernet_tag: int | None = Field(default=None, ge=0)

    @model_validator(mode='after')
    def identity(self):
        if self.kind == 'interface_service' and (self.interface is None or self.service_instance is None):
            raise ValueError('Missing interface attachment')
        if self.kind == 'evpn' and (self.evpn_instance is None or self.ethernet_tag is None):
            raise ValueError('Missing EVI attachment')
        return self

class BridgeDomain(Contract):
    identifier: int = Field(ge=1)
    members: list[BridgeMember] = Field(default_factory=list)

class EVI(Contract):
    identifier: int = Field(ge=1)
    type: Literal['vlan-based', 'vlan-aware']

class VFINeighbor(Contract):
    address: IPvAnyAddress
    encapsulation: Literal['mpls']

class VFI(Contract):
    bridge_domain: int | None = Field(default=None, ge=1, le=16777215)
    identifier: int = Field(ge=1)
    mode: Literal['manual', 'autodiscovery']
    vpn_id: int | None = Field(default=None, ge=1)
    neighbors: list[VFINeighbor] = Field(default_factory=list)

class L2VPN(Contract):
    evpn_declared: bool | None = None
    replication_type: Literal['ingress'] | None = None
    router_id_interface: str | None = None
    evpn_instances: list[EVI] = Field(default_factory=list)
    bridge_domains: list[BridgeDomain] = Field(default_factory=list)
    vfis: list[VFI] = Field(default_factory=list)

class CiscoExtensions(Contract):
    config_archive: ConfigArchive = Field(default_factory=ConfigArchive)
    call_home: CallHome = Field(default_factory=CallHome)
    ip_services: IPServices = Field(default_factory=IPServices)
    dns: DNS = Field(default_factory=DNS)
    file_transfer: FileTransfer = Field(default_factory=FileTransfer)
    netflow: NetFlow = Field(default_factory=NetFlow)
    virtual_services: list[VirtualService] = Field(default_factory=list)
    boot: Boot = Field(default_factory=Boot)
    pki: PKI = Field(default_factory=PKI)
    mpls: MPLS = Field(default_factory=MPLS)
    community_lists: list[CommunityList] = Field(default_factory=list)
    isis: list[IsisProcess] = Field(default_factory=list)
    multicast: Multicast = Field(default_factory=Multicast)
    ethernet_services: list[EthernetService] = Field(default_factory=list)
    l2vpn: L2VPN = Field(default_factory=L2VPN)

class BGPPeer(Contract):
    peer: str = Field(min_length=1)
    kind: Literal['neighbor', 'group']
    remote_as: int | None = Field(default=None, ge=1, le=4294967295)
    description: str | None = None
    enabled: bool | None = None
    update_source: str | None = None
    active: bool | None = None
    route_reflector_client: bool | None = None
    next_hop_self: bool | None = None
    send_community: Literal['command_without_option', 'standard', 'extended', 'both'] | None = None
    import_policies: list[str] = Field(default_factory=list)
    export_policies: list[str] = Field(default_factory=list)
    inherited_group: str | None = None
    additional_paths_advertise_selection: Literal['all', 'best'] | None = None
    allowas_in: AllowASIn | None = None

class BGPNeighbor(Contract):
    peer: str = Field(min_length=1)
    kind: Literal['neighbor', 'group'] = 'neighbor'
    remote_as: int | None = Field(default=None, ge=1, le=4294967295)
    description: str | None = None
    enabled: bool | None = None
    update_source: str | None = None
    active: bool | None = None
    route_reflector_client: bool | None = None
    next_hop_self: bool | None = None
    send_community: Literal['command_without_option', 'standard', 'extended', 'both'] | None = None
    import_policies: list[str] = Field(default_factory=list)
    export_policies: list[str] = Field(default_factory=list)
    inherited_group: str | None = None
    additional_paths_advertise_selection: Literal['all', 'best'] | None = None
    allowas_in: AllowASIn | None = None

class BGPPeerGroup(Contract):
    name: str = Field(min_length=1)
    remote_as: int | None = Field(default=None, ge=1, le=4294967295)
    description: str | None = None
    enabled: bool | None = None
    update_source: str | None = None
    active: bool | None = None
    route_reflector_client: bool | None = None
    next_hop_self: bool | None = None
    send_community: Literal['command_without_option', 'standard', 'extended', 'both'] | None = None
    import_policies: list[str] = Field(default_factory=list)
    export_policies: list[str] = Field(default_factory=list)
    inherited_group: str | None = None
    additional_paths_advertise_selection: Literal['all', 'best'] | None = None
    allowas_in: AllowASIn | None = None

class Authentication(Contract):
    method: Literal['local', 'line_password', 'aaa']
    method_list: str | None = None

class RoutingPolicyMatch(Contract):
    kind: Literal['acl', 'prefix_set_ipv4', 'prefix_set_ipv6', 'community']
    name: str = Field(min_length=1)

class NumericPolicyAction(Contract):
    kind: Literal['local_preference', 'metric', 'cisco_weight']
    value: StrictInt

class ASPathPolicyAction(Contract):
    kind: Literal['as_path_prepend'] = 'as_path_prepend'
    as_numbers: list[Annotated[int, Field(ge=1, le=4294967295)]]

class CommunityPolicyAction(Contract):
    kind: Literal['community'] = 'community'
    communities: list[Annotated[str, Field(pattern=r'^[0-9]+:[0-9]+$')]]
    additive: bool

class ACLAny(Contract):
    kind: Literal['any'] = 'any'
    address_family: Literal['ipv4', 'ipv6'] | None = None

class ACLHost(Contract):
    kind: Literal['host'] = 'host'
    address: IPvAnyAddress

class ACLPrefix(Contract):
    kind: Literal['prefix'] = 'prefix'
    prefix: IPvAnyNetwork

class ACLWildcard(Contract):
    kind: Literal['wildcard'] = 'wildcard'
    address: IPv4Address
    wildcard_mask: IPv4Address

class ACLObjectGroup(Contract):
    kind: Literal['object_group'] = 'object_group'
    name: str = Field(min_length=1)

class Interface(Contract):
    name: str = Field(min_length=1, description='Native interface identifier; NEVER translate port names implicitly')
    kind: Literal['physical', 'subinterface', 'loopback', 'svi', 'lag', 'tunnel', 'other', 'unknown'] = 'unknown'
    parent_interface: str | None = None
    subinterface_index: int | None = Field(default=None, ge=0)
    description: str | None = None
    admin_enabled: bool | None = None
    mtu: int | None = Field(default=None, ge=64, le=65535)
    ipv4_addresses: list[IPv4InterfaceAddress] = Field(default_factory=list)
    ipv6_addresses: list[IPv6InterfaceAddress] = Field(default_factory=list)
    vrf: str | None = None
    switchport_mode: Literal['access', 'trunk', 'hybrid', 'routed', 'unknown'] | None = None
    access_vlan: int | None = Field(default=None, ge=1, le=4094)
    native_vlan: int | None = Field(default=None, ge=1, le=4094)
    trunk_allowed_vlans: list[int] | None = None
    lag: str | None = None
    acl_ingress: list[str] = Field(default_factory=list)
    acl_egress: list[str] = Field(default_factory=list)

    @model_validator(mode='after')
    def unique_trunk_vlans(self):
        if self.trunk_allowed_vlans is not None:
            if len(set(self.trunk_allowed_vlans)) != len(self.trunk_allowed_vlans):
                raise ValueError('Duplicate trunk VLAN IDs')
            if any((x < 1 or x > 4094 for x in self.trunk_allowed_vlans)):
                raise ValueError('Trunk VLAN IDs must be 1-4094')
        return self
    ipv4_assignment_method: Literal['dhcp'] | None = None
    pim_bsr_border: bool | None = None
    sap_listen_enabled: bool | None = None
    ethernet: Ethernet = Field(default_factory=Ethernet)
    encapsulation: Encapsulation | None = None
    ipv6_enabled: bool | None = None
    unnumbered_interface: str | None = None
    tcp_mss: int | None = Field(default=None, ge=1, le=65535)
    proxy_arp: bool | None = None
    redirects: bool | None = None
    keepalive_enabled: bool | None = None
    mpls_enabled: bool | None = None
    pim_mode: Literal['sparse-mode', 'dense-mode', 'sparse-dense-mode', 'passive'] | None = None
    isis_process: str | None = None
    isis_network_type: Literal['point-to-point', 'broadcast'] | None = None
    ospf_network_type: Literal['point-to-point', 'broadcast', 'non-broadcast', 'point-to-multipoint'] | None = None
    ospf_bindings: list[OSPFBinding] = Field(default_factory=list)
    flow_directions: list[Literal['ingress', 'egress']] = Field(default_factory=list)
    cdp_enabled: bool | None = None
    mop_enabled: bool | None = None
    mop_sysid: bool | None = None

class AAA(Contract):
    enabled: bool | None = None
    local_users: list[UserAccount] = Field(default_factory=list)
    servers: list[AuthServer] = Field(default_factory=list)
    password_policy: PasswordPolicy = Field(default_factory=PasswordPolicy)

class ManagementLine(Contract):
    name: str = Field(min_length=1, description='Native management line, e.g. vty 0 4')
    allowed_transports: list[str] = Field(default_factory=list)
    idle_timeout_seconds: int | None = Field(default=None, ge=0)
    access_list: str | None = None
    authentication: Authentication | None = None
    logging_synchronous: bool | None = None
    privilege_level: int | None = Field(default=None, ge=0, le=15)
    stopbits: int | None = Field(default=None, ge=1, le=2)
    screen_length: int | None = Field(default=None, ge=0, le=512)
    preferred_transports: list[str] | None = None

class Management(Contract):
    ssh_enabled: bool | None = None
    ssh_version: str | None = None
    telnet_enabled: bool | None = None
    http_enabled: bool | None = None
    https_enabled: bool | None = None
    lines: list[ManagementLine] = Field(default_factory=list)

class System(Contract):
    hostname: str | None = None
    domain_name: str | None = None
    dns_servers: list[str] = Field(default_factory=list)
    ntp_enabled: bool | None = None
    ntp_servers: list[NTPServer] = Field(default_factory=list)
    syslog_destinations: list[SyslogDestination] = Field(default_factory=list)
    snmp: SNMP | None = None
    aaa: AAA | None = None
    management: Management | None = None
    login_success_logging: bool | None = None
    console_logging: bool | None = None
    source_routing: bool | None = None
    dns_lookup_enabled: bool | None = None
    password_encryption_service: bool | None = None
    ipv6_unicast_routing: bool | None = None
    syslog_source_interface: str | None = None
    timestamps: list[TimestampPolicy] = Field(default_factory=list)
    http_authentication: Literal['local', 'aaa', 'enable'] | None = None
    flow_export: FlowExport = Field(default_factory=FlowExport)
    banners: list[Banner] = Field(default_factory=list)

class OSPFProcess(Contract):
    identifier: str = Field(min_length=1, description='Native process ID; semantics differ across vendors')
    network_instance: str | None = None
    router_id: IPv4Address | None = None
    network_statements: list[OSPFNetworkStatement] = Field(default_factory=list)
    passive_interfaces: list[str] = Field(default_factory=list)
    version: Literal[2, 3]
    areas: list[OSPFArea] = Field(default_factory=list)
    virtual_links: list[VirtualLink] = Field(default_factory=list)
    log_adjacency_changes: bool | None = None
    redistributions: list[Redistribution] = Field(default_factory=list)
    default_origination: DefaultOrigination | None = None

class RoutingPolicyStatement(Contract):
    identifier: str = Field(min_length=1)
    decision: Literal['accept', 'reject', 'next', 'unknown'] | None = None
    matches: list[RoutingPolicyMatch] = Field(default_factory=list)
    actions: list[RoutingPolicyAction] = Field(default_factory=list)

class RoutingPolicy(Contract):
    name: str = Field(min_length=1)
    statements: list[RoutingPolicyStatement] = Field(default_factory=list)

class ACLEntry(Contract):
    sequence: int | None = Field(default=None, ge=0)
    action: Literal['permit', 'deny', 'reject', 'unknown']
    protocol: str | None = None
    source: ACLAddressMatch | None = None
    destination: ACLAddressMatch | None = None
    source_port: PortMatch | None = None
    destination_port: PortMatch | None = None
    log: bool | None = None
    description: str | None = None

class ACLSet(Contract):
    name: str = Field(min_length=1)
    family: Literal['ipv4', 'ipv6', 'l2', 'mixed', 'unknown'] = 'unknown'
    entries: list[ACLEntry] = Field(default_factory=list, description='Order is semantically significant')

    @model_validator(mode='after')
    def unique_sequences(self):
        seq = [x.sequence for x in self.entries if x.sequence is not None]
        if len(seq) != len(set(seq)):
            raise ValueError('Duplicate ACL sequence numbers')
        return self

class Security(Contract):
    acl_sets: list[ACLSet] = Field(default_factory=list)
    acl_attachments: list[ACLAttachment] = Field(default_factory=list)

class QoS(Contract):
    attachments: list[QoSAttachment] = Field(default_factory=list)
    class_maps: list[ClassMap] = Field(default_factory=list)
    policy_maps: list[PolicyMap] = Field(default_factory=list)

class BGPAddressFamily(Contract):
    auto_summary: bool | None = None
    synchronization: bool | None = None
    afi: Literal['ipv4', 'ipv6', 'vpnv4', 'vpnv6', 'l2vpn']
    safi: str | None = None
    peers: list[BGPPeer] = Field(default_factory=list)
    dampening: bool | None = None
    additional_paths_selection: Literal['all', 'best'] | None = None
    additional_paths_send: bool | None = None
    additional_paths_receive: bool | None = None
    maximum_paths: list['MaximumPaths'] = Field(default_factory=list)

class BGPProcess(Contract):
    local_as: int = Field(ge=1, le=4294967295)
    network_instance: str | None = None
    router_id: IPv4Address | None = None
    networks: list[BGPNetwork] = Field(default_factory=list)
    log_neighbor_changes: bool | None = None
    compare_med: bool | None = None
    deterministic_med: bool | None = None
    default_ipv4_unicast: bool | None = None
    synchronization: bool | None = None
    auto_summary: bool | None = None
    enforce_first_as: bool | None = None
    dampening: bool | None = None
    additional_paths_selection: Literal['all', 'best'] | None = None
    additional_paths_send: bool | None = None
    additional_paths_receive: bool | None = None
    maximum_paths: list['MaximumPaths'] = Field(default_factory=list)
    aggregates: list['Aggregate'] = Field(default_factory=list)
    redistributions: list['Redistribution'] = Field(default_factory=list)
    neighbors: list[BGPNeighbor] = Field(default_factory=list)
    peer_groups: list[BGPPeerGroup] = Field(default_factory=list)
    address_families: list[BGPAddressFamily] = Field(default_factory=list)

class Routing(Contract):
    static_routes: list[StaticRoute] = Field(default_factory=list)
    routing_policies: list[RoutingPolicy] = Field(default_factory=list)
    rip: list[RIPProcess] = Field(default_factory=list)
    bgp: list[BGPProcess] = Field(default_factory=list)
    ospf: list[OSPFProcess] = Field(default_factory=list)
    prefix_lists: list[PrefixList] = Field(default_factory=list)

class NormalizedConfig(Contract):
    layer2: Layer2 = Field(default_factory=Layer2)
    security: Security = Field(default_factory=Security)
    nat: list[NATRule] = Field(default_factory=list)
    vpn_tunnels: list[VPNTunnel] = Field(default_factory=list)

    @model_validator(mode='after')
    def unique_ids(self):
        for label, ids in [('interface', [x.name for x in self.interfaces]), ('VLAN', [x.vlan_id for x in self.layer2.vlans]), ('network_instance', [x.name for x in self.network_instances]), ('ACL', [(x.name, x.family) for x in self.security.acl_sets])]:
            if len(ids) != len(set(ids)):
                raise ValueError(f'Duplicate {label} identity')
        return self
    system: System = Field(default_factory=System)
    interfaces: list[Interface] = Field(default_factory=list)
    network_instances: list[NetworkInstance] = Field(default_factory=list)
    routing: Routing = Field(default_factory=Routing)
    qos: QoS = Field(default_factory=QoS)
    cisco: CiscoExtensions = Field(default_factory=CiscoExtensions)

ACLAddressMatch = Annotated[ACLAny | ACLHost | ACLPrefix | ACLWildcard | ACLObjectGroup, Field(discriminator='kind')]
RoutingPolicyAction = Annotated[NumericPolicyAction | ASPathPolicyAction | CommunityPolicyAction, Field(discriminator='kind')]

for _model in tuple(globals().values()):
    if isinstance(_model,type) and issubclass(_model,Contract):
        _model.model_rebuild()

@lru_cache(maxsize=1)
def business_schema():
    """Public schema: configured properties may be absent, never null/default facts."""
    def clean(value):
        if isinstance(value,list):return [clean(v) for v in value]
        if not isinstance(value,dict):return value
        value={k:clean(v) for k,v in value.items() if k!='default'}
        if 'anyOf' in value:value['anyOf']=[v for v in value['anyOf'] if v.get('type')!='null']
        return value
    schema=clean(deepcopy(NormalizedConfig.model_json_schema()))
    schema.update({'$schema':'https://json-schema.org/draft/2020-12/schema','$id':'urn:cisco-normalizer:business:1.0.0','title':'Configured network facts - business export 1.0.0'})
    return schema

