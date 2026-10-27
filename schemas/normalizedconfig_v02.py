"""Internal OpenConfig-aligned contract 0.2, with explicit native extension boundary.

v0.1 remains byte-for-byte in normalizedconfig.py. NativeObservation is typed,
source-scoped vendor data, never by itself evidence of full normalization.
"""
from __future__ import annotations
from typing import Literal,get_args,get_origin
from copy import deepcopy
from ipaddress import ip_network
from pydantic import Field, model_validator, StrictStr, StrictInt, StrictBool
from . import normalizedconfig as v1


class Ethernet(v1.Contract):
    speed_mode: Literal['auto','fixed'] | None=None
    speed_bps: int | None=Field(default=None,gt=0)
    duplex: Literal['auto','half','full'] | None=None
    negotiation: Literal['auto'] | None=None
    media: str | None=None
    @model_validator(mode='after')
    def speed_consistency(self):
        if self.speed_mode=='auto' and self.speed_bps is not None:raise ValueError('Auto speed has no configured numeric rate')
        if self.speed_mode=='fixed' and self.speed_bps is None:raise ValueError('Fixed speed needs a rate')
        return self


class Encapsulation(v1.Contract):
    kind: Literal['dot1q','qinq','untagged']
    outer_vlan: int | None=Field(default=None,ge=1,le=4094)
    inner_vlan: int | None=Field(default=None,ge=1,le=4094)
    @model_validator(mode='after')
    def coherent(self):
        if self.kind in ('dot1q','qinq') and self.outer_vlan is None:raise ValueError('Tagged encapsulation needs outer VLAN')
        if self.kind=='qinq' and self.inner_vlan is None:raise ValueError('QinQ needs inner VLAN')
        return self


class OSPFBinding(v1.Contract):
    version: Literal[2,3]
    process: str
    area: str


class Interface(v1.Interface):
    ethernet: Ethernet=Field(default_factory=Ethernet)
    encapsulation: Encapsulation | None=None
    ipv6_enabled: bool | None=None
    unnumbered_interface: str | None=None
    tcp_mss: int | None=Field(default=None,ge=1,le=65535)
    proxy_arp: bool | None=None
    redirects: bool | None=None
    keepalive_enabled: bool | None=None
    mpls_enabled: bool | None=None
    pim_mode: Literal['sparse-mode','dense-mode','sparse-dense-mode','passive'] | None=None
    isis_process: str | None=None
    isis_network_type: Literal['point-to-point','broadcast'] | None=None
    ospf_network_type: Literal['point-to-point','broadcast','non-broadcast','point-to-multipoint'] | None=None
    ospf_bindings: list[OSPFBinding]=Field(default_factory=list)
    flow_directions: list[Literal['ingress','egress']]=Field(default_factory=list)
    cdp_enabled: bool | None=None
    mop_enabled: bool | None=None
    mop_sysid: bool | None=None


class NetworkInstance(v1.NetworkInstance):
    description: str | None=None


class BGPPeerOptions(v1.Contract):
    peer: str
    kind: Literal['neighbor','group']
    remote_as: int | None=Field(default=None,ge=1,le=4294967295)
    update_source: str | None=None
    active: bool | None=None
    route_reflector_client: bool | None=None
    next_hop_self: bool | None=None
    # command_without_option is an explicit syntax form, not a platform default.
    send_community: Literal['command_without_option','standard','extended','both'] | None=None
    import_policies: list[str]=Field(default_factory=list)
    export_policies: list[str]=Field(default_factory=list)
    inherited_group: str | None=None


class BGPAddressFamily(v1.Contract):
    afi: Literal['ipv4','ipv6','vpnv4','vpnv6','l2vpn']
    safi: str | None=None
    peers: list[BGPPeerOptions]=Field(default_factory=list)
    dampening: bool | None=None
    additional_paths_selection: Literal['all','best'] | None=None
    additional_paths_send: bool | None=None
    additional_paths_receive: bool | None=None
    maximum_paths: list['MaximumPaths']=Field(default_factory=list)


class BGPNetwork(v1.Contract):
    prefix: v1.IPvAnyNetwork
    afi: str | None=None
    safi: str | None=None


class BGPProcess(v1.BGPProcess):
    peer_options: list[BGPPeerOptions]=Field(default_factory=list)
    family_options: list[BGPAddressFamily]=Field(default_factory=list)
    networks: list[BGPNetwork]=Field(default_factory=list)
    log_neighbor_changes: bool | None=None
    compare_med: bool | None=None
    deterministic_med: bool | None=None
    default_ipv4_unicast: bool | None=None
    synchronization: bool | None=None
    auto_summary: bool | None=None
    enforce_first_as: bool | None=None
    dampening: bool | None=None
    additional_paths_selection: Literal['all','best'] | None=None
    additional_paths_send: bool | None=None
    additional_paths_receive: bool | None=None
    maximum_paths: list['MaximumPaths']=Field(default_factory=list)
    aggregates: list['Aggregate']=Field(default_factory=list)
    redistributions: list['Redistribution']=Field(default_factory=list)


class MaximumPaths(v1.Contract):
    type: Literal['ibgp','ebgp','eibgp']
    count: int=Field(ge=1,le=512)


class Aggregate(v1.Contract):
    prefix: v1.IPvAnyNetwork
    options: list[Literal['summary-only','as-set']]
    afi: str | None=None
    safi: str | None=None


class Redistribution(v1.Contract):
    protocol: Literal['connected','static','bgp','ospf','ospfv3','isis','eigrp','rip']
    process: str | None=None
    subnets: bool | None=None
    route_map: str | None=None
    afi: str | None=None
    safi: str | None=None


class DefaultOrigination(v1.Contract):
    enabled: bool
    always: bool | None=None


class OSPFArea(v1.OSPFArea):
    type: Literal['stub','nssa','normal'] | None=None


class VirtualLink(v1.Contract):
    area: str
    peer_router_id: v1.IPv4Address


class OSPFProcess(v1.OSPFProcess):
    version: Literal[2,3]
    areas: list[OSPFArea]=Field(default_factory=list)
    virtual_links: list[VirtualLink]=Field(default_factory=list)
    log_adjacency_changes: bool | None=None
    redistributions: list[Redistribution]=Field(default_factory=list)
    default_origination: DefaultOrigination | None=None


class PrefixListEntry(v1.Contract):
    sequence: int | None=Field(default=None,ge=0)
    action: Literal['permit','deny']
    prefix: v1.IPvAnyNetwork
    ge: int | None=Field(default=None,ge=0,le=128)
    le: int | None=Field(default=None,ge=0,le=128)
    @model_validator(mode='after')
    def lengths(self):
        p=ip_network(self.prefix);limit=p.max_prefixlen
        for bound in (self.ge,self.le):
            if bound is not None and not p.prefixlen<=bound<=limit:raise ValueError('Invalid prefix length bound')
        if self.ge is not None and self.le is not None and self.ge>self.le:raise ValueError('ge exceeds le')
        return self


class PrefixList(v1.Contract):
    name: str
    family: Literal['ipv4','ipv6']
    entries: list[PrefixListEntry]=Field(default_factory=list)
    @model_validator(mode='after')
    def identities(self):
        seq=[x.sequence for x in self.entries if x.sequence is not None]
        if len(seq)!=len(set(seq)):raise ValueError('Duplicate prefix sequence')
        if any(ip_network(x.prefix).version!=(4 if self.family=='ipv4' else 6) for x in self.entries):raise ValueError('Mixed prefix family')
        return self


class Routing(v1.Routing):
    bgp: list[BGPProcess]=Field(default_factory=list)
    ospf: list[OSPFProcess]=Field(default_factory=list)
    prefix_lists: list[PrefixList]=Field(default_factory=list)


class ManagementLine(v1.ManagementLine):
    logging_synchronous: bool | None=None
    privilege_level: int | None=Field(default=None,ge=0,le=15)
    stopbits: int | None=Field(default=None,ge=1,le=2)
    screen_length: int | None=Field(default=None,ge=0,le=512)
    preferred_transports: list[str] | None=None


class Management(v1.Management):
    lines: list[ManagementLine]=Field(default_factory=list)


class TimestampPolicy(v1.Contract):
    category: Literal['debug','log']
    format: Literal['datetime','uptime']
    options: list[Literal['msec','localtime','show-timezone','year']]=Field(default_factory=list)


class CommunityListEntry(v1.Contract):
    action: Literal['permit','deny']
    expression: str


class CommunityList(v1.Contract):
    name: str
    dialect: Literal['cisco_expanded_regex']='cisco_expanded_regex'
    entries: list[CommunityListEntry]=Field(default_factory=list)


class Banner(v1.Contract):
    type: Literal['login','motd','exec','incoming']
    delimiter: str
    source_line: int=Field(ge=1)


class FlowExport(v1.Contract):
    source_interface: str | None=None
    version: int | None=Field(default=None,ge=1,le=10)
    as_mode: Literal['origin-as','peer-as'] | None=None
    cache_timeout_active_minutes: int | None=Field(default=None,ge=1)
    cache_timeout_inactive_seconds: int | None=Field(default=None,ge=1)


class System(v1.System):
    management: Management | None=None
    login_success_logging: bool | None=None
    console_logging: bool | None=None
    source_routing: bool | None=None
    dns_lookup_enabled: bool | None=None
    password_encryption_service: bool | None=None
    ipv6_unicast_routing: bool | None=None
    syslog_source_interface: str | None=None
    timestamps: list[TimestampPolicy]=Field(default_factory=list)
    http_authentication: Literal['local','aaa','enable'] | None=None
    flow_export: FlowExport=Field(default_factory=FlowExport)
    banners: list[Banner]=Field(default_factory=list)


class Scope(v1.Contract):
    root_line: int=Field(ge=1)
    root_command: str
    ancestors: list[str]=Field(default_factory=list)
    ancestor_lines: list[int]=Field(default_factory=list)
    @model_validator(mode='after')
    def lengths(self):
        if len(self.ancestors)!=len(self.ancestor_lines):raise ValueError('Mismatched scope coordinates')
        return self


class NativeParameter(v1.Contract):
    name: str
    # Scalar types remain distinct (strict validation avoids bool→int coercion).
    value: StrictStr | StrictInt | StrictBool
    validation: Literal['validated','unvalidated']


class CiscoObservation(v1.Contract):
    domain: Literal['ethernet','bgp','ospf','qos','pki','mpls','multicast','isis','l2vpn','services','interface','routing','acl','vrf','policy','prefix']
    rule: str
    source_line: int=Field(ge=1)
    scope: Scope
    parameters: list[NativeParameter]
    semantic_completeness: Literal['partial']='partial'
    justification: str=Field(min_length=1)


class OpaqueBlock(v1.Contract):
    kind: Literal['certificate','banner']
    line_start: int=Field(ge=1)
    line_end: int=Field(ge=1)
    parent_line: int | None=None
    sha256: str=Field(pattern=r'^[0-9a-f]{64}$')


class QoSMatch(v1.Contract):
    kind: Literal['dscp','precedence','protocol','acl']
    value: str


class QoSAction(v1.Contract):
    kind: Literal['set_dscp','set_precedence','priority_percent','fair_queue']
    value: StrictStr | StrictInt | StrictBool
    @model_validator(mode='after')
    def constraints(self):
        if self.kind=='priority_percent' and (type(self.value) is not int or not 0<=self.value<=100):raise ValueError('Invalid QoS percentage')
        if self.kind=='fair_queue' and type(self.value) is not bool:raise ValueError('Queue flag must be boolean')
        return self


class ClassMap(v1.Contract):
    name: str
    match_mode: Literal['match-any','match-all']
    matches: list[QoSMatch]=Field(default_factory=list)


class PolicyClass(v1.Contract):
    name: str
    actions: list[QoSAction]=Field(default_factory=list)


class PolicyMap(v1.Contract):
    name: str
    classes: list[PolicyClass]=Field(default_factory=list)


class QoS(v1.QoS):
    class_maps: list[ClassMap]=Field(default_factory=list)
    policy_maps: list[PolicyMap]=Field(default_factory=list)


class Trustpoint(v1.Contract):
    name: str
    enrollment: Literal['selfsigned','terminal','pkcs12'] | None=None
    revocation_check: Literal['none','crl','ocsp'] | None=None
    subject_name: str | None=None
    keypair_reference: str | None=None


class Certificate(v1.Contract):
    type: Literal['ca','self-signed']
    identifier: str=Field(pattern=r'^[0-9a-fA-F]+$')
    source_line: int=Field(ge=1)


class CertificateChain(v1.Contract):
    name: str
    certificates: list[Certificate]=Field(default_factory=list)


class LDP(v1.Contract):
    router_id_interface: str | None=None
    force: bool | None=None


class MPLS(v1.Contract):
    label_protocol: Literal['ldp','tdp'] | None=None
    ldp: LDP=Field(default_factory=LDP)


class PKI(v1.Contract):
    trustpoints: list[Trustpoint]=Field(default_factory=list)
    chains: list[CertificateChain]=Field(default_factory=list)


class IsisProcess(v1.Contract):
    name: str
    net: str | None=Field(default=None,pattern=r'^[0-9A-Fa-f.]+$')
    passive_interfaces: list[str]=Field(default_factory=list)


class Multicast(v1.Contract):
    routing_enabled: bool | None=None
    rendezvous_points: list[v1.IPvAnyAddress]=Field(default_factory=list)


class EthernetService(v1.Contract):
    interface: str
    instance: int=Field(ge=1)
    encapsulation: Encapsulation | None=None
    bridge_domain: int | None=Field(default=None,ge=1,le=16777215)


class BridgeMember(v1.Contract):
    kind: Literal['interface_service','evpn']
    interface: str | None=None
    service_instance: int | None=Field(default=None,ge=1)
    evpn_instance: int | None=Field(default=None,ge=1)
    ethernet_tag: int | None=Field(default=None,ge=0)
    @model_validator(mode='after')
    def identity(self):
        if self.kind=='interface_service' and (self.interface is None or self.service_instance is None):raise ValueError('Missing interface attachment')
        if self.kind=='evpn' and (self.evpn_instance is None or self.ethernet_tag is None):raise ValueError('Missing EVI attachment')
        return self


class BridgeDomain(v1.Contract):
    identifier: int=Field(ge=1)
    members: list[BridgeMember]=Field(default_factory=list)


class EVI(v1.Contract):
    identifier: int=Field(ge=1)
    type: Literal['vlan-based','vlan-aware']


class VFINeighbor(v1.Contract):
    address: v1.IPvAnyAddress
    encapsulation: Literal['mpls']


class VFI(v1.Contract):
    identifier: int=Field(ge=1)
    mode: Literal['manual','autodiscovery']
    vpn_id: int | None=Field(default=None,ge=1)
    neighbors: list[VFINeighbor]=Field(default_factory=list)


class L2VPN(v1.Contract):
    evpn_declared: bool | None=None
    replication_type: Literal['ingress'] | None=None
    router_id_interface: str | None=None
    evpn_instances: list[EVI]=Field(default_factory=list)
    bridge_domains: list[BridgeDomain]=Field(default_factory=list)
    vfis: list[VFI]=Field(default_factory=list)


class CiscoExtensions(v1.Contract):
    observations: list[CiscoObservation]=Field(default_factory=list)
    opaque_blocks: list[OpaqueBlock]=Field(default_factory=list)
    pki: PKI=Field(default_factory=PKI)
    mpls: MPLS=Field(default_factory=MPLS)
    community_lists: list[CommunityList]=Field(default_factory=list)
    isis: list[IsisProcess]=Field(default_factory=list)
    multicast: Multicast=Field(default_factory=Multicast)
    ethernet_services: list[EthernetService]=Field(default_factory=list)
    l2vpn: L2VPN=Field(default_factory=L2VPN)


class Configuration(v1.Configuration):
    system: System=Field(default_factory=System)
    interfaces: list[Interface]=Field(default_factory=list)
    network_instances: list[NetworkInstance]=Field(default_factory=list)
    routing: Routing=Field(default_factory=Routing)
    qos: QoS=Field(default_factory=QoS)
    cisco: CiscoExtensions=Field(default_factory=CiscoExtensions)


class NormalizedConfig(v1.NormalizedConfig):
    schema_version: Literal['0.2.0']='0.2.0'
    configuration: Configuration=Field(default_factory=Configuration)


def migrate_v01(document:dict,ospf_version:int|None=None)->NormalizedConfig:
    v1.NormalizedConfig.model_validate(document)
    data=deepcopy(document);data['schema_version']='0.2.0'
    processes=data['configuration']['routing']['ospf']
    if processes and ospf_version is None:
        if document['parsing']['parser_name']=='TTP official templates + source-numbered project extensions':ospf_version=2
        else:raise ValueError('v0.1 did not identify OSPF version; supply a justified version explicitly')
    for process in processes:process['version']=ospf_version
    return NormalizedConfig.model_validate(data)


def project_v01(document:dict)->dict:
    """Explicit lossy projection: discard extension fields, retain valid proofs only.

    This is not a round-trip guarantee. The discarded paths are returned by the
    migration CLI's report, and callers must not present v0.1 as feature-equivalent.
    """
    def trim(value,cls):
        if not isinstance(value,dict):return value
        result={}
        for name,field in cls.model_fields.items():
            if name not in value:continue
            v=value[name];ann=field.annotation
            if get_origin(ann) is not list:
                possible=[a for a in get_args(ann) if isinstance(a,type) and issubclass(a,v1.Contract)]
                if possible:ann=possible[0]
            origin=getattr(ann,'__origin__',None)
            if origin is list:
                target=ann.__args__[0]
                if isinstance(target,type) and issubclass(target,v1.Contract):v=[trim(x,target) for x in v]
            elif isinstance(ann,type) and issubclass(ann,v1.Contract):v=trim(v,ann)
            result[name]=v
        return result
    doc=trim(document,v1.NormalizedConfig);doc['schema_version']='0.1.0'
    def exists(path):
        current=doc
        try:
            for part in path.strip('/').split('/'):current=current[int(part)] if isinstance(current,list) else current[part]
            return True
        except (KeyError,IndexError,ValueError,TypeError):return False
    doc['evidence']=[e for e in doc['evidence'] if exists(e['path'])]
    # A v3 process cannot be downgraded as if it were v2.
    if any(p.get('version')==3 for p in document['configuration']['routing']['ospf']):
        raise ValueError('Cannot project OSPFv3 into v0.1 without losing protocol identity')
    v1.NormalizedConfig.model_validate(doc)
    return doc
