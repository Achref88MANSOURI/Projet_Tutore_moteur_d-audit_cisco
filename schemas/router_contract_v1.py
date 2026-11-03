"""Canonical router configuration contract V1 used by the normalizer.

None means indeterminate; [] requires external evidence of completeness. References
are literal and need not resolve. Serialize with model_dump(mode="json") without
exclude_none/exclude_unset to retain the fixed topology. No operational or audit data.
"""
from __future__ import annotations
from ipaddress import IPv4Address as _IPv4Address, IPv6Address as _IPv6Address, IPv4Network, IPv6Network, ip_network
from typing import Annotated, Literal, get_args, get_origin
from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress as _IPvAnyAddress, IPvAnyNetwork as _IPvAnyNetwork, StrictStr, StrictInt, StrictBool, BeforeValidator, model_validator


def _ip_input(value):
    if not isinstance(value, (str, _IPv4Address, _IPv6Address, IPv4Network, IPv6Network)):
        raise ValueError("IP values require a textual literal or an ipaddress object")
    return value


IPv4Address = Annotated[_IPv4Address, BeforeValidator(_ip_input)]
IPv6Address = Annotated[_IPv6Address, BeforeValidator(_ip_input)]
IPvAnyAddress = Annotated[_IPvAnyAddress, BeforeValidator(_ip_input)]
IPvAnyNetwork = Annotated[_IPvAnyNetwork, BeforeValidator(_ip_input)]
ASN = Annotated[StrictInt, Field(ge=1, le=4294967295)]
Port = Annotated[StrictInt, Field(ge=0, le=65535)]
Name = Annotated[StrictStr, Field(min_length=1)]
AFI = Literal['ipv4', 'ipv6', 'vpnv4', 'vpnv6']
SAFI = Literal['unicast', 'multicast', 'labeled-unicast', 'vpn-unicast', 'mdt', 'flowspec', 'other']
NetworkType = Literal['point-to-point', 'broadcast', 'non-broadcast', 'point-to-multipoint']


class Contract(BaseModel):
    model_config = ConfigDict(extra='forbid', validate_assignment=True, validate_default=True)

    @model_validator(mode='before')
    @classmethod
    def strict_collections_and_literals(cls, value):
        # Pydantic otherwise coerces tuples/sets to lists and 1 to Literal[True].
        if isinstance(value, dict):
            for key, item in value.items():
                field = cls.model_fields.get(key)
                if field is None or item is None:
                    continue
                annotation = field.annotation
                alternatives = get_args(annotation) if get_origin(annotation) is not Literal else (annotation,)
                alternatives = (annotation,) + alternatives
                if any(get_origin(t) is list for t in alternatives) and not isinstance(item, list):
                    raise ValueError(f'{key} requires a list')
                list_types = [t for t in alternatives if get_origin(t) is list]
                for list_type in list_types:
                    element_type = get_args(list_type)[0]
                    if get_origin(element_type) is Literal:
                        choices = get_args(element_type)
                        if any(not any(type(entry) is type(c) and entry == c for c in choices) for entry in item):
                            raise ValueError(f'{key} requires exact literal elements')
                literals = [t for t in alternatives if get_origin(t) is Literal]
                if literals:
                    choices = [c for t in literals for c in get_args(t)]
                    if not any(type(item) is type(choice) and item == choice for choice in choices):
                        raise ValueError(f'{key} requires an exact literal value')
        return value


class IPv4InterfaceAddress(Contract):
    address: IPv4Address
    prefix_length: StrictInt = Field(ge=0, le=32)
    secondary: StrictBool | None = None


class IPv6InterfaceAddress(Contract):
    address: IPv6Address
    prefix_length: StrictInt = Field(ge=0, le=128)


class LAG(Contract):
    name: StrictStr = Field(min_length=1)
    members: list[StrictStr] | None = None
    lacp_mode: Literal['active', 'passive', 'on', 'unknown'] | None = None


class NetworkInstance(Contract):
    name: StrictStr = Field(min_length=1)
    kind: Literal['DEFAULT_INSTANCE', 'L3VRF', 'OTHER', 'UNKNOWN']
    route_distinguisher: StrictStr | None = None
    route_targets_import: list[StrictStr] | None = None
    route_targets_export: list[StrictStr] | None = None
    description: StrictStr | None = None
    address_families: list[NetworkInstanceAF] | None = None


class NTPServer(Contract):
    address: StrictStr = Field(min_length=1)
    prefer: StrictBool | None = None
    source_interface: StrictStr | None = None
    network_instance: StrictStr | None = None
    association_type: Literal['server','peer'] | None = None
    key_id: StrictInt | None = Field(default=None, ge=1, le=65535)
    version: StrictInt | None = Field(default=None, ge=1, le=4)


class SyslogDestination(Contract):
    address: StrictStr = Field(min_length=1)
    port: StrictInt | None = Field(default=None, ge=1, le=65535)
    transport: Literal['udp', 'tcp', 'tls', 'unknown'] | None = None
    severity: StrictStr | None = None
    vrf: Name | None = None


class UserAccount(Contract):
    username: StrictStr = Field(min_length=1)
    privilege_level: StrictInt | None = Field(default=None, ge=0, le=15)
    credential_configured: StrictBool | None = None
    credential_type: StrictStr | None = None
    algorithm_type: Literal['md5', 'sha256', 'scrypt'] | None = None
    nopassword: StrictBool | None = None
    access_class: Name | None = None
    view: Name | None = None


class SNMPCommunity(Contract):
    access: Literal['ro','rw','unknown'] | None = None
    access_list: Name | None = None
    access_list_v6: Name | None = None
    view: Name | None = None
    identifier_redacted: Literal[True] = True


class SNMPGroup(Contract):
    name: Name
    version: Literal['v1', 'v2c', 'v3'] | None = None
    security_level: Literal['noauth', 'auth', 'priv'] | None = None
    read_view: Name | None = None
    write_view: Name | None = None
    notify_view: Name | None = None
    access_list: Name | None = None


class SNMPUser(Contract):
    username: Name
    group_reference: Name | None = None
    version: Literal['1', '2c', '3'] | None = None
    remote_ip: IPvAnyAddress | None = None
    authentication_algorithm: Name | None = None
    privacy_algorithm: Name | None = None
    authentication_secret_configured: StrictBool | None = None
    privacy_secret_configured: StrictBool | None = None


class SNMPHost(Contract):
    destination: Name
    vrf: Name | None = None
    type: Literal['traps', 'informs'] = 'traps'
    version: Literal['1', '2c', '3'] | None = None
    community_or_user: Name | None = None
    udp_port: Annotated[StrictInt, Field(ge=1, le=65535)] | None = None
    notification_types: list[Name] | None = None


class SNMPView(Contract):
    name: Name
    oid: Name
    included: StrictBool = True


class SNMPTrapConfig(Contract):
    enabled: StrictBool | None = None
    notification_types: list[Name] | None = None


class OSPFArea(Contract):
    area_id: StrictStr = Field(min_length=1)
    interfaces: list[StrictStr] | None = None
    type: Literal['stub', 'nssa', 'normal'] | None = None
    authentication: RoutingAuthentication | None = None


class PortMatch(Contract):
    operator: Literal['eq', 'neq', 'lt', 'gt', 'range']
    start: StrictInt = Field(ge=0, le=65535)
    end: StrictInt | None = Field(default=None, ge=0, le=65535)

    @model_validator(mode='after')
    def valid_range(self):
        if self.operator == 'range':
            if self.end is None or self.end < self.start:
                raise ValueError('range requires end >= start')
        elif self.end is not None:
            raise ValueError('only range permits end')
        return self


class ACLAttachment(Contract):
    acl_name: StrictStr = Field(min_length=1)
    interface_name: StrictStr = Field(min_length=1)
    direction: Literal['ingress', 'egress']


class NATRule(Contract):
    identifier: StrictStr | None = Field(default=None, min_length=1)
    type: Literal['static', 'dynamic', 'pat', 'other', 'unknown']
    source_match: StrictStr | None = None
    translated_source: StrictStr | None = None
    destination_match: StrictStr | None = None
    translated_destination: StrictStr | None = None
    ingress_interface: StrictStr | None = None
    egress_interface: StrictStr | None = None
    network_instance: StrictStr | None = None
    protocol: StrictStr | None = None
    original_port: Port | None = None
    translated_port: Port | None = None
    pool_reference: Name | None = None
    acl_reference: Name | None = None
    overload: StrictBool | None = None


class VPNTunnel(Contract):
    identifier: StrictStr = Field(min_length=1)
    technology: Literal['ipsec', 'gre', 'wireguard', 'ssl', 'other', 'unknown']
    local_endpoint: IPvAnyAddress | None = None
    remote_endpoint: IPvAnyAddress | None = None
    tunnel_interface: StrictStr | None = None
    network_instance: StrictStr | None = None
    local_source_interface: Name | None = None
    mode: StrictStr | None = None
    ipsec_profile_reference: Name | None = None
    crypto_proposal_references: list[Name] | None = None


class QoSAttachment(Contract):
    policy_name: StrictStr = Field(min_length=1)
    interface_name: StrictStr = Field(min_length=1)
    direction: Literal['ingress', 'egress']


class AllowASIn(Contract):
    enabled: StrictBool
    configured_max_occurrences: StrictInt | None = Field(default=None, ge=1, le=10)


class PasswordPolicy(Contract):
    minimum_length: StrictInt | None = Field(default=None, ge=0)


class ConfigLogging(Contract):
    declared: StrictBool | None = None
    hidekeys: StrictBool | None = None


class ConfigArchive(Contract):
    declared: StrictBool | None = None
    config_logging: ConfigLogging = Field(default_factory=ConfigLogging)


class CallHomeProfile(Contract):
    name: StrictStr = Field(min_length=1)
    active: StrictBool | None = None
    transport_methods: list[Literal['http', 'email']] | None = None


class CallHome(Contract):
    declared: StrictBool | None = None
    enabled: StrictBool | None = None
    contact_email: Name | None = None
    profiles: list[CallHomeProfile] | None = None


class BroadcastForwarding(Contract):
    protocol: Literal['nd']
    enabled: StrictBool


class IPServices(Contract):
    cef_ipv4_enabled: StrictBool | None = None
    cef_ipv6_enabled: StrictBool | None = None
    icmp_unreachable_rate_limit_enabled: StrictBool | None = None
    tcp_synwait_seconds: StrictInt | None = Field(default=None, ge=5, le=300)
    broadcast_forwarding_protocols: list[BroadcastForwarding] | None = None
    source_routing: StrictBool | None = None
    ipv6_unicast_routing: StrictBool | None = None
    password_encryption_service: StrictBool | None = None


class DNSView(Contract):
    name: StrictStr = Field(min_length=1)
    network_instance: StrictStr = Field(min_length=1)
    declared: StrictBool


class DNS(Contract):
    lookup_source_interface: StrictStr | None = None
    views: list[DNSView] | None = None
    lookup_enabled: StrictBool | None = None
    servers: list[IPvAnyAddress] | None = None


class TFTPClient(Contract):
    source_interface: StrictStr | None = None


class FileTransfer(Contract):
    tftp: TFTPClient = Field(default_factory=TFTPClient)


class Collector(Contract):
    address: IPvAnyAddress
    port: StrictInt = Field(ge=1, le=65535)


class AggregationCache(Contract):
    aggregation: Literal['as']
    destinations: list[Collector] | None = None
    entries: Annotated[StrictInt, Field(ge=1024, le=2000000)] | None = None
    enabled: StrictBool | None = None
    timeout_active_minutes: Annotated[StrictInt, Field(ge=1, le=60)] | None = None
    timeout_inactive_seconds: Annotated[StrictInt, Field(ge=10, le=600)] | None = None


class AutoRP(Contract):
    listener_configured: StrictBool | None = None
    discovery_scope: StrictInt | None = Field(default=None, ge=1, le=255)


class BSRCandidate(Contract):
    source_interface: StrictStr = Field(min_length=1)
    hash_mask_length: StrictInt = Field(ge=0, le=32)


class RPCandidate(Contract):
    source_interface: StrictStr = Field(min_length=1)


class SSM(Contract):
    range_selector: Literal['default'] | None = None


class MSDPPeer(Contract):
    address: IPv4Address
    connect_source_interface: StrictStr = Field(min_length=1)


class MSDP(Contract):
    peers: list[MSDPPeer] | None = None


class RIPRedistribution(Contract):
    protocol: Literal['bgp']
    source_bgp_as: StrictInt = Field(ge=1, le=4294967295)
    metric: StrictInt = Field(ge=0, le=16)


class RIPScope(Contract):
    network_statements: list[IPv4Address] | None = None
    auto_summary: StrictBool | None = None
    redistributions: list[RIPRedistribution] | None = None


class RIPFamily(RIPScope):
    afi: Literal['ipv4']
    network_instance: StrictStr = Field(min_length=1)
    interface_settings: list[RIPInterfaceSettings] | None = None


class RIPProcess(RIPScope):
    declared: StrictBool | None = None
    address_families: list[RIPFamily] | None = None
    identifier: Name | None = None
    network_instance: Name | None = None
    interface_settings: list[RIPInterfaceSettings] | None = None


class VirtualService(Contract):
    name: StrictStr = Field(min_length=1)
    declared: StrictBool


class BootImage(Contract):
    location: Name
    source_device: Name | None = None


class Boot(Contract):
    configuration_register: StrictStr | None = Field(default=None, pattern='^0x[0-9A-Fa-f]{1,4}$')
    images: list[BootImage] | None = None


class Ethernet(Contract):
    speed_mode: Literal['auto', 'fixed'] | None = None
    speed_bps: StrictInt | None = Field(default=None, gt=0)
    duplex: Literal['auto', 'half', 'full'] | None = None
    negotiation: Literal['auto'] | None = None
    media: StrictStr | None = None

    @model_validator(mode='after')
    def speed_consistency(self):
        if self.speed_mode == 'auto' and self.speed_bps is not None:
            raise ValueError('Auto speed has no configured numeric rate')
        if self.speed_mode == 'fixed' and self.speed_bps is None:
            raise ValueError('Fixed speed needs a rate')
        return self


class Encapsulation(Contract):
    kind: Literal['dot1q', 'qinq', 'untagged']
    outer_vlan: StrictInt | None = Field(default=None, ge=1, le=4094)
    inner_vlan: StrictInt | None = Field(default=None, ge=1, le=4094)

    @model_validator(mode='after')
    def coherent(self):
        if self.kind in ('dot1q', 'qinq') and self.outer_vlan is None:
            raise ValueError('Tagged encapsulation needs outer VLAN')
        if self.kind == 'untagged' and (self.outer_vlan is not None or self.inner_vlan is not None):
            raise ValueError('Untagged encapsulation cannot carry VLAN tags')
        if self.kind != 'qinq' and self.inner_vlan is not None:
            raise ValueError('Inner VLAN requires QinQ')
        if self.kind == 'qinq' and self.inner_vlan is None:
            raise ValueError('QinQ needs inner VLAN')
        return self


class OSPFBinding(Contract):
    version: Literal[2, 3]
    process: Name
    area: Name


class BGPNetwork(Contract):
    prefix: IPvAnyNetwork
    afi: AFI | None = None
    safi: SAFI | None = None
    network_instance: Name | None = None
    native_safi: Name | None = None

    @model_validator(mode='after')
    def prefix_family(self):
        if self.afi is not None and self.prefix.version != (4 if self.afi in ('ipv4', 'vpnv4') else 6):
            raise ValueError('Prefix family differs from AFI')
        return self


class MaximumPaths(Contract):
    type: Literal['ibgp', 'ebgp', 'eibgp']
    count: StrictInt = Field(ge=1, le=512)


class Aggregate(Contract):
    prefix: IPvAnyNetwork
    options: list[Literal['summary-only', 'as-set']] | None = None
    afi: AFI | None = None
    safi: SAFI | None = None
    network_instance: Name | None = None
    native_safi: Name | None = None

    @model_validator(mode='after')
    def prefix_family(self):
        if self.afi is not None and self.prefix.version != (4 if self.afi in ('ipv4', 'vpnv4') else 6):
            raise ValueError('Prefix family differs from AFI')
        return self


class Redistribution(Contract):
    protocol: Literal['connected', 'static', 'bgp', 'ospf', 'ospfv3', 'isis', 'eigrp', 'rip']
    process: StrictStr | None = None
    subnets: StrictBool | None = None
    route_map: StrictStr | None = None
    afi: AFI | None = None
    safi: SAFI | None = None
    network_instance: Name | None = None
    native_safi: Name | None = None


class DefaultOrigination(Contract):
    enabled: StrictBool
    always: StrictBool | None = None


class VirtualLink(Contract):
    area: Name
    peer_router_id: IPv4Address
    authentication: RoutingAuthentication | None = None


class PrefixListEntry(Contract):
    sequence: StrictInt | None = Field(default=None, ge=0)
    action: Literal['permit', 'deny']
    prefix: IPvAnyNetwork
    ge: StrictInt | None = Field(default=None, ge=0, le=128)
    le: StrictInt | None = Field(default=None, ge=0, le=128)

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
    name: Name
    family: Literal['ipv4', 'ipv6']
    entries: list[PrefixListEntry] | None = None

    @model_validator(mode='after')
    def identities(self):
        seq = [x.sequence for x in (self.entries or []) if x.sequence is not None]
        if len(seq) != len(set(seq)):
            raise ValueError('Duplicate prefix sequence')
        if any((ip_network(x.prefix).version != (4 if self.family == 'ipv4' else 6) for x in (self.entries or []))):
            raise ValueError('Mixed prefix family')
        return self


class TimestampPolicy(Contract):
    category: Literal['debug', 'log']
    format: Literal['datetime', 'uptime']
    options: list[Literal['msec', 'localtime', 'show-timezone', 'year']] | None = None


class CommunityListEntry(Contract):
    action: Literal['permit', 'deny']
    expression: StrictStr


class CommunityList(Contract):
    name: Name
    dialect: Literal['cisco_expanded_regex', 'standard', 'expanded', 'other'] | None = None
    entries: list[CommunityListEntry] | None = None


class Banner(Contract):
    type: Literal['login', 'motd', 'exec', 'incoming']
    text_present: StrictBool | None = None


class FlowExport(Contract):
    source_interface: StrictStr | None = None
    version: StrictInt | None = Field(default=None, ge=1, le=10)
    as_mode: Literal['origin-as', 'peer-as'] | None = None
    cache_timeout_active_minutes: StrictInt | None = Field(default=None, ge=1)
    cache_timeout_inactive_seconds: StrictInt | None = Field(default=None, ge=1)


class QoSMatch(Contract):
    kind: Literal['dscp', 'precedence', 'protocol', 'acl']
    value: StrictStr
    address_family: Literal['ipv4', 'ipv6', 'ipv4_ipv6'] | None = None


class QoSAction(Contract):
    kind: Literal['set_dscp', 'set_precedence', 'priority_percent', 'fair_queue']
    value: StrictStr | StrictInt | StrictBool

    @model_validator(mode='after')
    def constraints(self):
        if self.kind in ('set_dscp', 'set_precedence'):
            limit = 63 if self.kind == 'set_dscp' else 7
            if type(self.value) is bool or (type(self.value) is int and not 0 <= self.value <= limit):
                raise ValueError('Invalid QoS marking')
            if type(self.value) is str and not self.value:
                raise ValueError('Empty QoS marking')
        if self.kind == 'priority_percent' and (type(self.value) is not int or not 0 <= self.value <= 100):
            raise ValueError('Invalid QoS percentage')
        if self.kind == 'fair_queue' and type(self.value) is not bool:
            raise ValueError('Queue flag must be boolean')
        return self


class ClassMap(Contract):
    name: Name
    match_mode: Literal['match-any', 'match-all']
    matches: list[QoSMatch] | None = None


class PolicyClass(Contract):
    name: Name
    actions: list[QoSAction] | None = None


class PolicyMap(Contract):
    name: Name
    classes: list[PolicyClass] | None = None


class Trustpoint(Contract):
    name: Name
    enrollment: Literal['selfsigned', 'terminal', 'pkcs12'] | None = None
    revocation_check: Literal['none', 'crl', 'ocsp'] | None = None
    subject_name: StrictStr | None = None
    keypair_reference: StrictStr | None = None


class Certificate(Contract):
    type: Literal['ca', 'self-signed']
    identifier: StrictStr = Field(pattern='^[0-9a-fA-F]+$')


class CertificateChain(Contract):
    name: Name
    certificates: list[Certificate] | None = None


class LDP(Contract):
    router_id_interface: StrictStr | None = None
    force: StrictBool | None = None


class MPLS(Contract):
    label_protocol: Literal['ldp', 'tdp'] | None = None
    ldp: LDP = Field(default_factory=LDP)


class PKI(Contract):
    trustpoints: list[Trustpoint] | None = None
    certificate_chains: list[CertificateChain] | None = None


class IsisProcess(Contract):
    name: Name | None = None
    declared: StrictBool | None = None
    net: StrictStr | None = Field(default=None, pattern='^[0-9A-Fa-f.]+$')
    passive_interfaces: list[StrictStr] | None = None
    network_instance: Name | None = None
    authentication: list[ISISAuthentication] | None = None
    interface_settings: list[ISISInterfaceSettings] | None = None
    redistributions: list[Redistribution] | None = None

    @model_validator(mode='after')
    def process_authentication_scope(self):
        if self.name is None and self.declared is not True:
            raise ValueError('An untagged IS-IS process needs an explicit declaration')
        if any(a.scope == 'interface' for a in (self.authentication or [])):
            raise ValueError('Interface authentication belongs to interface_settings')
        return self


class Multicast(Contract):
    auto_rp: AutoRP = Field(default_factory=AutoRP)
    bsr_candidates: list[BSRCandidate] | None = None
    rp_candidates: list[RPCandidate] | None = None
    ssm: SSM = Field(default_factory=SSM)
    msdp: MSDP = Field(default_factory=MSDP)
    routing_enabled: StrictBool | None = None
    rendezvous_points: list[IPvAnyAddress] | None = None


class BGPPeer(Contract):
    peer: StrictStr = Field(min_length=1)
    kind: Literal['neighbor', 'group']
    remote_as: StrictInt | None = Field(default=None, ge=1, le=4294967295)
    description: StrictStr | None = None
    enabled: StrictBool | None = None
    update_source: StrictStr | None = None
    active: StrictBool | None = None
    route_reflector_client: StrictBool | None = None
    next_hop_self: StrictBool | None = None
    send_community: Literal['command_without_option', 'standard', 'extended', 'both'] | None = None
    import_policies: list[StrictStr] | None = None
    export_policies: list[StrictStr] | None = None
    inherited_group: StrictStr | None = None
    additional_paths_advertise_selection: Literal['all', 'best'] | None = None
    allowas_in: AllowASIn | None = None
    local_as: ASN | None = None
    authentication: BGPAuthentication | None = None


class BGPNeighbor(Contract):
    peer: StrictStr = Field(min_length=1)
    kind: Literal['neighbor', 'group'] = 'neighbor'
    remote_as: StrictInt | None = Field(default=None, ge=1, le=4294967295)
    description: StrictStr | None = None
    enabled: StrictBool | None = None
    update_source: StrictStr | None = None
    active: StrictBool | None = None
    route_reflector_client: StrictBool | None = None
    next_hop_self: StrictBool | None = None
    send_community: Literal['command_without_option', 'standard', 'extended', 'both'] | None = None
    import_policies: list[StrictStr] | None = None
    export_policies: list[StrictStr] | None = None
    inherited_group: StrictStr | None = None
    additional_paths_advertise_selection: Literal['all', 'best'] | None = None
    allowas_in: AllowASIn | None = None
    local_as: ASN | None = None
    authentication: BGPAuthentication | None = None


class BGPPeerGroup(Contract):
    name: StrictStr = Field(min_length=1)
    remote_as: StrictInt | None = Field(default=None, ge=1, le=4294967295)
    description: StrictStr | None = None
    enabled: StrictBool | None = None
    update_source: StrictStr | None = None
    active: StrictBool | None = None
    route_reflector_client: StrictBool | None = None
    next_hop_self: StrictBool | None = None
    send_community: Literal['command_without_option', 'standard', 'extended', 'both'] | None = None
    import_policies: list[StrictStr] | None = None
    export_policies: list[StrictStr] | None = None
    inherited_group: StrictStr | None = None
    additional_paths_advertise_selection: Literal['all', 'best'] | None = None
    allowas_in: AllowASIn | None = None
    local_as: ASN | None = None
    authentication: BGPAuthentication | None = None


class Authentication(Contract):
    method: Literal['local', 'line_password', 'aaa']
    method_list: StrictStr | None = None


class RoutingPolicyMatch(Contract):
    kind: Literal['acl', 'prefix_set_ipv4', 'prefix_set_ipv6', 'community']
    name: StrictStr = Field(min_length=1)
    exact_match: StrictBool | None = None


class NumericPolicyAction(Contract):
    kind: Literal['local_preference', 'metric', 'cisco_weight']
    value: StrictInt


class ASPathPolicyAction(Contract):
    kind: Literal['as_path_prepend'] = 'as_path_prepend'
    as_numbers: list[Annotated[StrictInt, Field(ge=1, le=4294967295)]] | None = None


class CommunityPolicyAction(Contract):
    kind: Literal['community'] = 'community'
    communities: list[Annotated[StrictStr, Field(pattern='^[0-9]+:[0-9]+$')]] | None = None
    additive: StrictBool


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
    name: StrictStr = Field(min_length=1)


class URPF(Contract):
    mode: Literal['rx', 'any', 'legacy', 'off'] | None = None
    allow_default: StrictBool | None = None
    allow_self_ping: StrictBool | None = None
    acl: StrictStr | None = None
    l2_src: StrictBool | None = None


class IPv6URPF(Contract):
    mode: Literal['rx', 'any', 'off'] | None = None
    allow_default: StrictBool | None = None
    allow_self_ping: StrictBool | None = None
    acl: StrictStr | None = None


class Interface(Contract):
    bandwidth_kbps: Annotated[StrictInt, Field(ge=1, le=4294967295)] | None = None
    delay_tens_of_microseconds: Annotated[StrictInt, Field(ge=1, le=16777215)] | None = None
    removed_metric_settings: list[Literal['bandwidth_kbps', 'delay_tens_of_microseconds']] | None = None
    name: StrictStr = Field(min_length=1, description='Native interface identifier; NEVER translate port names implicitly')
    kind: Literal['physical', 'subinterface', 'loopback', 'lag', 'tunnel', 'other', 'unknown']
    parent_interface: StrictStr | None = None
    subinterface_index: StrictInt | None = Field(default=None, ge=0)
    description: StrictStr | None = None
    admin_enabled: StrictBool | None = None
    mtu: StrictInt | None = Field(default=None, ge=64, le=65535)
    vrf: StrictStr | None = None
    lag: StrictStr | None = None
    acl_ingress: list[StrictStr] | None = None
    acl_egress: list[StrictStr] | None = None
    pim_bsr_border: StrictBool | None = None
    sap_listen_enabled: StrictBool | None = None
    ethernet: Ethernet = Field(default_factory=Ethernet)
    encapsulation: Encapsulation | None = None
    tcp_mss: StrictInt | None = Field(default=None, ge=1, le=65535)
    proxy_arp: StrictBool | None = None
    redirects: StrictBool | None = None
    keepalive_enabled: StrictBool | None = None
    mpls_enabled: StrictBool | None = None
    pim_mode: Literal['sparse-mode', 'dense-mode', 'sparse-dense-mode', 'passive'] | None = None
    isis_process: StrictStr | None = None
    isis_network_type: Literal['point-to-point', 'broadcast'] | None = None
    ospf_network_type: Literal['point-to-point', 'broadcast', 'non-broadcast', 'point-to-multipoint'] | None = None
    ospf_bindings: list[OSPFBinding] | None = None
    flow_directions: list[Literal['ingress', 'egress']] | None = None
    cdp_enabled: StrictBool | None = None
    mop_enabled: StrictBool | None = None
    mop_sysid: StrictBool | None = None
    urpf: URPF = Field(default_factory=URPF)
    ipv6_urpf: IPv6URPF = Field(default_factory=IPv6URPF)
    ipv4: InterfaceIPv4 = Field(default_factory=lambda: InterfaceIPv4())
    ipv6: InterfaceIPv6 = Field(default_factory=lambda: InterfaceIPv6())


class AAA(Contract):
    server_groups: list[AAAServerGroup] | None = None
    enabled: StrictBool | None = None
    local_users: list[UserAccount] | None = None
    servers: list[AuthServer] | None = None
    password_policy: PasswordPolicy = Field(default_factory=PasswordPolicy)
    authentication_method_lists: list[AAAMethodList] | None = None
    authorization_method_lists: list[AAAMethodList] | None = None
    accounting_method_lists: list[AAAMethodList] | None = None
    radius_source_interface: Name | None = None
    tacacs_source_interface: Name | None = None
    enable_secrets: list[EnableSecret] | None = None
    enable_passwords: list[EnablePassword] | None = None
    authentication_enable: AAAMethodList | None = None


class EnableSecret(Contract):
    level: StrictInt | None = Field(default=15, ge=0, le=15)
    secret_type: Literal['0', '5', '7', '8', '9'] | None = None  # 0=cleartext, 5=md5, 7=cisco7, 8=sha256, 9=scrypt
    secret_configured: StrictBool = True
    algorithm_type: Literal['md5', 'sha256', 'scrypt'] | None = None
    credential_format: Literal['0', '5', '7', '8', '9'] | None = None
    removed: StrictBool | None = None


class EnablePassword(Contract):
    level: StrictInt | None = Field(default=None, ge=0, le=15)
    credential_format: Literal['0', '7'] | None = None
    secret_configured: StrictBool = True
    removed: StrictBool | None = None


class ManagementLine(Contract):
    name: StrictStr = Field(min_length=1, description='Native management line, e.g. vty 0 4')
    allowed_transports: list[StrictStr] | None = None
    idle_timeout_seconds: StrictInt | None = Field(default=None, ge=0)
    access_list: StrictStr | None = None
    access_list_vrf: StrictBool | None = None
    access_list_direction: Literal['in', 'out'] | None = None
    authentication: Authentication | None = None
    logging_synchronous: StrictBool | None = None
    privilege_level: StrictInt | None = Field(default=None, ge=0, le=15)
    stopbits: StrictInt | None = Field(default=None, ge=1, le=2)
    screen_length: StrictInt | None = Field(default=None, ge=0, le=512)
    preferred_transports: list[StrictStr] | None = None
    exec_disabled: StrictBool | None = None
    login_disabled: StrictBool | None = None
    transport_output: list[Literal['ssh', 'telnet']] | None = None
    transport_preferred: list[StrictStr] | None = None
    exec_shell_enabled: StrictBool | None = None
    exec_banner: StrictBool | None = None
    motd_banner: StrictBool | None = None
    accounting_commands: list[AAAAccountingLine] | None = None
    accounting_exec: list[AAAAccountingLine] | None = None
    accounting_connection: list[AAAAccountingLine] | None = None
    accounting_system: list[AAAAccountingLine] | None = None

    @model_validator(mode='after')
    def transport_selection(self):
        for selection in (self.allowed_transports, self.preferred_transports):
            if selection is not None and any(t in ('all', 'none') for t in selection) and len(selection) != 1:
                raise ValueError('all/none must stand alone')
        return self


class OSPFProcess(Contract):
    identifier: StrictStr = Field(min_length=1, description='Native process ID; semantics differ across vendors')
    network_instance: StrictStr | None = None
    router_id: IPv4Address | None = None
    network_statements: list[OSPFNetworkStatement] | None = None
    passive_interfaces: list[StrictStr] | None = None
    version: Literal[2, 3]
    areas: list[OSPFArea] | None = None
    virtual_links: list[VirtualLink] | None = None
    log_adjacency_changes: StrictBool | None = None
    redistributions: list[Redistribution] | None = None
    default_origination: DefaultOrigination | None = None
    passive_default: StrictBool | None = None
    non_passive_interfaces: list[Name] | None = None
    interface_settings: list[OSPFInterfaceSettings] | None = None

    @model_validator(mode='after')
    def consistent_scope(self):
        if set(self.passive_interfaces or []) & set(self.non_passive_interfaces or []):
            raise ValueError('Interface cannot be both passive and explicitly non-passive')
        if self.version == 2 and any(n.prefix is not None and n.prefix.version != 4 for n in (self.network_statements or [])):
            raise ValueError('OSPFv2 network statements require IPv4')
        return self


class RoutingPolicyStatement(Contract):
    identifier: StrictStr = Field(min_length=1)
    decision: Literal['accept', 'reject', 'next', 'unknown'] | None = None
    matches: list[RoutingPolicyMatch] | None = None
    actions: list[RoutingPolicyAction] | None = None
    unparsed_clauses: list[NativeClause] | None = None


class RoutingPolicy(Contract):
    name: StrictStr = Field(min_length=1)
    statements: list[RoutingPolicyStatement] | None = None


class ACLEntry(Contract):
    sequence: StrictInt | None = Field(default=None, ge=0)
    action: Literal['permit', 'deny', 'reject', 'unknown', 'remark']
    protocol: StrictStr | None = None
    source: ACLAddressMatch | None = None
    destination: ACLAddressMatch | None = None
    source_port: PortMatch | None = None
    destination_port: PortMatch | None = None
    log: StrictBool | None = None
    description: StrictStr | None = None
    log_input: StrictBool | None = None
    tcp_established: StrictBool | None = None
    fragments: StrictBool | None = None
    time_range: StrictStr | None = None
    unparsed_clauses: list[NativeClause] | None = None

    @model_validator(mode='after')
    def established_requires_tcp(self):
        if self.tcp_established is not None and self.protocol not in ('tcp', '6'):
            raise ValueError('Established is a TCP flag criterion')
        return self


class ACLSet(Contract):
    name: StrictStr = Field(min_length=1)
    family: Literal['ipv4', 'ipv6', 'mixed', 'unknown']
    entries: list[ACLEntry] | None = None

    @model_validator(mode='after')
    def unique_sequences(self):
        expected = {'ipv4': 4, 'ipv6': 6}.get(self.family)
        for entry in self.entries or []:
            for operand in (entry.source, entry.destination):
                if operand is None or expected is None:
                    continue
                version = None
                if isinstance(operand, ACLHost): version = operand.address.version
                elif isinstance(operand, ACLPrefix): version = operand.prefix.version
                elif isinstance(operand, ACLWildcard): version = 4
                elif isinstance(operand, ACLAny) and operand.address_family is not None:
                    version = 4 if operand.address_family == 'ipv4' else 6
                if version is not None and version != expected:
                    raise ValueError('ACL operand family differs from ACL family')
        seq = [x.sequence for x in (self.entries or []) if x.sequence is not None]
        if len(seq) != len(set(seq)):
            raise ValueError('Duplicate ACL sequence numbers')
        return self


class QoS(Contract):
    attachments: list[QoSAttachment] | None = None
    class_maps: list[ClassMap] | None = None
    policy_maps: list[PolicyMap] | None = None


class BGPAddressFamily(Contract):
    auto_summary: StrictBool | None = None
    synchronization: StrictBool | None = None
    afi: AFI
    safi: SAFI | None = None
    peers: list[BGPPeer] | None = None
    dampening: StrictBool | None = None
    additional_paths_selection: Literal['all', 'best'] | None = None
    additional_paths_send: StrictBool | None = None
    additional_paths_receive: StrictBool | None = None
    maximum_paths: list['MaximumPaths'] | None = None
    network_instance: Name | None = None
    native_safi: Name | None = None


class BGPProcess(Contract):
    local_as: StrictInt = Field(ge=1, le=4294967295)
    network_instance: StrictStr | None = None
    router_id: IPv4Address | None = None
    networks: list[BGPNetwork] | None = None
    log_neighbor_changes: StrictBool | None = None
    compare_med: StrictBool | None = None
    deterministic_med: StrictBool | None = None
    default_ipv4_unicast: StrictBool | None = None
    synchronization: StrictBool | None = None
    auto_summary: StrictBool | None = None
    enforce_first_as: StrictBool | None = None
    dampening: StrictBool | None = None
    additional_paths_selection: Literal['all', 'best'] | None = None
    additional_paths_send: StrictBool | None = None
    additional_paths_receive: StrictBool | None = None
    maximum_paths: list['MaximumPaths'] | None = None
    aggregates: list['Aggregate'] | None = None
    redistributions: list['Redistribution'] | None = None
    neighbors: list[BGPNeighbor] | None = None
    peer_groups: list[BGPPeerGroup] | None = None
    address_families: list[BGPAddressFamily] | None = None


class Device(Contract):
    vendor: Name | None = None
    platform: Name | None = None
    software_version: Name | None = None
    role: Name | None = None


class Identity(Contract):
    hostname: Name | None = None
    domain_name: Name | None = None
    banners: list[Banner] | None = None


class SSH(Contract):
    authentication_retries: Annotated[StrictInt, Field(ge=0)] | None = None
    version_setting: Literal['configured', 'removed'] | None = None
    enabled: StrictBool | None = None
    version: Literal[1, 2] | None = None
    timeout_seconds: Annotated[StrictInt, Field(ge=0)] | None = None
    session_limit: Annotated[StrictInt, Field(ge=1)] | None = None
    rsa_keypair_name: Name | None = None
    source_interface: Name | None = None
    pubkey_chain_enabled: StrictBool | None = None
    domain_list: list[Name] | None = None
    domain_lookup_enabled: StrictBool | None = None
    login_block_for: LoginBlockFor | None = None


class LoginBlockFor(Contract):
    seconds: Annotated[StrictInt, Field(ge=1)] = Field(..., description='Block duration in seconds')
    attempts: Annotated[StrictInt, Field(ge=1)] = Field(..., description='Number of failed attempts')
    within_seconds: Annotated[StrictInt, Field(ge=1)] = Field(..., description='Time window in seconds')


class RSAKey(Contract):
    label: Name | None = None
    modulus: Annotated[StrictInt, Field(ge=360, le=4096)] = Field(..., description='Key modulus in bits')
    usage: Literal['general', 'usage-keys'] | None = None
    modulus_bits: Annotated[StrictInt, Field(ge=360, le=4096)] | None = None


class Telnet(Contract):
    enabled: StrictBool | None = None


class HTTP(Contract):
    enabled: StrictBool | None = None
    authentication: Literal['local', 'aaa', 'enable', 'other'] | None = None


class Management(Contract):
    ssh: SSH = Field(default_factory=SSH)
    telnet: Telnet = Field(default_factory=Telnet)
    http: HTTP = Field(default_factory=HTTP)
    https: HTTP = Field(default_factory=HTTP)
    lines: list[ManagementLine] | None = None


class AAAMethod(Contract):
    group_protocol: Literal['radius', 'tacacs'] | None = None
    method: Literal['local', 'local-case', 'group', 'enable', 'line', 'none', 'if-authenticated', 'krb5', 'krb5-telnet', 'passwd-expiry', 'other']
    group_reference: Name | None = None
    native_method: Name | None = None


class AAAAccountingLine(Contract):
    privilege_level: Annotated[StrictInt, Field(ge=0, le=15)] | None = None
    method_list: Name
    service: Literal['commands', 'exec', 'connection', 'system']


class AAAMethodList(Contract):
    privilege_level: Annotated[StrictInt, Field(ge=0, le=15)] | None = None
    local_setting: Literal['configured', 'removed'] | None = None
    name: Name
    service: Name
    methods: list[AAAMethod] | None = None
    accounting_mode: Literal['start-stop', 'stop-only', 'wait-start', 'none', 'other'] | None = None


class AuthServer(Contract):
    protocol: Literal['radius', 'tacacs', 'other']
    name: Name | None = None
    address: Name | None = None  # Server declaration need not yet contain an address.
    key_configured: StrictBool | None = None
    key_format: Literal['0', '6', '7'] | None = None
    key_setting: Literal['configured', 'removed'] | None = None
    auth_port: Annotated[StrictInt, Field(ge=1, le=65535)] | None = None
    accounting_port: Annotated[StrictInt, Field(ge=1, le=65535)] | None = None
    source_interface: Name | None = None


    @model_validator(mode='after')
    def server_identity(self):
        if self.name is None and self.address is None:
            raise ValueError('AAA server needs a configured name or address')
        return self


class AAAServerReference(Contract):
    name: Name


class AAAServerGroup(Contract):
    name: Name
    protocol: Literal['radius', 'tacacs']
    servers: list[AAAServerReference] | None = None
    source_interface: Name | None = None


class SNMP(Contract):
    enabled: StrictBool | None = None
    communities: list[SNMPCommunity] | None = None
    users: list[SNMPUser] | None = None
    versions: list[Literal['1', '2c', '3']] | None = None
    location: StrictStr | None = None
    contact: StrictStr | None = None
    ifindex_persistent: StrictBool | None = None
    groups: list[SNMPGroup] | None = None
    hosts: list[SNMPHost] | None = None
    views: list[SNMPView] | None = None
    trap_config: SNMPTrapConfig | None = None
    engine_id: Name | None = None
    trap_source_interface: Name | None = None
    trap_source_vrf: Name | None = None


class NTP(Contract):
    enabled: StrictBool | None = None
    servers: list[NTPServer] | None = None
    source_interface: Name | None = None
    authentication_enabled: StrictBool | None = None
    authentication_keys: list[NTPAuthKey] | None = None
    trusted_keys: list[NTPTrustedKey] | None = None
    master: StrictBool | None = None


class NTPAuthKey(Contract):
    identifier: StrictInt = Field(ge=1, le=65535)
    algorithm: Literal['md5'] = 'md5'
    secret_configured: StrictBool = True
    credential_format: Literal['0', '7'] | None = None


class NTPTrustedKey(Contract):
    identifier: StrictInt = Field(ge=1, le=65535)
    range_end: StrictInt | None = None  # For ranges like 1-5


class Logging(Contract):
    destinations: list[SyslogDestination] | None = None
    source_interface: Name | None = None
    source_vrf: Name | None = None
    trap_severity: StrictStr | None = None  # Syslog configuration level, not audit severity.
    timestamps: list[TimestampPolicy] | None = None
    console_logging: StrictBool | None = None
    console_severity: StrictStr | None = None
    login_success_logging: StrictBool | None = None
    enabled: StrictBool | None = None
    buffered_size: StrictInt | None = None
    buffered_severity: StrictStr | None = None
    buffered_discriminator: Name | None = None


class FlowExporter(Contract):
    name: Name
    destinations: list[Collector] | None = None
    source_interface: Name | None = None
    version: Annotated[StrictInt, Field(ge=1, le=10)] | None = None


class FlowMonitoring(Contract):
    export: FlowExport | None = None
    aggregation_caches: list[AggregationCache] | None = None
    exporters: list[FlowExporter] | None = None


class System(Contract):
    identity: Identity = Field(default_factory=Identity)
    management: Management = Field(default_factory=Management)
    aaa: AAA = Field(default_factory=AAA)
    dns: DNS = Field(default_factory=DNS)
    ntp: NTP = Field(default_factory=NTP)
    logging: Logging = Field(default_factory=Logging)
    snmp: SNMP = Field(default_factory=SNMP)
    flow_monitoring: FlowMonitoring = Field(default_factory=FlowMonitoring)
    ip_services: IPServices = Field(default_factory=IPServices)
    file_transfer: FileTransfer = Field(default_factory=FileTransfer)
    config_archive: ConfigArchive = Field(default_factory=ConfigArchive)
    call_home: CallHome = Field(default_factory=CallHome)
    boot: Boot = Field(default_factory=Boot)


class InterfaceIPv4(Contract):
    assignment_method: Literal['dhcp', 'static', 'unnumbered', 'other'] | None = None
    addresses: list[IPv4InterfaceAddress] | None = None
    unnumbered_interface: Name | None = None

    @model_validator(mode='after')
    def coherent(self):
        if self.unnumbered_interface is not None and self.addresses:
            raise ValueError('Unnumbered interface cannot have numbered IPv4 addresses')
        if self.assignment_method == 'dhcp' and (self.addresses or self.unnumbered_interface):
            raise ValueError('DHCP cannot be combined with static or unnumbered addressing')
        return self


class InterfaceIPv6(Contract):
    enabled: StrictBool | None = None
    addresses: list[IPv6InterfaceAddress] | None = None


class NetworkInstanceAF(Contract):
    afi: Literal['ipv4', 'ipv6']
    safi: SAFI | None = None
    route_targets_import: list[Name] | None = None
    route_targets_export: list[Name] | None = None


class InterfaceReference(Contract):
    interface: Name


class StaticRoute(Contract):
    destination: IPvAnyNetwork
    next_hop: IPvAnyAddress | InterfaceReference | None = None
    outgoing_interface: Name | None = None
    network_instance: Name | None = None
    admin_distance: Annotated[StrictInt, Field(ge=1, le=255)] | None = None
    description: StrictStr | None = None

    @model_validator(mode='after')
    def coherent(self):
        if self.next_hop is None and self.outgoing_interface is None:
            raise ValueError('Static route needs next_hop or outgoing_interface')
        if isinstance(self.next_hop, (_IPv4Address, _IPv6Address)) and self.destination.version != self.next_hop.version:
            raise ValueError('Next-hop address family differs from destination')
        return self


LocalSetting = Literal['configured', 'removed']


class BGPAuthentication(Contract):
    local_setting: LocalSetting | None = None
    method: Literal['tcp_md5', 'tcp_ao', 'other'] | None = None
    native_method: Name | None = None
    key_reference: Name | None = None
    algorithm: Name | None = None
    key_ids: list[Annotated[StrictInt, Field(ge=0, le=65535)]] | None = None
    secret_configured: StrictBool | None = None
    credential_format: Name | None = None


class RoutingAuthenticationKey(Contract):
    kind: Literal['plaintext', 'message_digest']
    key_id: Annotated[StrictInt, Field(ge=1, le=255)] | None = None
    algorithm: Name | None = None
    secret_configured: StrictBool | None = None
    credential_format: Name | None = None
    local_setting: LocalSetting | None = None


class RoutingAuthentication(Contract):
    mode_setting: LocalSetting | None = None
    key_chain_setting: LocalSetting | None = None
    removed_key_chain_reference: Name | None = None
    keys: list[RoutingAuthenticationKey] | None = None
    # Vocabulary is deliberately conservative; native method/algorithm retain dialects.
    method: Literal['none', 'plaintext', 'message_digest', 'hmac', 'key_chain', 'ipsec', 'other'] | None = None
    native_method: Name | None = None
    algorithm: Name | None = None
    key_ids: list[Annotated[StrictInt, Field(ge=0, le=65535)]] | None = None
    key_chain_reference: Name | None = None
    secret_configured: StrictBool | None = None
    credential_format: Name | None = None


class OSPFNetworkStatement(Contract):
    area: Name
    prefix: IPvAnyNetwork | None = None
    address: IPv4Address | None = None
    wildcard_mask: IPv4Address | None = None

    @model_validator(mode='after')
    def wildcard_consistency(self):
        if (self.address is None) != (self.wildcard_mask is None):
            raise ValueError('Native OSPF address and wildcard must be supplied together')
        if self.prefix is None and self.address is None:
            raise ValueError('OSPF statement needs prefix or native address/wildcard')
        if self.address is not None and self.prefix is not None:
            mask = int(self.wildcard_mask) ^ 0xffffffff
            bits = f'{mask:032b}'
            if '01' in bits:
                raise ValueError('Noncontiguous wildcard cannot have a canonical prefix')
            expected = IPv4Network(f'{self.address}/{bits.count("1")}', strict=False)
            if self.prefix != expected:
                raise ValueError('Prefix does not match native address/wildcard')
        return self


class OSPFInterfaceSettings(Contract):
    interface: Name
    network_type: NetworkType | None = None
    cost: Annotated[StrictInt, Field(ge=1, le=65535)] | None = None
    priority: Annotated[StrictInt, Field(ge=0, le=255)] | None = None
    hello_interval: Annotated[StrictInt, Field(gt=0)] | None = None
    dead_interval: Annotated[StrictInt, Field(gt=0)] | None = None
    authentication: RoutingAuthentication | None = None


class ISISAuthentication(RoutingAuthentication):
    send_only: StrictBool | None = None
    send_only_setting: LocalSetting | None = None
    scope: Literal['process', 'area', 'domain', 'interface', 'level-1', 'level-2']
    level: Literal['level-1', 'level-2', 'level-1-2'] | None = None


class ISISInterfaceSettings(Contract):
    interface: Name
    level: Literal['level-1', 'level-2', 'level-1-2'] | None = None
    metric: Annotated[StrictInt, Field(ge=0, le=16777215)] | None = None
    network_type: Literal['point-to-point', 'broadcast'] | None = None
    passive: StrictBool | None = None
    authentication: list[ISISAuthentication] | None = None

    @model_validator(mode='after')
    def authentication_scope(self):
        if any(a.scope not in ('interface', 'level-1', 'level-2') for a in (self.authentication or [])):
            raise ValueError('Interface authentication cannot use process/area/domain scope')
        return self


class RIPInterfaceSettings(Contract):
    interface: Name
    send_versions: list[Literal[1, 2]] | None = None
    receive_versions: list[Literal[1, 2]] | None = None
    passive: StrictBool | None = None
    authentication: RoutingAuthentication | None = None


class NativeClause(Contract):
    """Non-secret, uninterpreted policy operand; never raw credential material."""
    keyword: Name
    operands: list[StrictStr] | None = None


class ASPathListEntry(Contract):
    sequence: Annotated[StrictInt, Field(ge=0)] | None = None
    action: Literal['permit', 'deny']
    expression: StrictStr


class ASPathList(Contract):
    name: Name
    dialect: Name | None = None
    entries: list[ASPathListEntry] | None = None


class RoutingPolicies(Contract):
    route_maps: list[RoutingPolicy] | None = None
    prefix_lists: list[PrefixList] | None = None
    community_lists: list[CommunityList] | None = None
    as_path_lists: list[ASPathList] | None = None


class Security(Contract):
    acls: list[ACLSet] | None = None
    acl_attachments: list[ACLAttachment] | None = None


class NATInterfaceRole(Contract):
    interface_name: Name
    role: Literal['inside', 'outside']


class NAT(Contract):
    rules: list[NATRule] | None = None
    interface_roles: list[NATInterfaceRole] | None = None


class CryptoProposal(Contract):
    name: Name
    encryption_algorithms: list[Name] | None = None
    integrity_algorithms: list[Name] | None = None
    dh_groups: list[Annotated[StrictInt, Field(ge=1)]] | None = None


class IPsecProfile(Contract):
    name: Name
    proposal_references: list[Name] | None = None
    ike_profile_reference: Name | None = None


class Crypto(Contract):
    proposals: list[CryptoProposal] | None = None
    ipsec_profiles: list[IPsecProfile] | None = None


class VPN(Contract):
    tunnels: list[VPNTunnel] | None = None
    crypto: Crypto | None = None


class SchedulerAllocation(Contract):
    configured: StrictBool
    interrupt_microseconds: Annotated[StrictInt, Field(ge=400, le=60000)] | None = None
    process_microseconds: Annotated[StrictInt, Field(ge=100, le=4000)] | None = None

    @model_validator(mode='after')
    def disabled_has_no_times(self):
        if self.configured is False and (self.interrupt_microseconds is not None or self.process_microseconds is not None):
            raise ValueError('Removed scheduler allocation has no configured times')
        return self


class CiscoExtensions(Contract):
    extension_version: Literal['1.0.0'] = '1.0.0'
    virtual_services: list[VirtualService] | None = None
    scheduler_allocation: SchedulerAllocation | None = None
    cdp_log_mismatch_duplex_enabled: StrictBool | None = None
    fpd_auto_upgrade: StrictBool | None = None
    ipv6_ioam_timestamp_enabled: StrictBool | None = None
    bgp_community_new_format: StrictBool | None = None
    qfp_utilization_monitor_load: Annotated[StrictInt, Field(ge=0, le=65535)] | None = None
    punt_keepalive_kernel_core_disabled: StrictBool | None = None


class Extensions(Contract):
    cisco: CiscoExtensions | None = None


class KeyChainKey(Contract):
    identifier: Annotated[StrictInt, Field(ge=0)]
    secret_configured: StrictBool | None = None
    credential_format: Literal['0', '6', '7'] | None = None
    cryptographic_algorithm: Literal['hmac-sha-1', 'hmac-sha-256', 'hmac-sha-384', 'hmac-sha-512', 'md5'] | None = None


class KeyChain(Contract):
    name: Name
    keys: list[KeyChainKey] | None = None


class InterfaceRoutingAuthentication(Contract):
    interface: Name
    protocol: Literal['ospf', 'isis', 'rip']
    network_instance: Name | None = None
    authentication: RoutingAuthentication | None = None
    isis_authentication: list[ISISAuthentication] | None = None

    @model_validator(mode='after')
    def protocol_shape(self):
        if self.protocol == 'isis' and self.authentication is not None:
            raise ValueError('IS-IS authentication requires level/scoped entries')
        if self.protocol != 'isis' and self.isis_authentication is not None:
            raise ValueError('Level-scoped authentication is specific to IS-IS')
        return self


EIGRPASN = Annotated[StrictInt, Field(ge=1, le=65535)]
EIGRPByte = Annotated[StrictInt, Field(ge=0, le=255)]


class EIGRPMetric(Contract):
    bandwidth_kbps: Annotated[StrictInt, Field(ge=0, le=4294967295)]
    delay_tens_of_microseconds: Annotated[StrictInt, Field(ge=0, le=4294967295)]
    reliability: EIGRPByte
    load: EIGRPByte
    mtu: Annotated[StrictInt, Field(ge=0, le=65535)]


class EIGRPMetricPolicyAction(Contract):
    kind: Literal['eigrp_metric']
    metric: EIGRPMetric


class EIGRPMetricWeights(Contract):
    tos: Literal[0]
    k1: EIGRPByte
    k2: EIGRPByte
    k3: EIGRPByte
    k4: EIGRPByte
    k5: EIGRPByte
    k6: EIGRPByte | None = None


class EIGRPNetworkStatement(Contract):
    address: IPv4Address
    wildcard_mask: IPv4Address | None = None


class EIGRPPassiveInterface(Contract):
    interface: Name
    passive: StrictBool


class EIGRPStub(Contract):
    enabled: StrictBool
    route_types: list[Literal['connected', 'static', 'summary', 'redistributed']] | None = None
    receive_only: StrictBool | None = None
    leak_map: Name | None = None

    @model_validator(mode='after')
    def exclusive(self):
        if self.receive_only is True and (self.route_types is not None or self.leak_map is not None):
            raise ValueError('Receive-only cannot be combined with advertised stub types')
        return self


class EIGRPAuthentication(Contract):
    method: Literal['md5', 'hmac-sha-256'] | None = None
    mode_setting: Literal['configured', 'removed'] | None = None
    key_chain_reference: Name | None = None
    removed_key_chain_reference: Name | None = None
    key_chain_setting: Literal['configured', 'removed'] | None = None
    secret_configured: StrictBool | None = None
    credential_format: Literal['0', '7'] | None = None


class EIGRPSummary(Contract):
    prefix: IPvAnyNetwork
    admin_distance: Annotated[StrictInt, Field(ge=0, le=255)] | None = None
    leak_map: Name | None = None
    local_setting: Literal['configured', 'removed']


class EIGRPInterfaceSettings(Contract):
    interface: Name  # 'default' means the named AF default block, never a fabricated interface.
    enabled: StrictBool | None = None
    passive: StrictBool | None = None
    hello_interval_seconds: Annotated[StrictInt, Field(ge=1, le=65535)] | None = None
    hold_time_seconds: Annotated[StrictInt, Field(ge=1, le=65535)] | None = None
    bandwidth_percent: Annotated[StrictInt, Field(ge=1, le=999999)] | None = None
    split_horizon: StrictBool | None = None
    next_hop_self: StrictBool | None = None
    authentication: EIGRPAuthentication | None = None
    summaries: list[EIGRPSummary] | None = None
    removed_settings: list[Literal['hello_interval_seconds', 'hold_time_seconds', 'bandwidth_percent']] | None = None


class EIGRPClassicInterface(EIGRPInterfaceSettings):
    afi: Literal['ipv4', 'ipv6']
    autonomous_system: EIGRPASN
    network_instance: Name | None = None

    @model_validator(mode='after')
    def family(self):
        if self.interface == 'default':
            raise ValueError('Classic interface settings require a native interface reference')
        if any(s.prefix.version != (4 if self.afi == 'ipv4' else 6) for s in self.summaries or []):
            raise ValueError('EIGRP summary family mismatch')
        return self


class EIGRPNeighbor(Contract):
    address: IPvAnyAddress
    interface: Name


class EIGRPFilter(Contract):
    kind: Literal['acl', 'prefix_list', 'route_map']
    reference: Name
    direction: Literal['in', 'out']
    interface: Name | None = None
    local_setting: Literal['configured', 'removed']


class EIGRPRedistribution(Contract):
    protocol: Literal['connected', 'static', 'bgp', 'ospf', 'isis', 'eigrp', 'rip']
    process: Name | None = None
    metric: EIGRPMetric | None = None
    route_map: Name | None = None

    @model_validator(mode='after')
    def source_identifier(self):
        if self.protocol in ('bgp', 'eigrp', 'ospf') and self.process is None:
            raise ValueError('Redistribution source requires its process identifier')
        return self


class EIGRPTopologySettings(Contract):
    auto_summary: StrictBool | None = None
    variance: Annotated[StrictInt, Field(ge=1, le=128)] | None = None
    maximum_paths: Annotated[StrictInt, Field(ge=1, le=64)] | None = None
    maximum_hops: Annotated[StrictInt, Field(ge=1, le=255)] | None = None
    internal_distance: Annotated[StrictInt, Field(ge=1, le=255)] | None = None
    external_distance: Annotated[StrictInt, Field(ge=1, le=255)] | None = None
    default_metric: EIGRPMetric | None = None
    active_time_minutes: Annotated[StrictInt, Field(ge=0, le=65535)] | None = None
    active_time_disabled: StrictBool | None = None
    redistributions: list[EIGRPRedistribution] | None = None
    filters: list[EIGRPFilter] | None = None
    removed_settings: list[Literal['variance', 'maximum_paths', 'maximum_hops', 'distance', 'default_metric', 'active_time']] | None = None


class EIGRPTopology(EIGRPTopologySettings):
    networks: list[EIGRPNetworkStatement] | None = None
    name: Name
    identifier: Annotated[StrictInt, Field(ge=1, le=255)] | None = None

    @model_validator(mode='after')
    def identity(self):
        if (self.name == 'base') != (self.identifier is None):
            raise ValueError('Base topology has no explicit TID; a named topology requires one')
        return self


class EIGRPInstanceSettings(EIGRPTopologySettings):
    enabled: StrictBool | None = None
    router_id: IPv4Address | None = None
    log_neighbor_changes: StrictBool | None = None
    metric_weights: EIGRPMetricWeights | None = None
    networks: list[EIGRPNetworkStatement] | None = None
    neighbors: list[EIGRPNeighbor] | None = None
    passive_default: StrictBool | None = None
    passive_interfaces: list[EIGRPPassiveInterface] | None = None
    stub: EIGRPStub | None = None
    interface_settings: list[EIGRPInterfaceSettings] | None = None
    topologies: list[EIGRPTopology] | None = None
    removed_instance_settings: list[Literal['router_id', 'metric_weights']] | None = None


class EIGRPAddressFamily(EIGRPInstanceSettings):
    afi: Literal['ipv4', 'ipv6']
    safi: Literal['unicast', 'multicast'] | None = None
    network_instance: Name | None = None
    autonomous_system: EIGRPASN | None = None

    @model_validator(mode='after')
    def family_consistency(self):
        version = 4 if self.afi == 'ipv4' else 6
        if self.afi == 'ipv6' and (self.networks is not None or self.safi == 'multicast' or any(t.networks is not None for t in self.topologies or [])):
            raise ValueError('IPv6 EIGRP has no IPv4 network statements or multicast SAFI')
        if any(n.address.version != version for n in self.neighbors or []):
            raise ValueError('EIGRP neighbor family mismatch')
        if any(s.prefix.version != version for i in self.interface_settings or [] for s in i.summaries or []):
            raise ValueError('EIGRP AF summary family mismatch')
        return self


class EIGRPProcess(EIGRPInstanceSettings):
    mode: Literal['classic', 'named']
    name: Name | None = None
    afi: Literal['ipv4', 'ipv6'] | None = None
    autonomous_system: EIGRPASN | None = None
    address_families: list[EIGRPAddressFamily] | None = None

    @model_validator(mode='after')
    def process_shape(self):
        if self.mode == 'named':
            if self.name is None or self.afi is not None or self.autonomous_system is not None:
                raise ValueError('Named EIGRP AS and family belong to its address families')
            if any(getattr(self, field) is not None for field in EIGRPInstanceSettings.model_fields if field != 'enabled'):
                raise ValueError('Named EIGRP routing settings belong to AF/interface/topology scopes')
            if any(af.autonomous_system is None for af in self.address_families or []):
                raise ValueError('Named EIGRP AF requires an explicit AS')
        elif self.name is not None or self.afi is None or self.autonomous_system is None:
            raise ValueError('Classic EIGRP requires its AS and family, not a virtual name')
        if self.afi == 'ipv6' and self.networks is not None:
            raise ValueError('Classic IPv6 EIGRP has interface activation instead of networks')
        if self.afi is not None and any(n.address.version != (4 if self.afi == 'ipv4' else 6) for n in self.neighbors or []):
            raise ValueError('Classic EIGRP neighbor family mismatch')
        return self


class Routing(Contract):
    eigrp: list[EIGRPProcess] | None = None
    eigrp_interfaces: list[EIGRPClassicInterface] | None = None
    key_chains: list[KeyChain] | None = None
    interface_authentication: list[InterfaceRoutingAuthentication] | None = None
    static_routes: list[StaticRoute] | None = None
    bgp: list[BGPProcess] | None = None
    ospf: list[OSPFProcess] | None = None
    isis: list[IsisProcess] | None = None
    rip: list[RIPProcess] | None = None
    rip_interfaces: list[RIPInterfaceSettings] | None = None


    @model_validator(mode='after')
    def eigrp_identities(self):
        identities = [(p.mode, p.name, p.afi, p.autonomous_system) for p in self.eigrp or []]
        if len(identities) != len(set(identities)):
            raise ValueError('Duplicate EIGRP process identity')
        interfaces = [(i.interface, i.afi, i.autonomous_system, i.network_instance) for i in self.eigrp_interfaces or []]
        if len(interfaces) != len(set(interfaces)):
            raise ValueError('Duplicate EIGRP interface scope')
        for process in self.eigrp or []:
            families = [(f.afi, f.safi, f.network_instance, f.autonomous_system) for f in process.address_families or []]
            if len(families) != len(set(families)):
                raise ValueError('Duplicate EIGRP address-family identity')
            for scope in [process] + list(process.address_families or []):
                selectors = [i.interface for i in scope.interface_settings or []]
                topologies = [(t.name, t.identifier) for t in scope.topologies or []]
                if len(selectors) != len(set(selectors)) or len(topologies) != len(set(topologies)):
                    raise ValueError('Duplicate EIGRP interface/topology identity')
        return self


class RouterContractV1(Contract):
    contract_version: Literal['1.0.0']
    device: Device
    system: System
    interfaces: list[Interface] | None
    interface_aggregations: list[LAG] | None
    network_instances: list[NetworkInstance] | None
    routing: Routing
    routing_policies: RoutingPolicies
    security: Security
    nat: NAT
    vpn: VPN
    qos: QoS
    mpls: MPLS
    multicast: Multicast
    pki: PKI
    extensions: Extensions

    @model_validator(mode='after')
    def unique_identities(self):
        groups = (
            ('interface', [i.name for i in (self.interfaces or [])]),
            ('LAG', [i.name for i in (self.interface_aggregations or [])]),
            ('network instance', [i.name for i in (self.network_instances or [])]),
            ('ACL', [(i.name, i.family) for i in (self.security.acls or [])]),
        )
        for label, names in groups:
            if len(names) != len(set(names)):
                raise ValueError(f'Duplicate {label} identity')
        return self


ACLAddressMatch = Annotated[ACLAny | ACLHost | ACLPrefix | ACLWildcard | ACLObjectGroup, Field(discriminator='kind')]
RoutingPolicyAction = Annotated[NumericPolicyAction | ASPathPolicyAction | CommunityPolicyAction | EIGRPMetricPolicyAction, Field(discriminator='kind')]

for _model in tuple(globals().values()):
    if isinstance(_model, type) and issubclass(_model, Contract):
        _model.model_rebuild()


def router_contract_v1_schema():
    """Public V1 schema; retain all nulls and declared defaults."""
    schema = RouterContractV1.model_json_schema()
    schema.update({'$schema': 'https://json-schema.org/draft/2020-12/schema',
                   '$id': 'urn:network-config-normalizer:router-contract:1.0.0'})
    return schema
