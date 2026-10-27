"""NormalizedConfig 0.1.0 — vendor-independent *internal* router config contract.

OpenConfig-aligned semantic vocabulary, NOT RFC7951/OpenConfig instance JSON.
Evidence/provenance and unknown statements are intentionally outside the data model.
Python 3.10+, Pydantic 2.x.  No parsing engine included in this contract.
"""
from __future__ import annotations

from enum import Enum
from ipaddress import IPv4Address, IPv6Address
from typing import Any, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, IPvAnyNetwork, model_validator


class Contract(BaseModel):
    model_config = ConfigDict(extra='forbid', validate_assignment=True, use_enum_values=True)


class SourceCompleteness(str, Enum):
    COMPLETE = 'complete'
    PARTIAL = 'partial'
    UNKNOWN = 'unknown'


class FactStatus(str, Enum):
    EXPLICIT = 'explicit'
    INFERRED_DEFAULT = 'inferred_default'
    ABSENT = 'absent'
    UNKNOWN = 'unknown'
    UNSUPPORTED = 'unsupported'
    NOT_APPLICABLE = 'not_applicable'


class CoverageStatus(str, Enum):
    FULL = 'supported'
    PARTIAL = 'partial'
    UNSUPPORTED = 'unsupported'
    NOT_EVALUATED = 'not_evaluated'


class Metadata(Contract):
    vendor: str = Field(min_length=1, description='Canonical vendor slug, e.g. cisco or juniper')
    os_family: str = Field(min_length=1, description='Native operating system, e.g. ios, iosxe, junos')
    os_version: str | None = None
    hostname_hint: str | None = None
    source_file: str = Field(min_length=1)
    source_sha256: str | None = Field(default=None, pattern=r'^[0-9a-f]{64}$')
    input_format: str = Field(min_length=1, description='cisco-running, junos-set, junos-braces, eos-cli, fortios-cli, etc.')
    source_kind: Literal['running','startup','candidate','backup','unknown'] = 'unknown'
    completeness: SourceCompleteness = SourceCompleteness.UNKNOWN
    completeness_basis: str | None = None
    os_detection_method: Literal['explicit','heuristic','device_metadata','unknown'] = 'unknown'
    redacted_secrets: bool = True


class IPv4InterfaceAddress(Contract):
    address: IPv4Address
    prefix_length: int = Field(ge=0, le=32)
    secondary: bool | None = None


class IPv6InterfaceAddress(Contract):
    address: IPv6Address
    prefix_length: int = Field(ge=0, le=128)


class Interface(Contract):
    name: str = Field(min_length=1, description='Native interface identifier; NEVER translate port names implicitly')
    kind: Literal['physical','subinterface','loopback','svi','lag','tunnel','other','unknown'] = 'unknown'
    parent_interface: str | None = None
    subinterface_index: int | None = Field(default=None, ge=0)
    description: str | None = None
    admin_enabled: bool | None = None
    mtu: int | None = Field(default=None, ge=64, le=65535)
    ipv4_addresses: list[IPv4InterfaceAddress] = Field(default_factory=list)
    ipv6_addresses: list[IPv6InterfaceAddress] = Field(default_factory=list)
    vrf: str | None = None
    switchport_mode: Literal['access','trunk','hybrid','routed','unknown'] | None = None
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
            if any(x < 1 or x > 4094 for x in self.trunk_allowed_vlans):
                raise ValueError('Trunk VLAN IDs must be 1-4094')
        return self


class VLAN(Contract):
    vlan_id: int = Field(ge=1, le=4094)
    name: str | None = None
    admin_status: Literal['active','suspended','unknown'] | None = None
    tagged_interfaces: list[str] = Field(default_factory=list)
    untagged_interfaces: list[str] = Field(default_factory=list)


class LAG(Contract):
    name: str = Field(min_length=1)
    members: list[str] = Field(default_factory=list)
    lacp_mode: Literal['active','passive','on','unknown'] | None = None


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
    kind: Literal['DEFAULT_INSTANCE','L3VRF','L2VSI','L2L3','OTHER','UNKNOWN'] = 'UNKNOWN'
    route_distinguisher: str | None = None
    route_targets_import: list[str] = Field(default_factory=list)
    route_targets_export: list[str] = Field(default_factory=list)
    interface_names: list[str] = Field(default_factory=list)


class NTPServer(Contract):
    address: str = Field(min_length=1)
    prefer: bool | None = None
    source_interface: str | None = None
    network_instance: str | None = None


class SyslogDestination(Contract):
    address: str = Field(min_length=1)
    port: int | None = Field(default=None, ge=1, le=65535)
    transport: Literal['udp','tcp','tls','unknown'] | None = None
    severity: str | None = None


class UserAccount(Contract):
    username: str = Field(min_length=1)
    privilege_level: int | None = Field(default=None, ge=0, le=15)
    credential_configured: bool | None = None
    credential_type: str | None = None
    # Credential values intentionally omitted. Store protected source separately.


class AuthServer(Contract):
    protocol: Literal['radius','tacacs','other']
    address: str = Field(min_length=1)
    port: int | None = Field(default=None, ge=1, le=65535)


class AAA(Contract):
    enabled: bool | None = None
    local_users: list[UserAccount] = Field(default_factory=list)
    servers: list[AuthServer] = Field(default_factory=list)
    method_lists: list[str] = Field(default_factory=list)


class SNMPCommunity(Contract):
    # A SNMP community is a sensitive string; it must be masked in public exports.
    name: str = Field(min_length=1)
    access: Literal['ro','rw','unknown'] = 'unknown'
    access_list: str | None = None


class SNMP(Contract):
    enabled: bool | None = None
    communities: list[SNMPCommunity] = Field(default_factory=list)
    version: list[str] = Field(default_factory=list)
    location: str | None = None
    contact: str | None = None


class ManagementLine(Contract):
    name: str = Field(min_length=1, description='Native management line, e.g. vty 0 4')
    allowed_transports: list[str] = Field(default_factory=list)
    idle_timeout_seconds: int | None = Field(default=None, ge=0)
    access_list: str | None = None
    authentication: str | None = None


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
    aaa: AAA | None = None
    snmp: SNMP | None = None
    management: Management | None = None
    login_banner_present: bool | None = None


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


class BGPNeighbor(Contract):
    peer: str = Field(min_length=1, description='IPv4, IPv6 address or vendor-native peer identity')
    remote_as: int | None = Field(default=None, ge=1, le=4294967295)
    description: str | None = None
    peer_group: str | None = None
    import_policies: list[str] = Field(default_factory=list)
    export_policies: list[str] = Field(default_factory=list)
    enabled: bool | None = None


class BGPProcess(Contract):
    local_as: int = Field(ge=1, le=4294967295)
    network_instance: str | None = None
    router_id: IPv4Address | None = None
    neighbors: list[BGPNeighbor] = Field(default_factory=list)
    peer_groups: list[str] = Field(default_factory=list)
    address_families: list[str] = Field(default_factory=list)


class OSPFNetworkStatement(Contract):
    prefix: IPvAnyNetwork
    area: str = Field(min_length=1)


class OSPFArea(Contract):
    area_id: str = Field(min_length=1)
    interfaces: list[str] = Field(default_factory=list)


class OSPFProcess(Contract):
    identifier: str = Field(min_length=1, description='Native process ID; semantics differ across vendors')
    network_instance: str | None = None
    router_id: IPv4Address | None = None
    areas: list[OSPFArea] = Field(default_factory=list)
    network_statements: list[OSPFNetworkStatement] = Field(default_factory=list)
    passive_interfaces: list[str] = Field(default_factory=list)


class RoutingPolicyMatch(Contract):
    kind: str = Field(min_length=1)
    value: str = Field(min_length=1)


class RoutingPolicyAction(Contract):
    kind: str = Field(min_length=1)
    value: str | None = None


class RoutingPolicyStatement(Contract):
    identifier: str = Field(min_length=1)
    decision: Literal['accept','reject','next','unknown'] | None = None
    matches: list[RoutingPolicyMatch] = Field(default_factory=list)
    actions: list[RoutingPolicyAction] = Field(default_factory=list)


class RoutingPolicy(Contract):
    name: str = Field(min_length=1)
    statements: list[RoutingPolicyStatement] = Field(default_factory=list)


class PrefixSet(Contract):
    name: str = Field(min_length=1)
    prefixes: list[str] = Field(default_factory=list)


class Routing(Contract):
    static_routes: list[StaticRoute] = Field(default_factory=list)
    bgp: list[BGPProcess] = Field(default_factory=list)
    ospf: list[OSPFProcess] = Field(default_factory=list)
    routing_policies: list[RoutingPolicy] = Field(default_factory=list)
    prefix_sets: list[PrefixSet] = Field(default_factory=list)


class ACLAddressMatch(Contract):
    kind: Literal['any','prefix','host','object_group','wildcard','unknown']
    value: str | None = None
    # A wildcard expression is retained as-is if not unambiguously convertible.


class PortMatch(Contract):
    operator: Literal['eq','neq','lt','gt','range']
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


class ACLEntry(Contract):
    sequence: int | None = Field(default=None, ge=0)
    action: Literal['permit','deny','reject','unknown']
    protocol: str | None = None
    source: ACLAddressMatch | None = None
    destination: ACLAddressMatch | None = None
    source_port: PortMatch | None = None
    destination_port: PortMatch | None = None
    log: bool | None = None
    description: str | None = None


class ACLSet(Contract):
    name: str = Field(min_length=1)
    family: Literal['ipv4','ipv6','l2','mixed','unknown'] = 'unknown'
    entries: list[ACLEntry] = Field(default_factory=list, description='Order is semantically significant')

    @model_validator(mode='after')
    def unique_sequences(self):
        seq = [x.sequence for x in self.entries if x.sequence is not None]
        if len(seq) != len(set(seq)):
            raise ValueError('Duplicate ACL sequence numbers')
        return self


class ACLAttachment(Contract):
    acl_name: str = Field(min_length=1)
    interface_name: str = Field(min_length=1)
    direction: Literal['ingress','egress']


class Security(Contract):
    acl_sets: list[ACLSet] = Field(default_factory=list)
    acl_attachments: list[ACLAttachment] = Field(default_factory=list)


class NATRule(Contract):
    identifier: str = Field(min_length=1)
    type: Literal['static','dynamic','pat','other','unknown'] = 'unknown'
    source_match: str | None = None
    translated_source: str | None = None
    destination_match: str | None = None
    translated_destination: str | None = None
    ingress_interface: str | None = None
    egress_interface: str | None = None
    network_instance: str | None = None


class VPNTunnel(Contract):
    identifier: str = Field(min_length=1)
    technology: Literal['ipsec','gre','wireguard','ssl','other','unknown'] = 'unknown'
    local_endpoint: str | None = None
    remote_endpoint: str | None = None
    tunnel_interface: str | None = None
    network_instance: str | None = None
    # Not a full IPsec/key/crypto policy model in v0.1.


class QoSAttachment(Contract):
    policy_name: str = Field(min_length=1)
    interface_name: str = Field(min_length=1)
    direction: Literal['ingress','egress']


class QoS(Contract):
    policy_names: list[str] = Field(default_factory=list)
    attachments: list[QoSAttachment] = Field(default_factory=list)


class Configuration(Contract):
    system: System = Field(default_factory=System)
    interfaces: list[Interface] = Field(default_factory=list)
    layer2: Layer2 = Field(default_factory=Layer2)
    network_instances: list[NetworkInstance] = Field(default_factory=list)
    routing: Routing = Field(default_factory=Routing)
    security: Security = Field(default_factory=Security)
    nat: list[NATRule] = Field(default_factory=list)
    vpn_tunnels: list[VPNTunnel] = Field(default_factory=list)
    qos: QoS = Field(default_factory=QoS)

    @model_validator(mode='after')
    def unique_ids(self):
        for label, ids in [
            ('interface', [x.name for x in self.interfaces]),
            ('VLAN', [x.vlan_id for x in self.layer2.vlans]),
            ('network_instance', [x.name for x in self.network_instances]),
            ('ACL', [(x.name, x.family) for x in self.security.acl_sets]),
        ]:
            if len(ids) != len(set(ids)):
                raise ValueError(f'Duplicate {label} identity')
        return self


class Evidence(Contract):
    path: str = Field(pattern=r'^/configuration(?:/.*)?$', description='JSON Pointer within the configuration object')
    status: FactStatus
    source_file: str | None = None
    line_start: int | None = Field(default=None, ge=1)
    line_end: int | None = Field(default=None, ge=1)
    raw_command: str | None = None
    parser_rule: str | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    basis: str | None = Field(default=None, description='Justification for inferred defaults and conclusive absence')

    @model_validator(mode='after')
    def source_consistency(self):
        if self.line_end is not None and self.line_start is not None and self.line_end < self.line_start:
            raise ValueError('line_end must be >= line_start')
        if self.status == FactStatus.EXPLICIT and self.line_start is None:
            raise ValueError('Explicit evidence needs source line')
        if self.status in (FactStatus.INFERRED_DEFAULT, FactStatus.ABSENT) and not self.basis:
            raise ValueError('Inferred default / conclusive absence needs justification')
        return self


class UnknownCommand(Contract):
    line_start: int = Field(ge=1)
    line_end: int | None = Field(default=None, ge=1)
    raw_text: str
    parent_context: str | None = None
    reason: Literal['unrecognized','not_implemented','unsupported_semantics','vendor_specific']


class FeatureCoverage(Contract):
    feature: str = Field(min_length=1)
    status: CoverageStatus
    note: str | None = None


class Diagnostic(Contract):
    severity: Literal['info','warning','error']
    code: str = Field(min_length=1)
    message: str = Field(min_length=1)
    source_line: int | None = Field(default=None, ge=1)
    config_path: str | None = None


class Parsing(Contract):
    parser_name: str = Field(min_length=1)
    parser_version: str = Field(min_length=1)
    native_tree_file: str | None = Field(default=None, description='Path to separately archived native AST')
    feature_coverage: list[FeatureCoverage] = Field(default_factory=list)
    unknown_commands: list[UnknownCommand] = Field(default_factory=list)
    diagnostics: list[Diagnostic] = Field(default_factory=list)
    total_source_lines: int | None = Field(default=None, ge=0)
    recognized_source_lines: int | None = Field(default=None, ge=0)

    @model_validator(mode='after')
    def valid_count(self):
        if self.total_source_lines is not None and self.recognized_source_lines is not None:
            if self.recognized_source_lines > self.total_source_lines:
                raise ValueError('Recognized lines exceed total lines')
        return self


class NormalizedConfig(Contract):
    schema_version: Literal['0.1.0'] = '0.1.0'
    metadata: Metadata
    configuration: Configuration = Field(default_factory=Configuration)
    evidence: list[Evidence] = Field(default_factory=list)
    parsing: Parsing

    @model_validator(mode='after')
    def ensure_evidence_integrity(self):
        # A claim of conclusive absence needs a known-complete source.
        if self.metadata.completeness != SourceCompleteness.COMPLETE:
            if any(e.status == FactStatus.ABSENT for e in self.evidence):
                raise ValueError('Conclusive absence cannot be asserted on partial/unknown source')
        # Defaults must be tied to a known source OS version, not to an unspecified train.
        if not self.metadata.os_version:
            if any(e.status == FactStatus.INFERRED_DEFAULT for e in self.evidence):
                raise ValueError('An inferred platform default needs an OS version')
        # Positive observations must refer to an actually populated value.
        doc = {'configuration': self.configuration.model_dump(mode='json')}
        for e in self.evidence:
            if e.status not in (FactStatus.EXPLICIT, FactStatus.INFERRED_DEFAULT):
                continue
            cur: Any = doc
            try:
                for token in e.path.lstrip('/').split('/'):
                    token = token.replace('~1','/').replace('~0','~')
                    cur = cur[int(token)] if isinstance(cur,list) else cur[token]
            except (KeyError, IndexError, TypeError, ValueError) as ex:
                raise ValueError(f'Evidence points to a nonexistent value: {e.path}') from ex
            if cur is None:
                raise ValueError(f'Known evidence points to null: {e.path}')
        return self

    def semantic_warnings(self) -> list[str]:
        """Best-effort referential checks; do not modify parsed facts."""
        c = self.configuration
        warnings = []
        acl_ids = {x.name for x in c.security.acl_sets}
        ifaces = {x.name for x in c.interfaces}
        vrfs = {x.name for x in c.network_instances}
        for x in c.security.acl_attachments:
            if x.acl_name not in acl_ids:
                warnings.append(f'ACL attachment references unknown ACL: {x.acl_name}')
            if x.interface_name not in ifaces:
                warnings.append(f'ACL attachment references unknown interface: {x.interface_name}')
        for x in c.interfaces:
            if x.vrf and x.vrf not in vrfs:
                warnings.append(f'Interface {x.name} references unknown network-instance: {x.vrf}')
        return warnings


if __name__ == '__main__':
    import json
    from pathlib import Path
    out = Path(__file__).with_name('normalizedconfig_v0_1.schema.json')
    out.write_text(json.dumps(NormalizedConfig.model_json_schema(), indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(out)
