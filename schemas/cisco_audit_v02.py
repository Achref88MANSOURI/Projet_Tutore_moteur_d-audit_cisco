"""Additive 0.2.1 audit properties. Configured facts, never operational state."""
from typing import Literal
from pydantic import Field, IPvAnyAddress
from .normalizedconfig import Contract, IPv4Address


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
    # Cisco's http method can carry HTTPS; no tls flag can be inferred here.
    transport_methods: list[Literal['http','email']] = Field(default_factory=list)


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
    # Identity is a necessary dependency; P2 capacity/timeouts remain native.
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
    # Network numbers select RIP participation, not advertised BGP prefixes.
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
    # Raw register is configured intent, without an invented platform bit decode.
    configuration_register: str | None = Field(default=None, pattern=r'^0x[0-9A-Fa-f]{1,4}$')
