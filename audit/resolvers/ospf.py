"""OSPF area membership resolver.

Derives interface→area membership from explicit bindings and network statements,
following Cisco IOS documented behavior. This resolver belongs to the audit layer,
not the normalizer: the normalizer stores only explicit configuration.

Reference: F14_pilot_validation.md §4
"""

from __future__ import annotations
from collections import defaultdict
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, ip_network
from typing import Any

from schemas.router_contract_v1 import RouterContractV1
from normalizer.common.addresses import area_id


@dataclass(frozen=True)
class InterfaceMembership:
    """Resolved interface membership in an OSPF area."""
    name: str
    source: str  # 'interface' | 'network'
    evidence_index: int  # index in network_statements or ospf_bindings


@dataclass(frozen=True)
class ResolvedArea:
    """Resolved OSPF area with member interfaces."""
    area_id: str
    interfaces: list[InterfaceMembership]
    declared: bool  # True if area exists in areas[] (has explicit config)
    evidence: list[str]  # 'area' | 'network' | 'binding'


@dataclass(frozen=True)
class ResolvedProcess:
    """Resolved OSPF process with all areas."""
    identifier: str
    version: int
    network_instance: str | None
    areas: dict[str, ResolvedArea]  # key = canonical area_id


def _canonical_area_id(area: str) -> str:
    """Canonicalize area identifier (e.g., '1' -> '0.0.0.1', '0.0.0.0' -> '0.0.0.0')."""
    try:
        return area_id(area)
    except (ValueError, TypeError):
        return None


def _wildcard_to_network(address: str, wildcard: str) -> IPv4Network | None:
    """Convert address/wildcard to IPv4Network. Returns None for non-contiguous wildcard."""
    wc = IPv4Address(wildcard)
    mask_int = int(wc) ^ 0xffffffff
    bits = f"{mask_int:032b}"
    if "01" in bits:
        return None  # non-contiguous wildcard
    try:
        return IPv4Network(f"{address}/{bits.count('1')}", strict=False)
    except ValueError:
        return None


def _address_matches_network(addr: str, network: IPv4Network | None) -> bool:
    """Check if an IPv4 address matches a network statement.
    
    Uses native wildcard semantics (like ACL), not prefix.
    If network is None (non-contiguous wildcard), falls back to exact address match
    which is the safe conservative behavior.
    """
    if network is None:
        return False  # Cannot reliably match non-contiguous wildcard
    try:
        return IPv4Address(addr) in network
    except ValueError:
        return False


def _collect_interface_addresses(contract: RouterContractV1 | dict) -> dict[str, list[str]]:
    """Collect primary IPv4 addresses per interface."""
    result = defaultdict(list)
    interfaces = contract.interfaces if isinstance(contract, RouterContractV1) else contract.get("interfaces", [])
    for iface in interfaces or []:
        if isinstance(iface, dict):
            ipv4 = iface.get("ipv4")
            if ipv4 and ipv4.get("addresses"):
                for addr_obj in ipv4["addresses"]:
                    if addr_obj.get("address") and addr_obj.get('secondary') is False:
                        result[iface["name"]].append(addr_obj["address"])
        else:
            if iface.ipv4 and iface.ipv4.addresses:
                for addr_obj in iface.ipv4.addresses:
                    if addr_obj.address and addr_obj.secondary is False:
                        result[iface.name].append(addr_obj.address)
    return result


def _collect_interface_vrf(contract: RouterContractV1 | dict) -> dict[str, str | None]:
    """Collect VRF per interface."""
    result = {}
    interfaces = contract.interfaces if isinstance(contract, RouterContractV1) else contract.get("interfaces", [])
    for iface in interfaces or []:
        if isinstance(iface, dict):
            result[iface["name"]] = iface.get("vrf")
        else:
            result[iface.name] = iface.vrf
    return result


def ospf_areas(contract: RouterContractV1 | dict[str, Any]) -> dict[tuple[str, int, str | None], dict[str, ResolvedArea]]:
    """Resolve OSPF area membership for all processes.

    Returns:
        Dict keyed by (process_identifier, version, network_instance) mapping to
        dict of area_id -> ResolvedArea.

    Algorithm (per F14_pilot_validation.md §4):
    1. Universe = union of three sources, canonicalized:
       - areas[].area_id (explicit area config)
       - network_statements[].area
       - ospf_bindings[].area (explicit ip ospf <pid> area <area>)
    2. For each interface:
       a) Explicit binding 'ip ospf <pid> area' if exists (priority)
       b) Else first matching network_statement in configuration order
       c) With interface.vrf == process.network_instance
    3. Match by native address/wildcard_mask (never by prefix, which is null for non-contiguous)
    4. No invented interfaces; area without members listed with interfaces: []
    """
    # Accept both RouterContractV1 model and dict (for JSON input)
    if isinstance(contract, dict):
        # Minimal dict navigation - assume validated structure
        c = contract
    else:
        c = contract.model_dump(mode="python")

    routing = c.get("routing") or {}
    ospf_processes = routing.get("ospf") or []
    interfaces = c.get("interfaces") or []

    # Pre-collect interface data
    iface_addresses = _collect_interface_addresses(contract)
    iface_vrf = _collect_interface_vrf(contract)

    result: dict[tuple[str, int, str | None], dict[str, ResolvedArea]] = {}

    for proc_idx, proc in enumerate(ospf_processes):
        proc_id = proc.get("identifier")
        version = proc.get("version", 2)
        net_instance = proc.get("network_instance")
        key = (proc_id, version, net_instance)

        # Build universe of area IDs
        area_universe: set[str] = set()

        # Source 1: explicit areas[]
        areas = proc.get("areas") or []
        declared_areas: dict[str, dict] = {}
        for a in areas:
            aid = _canonical_area_id(a.get("area_id", ""))
            if aid:
                area_universe.add(aid)
                declared_areas[aid] = a

        # Source 2: network_statements
        network_stmts = proc.get("network_statements") or []
        for idx, ns in enumerate(network_stmts):
            aid = _canonical_area_id(ns.get("area", ""))
            if aid:
                area_universe.add(aid)

        # Source 3 is authoritative even without a separate optional area object.
        for iface in interfaces:
            if iface.get('vrf')!=net_instance:continue
            for binding in iface.get('ospf_bindings') or []:
                if binding.get('version')==version and binding.get('process')==proc_id:
                    aid=_canonical_area_id(binding.get('area',''))
                    if aid:area_universe.add(aid)

        # Prepare resolved areas dict
        resolved_areas: dict[str, ResolvedArea] = {}
        for aid in sorted(area_universe, key=IPv4Address):
            resolved_areas[aid] = ResolvedArea(
                area_id=aid,
                interfaces=[],
                declared=aid in declared_areas,
                evidence=[]
            )

        # Add evidence sources
        for aid in declared_areas:
            resolved_areas[aid].evidence.append("area")

        for idx, ns in enumerate(network_stmts):
            aid = _canonical_area_id(ns.get("area", ""))
            if aid and "network" not in resolved_areas[aid].evidence:
                resolved_areas[aid].evidence.append("network")

        # Build network statement matchers in configuration order
        network_matchers = []
        for idx, ns in enumerate(network_stmts):
            aid = _canonical_area_id(ns.get("area", ""))
            if aid and version == 2 and (ns.get('address') is not None or ip_network(ns['prefix']).version == 4):
                network_matchers.append((ns, aid, idx))

        # Resolve each interface
        for iface in (interfaces or []):
            iface_name = iface.get("name")
            iface_vrf_val = iface.get("vrf")
            addresses = iface_addresses.get(iface_name, [])

            # Skip if VRF mismatch
            if iface_vrf_val != net_instance:
                continue

            # Check explicit binding first (priority per Cisco docs)
            explicit_binding = None
            binding_index = None
            for index,binding in enumerate(iface.get("ospf_bindings") or []):
                if binding.get("version") == version and binding.get("process") == proc_id:
                    explicit_binding = binding
                    binding_index = index
                    break

            if explicit_binding:
                aid = _canonical_area_id(explicit_binding.get("area", ""))
                if aid in resolved_areas:
                    # Check if already added via binding (avoid duplicates)
                    existing = any(m.name == iface_name and m.source == "interface"
                                   for m in resolved_areas[aid].interfaces)
                    if not existing:
                        resolved_areas[aid].interfaces.append(InterfaceMembership(
                            name=iface_name,
                            source="interface",
                            evidence_index=binding_index
                        ))
                        if "binding" not in resolved_areas[aid].evidence:
                            resolved_areas[aid].evidence.append("binding")
                continue

            # No explicit binding: try network statements in order
            for addr in addresses:
                matched = False
                for statement, aid, ns_idx in network_matchers:
                    from .routing_common import wildcard_match
                    match = (wildcard_match(addr, statement['address'], statement['wildcard_mask'])
                             if statement.get('address') is not None else
                             _address_matches_network(addr, IPv4Network(statement['prefix'])))
                    if match:
                        if aid in resolved_areas:
                            existing = any(m.name == iface_name and m.source == "network"
                                           for m in resolved_areas[aid].interfaces)
                            if not existing:
                                resolved_areas[aid].interfaces.append(InterfaceMembership(
                                    name=iface_name,
                                    source="network",
                                    evidence_index=ns_idx
                                ))
                        matched = True
                        break  # First match wins (Cisco sequential evaluation)
                if matched:
                    break  # Interface assigned, stop checking other addresses

        result[key] = resolved_areas

    return result


def get_interface_area(contract: RouterContractV1 | dict[str, Any],
                       interface_name: str,
                       process_identifier: str,
                       version: int = 2,
                       network_instance: str | None = None) -> str | None:
    """Convenience: get resolved area for a specific interface in a process.

    Returns canonical area_id or None if interface not member of process.
    """
    resolved = ospf_areas(contract)
    key = (process_identifier, version, network_instance)
    if key not in resolved:
        return None
    for area in resolved[key].values():
        for m in area.interfaces:
            if m.name == interface_name:
                return area.area_id
    return None


def get_process_areas(contract: RouterContractV1 | dict[str, Any],
                      process_identifier: str,
                      version: int = 2,
                      network_instance: str | None = None) -> dict[str, ResolvedArea] | None:
    """Convenience: get all resolved areas for a process."""
    resolved = ospf_areas(contract)
    return resolved.get((process_identifier, version, network_instance))


def resolve(c):
    """Resolve membership plus authentication, with explicit uncertainty guards.

    The legacy membership API remains available. Overlapping distinct areas and
    competing processes are candidate relationships, never positive evidence.
    """
    from .routing_common import (Scope, Relation, Authentication, Property, Key, prop,
                                 local_property, interface_auth, primary_addresses,
                                 wildcard_match, passive, guarded)
    membership = ospf_areas(c)
    scopes, candidates, used_auth = [], defaultdict(list), set()
    for p, process in enumerate(c['routing'].get('ospf') or []):
        path = f'/routing/ospf/{p}'
        version, vrf = process.get('version'), process.get('network_instance')
        unsupported = version != 2 or any(
            ns.get('address') is None and ip_network(ns['prefix']).version != 4 or not _canonical_area_id(ns['area'])
            for ns in process.get('network_statements') or [])
        areas = membership.get((process['identifier'], version, vrf), {})
        relations = []
        for area in areas.values():
            for member in area.interfaces:
                i, interface = next((i, f) for i, f in enumerate(c.get('interfaces') or []) if f['name'] == member.name)
                bindings = interface.get('ospf_bindings') or []
                explicit = [(n, b) for n, b in enumerate(bindings) if b['version'] == version]
                if explicit and not any(b['process'] == process['identifier'] for _, b in explicit):
                    continue
                pointers = [f'/interfaces/{i}/name']
                matches = []
                if member.source == 'interface':
                    pointers.append(f'/interfaces/{i}/ospf_bindings/{member.evidence_index}')
                else:
                    pointers.append(f'{path}/network_statements/{member.evidence_index}')
                    pointers += [f'/interfaces/{i}/ipv4/addresses/{n}/address' for n, _ in primary_addresses(interface)]
                    for n, statement in enumerate(process.get('network_statements') or []):
                        if statement.get('address') is None and ip_network(statement['prefix']).version != 4:
                            continue
                        if any(wildcard_match(address['address'], statement['address'], statement['wildcard_mask'])
                               if statement.get('address') is not None else IPv4Address(address['address']) in IPv4Network(statement['prefix'])
                               for _, address in primary_addresses(interface)):
                            matches.append(statement['area'])
                            pointers.append(f'{path}/network_statements/{n}')
                ambiguous = len(set(matches)) > 1 or len({b['area'] for _, b in explicit if b['process'] == process['identifier']}) > 1
                local, local_path, collision = interface_auth(c, 'ospf', member.name, vrf, process, path)
                if local_path:
                    used_auth.add(local_path)
                mode = local_property(local, local_path, 'method', 'mode_setting')
                # no ip ospf authentication removes the interface override.
                # Area inheritance is distinct from explicit authentication null.
                if mode.origin in ('unknown', 'removed') and not ambiguous:
                    a = next(((n, a) for n, a in enumerate(process.get('areas') or []) if a['area_id'] == area.area_id), None)
                    if a:
                        n, target = a
                        inherited = local_property(target.get('authentication'), f'{path}/areas/{n}/authentication', 'method', 'mode_setting', inherited=True)
                        if inherited.origin != 'unknown':
                            mode = inherited
                if ambiguous:
                    mode = Property(status='AMBIGUOUS', rule='OSPF_AREA_POLICY_AMBIGUOUS')
                key_meta = [Key(identifier=k.get('key_id'), pointer=f'{local_path}/keys/{n}', secret_configured=k.get('secret_configured'))
                            for n, k in enumerate((local or {}).get('keys') or [])]
                from .routing_common import chain_auth
                auth = chain_auth(c, mode, local_property(local, local_path, 'key_chain_reference', 'key_chain_setting'))
                auth = auth.model_copy(update={'keys': auth.keys + key_meta})
                relation = Relation(protocol='ospf', subject=member.name, status='AMBIGUOUS' if ambiguous or collision else 'NOT_SUPPORTED' if unsupported else 'RESOLVED',
                    derivation='explicit' if member.source == 'interface' else 'derived',
                    rule='OSPF_EXPLICIT_BINDING_PRIORITY' if member.source == 'interface' else 'OSPF_PRIMARY_NATIVE_WILDCARD',
                    pointers=list(dict.fromkeys(pointers)), area=None if ambiguous else area.area_id,
                    passive=passive(process, path, member.name), authentication=auth)
                relations.append(guarded(c, relation))
                candidates[(member.name, version, vrf)].append((len(scopes), len(relations) - 1))
        scopes.append(Scope(protocol='ospf', identifier=process['identifier'], pointer=path, process_pointer=path, afi='ipv4' if version == 2 else 'ipv6',
            status='NOT_SUPPORTED' if unsupported else 'RESOLVED', rule='OSPF_SCOPE_OUTSIDE_VALIDATED_IPV4_DOMAIN' if unsupported else 'OSPF_IPV4_CONFIGURATION',
            network_instance=vrf, version=prop(version, path + '/version'), relations=relations,
            network_pointers=[f'{path}/network_statements/{n}' for n, _ in enumerate(process.get('network_statements') or [])],
            area_pointers=[f'{path}/areas/{n}' for n, _ in enumerate(process.get('areas') or [])]))
    for competing in candidates.values():
        if len(competing) > 1:
            for s, r in competing:
                scopes[s].relations[r] = scopes[s].relations[r].model_copy(update={'status': 'AMBIGUOUS', 'rule': 'MULTIPLE_OSPF_PROCESSES_SELECT_INTERFACE'})
    orphans = []
    for i, interface in enumerate(c.get('interfaces') or []):
        for n, binding in enumerate(interface.get('ospf_bindings') or []):
            if not any(s.identifier == binding['process'] and s.network_instance == interface.get('vrf') and s.version.value == binding['version'] for s in scopes):
                orphans.append(Relation(protocol='ospf', subject=interface['name'], subject_kind='reference', status='UNRESOLVED_REFERENCE',
                    derivation='explicit', rule='OSPF_PROCESS_TARGET_MISSING', pointers=[f'/interfaces/{i}/ospf_bindings/{n}']))
    for i, item in enumerate(c['routing'].get('interface_authentication') or []):
        path = f'/routing/interface_authentication/{i}/authentication'
        if item['protocol'] == 'ospf' and item.get('authentication') and path not in used_auth:
            orphans.append(Relation(protocol='ospf', subject=item['interface'], subject_kind='reference', status='UNRESOLVED_REFERENCE',
                derivation='explicit', rule='OSPF_AUTHENTICATION_WITHOUT_RESOLVED_MEMBERSHIP', pointers=[path]))
    return scopes, orphans
