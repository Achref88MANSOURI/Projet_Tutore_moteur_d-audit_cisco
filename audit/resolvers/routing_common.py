"""Typed configuration relationships. No CLI, device clock or CIS verdicts."""
from typing import Literal
from ipaddress import IPv4Address, IPv4Network
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr
from schemas.router_contract_v1 import RouterContractV1, RoutingIntegrityIssue

Status = Literal['RESOLVED', 'UNKNOWN', 'UNRESOLVED_REFERENCE', 'AMBIGUOUS', 'NOT_SUPPORTED', 'PLATFORM_DEPENDENT']
InputCompleteness = Literal['complete', 'partial', 'unknown']
Applicability = Literal['APPLICABLE', 'NOT_APPLICABLE', 'APPLICABILITY_UNKNOWN']


class ResolutionModel(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)


class Property(ResolutionModel):
    value: StrictBool | StrictInt | StrictStr | list[StrictInt] | None = None
    status: Status = 'UNKNOWN'
    origin: Literal[
        'configured', 'inherited', 'removed', 'reset', 'derived', 'unknown',
        'documented_default', 'proven_absent',
    ] = 'unknown'
    pointers: list[str] = Field(default_factory=list)
    rule: str = 'CONFIGURATION_NOT_DEMONSTRATED'
    source_command_present: StrictBool | None = None
    inheritance_checked: StrictBool | None = None
    scope_complete: StrictBool | None = None
    reference_id: StrictStr | None = None
    qualification: StrictStr | None = None


class Key(ResolutionModel):
    identifier: int | None
    pointer: str
    secret_configured: bool | None
    temporal_status: Literal['INDETERMINATE'] = 'INDETERMINATE'
    accept_lifetime: str | None = None
    send_lifetime: str | None = None
    secret_origin: Literal['configured', 'removed', 'proven_absent', 'unknown'] = 'unknown'
    secret_rule: str = 'KEY_SECRET_PRESENCE_NOT_DEMONSTRATED'


class Authentication(ResolutionModel):
    enabled: Property = Field(default_factory=Property)
    mode: Property = Field(default_factory=Property)
    key_chain: Property = Field(default_factory=Property)
    key_presence: Property = Field(default_factory=Property)
    secret: Property = Field(default_factory=Property)
    inherited_from: Property = Field(default_factory=Property)
    keys: list[Key] = Field(default_factory=list)
    # Secret presence and an authentication mode never prove actual key use.
    usability: Literal['INDETERMINATE'] = 'INDETERMINATE'


class Relation(ResolutionModel):
    protocol: Literal['eigrp', 'ospf', 'rip', 'bgp']
    subject: str
    subject_kind: Literal['interface', 'neighbor', 'reference'] = 'interface'
    status: Status = 'RESOLVED'
    derivation: Literal['explicit', 'derived', 'unknown'] = 'derived'
    rule: str
    pointers: list[str] = Field(default_factory=list)
    applicability: Applicability = 'APPLICABILITY_UNKNOWN'
    area: str | None = None
    passive: Property = Field(default_factory=Property)
    enabled: Property = Field(default_factory=Property)
    authentication: Authentication = Field(default_factory=Authentication)
    send_versions: Property = Field(default_factory=Property)
    receive_versions: Property = Field(default_factory=Property)


class Scope(ResolutionModel):
    protocol: Literal['eigrp', 'ospf', 'rip', 'bgp']
    identifier: str
    pointer: str
    process_pointer: str
    status: Status = 'RESOLVED'
    rule: str = 'SCOPED_CONFIGURATION'
    applicability: Applicability = 'APPLICABILITY_UNKNOWN'
    afi: str | None = None
    safi: str | None = None
    autonomous_system: int | None = None
    network_instance: str | None = None
    vrf: Property = Field(default_factory=Property)
    version: Property = Field(default_factory=Property)
    send_versions: Property = Field(default_factory=Property)
    receive_versions: Property = Field(default_factory=Property)
    enabled: Property = Field(default_factory=Property)
    network_pointers: list[str] = Field(default_factory=list)
    area_pointers: list[str] = Field(default_factory=list)
    relations: list[Relation] = Field(default_factory=list)


class RoutingResolution(ResolutionModel):
    resolution_version: Literal['1.0.0'] = '1.0.0'
    basis: Literal['CONFIGURATION_ONLY'] = 'CONFIGURATION_ONLY'
    input_completeness: InputCompleteness = 'unknown'
    platform_family: Literal['ios', 'iosxe', 'unknown'] = 'unknown'
    scopes: list[Scope] = Field(default_factory=list)
    orphans: list[Relation] = Field(default_factory=list)
    integrity_issues: list[RoutingIntegrityIssue] = Field(default_factory=list)


def document(contract):
    # Validate external JSON before joining references; never mutate input.
    model = RouterContractV1.model_validate(contract) if isinstance(contract, dict) else contract
    if not isinstance(model, RouterContractV1):
        raise TypeError('A validated RouterContractV1 is required')
    return model.model_dump(mode='json')


def prop(value, pointer, *, origin='configured', rule='EXPLICIT_CONFIGURATION'):
    return Property(value=value, status='RESOLVED', origin=origin, pointers=[pointer], rule=rule)


def local_property(auth, path, field, setting, *, inherited=False):
    if not auth or auth.get(setting) is None:
        return Property()
    removed = auth[setting] == 'removed'
    return Property(value=None if removed else auth.get(field), status='RESOLVED',
                    origin='removed' if removed else 'inherited' if inherited else 'configured',
                    pointers=[path + '/' + setting] + ([path + '/' + field] if not removed and auth.get(field) is not None else []),
                    rule='EXPLICIT_REMOVAL' if removed else 'DOCUMENTED_PROPERTY_INHERITANCE' if inherited else 'EXPLICIT_CONFIGURATION')


def chain_auth(c, mode, chain):
    keys = []
    if chain.value is not None:
        matches = [(i, ch) for i, ch in enumerate(c['routing'].get('key_chains') or []) if ch['name'] == chain.value]
        if len(matches) != 1:
            chain = chain.model_copy(update={'status': 'UNRESOLVED_REFERENCE' if not matches else 'AMBIGUOUS', 'rule': 'KEY_CHAIN_TARGET_NOT_UNIQUE'})
        else:
            index, target = matches[0]
            path = f'/routing/key_chains/{index}'
            chain = chain.model_copy(update={'pointers': chain.pointers + [path + '/name'], 'rule': 'KEY_CHAIN_DECLARATION_RESOLVED'})
            identifiers = [k['identifier'] for k in target.get('keys') or []]
            if len(identifiers) != len(set(identifiers)):
                chain = chain.model_copy(update={'status': 'AMBIGUOUS', 'rule': 'KEY_IDENTIFIER_NOT_UNIQUE'})
            for n, key in enumerate(target.get('keys') or []):
                secret = key.get('secret_configured')
                keys.append(Key(identifier=key['identifier'], pointer=f'{path}/keys/{n}', secret_configured=secret,
                                secret_origin='configured' if secret is True else 'removed' if secret is False else 'unknown',
                                secret_rule='EXPLICIT_KEY_SECRET_PRESENCE' if secret is True else 'EXPLICIT_KEY_SECRET_REMOVAL' if secret is False else 'KEY_SECRET_PRESENCE_NOT_DEMONSTRATED',
                                accept_lifetime=(key.get('accept_lifetime') or {}).get('specification'),
                                send_lifetime=(key.get('send_lifetime') or {}).get('specification')))
    presence = prop(True, keys[0].pointer, origin='derived', rule='DECLARED_KEY_INVENTORY_NONEMPTY') if keys else Property()
    enabled = prop(True, chain.pointers[0], origin=chain.origin, rule='KEY_CHAIN_REFERENCE_ENABLES_AUTHENTICATION') if chain.status == 'RESOLVED' and chain.value is not None else Property()
    return Authentication(enabled=enabled, mode=mode, key_chain=chain, key_presence=presence, keys=keys)


def primary_addresses(interface):
    return [(i, a) for i, a in enumerate((interface.get('ipv4') or {}).get('addresses') or [])
            if a.get('secondary') is False and a.get('address') is not None]


def wildcard_match(address, network, wildcard):
    # Cisco OR comparison works for both contiguous and noncontiguous wildcards.
    wc = int(IPv4Address(wildcard))
    return int(IPv4Address(address)) | wc == int(IPv4Address(network)) | wc


def classful(address):
    first = int(str(address).split('.')[0])
    size = 8 if 1 <= first <= 126 else 16 if 128 <= first <= 191 else 24 if 192 <= first <= 223 else None
    return IPv4Network(f'{address}/{size}', strict=False) if size is not None else None


def network_match(interface, statement):
    wc = statement.get('wildcard_mask')
    major = classful(statement['address']) if wc is None else None
    return [(i, a) for i, a in primary_addresses(interface) if
            (wildcard_match(a['address'], statement['address'], wc) if wc is not None else
             major is not None and IPv4Address(a['address']) in major)]


def passive(scope, path, name):
    matches = [(i, p) for i, p in enumerate(scope.get('passive_interfaces') or []) if interface_identity(p.get('interface') if isinstance(p, dict) else p) == interface_identity(name)]
    if matches:
        i, item = matches[-1]
        return prop(item['passive'] if isinstance(item, dict) else True, f'{path}/passive_interfaces/{i}' + ('/passive' if isinstance(item, dict) else ''))
    if name in (scope.get('non_passive_interfaces') or []):
        return prop(False, f'{path}/non_passive_interfaces/{scope["non_passive_interfaces"].index(name)}')
    return prop(scope['passive_default'], path + '/passive_default', origin='inherited') if scope.get('passive_default') is not None else Property()


def interface_identity(name):
    """Cisco permits whitespace between the native type and numeric identifier.

    No abbreviation expansion or platform-specific alias is guessed.
    """
    return ''.join(name.split())


def interface_auth(c, protocol, interface, vrf, owner, owner_path):
    """Join local configuration from either canonical storage location."""
    matches = [(item.get('authentication'), f'{owner_path}/interface_settings/{i}/authentication')
               for i, item in enumerate(owner.get('interface_settings') or []) if item['interface'] == interface and item.get('authentication')]
    matches += [(item.get('authentication'), f'/routing/interface_authentication/{i}/authentication')
                for i, item in enumerate(c['routing'].get('interface_authentication') or [])
                if item['interface'] == interface and item['protocol'] == protocol and item.get('network_instance') == vrf and item.get('authentication')]
    if len(matches) > 1:
        return None, None, True
    return (*matches[0], False) if matches else (None, None, False)


def guarded(c, relation):
    relevant = [i for i in c['routing'].get('integrity_issues') or [] if i['protocol'] in (relation.protocol, 'interface', 'key_chain')]
    if relevant and relation.status == 'RESOLVED':
        return relation.model_copy(update={'status': 'NOT_SUPPORTED', 'rule': relation.rule + '; ROUTING_INTEGRITY_GAP'})
    return relation
