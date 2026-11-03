"""Validation of the single business contract for Python consumers."""
from jsonschema import Draft202012Validator, FormatChecker
from schemas.router_contract_v1 import RouterContractV1, router_contract_v1_schema


def boolean(value):
    """Accept a captured boolean, never infer one from a nonempty string."""
    if type(value) is not bool:
        raise ValueError('Configured flag must be a boolean')
    return value


def validate(document):
    model = RouterContractV1.model_validate(document)
    Draft202012Validator(router_contract_v1_schema(), format_checker=FormatChecker()).validate(
        model.model_dump(mode='json'))
    return model


class IncompleteReferenceError(ValueError):
    """A known source definition was removed, but its reference would survive."""


def validate_preserved_references(original, published):
    """Do not turn a suppressed definition into an apparently external reference.

    Literal references absent from the supplied configuration remain legitimate.
    This gate applies only to definitions that existed before publication.
    Messages deliberately omit configuration values and object names.
    """
    def names(document, section, field):
        return {row['name'] for row in document[section].get(field) or []}

    groups = {'route map': ('routing_policies', 'route_maps'),
        'ACL': ('security', 'acls'), 'prefix list': ('routing_policies', 'prefix_lists'),
        'community list': ('routing_policies', 'community_lists'),
        'class map': ('qos', 'class_maps'), 'policy map': ('qos', 'policy_maps')}
    removed = {kind: names(original, *location) - names(published, *location)
               for kind, location in groups.items()}

    def check(kind, references):
        if any(name in removed[kind] for name in references or []):
            raise IncompleteReferenceError(f'A referenced {kind} definition was removed as incomplete; export refused')

    for process in published['routing'].get('bgp') or []:
        peers = (process.get('neighbors') or []) + (process.get('peer_groups') or [])
        for family in process.get('address_families') or []:
            peers += family.get('peers') or []
        for peer in peers:
            check('route map', peer.get('import_policies'))
            check('route map', peer.get('export_policies'))
    def routing_references(value):
        if isinstance(value, list):
            for item in value:
                routing_references(item)
        elif isinstance(value, dict):
            if value.get('local_setting') == 'removed':
                return
            for key in ('route_map', 'leak_map'):
                check('route map', [value.get(key)])
            if 'reference' in value:
                kind = {'acl': 'ACL', 'prefix_list': 'prefix list', 'route_map': 'route map'}.get(value.get('kind'))
                if kind:
                    check(kind, [value['reference']])
            for item in value.values():
                if isinstance(item, (dict, list)):
                    routing_references(item)
    routing_references(published['routing'])
    match_kinds = {'acl': 'ACL', 'community': 'community list',
        'prefix_set_ipv4': 'prefix list', 'prefix_set_ipv6': 'prefix list'}
    for policy in published['routing_policies'].get('route_maps') or []:
        for statement in policy.get('statements') or []:
            for match in statement.get('matches') or []:
                if match['kind'] in match_kinds:
                    check(match_kinds[match['kind']], [match['name']])
    for attachment in published['security'].get('acl_attachments') or []:
        check('ACL', [attachment['acl_name']])
    management = published['system'].get('management') or {}
    for line in management.get('lines') or []:
        check('ACL', [line.get('access_list')])
    for community in (published['system'].get('snmp') or {}).get('communities') or []:
        check('ACL', [community.get('access_list')])
    for class_map in published['qos'].get('class_maps') or []:
        for match in class_map.get('matches') or []:
            if match['kind'] == 'acl':
                check('ACL', [match['value']])
    for policy in published['qos'].get('policy_maps') or []:
        check('class map', [c['name'] for c in policy.get('classes') or []])
    for attachment in published['qos'].get('attachments') or []:
        check('policy map', [attachment['policy_name']])
