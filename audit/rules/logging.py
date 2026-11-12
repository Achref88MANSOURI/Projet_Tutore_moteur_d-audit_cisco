"""LOG-01: declared destinations only, without parsing or source authentication."""
from ipaddress import ip_address
import re

from ..models import AuditStatus as S


def _remote_address(address):
    """An interpretable target, not a claim about DNS, topology or reachability."""
    if address != address.strip() or '%' in address:
        return False
    try:
        target = ip_address(address)
    except ValueError:
        name = address.lower().removesuffix('.')
        if (not name or len(name) > 253 or name == 'localhost' or name.endswith('.localhost')
                or re.fullmatch(r'[0-9.]+', name)):
            return False
        return all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                   for label in name.split('.'))
    target = getattr(target, 'ipv4_mapped', None) or target
    return not (target.is_loopback or target.is_unspecified or target.is_multicast
                or str(target) == '255.255.255.255')


def log01(destinations):
    """Return status and an original collection index for minimal address proof.

    V1 carries no verifiable collection completeness proof. Even [] therefore
    requires review; LOG-01 cannot establish an absence FAIL through this API.
    Omitted port/transport do not negate an otherwise declared destination.
    Explicit transport='unknown' is conservatively left for manual review.
    """
    for index, destination in enumerate(destinations or []):
        if destination.transport != 'unknown' and _remote_address(destination.address):
            return S.PASS, index
    return S.NEEDS_REVIEW, None
