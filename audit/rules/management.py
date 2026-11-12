"""AAA-01 and SSH-01: explicit comparisons, never bool(unknown)."""
from ..models import AuditStatus as S


def aaa01(enabled):
    if enabled is True:
        return S.PASS
    if enabled is False:
        return S.FAIL
    return S.NEEDS_REVIEW


def ssh01(version):
    if version == 2:
        return S.PASS
    if version == 1:
        return S.FAIL
    return S.NEEDS_REVIEW
