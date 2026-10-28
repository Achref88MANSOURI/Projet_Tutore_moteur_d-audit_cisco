"""Reject explicit non-IOS router exports without scanning opaque hex as hardware IDs."""
import re


def unsupported_platform(text):
    if re.search(r'!!\s*IOS XR|IOS XR Configuration|^!! Last configuration|^vrf (?!definition\b)\S+|^router static\s*$|^ssh server v2\s*$|^ +ipv4 (?:address|unnumbered|point-to-point)\b',text,re.M|re.I):return 'iosxr'
    if re.search(r'^ASA Version|^!Command:|^feature \S+|^boot nxos',text,re.M):return 'asa_or_nxos'
    if re.search(r'^(?:license udi pid (?:WS-C\S+|C9[0-9]{3}\S*)|boot system .*?(?:vios_l2|cat[239][0-9]{3}))',text,re.M|re.I):return 'switch_platform'
    return None
