"""Source locations and CLI block boundaries, independently of field extraction.

PKI bytes and banner bodies are opaque blocks. In particular quit closes a
certificate; it is never attached to the last line of hex data.
"""
from dataclasses import dataclass, field
import hashlib
import re


def redacted(text):
    if text.startswith(('ip community-list ', 'ip bgp-community ', 'service password-encryption', 'no service password-encryption')) or re.match(r'(?:no )?neighbor \S+ send-community', text):
        return text
    if re.search(r'(?i)\b(?:secret|password|pre-shared-key|key-string|server-key|key)\b|^snmp-server (?:community|host|user)\b', text):
        return '[REDACTED credential-bearing command]'
    return text


@dataclass
class Node:
    line: int
    text: str
    indent: int
    parent: int | None
    root: int
    family: str
    kind: str = 'command'
    end_line: int | None = None
    children: list[int] = field(default_factory=list)
    opaque_sha256: str | None = None

    def public(self):
        return {**self.__dict__, 'text': redacted(self.text)}


def root_family(text):
    if text.startswith('interface '): return 'interfaces'
    if text.startswith('router bgp '): return 'bgp'
    if text.startswith(('router ospf ', 'ipv6 router ospf ')): return 'ospf'
    if text.startswith(('vrf definition ', 'ip vrf ')): return 'vrf'
    if text.startswith('ip access-list standard '): return 'acl_standard'
    if text.startswith(('ip access-list extended ', 'ipv6 access-list ')): return 'acl_extended'
    if text.startswith('access-list '):
        try:
            number = int(text.split()[1])
            return 'acl_standard' if 1 <= number <= 99 or 1300 <= number <= 1999 else 'acl_extended'
        except ValueError: return 'other'
    if text.startswith('route-map '): return 'policies'
    if text.startswith(('ip prefix-list ', 'ipv6 prefix-list ')): return 'prefix'
    if text.startswith(('ip route ', 'ipv6 route ')): return 'routes'
    if text.startswith(('router isis ', 'class-map ', 'policy-map ', 'mpls ', 'l2vpn ', 'l2 vfi ', 'bridge-domain ', 'crypto pki ', 'vlan ', 'ip pim ', 'ip multicast')): return 'advanced'
    return 'services'


def inventory(text):
    lines = text.splitlines()
    nodes, stack = {}, []
    i = 0
    while i < len(lines):
        raw = lines[i]
        i += 1
        value = raw.strip()
        if not value or value.startswith('!'):
            continue
        indent = len(raw) - len(raw.lstrip())
        if value == 'end':
            nodes[i] = Node(i, value, indent, None, i, 'other', 'footer')
            stack.clear()
            continue
        if value == 'quit':
            # Find the open certificate before normal indentation popping: quit
            # can be printed at the same indentation as the certificate header.
            while stack and not nodes[stack[-1]].text.startswith('certificate '):
                stack.pop()
        else:
            while stack and indent <= nodes[stack[-1]].indent:
                stack.pop()
        parent = stack[-1] if stack else None
        root = nodes[parent].root if parent else i
        family = nodes[parent].family if parent else root_family(value)
        kind = 'boundary' if value in ('quit', 'exit-address-family', 'exit') else 'command'
        if value.startswith(('Building configuration', 'Current configuration')):
            kind = 'wrapper'
        node = Node(i, value, indent, parent, root, family, kind)
        nodes[i] = node
        if parent:
            nodes[parent].children.append(i)
        if value.startswith('banner '):
            parts = value.split(maxsplit=2)
            if len(parts) == 3:
                delimiter = '^C' if parts[2].startswith('^C') else parts[2][:1]
                remainder = parts[2][len(delimiter):]
                start = i + 1
                body = []
                if delimiter not in remainder:
                    while i < len(lines):
                        body.append(lines[i])
                        i += 1
                        if delimiter in lines[i - 1]:
                            break
                    if body:
                        blob = Node(start, '<opaque banner body>', indent + 1, node.line, root, family,
                                    'opaque_banner', i, opaque_sha256=hashlib.sha256('\n'.join(body).encode()).hexdigest())
                        nodes[start] = blob
                        node.children.append(start)
            continue
        if value.startswith('certificate ') and family == 'advanced':
            body, start = [], i + 1
            while i < len(lines) and re.fullmatch(r'[0-9A-Fa-f\s]+', lines[i]) and lines[i].strip():
                body.append(lines[i])
                i += 1
            if body:
                blob = Node(start, '<opaque certificate data>', indent + 1, node.line, root, family,
                            'opaque_pki', i, opaque_sha256=hashlib.sha256('\n'.join(body).encode()).hexdigest())
                nodes[start] = blob
                node.children.append(start)
        if kind != 'boundary':
            stack.append(node.line)
        elif value=='quit' and stack:
            stack.pop()
    return nodes


def ancestors(node, nodes):
    result = []
    current = node.parent
    while current is not None:
        result.append(nodes[current])
        current = nodes[current].parent
    return list(reversed(result))
