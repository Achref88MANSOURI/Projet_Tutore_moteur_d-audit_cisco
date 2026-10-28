"""PKI metadata and references; certificate bodies are never normalized."""
from schemas import normalized_config as s


def handle(state,r):
    root = state.root(r)
    rule = r['rule']
    v = r['values']
    line = r['source_line']
    if root is None:
        return
    pki = state.c.cisco.pki
    if root['rule'] == 'advanced_pki_trust':
        name = root['values']['name']
        obj = next((t for t in pki.trustpoints if t.name == name), None)
        if obj is None:
            obj = s.Trustpoint(name=name)
            pki.trustpoints.append(obj)
        path = f'cisco/pki/trustpoints/{pki.trustpoints.index(obj)}'
        if rule == 'advanced_pki_trust':
            state.bind(path, line, list(v))
            return
        field = {'advanced_pki_enrollment': ('enrollment', 'method'), 'advanced_pki_revocation': ('revocation_check', 'method'), 'advanced_pki_subject': ('subject_name', 'subject'), 'advanced_pki_keypair': ('keypair_reference', 'name')}.get(rule)
        if field:
            state.assign(obj, field[0], v[field[1]], path, line, list(v))
    elif root['rule'] == 'advanced_pki_chain':
        name = root['values']['name']
        obj = next((c for c in pki.chains if c.name == name), None)
        if obj is None:
            obj = s.CertificateChain(name=name)
            pki.chains.append(obj)
        path = f'cisco/pki/chains/{pki.chains.index(obj)}'
        if rule == 'advanced_pki_chain':
            state.bind(path, line, list(v))
        elif rule == 'advanced_pki_certificate':
            obj.certificates.append(s.Certificate(type=v['type'], identifier=v['identifier']))
            state.bind(path + '/certificates', line, list(v))

