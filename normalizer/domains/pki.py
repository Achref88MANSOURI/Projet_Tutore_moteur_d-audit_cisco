"""PKI metadata and references; certificate bodies are never normalized."""
from normalizer.common.collections import collection
from schemas import router_contract_v1 as s


def handle(state,r):
    root = state.root(r)
    rule = r['rule']
    v = r['values']
    line = r['source_line']
    if root is None:
        return
    pki = state.c.pki
    if root['rule'] == 'advanced_pki_trust':
        name = root['values']['name']
        obj = next((t for t in (pki.trustpoints or []) if t.name == name), None)
        if obj is None:
            obj = s.Trustpoint(name=name)
            collection(pki, 'trustpoints').append(obj)
        path = f'pki/trustpoints/{(pki.trustpoints or []).index(obj)}'
        if rule == 'advanced_pki_trust':
            state.bind(path, line, list(v))
            return
        field = {'advanced_pki_enrollment': ('enrollment', 'method'), 'advanced_pki_revocation': ('revocation_check', 'method'), 'advanced_pki_subject': ('subject_name', 'subject'), 'advanced_pki_keypair': ('keypair_reference', 'name')}.get(rule)
        if field:
            state.assign(obj, field[0], v[field[1]], path, line, list(v))
    elif root['rule'] == 'advanced_pki_chain':
        name = root['values']['name']
        obj = next((c for c in (pki.certificate_chains or []) if c.name == name), None)
        if obj is None:
            obj = s.CertificateChain(name=name)
            collection(pki, 'certificate_chains').append(obj)
        path = f'pki/certificate_chains/{(pki.certificate_chains or []).index(obj)}'
        if rule == 'advanced_pki_chain':
            state.bind(path, line, list(v))
        elif rule == 'advanced_pki_certificate':
            collection(obj, 'certificates').append(s.Certificate(type=v['type'], identifier=v['identifier']))
            state.bind(path + '/certificates', line, list(v))

