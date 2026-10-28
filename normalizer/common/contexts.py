"""Structural context access; domains never reparse the input configuration."""


def root(state, record):
    return state.records.get(record['root_line'])


def address_family(state, record):
    for line in reversed(record['context_lines']):
        parent = state.records.get(line, {})
        if parent.get('rule', '').startswith('bgp_af') and 'afi' in parent['values']:
            return parent['values']
    return None


def at(document, path):
    value = document
    for token in path.strip('/').split('/') if path.strip('/') else []:
        token = token.replace('~1', '/').replace('~0', '~')
        if isinstance(value, list):
            value = value[int(token)]
        elif isinstance(value, dict):
            value = value[token]
        else:
            value = getattr(value, token)
    return value


def child(path, key):
    return path + '/' + str(key).replace('~', '~0').replace('/', '~1')
