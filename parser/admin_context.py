"""IOS/IOS-XE AAA/SSH immediate scopes; no inferred parent associations."""
import re


def allowed(rule, node, nodes, values):
    if rule in ('services_ssh_timeout', 'services_ssh_timeout_remove'):
        return node.parent is None and (rule.endswith('_remove') or 0 <= values['seconds'] <= 120)
    if rule in ('services_ssh_version_remove', 'services_ssh_version_default'):
        return node.parent is None and (rule.endswith('_default') or values.get('version') in ('1','2'))
    root = nodes[node.root]
    direct = node.parent == root.line
    if rule in ('services_aaa_on', 'services_aaa_off'):
        return node.parent is None  # 'aaa new-model' only exists in global configuration.
    if rule in ('admin_aaa_group_member','admin_aaa_group_member_remove'):
        return direct and re.fullmatch(r'aaa group server (?:radius|tacacs\+) \S+', root.text) is not None
    if rule in ('admin_aaa_group_radius_source', 'admin_aaa_group_radius_source_remove',
                'admin_aaa_group_tacacs_source', 'admin_aaa_group_tacacs_source_remove'):
        return direct and re.fullmatch(r'aaa group server (?:radius|tacacs\+) \S+', root.text) is not None
    if rule.startswith('admin_server_key') or rule in ('services_auth_address', 'services_auth_ports'):
        if not direct or re.fullmatch(r'(?:radius|tacacs) server \S+', root.text) is None:
            return False
        radius = root.text.startswith('radius ')
        if rule == 'services_auth_ports' and not radius:
            return False  # TACACS+ has a different native port syntax.
        if radius and (values.get('credential_format') == '6' or values.get('removed')):
            return False  # Only explicitly verified RADIUS forms are accepted.
        return True
    if rule.startswith('admin_'):
        if node.parent is not None:
            return False
        if rule.startswith('admin_authentication_enable') and values.get('name') != 'default':
            return False  # IOS reference documents only the default enable list.
        if rule == 'admin_ssh_timeout' and not 0 <= values['seconds'] <= 120:
            return False
        if rule == 'admin_ssh_retries' and not 0 <= values['retries'] <= 5:
            return False
    if rule in ('services_radius', 'services_tacacs', 'services_ssh_version'):
        if node.parent is not None:
            return False
        if rule == 'services_ssh_version' and values.get('version') not in ('1','2'):
            return False
    if rule in ('services_login','services_login_plain'):
        return direct and root.text.startswith('line ')
    return True
