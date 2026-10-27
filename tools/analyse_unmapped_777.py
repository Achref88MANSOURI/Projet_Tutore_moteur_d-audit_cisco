r"""Read-only diagnosis of the frozen 777 extracted-but-unmapped occurrences.

Writes only outputs/analysis_777. Does not execute or change the conversion pipeline.
Run from the project: .\.venv\Scripts\python.exe tools/analyse_unmapped_777.py
"""
from __future__ import annotations

import ast
from collections import Counter, defaultdict
import copy
import csv
import hashlib
import html
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from jsonschema import Draft202012Validator
from parser.inventory import redacted
from schemas.normalizedconfig import NormalizedConfig

OUT = ROOT / 'outputs/analysis_777'
CAUSES = {
    'A_mapping_v01': 'Mapping direct possible dans v0.1',
    'B_resolution_v01': 'Mapping possible après résolution d’une référence',
    'C_convention': 'Convention sémantique à préciser',
    'D_capture_contexte': 'Capture trop générale / mauvais concept',
    'E_structure': 'Structure de contexte insuffisante dans v0.1',
    'F_champ': 'Propriété ou modèle métier absent de v0.1',
}

# A diagnostic catalogue, NOT parser rules or an updated contract. Proposed fields
# are descriptive design targets only and are never injected into NormalizedConfig.
CATALOG = {}


def group(rules, family, explanation, target, model, priority='P2'):
    for rule in rules.split():
        assert rule not in CATALOG, rule
        CATALOG[rule] = dict(functional_family=family, explanation=explanation,
                             target=target, model=model, priority=priority)


group('if_speed if_duplex if_negotiation if_media', 'Ethernet / paramètres physiques',
      'Interface ne possède ni vitesse, ni duplex, ni négociation, ni type de média. Conserver auto séparément d’une valeur numérique et définir les unités.',
      'Extension proposée : Interface.ethernet (speed, duplex, negotiation, media)', 'Interface', 'P1')
group('if_no_ipv4', 'Adressage / comportement IP',
      'La branche interface ignore cette règle. Une liste ipv4_addresses vide avec preuve explicit peut représenter l’absence explicite d’adresse configurée directement. Cela ne signifie pas IPv4 désactivé, notamment avec ip unnumbered.',
      '/configuration/interfaces/{i}/ipv4_addresses = [] + Evidence explicit', 'Interface', 'P0')
group('if_ipv6_enable if_proxyarp if_unnumbered if_mss if_redirects if_keepalive_off', 'Adressage / comportement IP',
      'Les paramètres d’activation IPv6, de prêt d’adresse, proxy ARP, MSS, redirects et keepalive ne sont pas des adresses statiques ni un état administratif. Aucun champ dédié ne conserve leur sens.',
      'Extension proposée : paramètres IP et keepalive d’Interface', 'Interface')
group('if_dot1q', 'VLAN / encapsulation',
      'Le tag 802.1Q d’une sous-interface n’est pas son subinterface_index et n’est pas un access_vlan. Ne pas déduire l’encapsulation du suffixe du nom.',
      'Extension proposée : Interface.encapsulation.dot1q_vlan', 'Interface', 'P1')
group('if_dot1q_lower', 'L2VPN / EVPN / services Ethernet',
      'Encapsulation d’un service instance imbriqué. Le contrat ne possède pas d’objet service Ethernet ; ne pas affecter ce tag à l’interface physique.',
      'Extension proposée : EthernetService.encapsulation', 'Interface', 'P1')
group('if_flow', 'Télémétrie / NetFlow',
      'L’attachement d’un moniteur de flux n’est pas représenté dans le contrat.',
      'Extension proposée : flow_monitors et attachements par interface/direction', 'Interface')
group('if_mpls advanced_mpls_label advanced_mpls_ldp', 'MPLS / LDP',
      'Activation MPLS, protocole de labels et router-id LDP n’ont pas de modèle dans v0.1.',
      'Extension proposée : MPLS, LDP et activation par interface', 'Configuration')
group('if_isis if_isis_network advanced_isis advanced_isis_net advanced_isis_passive', 'IS-IS',
      'Les processus, NET, interfaces et paramètres IS-IS sont extraits, mais aucun modèle IS-IS n’existe dans Routing.',
      'Extension proposée : Routing.isis et associations aux interfaces', 'Routing')
group('if_pim advanced_multicast advanced_pim_rp', 'Multicast / PIM',
      'Activation multicast, mode PIM d’interface et rendezvous-point nécessitent un modèle multicast distinct.',
      'Extension proposée : multicast/PIM global et par interface', 'Configuration')
group('if_tunnel_source', 'Tunnels',
      'La source est Loopback0, une référence d’interface. La résoudre vers une adresse explicite unique avec deux preuves est possible ; conserver la référence native. Ne pas inventer un mode GRE.',
      '/configuration/vpn_tunnels/{i}/local_endpoint après résolution + preuves source et adresse', 'VPNTunnel', 'P0')
group('if_tunnel_destination', 'Tunnels',
      'La branche interface abandonne ce mapping faute de mode explicite. Pourtant VPNTunnel autorise technology=unknown : la destination peut être conservée avec son interface Tunnel0 sans deviner la technologie.',
      '/configuration/vpn_tunnels/{i}/remote_endpoint ; technology=unknown', 'VPNTunnel', 'P0')
group('bgp_activate bgp_deactivate', 'BGP : familles et groupes',
      'activate/no activate porte sur une famille d’adresses d’un voisin ou groupe. BGPNeighbor.enabled ne possède pas cette portée et ne doit pas servir de remplacement.',
      'Extension proposée : voisin/groupe → address_families → enabled', 'BGPNeighbor', 'P1')
group('bgp_route_map', 'BGP : familles et groupes',
      'Le mapper refuse la portée address-family et les groupes nommés. Les import_policies/export_policies globaux d’un voisin ne conservent pas cette portée ni l’héritage de groupe.',
      'Extension proposée : politiques par famille, sur voisin ou groupe typé', 'BGPNeighbor', 'P1')
group('bgp_remote_as', 'BGP : familles et groupes',
      'Ces trois remote-as concernent des groupes nommés, sans membre explicite exploitable par l’héritage actuel. peer_groups ne stocke que des noms. Créer un faux voisin as3/as1 ferait perdre la distinction groupe/voisin.',
      'Extension proposée : BGPProcess.peer_groups structurés avec remote_as', 'BGPProcess', 'P1')
group('bgp_update_source bgp_send_community bgp_send_community_option bgp_reflector bgp_next_hop', 'BGP : paramètres de session',
      'Source de session, communautés envoyées, route-reflector et next-hop-self n’ont pas de champs dédiés. Leur portée et leur héritage doivent aussi être conservés.',
      'Extension proposée : paramètres de session et propriétés par AF du voisin/groupe', 'BGPNeighbor', 'P1')
group('bgp_network4 bgp_network bgp_redistribute_process bgp_aggregate', 'BGP : annonces et redistribution',
      'BGPProcess ne décrit pas les annonces network, agrégations ou redistributions. Une route statique ou une simple routing_policy ne représente pas leur activation dans BGP.',
      'Extension proposée : BGP AF networks, aggregates et redistribution', 'BGPProcess', 'P1')
group('bgp_log_changes bgp_dampening bgp_additional_select bgp_additional_send bgp_maximum_paths', 'BGP : paramètres du processus',
      'Journalisation des voisins, amortissement, additional-paths et maximum-paths ne sont pas modélisés.',
      'Extension proposée : options BGP du processus et de ses AF', 'BGPProcess')
group('if_ospf3 ospf3_header ospf_router_id ospf_area ospf_virtual_link ospf_log ospf_default ospf_redistribute ospf_redistribute_simple if_ospf_network', 'OSPF',
      'OSPFProcess ne distingue pas OSPFv2/v3. Les options de zone, virtual-link, type de réseau, redistribution et injection de défaut n’ont pas de champs adaptés. Les router-id v3 restent natifs pour éviter une fusion avec v2.',
      'Extension proposée : version OSPF, processus/AF, zones typées et options de redistribution', 'OSPFProcess', 'P1')
group('advanced_pki_trust advanced_pki_enrollment advanced_pki_revocation advanced_pki_chain advanced_pki_certificate advanced_pki_subject advanced_pki_keypair', 'PKI / certificats',
      'Les déclarations de trustpoint, méthode d’enrôlement, révocation et métadonnées de certificat n’ont pas de modèle PKI. Les corps de certificats opaques sont hors des 777.',
      'Extension proposée : security.pki (trustpoints, enrollment, revocation, références de certificats/clefs)', 'Security')
group('advanced_qos_classmap advanced_qos_class advanced_qos_match_dscp advanced_qos_set_dscp advanced_qos_match_protocol advanced_qos_set_precedence advanced_qos_match_acl advanced_qos_match_precedence advanced_qos_priority advanced_qos_fair', 'QoS : classes et actions',
      'QoS ne stocke que les noms de policies et leurs attachements. Classifiers, matches, marquage, priorité et fair-queue ne peuvent pas être réduits à ces noms.',
      'Extension proposée : QoS.class_maps, classes, matches et actions ordonnées', 'QoS', 'P1')
group('advanced_l2_member advanced_l2_bridge advanced_l2_neighbor advanced_l2_evpn_global advanced_l2_replication advanced_l2_rid advanced_l2_evpn advanced_l2_vfi advanced_l2_vpnid', 'L2VPN / EVPN / services Ethernet',
      'Bridge-domains, VFI, pseudowires, EVI et réplication EVPN dépassent les seuls VLAN/LAG de Layer2. member reste en plus une capture texte composite à typer.',
      'Extension proposée : bridge_domains, Ethernet services, pseudowires et EVPN', 'Layer2', 'P1')
group('vrf_description', 'VRF : métadonnées',
      'NetworkInstance possède name, kind, RD, RT et interfaces, mais aucun champ description.',
      'Extension proposée : NetworkInstance.description', 'NetworkInstance', 'P2')
group('services_logging_source', 'Gestion / journalisation / bannières',
      'SyslogDestination ne conserve pas l’interface source ; ne pas confondre avec l’adresse de destination.',
      'Extension proposée : syslog source_interface, avec portée globale/VRF explicite', 'SyslogDestination')
group('services_banner', 'Gestion / journalisation / bannières',
      'Les quatre en-têtes restants sont des bannières exec/incoming. login_banner_present ne représente pas ces types. Leur contenu opaque est compté ailleurs.',
      'Extension proposée : bannières typées, présence et empreinte sans exposer le contenu', 'System')
group('services_transport', 'Gestion / journalisation / bannières',
      'transport input all est refusé par la liste blanche du mapper. Le schéma list[str] accepte all, mais son sens canonique doit être défini. Ne pas développer arbitrairement all en ssh+telnet.',
      '/configuration/system/management/lines/{i}/allowed_transports : définir la convention all', 'ManagementLine', 'P0')
group('services_login', 'Gestion / journalisation / bannières',
      'Ces six lignes globales login on-success log sont capturées par le motif générique login method. Elles règlent un événement de journalisation, pas l’authentification d’une ligne VTY. Le garde de contexte empêche le mauvais mapping.',
      'Règle TTP dédiée au login logging global ; champ futur management.login_logging', 'Management', 'P0')


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def dump(name, value):
    (OUT / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def frozen_inputs():
    paths = []
    for folder in ('parser', 'normalizer', 'schemas', 'templates', 'configs', 'baseline', 'tests', 'outputs/corpus_20', 'outputs/pilot_5'):
        paths.extend(p for p in (ROOT / folder).rglob('*') if p.is_file() and '__pycache__' not in p.parts)
    paths.extend(p for p in ROOT.glob('*.py'))
    paths.extend(p for p in (ROOT / 'outputs').glob('*') if p.is_file())
    return {p.relative_to(ROOT).as_posix(): digest(p) for p in sorted(set(paths))}


def source_refs():
    result = {}
    for file in ('normalizer/mapping.py', 'schemas/normalizedconfig.py'):
        tree = ast.parse((ROOT / file).read_text(encoding='utf-8'))
        for node in ast.walk(tree):
            if isinstance(node, (ast.ClassDef, ast.FunctionDef)):
                result[node.name] = f'{file}:{node.lineno}'
    return result


def classify(rule, record, context):
    if rule in ('if_no_ipv4', 'if_tunnel_destination'): return 'A_mapping_v01'
    if rule == 'if_tunnel_source': return 'B_resolution_v01'
    if rule == 'services_transport': return 'C_convention'
    if rule == 'services_login': return 'D_capture_contexte'
    if rule.startswith('prefix_') or rule in ('bgp_activate', 'bgp_deactivate', 'bgp_route_map', 'bgp_remote_as', 'if_ospf3', 'ospf3_header'):
        return 'E_structure'
    if any(c['text'].startswith(('ipv6 router ospf ', 'router ospfv3 ')) for c in context):
        return 'E_structure'
    return 'F_champ'


def prefix_info(records):
    groups = defaultdict(list)
    for r in records.values():
        if r['family'] == 'prefix':
            groups[(r['rule'].startswith('prefix_ipv6'), r['values']['name'])].append(r)
    return groups


def build_rows():
    rules = {r['id']: r for r in read(ROOT / 'templates/rules.json')}
    refs = source_refs()
    manifest = {m['id']: m for m in read(ROOT / 'configs/manifest.json')}
    rows, docs, file_data = [], {}, {}
    for file_id in sorted(manifest):
        folder = ROOT / 'outputs/corpus_20' / file_id
        native = read(folder / 'parsed_native.json')
        coverage = read(folder / 'coverage_report.json')
        docs[file_id] = read(folder / 'normalized_config.json')
        unknown = {r['line_start']: r for r in docs[file_id]['parsing']['unknown_commands']}
        records = {r['source_line']: r for r in native['records']}
        nodes = {r['line']: r for r in native['source_inventory']}
        source = ROOT / manifest[file_id]['config_file']
        lines = source.read_text(encoding='utf-8-sig').splitlines()
        pref_groups = prefix_info(records)
        file_data[file_id] = dict(records=records, nodes=nodes, lines=lines)
        for command in coverage['commands']:
            if command['status'] != 'extracted_unmapped': continue
            line = command['line']
            record = records[line]
            rule = record['rule']
            assert command['template_rule'] == rule
            assert not command['normalized_paths'], (file_id, line)
            assert unknown[line]['raw_text'] == command['text'], (file_id, line)
            assert nodes[line]['text'] == command['text'] == redacted(lines[line-1].strip()), (file_id, line)
            # Check the entire lexical ancestor chain, not just that a root exists.
            ancestors, parent = [], nodes[line]['parent']
            while parent is not None:
                ancestors.append(parent)
                parent = nodes[parent]['parent']
            assert list(reversed(ancestors)) == record['context_lines']
            assert record['root_line'] in nodes
            context = [nodes[n] for n in record['context_lines']]
            assert rule in CATALOG or rule.startswith('prefix_'), rule
            if rule.startswith('prefix_'):
                detail = dict(functional_family='Filtrage : prefix-lists', priority='P1', model='PrefixSet',
                    explanation='PrefixSet ne décrit qu’une liste de préfixes. Action deny, séquence et longueurs ge/le exigent des entrées de filtre ordonnées. Le mapper écarte toute la liste si une entrée est complexe.',
                    target='Extension proposée : PrefixListEntry(sequence, action, prefix, ge, le), distinct de PrefixSet')
            else: detail = CATALOG[rule].copy()
            if rule.startswith('prefix_'):
                members = pref_groups[(rule.startswith('prefix_ipv6'), record['values']['name'])]
                detail['explanation'] += f' Liste {record["values"]["name"]} : {len(members)} entrée(s) capturée(s).'
            af = [n['text'] for n in context if n['text'].startswith('address-family ')]
            flags = []
            if not record['values']: flags.append('values_vide')
            constants = re.findall(r'{{\s*(\w+)\s*\|\s*set\((True|False)\)', rules[rule]['pattern'])
            missing_constants = [name for name, value in constants if name not in record['values']]
            if missing_constants: flags.append('constante_set_non_exportee:' + ','.join(missing_constants))
            if rule == 'advanced_l2_member': flags.append('capture_composite_a_typer')
            if rule == 'services_login': flags.append('concept_login_global_mal_classe')
            if af: flags.append('portee_address_family')
            handler = ('interface' if record['family'] == 'interfaces' else
                       'routing_bgp' if record['family'] == 'bgp' else
                       'routing_ospf' if record['family'] == 'ospf' else
                       'finish_links' if record['family'] == 'prefix' else
                       'vrf' if record['family'] == 'vrf' else
                       'services' if record['family'] == 'services' else 'run')
            cause = classify(rule, record, context)
            row = dict(file_id=file_id, config_file=manifest[file_id]['config_file'], hostname=manifest[file_id]['hostname_description'],
                line=line, line_end=command['line_end'], command=command['text'], rule=rule,
                native_values=record['values'], root_line=record['root_line'],
                root=nodes[record['root_line']]['text'], context=[dict(line=n['line'], text=n['text']) for n in context],
                address_family=af[-1] if af else None, tree_verified=True, ttp_pattern=rules[rule]['pattern'],
                cause=cause, cause_label=CAUSES[cause], quality_flags=flags,
                mapper_reference=refs[handler], contract_reference=refs[detail['model']], **detail)
            rows.append(row)
    assert len(rows) == 777
    assert len({r['rule'] for r in rows}) == 90
    assert len({(r['file_id'], r['line']) for r in rows}) == 777
    return rows, docs, file_data, manifest


def probe_candidates(rows, docs, file_data):
    """Validate isolated in-memory proposals, never write converted configs."""
    schema = Draft202012Validator(read(ROOT / 'schemas/normalizedconfig_v0_1.schema.json'))
    probes = []
    for row in rows:
        rule = row['rule']
        if row['cause'] not in ('A_mapping_v01', 'B_resolution_v01', 'C_convention'): continue
        doc = copy.deepcopy(docs[row['file_id']])
        data = file_data[row['file_id']]
        evidence = dict(status='explicit', source_file=doc['metadata']['source_file'],
                        line_start=row['line'], line_end=row['line'], raw_command=row['command'],
                        parser_rule='analysis-only:' + rule, confidence=1)
        if rule == 'if_no_ipv4':
            name = data['records'][row['root_line']]['values']['name']
            index = next(i for i, x in enumerate(doc['configuration']['interfaces']) if x['name'] == name)
            assert doc['configuration']['interfaces'][index]['ipv4_addresses'] == [], (row['file_id'], row['line'])
            path = f'/configuration/interfaces/{index}/ipv4_addresses'
            doc['configuration']['interfaces'][index]['ipv4_addresses'] = []
            proposal, explanation = [], 'Liste vide explicitement prouvée ; aucun booléen IPv4 désactivé déduit.'
        elif rule in ('if_tunnel_source', 'if_tunnel_destination'):
            name = data['records'][row['root_line']]['values']['name']
            tunnel = dict(identifier=name, tunnel_interface=name, technology='unknown')
            index = len(doc['configuration']['vpn_tunnels'])
            if rule == 'if_tunnel_destination':
                field, proposal = 'remote_endpoint', row['native_values']['destination']
                explanation = 'Technologie unknown conservée ; aucun mode de tunnel deviné.'
            else:
                field = 'local_endpoint'
                source = row['native_values']['source']
                interface = next(x for x in doc['configuration']['interfaces'] if x['name'] == source)
                assert len(interface['ipv4_addresses']) == 1, 'Resolution must be unique'
                assert interface['ipv4_addresses'][0]['secondary'] is not True
                proposal = interface['ipv4_addresses'][0]['address']
                source_record = next(r for r in data['records'].values() if r['rule'] in ('if_ipv4', 'if_ipv4_secondary')
                    and r['values']['address'] == proposal and data['nodes'][r['root_line']]['text'] == 'interface ' + source)
                proof = dict(evidence, path=f'/configuration/vpn_tunnels/{index}/local_endpoint',
                             line_start=source_record['source_line'], line_end=source_record['source_line'],
                             raw_command=data['nodes'][source_record['source_line']]['text'])
                doc['evidence'].append(proof)
                explanation = f'Résolution conditionnelle {source} → {proposal}, avec preuve de référence et d’adresse. Adresse dynamique future non résolue par cette proposition.'
            tunnel[field] = proposal
            doc['configuration']['vpn_tunnels'].append(tunnel)
            path = f'/configuration/vpn_tunnels/{index}/{field}'
        else:
            assert row['native_values']['transports'] == 'all'
            name = data['nodes'][row['root_line']]['text'][5:]
            index = next(i for i, x in enumerate(doc['configuration']['system']['management']['lines']) if x['name'] == name)
            path = f'/configuration/system/management/lines/{index}/allowed_transports'
            doc['configuration']['system']['management']['lines'][index]['allowed_transports'] = ['all']
            proposal, explanation = ['all'], 'Acceptation de type uniquement. Ne valide pas une convention sémantique du mot all.'
        doc['evidence'].append(dict(evidence, path=path))
        # Input labels/coverage deliberately stay unchanged: this is a proposal,
        # not a newly converted configuration or a coverage improvement.
        NormalizedConfig.model_validate(doc)
        schema.validate(doc)
        probes.append(dict(file_id=row['file_id'], line=row['line'], rule=rule, path=path,
                           value=proposal, pydantic_valid=True, jsonschema_valid=True,
                           semantic_status='convention_required' if rule == 'services_transport' else
                           'conditional_resolution' if rule == 'if_tunnel_source' else 'direct_candidate',
                           explanation=explanation))
    assert len(probes) == 34
    return probes


def aggregate(rows, key):
    result = []
    for value, count in Counter(r[key] for r in rows).most_common():
        selected = [r for r in rows if r[key] == value]
        result.append(dict(name=value, count=count, files=len({r['file_id'] for r in selected}),
                           rules=len({r['rule'] for r in selected}), causes=dict(Counter(r['cause'] for r in selected))))
    return result


def write_csv(name, rows):
    if not rows: return
    with (OUT / name).open('w', encoding='utf-8-sig', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows({k: json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else v for k, v in row.items()} for row in rows)


def md(value):
    return str(value).replace('|', '\\|').replace('\n', ' ')


def table(headers, rows):
    return '\n'.join(['| ' + ' | '.join(headers) + ' |', '| ' + ' | '.join('---' for _ in headers) + ' |'] +
                     ['| ' + ' | '.join(md(v) for v in row) + ' |' for row in rows])


def reports(rows, stats, probes, manifest):
    parts = [
        '# Analyse des 777 occurrences extraites mais non mappées\n',
        '**Résultat : 30 occurrences ont un mapping direct possible dans le contrat v0.1 actuel. Une source de tunnel peut aussi être résolue sous condition. Les autres nécessitent une convention, une correction de classification ou un modèle plus riche. Aucun mapping n’a été appliqué par cet audit.**\n',
        '## Ce que compte le nombre 777\n',
        'Il s’agit de **777 occurrences de commandes**, dans **20 configurations**, reconnues par **90 règles TTP distinctes**. Ce ne sont ni 777 champs atomiques, ni 777 commandes uniques, ni 777 erreurs de syntaxe. Une commande peut porter plusieurs paramètres ; plusieurs fichiers répètent la même commande. La fréquence exacte des textes et celle des règles sont fournies séparément.\n',
        'Une commande est « extraite mais non mappée » quand TTP reconnaît son motif, mais que sa signification n’est pas inscrite dans les champs normalisés. Son texte, sa ligne et son contexte sont conservés dans parsed_native.json et dans les commandes non converties de normalized_config.json. Les 777 chemins normalized_paths sont vides.\n',
        'Les **777/777** occurrences ont été retrouvées à leur ligne réelle ; toute leur chaîne de parents dans l’arbre a été vérifiée. Cela prouve la conservation du texte et du contexte lexical, pas une interprétation métier complète. Les corps opaques de certificats et bannières ne font pas partie de ces 777.\n',
        'Le chiffre précédent de 1 827 concernait les commandes non converties de l’ancien adaptateur. Ici, on examine uniquement les 777 occurrences déjà reconnues par les templates du nouveau pipeline TTP mais sans mapping. Les commandes sans interprétation TTP et les blocs opaques sont dans d’autres catégories : on ne peut pas présenter 1 827 − 777 comme un gain de conversion.\n',
        '## Causes : une seule catégorie principale par occurrence\n',
        table(['Cause', 'Occurrences', '% des 777'], [(CAUSES[k], v, f'{v/777:.1%}') for k, v in stats['causes'].items()]),
        '\nUne « structure insuffisante » signifie que le contrat ne distingue pas correctement la portée AF, un groupe BGP, une version OSPF ou des entrées de filtre ordonnées. Un « champ absent » désigne une propriété métier sans emplacement dédié. Ces deux catégories demandent une évolution de modèle pour une représentation fidèle ; elles ne sont pas des échecs de reconnaissance TTP.\n',
        '## Familles fonctionnelles\n',
        table(['Famille', 'Occurrences', 'Fichiers', 'Règles'], [(x['name'], x['count'], x['files'], x['rules']) for x in stats['families']]),
        '\n## Ce qui peut être amélioré avec v0.1\n',
        '- **29 `no ip address`** : associer `ipv4_addresses=[]` à une preuve `explicit`. Les 29 interfaces ont déjà une liste vide ; le gain serait la signification et la provenance de cette liste. Cela ne veut pas dire « pas de connectivité IPv4 » : `ip unnumbered` reste un sujet distinct.\n'
        '- **1 `tunnel destination`** : créer un VPNTunnel lié à `Tunnel0`, renseigner `remote_endpoint=195.177.253.41` et laisser `technology=unknown`. Le contrat autorise cette technologie inconnue ; le refus actuel du mapper est trop strict.\n'
        '- **1 `tunnel source Loopback0`** : dans ce corpus, Loopback0 possède une adresse IPv4 explicite unique, `94.45.227.2`. La résolution peut alimenter `local_endpoint` avec deux preuves : la référence source et l’adresse de Loopback0. Une source dynamique ou ambiguë devra rester non résolue.\n'
        '- **3 `transport input all`** : `allowed_transports=["all"]` passe le schéma, mais aucune convention canonique du mot `all` n’est définie. Ce sont des cas de convention, pas des types refusés par Pydantic. Ne pas traduire automatiquement en `ssh` + `telnet`.\n',
        'Les **34 propositions isolées en mémoire** (29 + 1 + 1 + 3) passent Pydantic et le schéma JSON originaux. Cette validation établit la compatibilité structurelle ; elle ne valide pas la convention `all`, ni une prise en charge complète des tunnels. Aucun JSON converti existant n’a été réécrit et les statistiques de couverture restent inchangées.\n',
        '## Qualité des captures : anomalies secondaires\n',
        f'- **{stats["empty_values"]} occurrences ont `values={{}}`** : le motif et la source sont présents, mais aucun paramètre n’est exporté. Ce sont surtout des commandes à sens littéral (`no ip address`, `mpls ip`, etc.).\n'
        f'- **{stats["missing_set_constants"]} occurrences omettent au moins une constante `set(True/False)` déclarée dans leur template**, y compris des captures non vides comme `neighbor … activate` qui conservent le voisin mais perdent le booléen `enabled`. Ce nombre recoupe d’autres catégories : ne pas l’ajouter aux 777. Le rule ID et la commande permettent de retrouver le sens, mais le JSON natif devrait l’expliciter.\n'
        '- **6 `login on-success log`** sont reconnus par la règle générique `services_login`, sous un contexte global. Ce ne sont pas des méthodes d’authentification VTY. Le garde de contexte actuel évite le mauvais mapping ; il faut une règle dédiée à la journalisation des connexions et un champ adapté.\n'
        '- **6 `advanced_l2_member`** conservent un texte composite ; ses composantes interface, service-instance et pseudowire doivent être typées selon la syntaxe rencontrée. L’arbre préserve le bloc, mais la capture n’est pas une structure métier complète.\n',
        'Ces constats sont des limites du pipeline local figé et de ses templates, pas une conclusion générale sur toutes les capacités de TTP.\n',
        '## Priorités proposées\n',
        '1. Corriger les constantes absentes de l’export natif et séparer le login logging global. Ces corrections améliorent la qualité des données sans prétendre que chaque propriété possède un champ dans v0.1.\n'
        '2. Ajouter les 30 mappings directs avec preuves ; traiter la source de tunnel par résolution contrôlée ; formaliser `all` avant mapping. Écrire des tests ciblés avant de changer les compteurs.\n'
        '3. Concevoir une révision du contrat pour les paramètres Ethernet, les voisins/groupes BGP par AF, OSPFv3 et les prefix-lists ordonnées. La simple copie de chaînes dans un champ générique ne suffit pas.\n'
        '4. Ajouter ensuite les modèles QoS, IS-IS, MPLS, multicast, services L2/EVPN et PKI suivant les besoins du projet. Réutiliser les captures et préserver les avertissements de prise en charge partielle.\n',
        '## Répartition par fichier\n',
        table(['Fichier', 'Hôte', 'Occurrences', 'Règles', 'Direct v0.1', 'Résolution', 'Convention', 'Capture/contexte', 'Structure', 'Champ absent'],
              [(x['name'], manifest[x['name']]['hostname_description'], x['count'], x['rules'], *[x['causes'].get(k,0) for k in CAUSES]) for x in stats['files']]),
        '\n## Les 90 règles, par fréquence\n',
        table(['Règle', 'Occurrences', 'Fichiers', 'Famille', 'Cause(s)', 'Exemple'],
              [(x['name'], x['count'], x['files'], next(r['functional_family'] for r in rows if r['rule']==x['name']),
                ', '.join(f'{CAUSES[k]} : {v}' for k,v in x['causes'].items()),
                next(f'{r["file_id"]}:{r["line"]} — {r["command"]}' for r in rows if r['rule']==x['name'])) for x in stats['rules']]),
        '\n## Détail et reproduction\n',
        'Le [rapport HTML filtrable](RAPPORT_777.html) contient les 777 lignes : commande, données natives, contexte, diagnostic, champ actuel ou extension proposée, et références au code et au contrat. Les extensions proposées sont des pistes de conception, pas un nouveau schéma validé.\n',
        '- [Détail JSON](occurrences_777.json) et [CSV](occurrences_777.csv) : une ligne par occurrence.\n'
        '- [Fréquences des règles](frequences_regles.csv), [textes exacts](frequences_commandes.csv), [familles](familles.csv), [fichiers](fichiers.csv).\n'
        '- [Propositions vérifiées en mémoire](probes_v01.json) ; [résumé et contrôles](summary.json) ; [empreintes avant/après](integrity.json).\n'
        '- Reproduction : `.\\.venv\\Scripts\\python.exe tools/analyse_unmapped_777.py` depuis la racine du sous-projet.\n',
        'Périmètre : résultats figés des 20 fichiers de `configs/manifest.json`, contrat 0.1.0 et code local. Cet audit ne consulte pas le réseau, ne modifie pas le parseur, n’installe aucune dépendance et ne complète pas les modèles. La conservation lexicale et la validation de type ne mesurent pas la précision sémantique du parseur.\n',
    ]
    (OUT / 'RAPPORT_777.md').write_text('\n'.join(parts), encoding='utf-8')
    write_html(rows, stats)


def write_html(rows, stats):
    esc = lambda x: html.escape(str(x), quote=True)
    tr = []
    for r in rows:
        contexts = ' → '.join(f'L{c["line"]} {c["text"]}' for c in r['context']) or '(global)'
        src = '../../' + r['config_file']
        mapper, mapper_line = r['mapper_reference'].split(':')
        contract, contract_line = r['contract_reference'].split(':')
        details = (f'<strong>Valeurs TTP</strong><pre>{esc(json.dumps(r["native_values"],ensure_ascii=False,indent=2))}</pre>'
                   f'<strong>Contexte vérifié</strong><p>{esc(contexts)}</p><p>Commande et chaîne de parents retrouvées dans l’arbre et la source.</p>'
                   f'<strong>Diagnostic</strong><p>{esc(r["explanation"])}</p><strong>Cible actuelle ou proposition</strong><p>{esc(r["target"])}</p>'
                   f'<p><a href="../../{esc(mapper)}">Mapper</a> ligne {mapper_line} · '
                   f'<a href="../../{esc(contract)}">Contrat {esc(r["model"])}</a> ligne {contract_line}</p>'
                   f'<strong>Motif TTP</strong><pre>{esc(r["ttp_pattern"])}</pre><p>Signaux secondaires : {esc(", ".join(r["quality_flags"]) or "aucun")}</p>')
        tr.append(f'<tr data-family="{esc(r["functional_family"])}" data-cause="{esc(r["cause"])}" data-file="{r["file_id"]}">'
                  f'<td><a href="{esc(src)}">{r["file_id"]}</a><br>L{r["line"]}<br>{esc(r["hostname"])}</td>'
                  f'<td><code>{esc(r["command"])}</code><br><small>{esc(r["rule"])}</small><details><summary>Données, contexte et diagnostic</summary>{details}</details></td>'
                  f'<td>{esc(r["functional_family"])}</td><td>{esc(r["cause_label"])}</td></tr>')
    options = lambda values: ''.join(f'<option value="{esc(v)}">{esc(label)}</option>' for v,label in values)
    family_options = options((x['name'], f'{x["name"]} ({x["count"]})') for x in stats['families'])
    cause_options = options((k, f'{v} ({stats["causes"].get(k,0)})') for k,v in CAUSES.items())
    file_options = options((x['name'], f'{x["name"]} ({x["count"]})') for x in stats['files'])
    families = ''.join(f'<tr><td>{esc(x["name"])}</td><td>{x["count"]}</td><td>{x["files"]}</td></tr>' for x in stats['families'])
    causes = ''.join(f'<tr><td>{esc(CAUSES[k])}</td><td>{v}</td></tr>' for k,v in stats['causes'].items())
    content = '''<!doctype html><html lang="fr"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Analyse des 777 occurrences non mappées</title>
<style>body{font:16px/1.55 system-ui,sans-serif;color:#182638;background:#f4f7fb;margin:0}main{max-width:1450px;margin:auto;padding:32px}h1{line-height:1.2}h2{margin-top:2em}.box{background:white;border:1px solid #d7dfeb;padding:20px;border-radius:12px;margin:16px 0}.metrics{display:flex;gap:14px;flex-wrap:wrap}.metrics div{background:#112c4b;color:white;padding:18px;border-radius:10px;flex:1;min-width:150px}.metrics b{font-size:30px;display:block}.grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}table{border-collapse:collapse;width:100%;background:white}th,td{padding:12px;border-bottom:1px solid #dbe2eb;vertical-align:top;text-align:left}th{background:#e6edf6}code,pre{font:13px/1.5 ui-monospace,Consolas,monospace;white-space:pre-wrap;overflow-wrap:anywhere}pre{background:#eef3f8;padding:12px}a{color:#165997}small{color:#52647d}input,select,button{font:inherit;padding:10px;border:1px solid #b6c4d6;border-radius:6px;max-width:100%}.filters{display:flex;flex-wrap:wrap;gap:12px;align-items:end}.filters label{display:flex;flex-direction:column;flex:1;min-width:180px}details{margin-top:10px}summary{cursor:pointer;color:#17538d}details p{max-width:850px}.tablewrap{overflow-x:auto}.commands td:first-child{min-width:110px}.commands td:nth-child(2){min-width:330px;width:55%}@media(max-width:850px){main{padding:16px}.grid{grid-template-columns:1fr}}</style>
<main><h1>777 commandes extraites, mais non mappées</h1>
<p>Audit des 20 configurations Cisco. <strong>Aucune modification du parseur ou des résultats.</strong></p>
<div class="metrics"><div><b>777</b>occurrences de commandes</div><div><b>90</b>règles TTP distinctes</div><div><b>30</b>mappings directs possibles en v0.1</div><div><b>777/777</b>sources et parents vérifiés</div></div>
<div class="box"><p><strong>« Extrait » :</strong> le motif de la commande est reconnu et conservé avec sa ligne et son contexte. <strong>« Non mappé » :</strong> sa signification ne figure pas dans les champs normalisés. Ce compteur ne mesure pas la précision sémantique et ne compte pas des champs atomiques.</p>
<p>29 <code>no ip address</code> peuvent recevoir une preuve explicite de liste vide. Une destination de tunnel peut être conservée avec technologie inconnue. Une source de tunnel demande une résolution de référence ; 3 <code>transport input all</code> demandent une convention. Ces 34 propositions passent le contrat en mémoire, sans être appliquées.</p>
<p>6 commandes globales <code>login on-success log</code> sont capturées par une règle d’authentification trop générale. <strong>EMPTY_COUNT</strong> captures ont un objet <code>values</code> vide ; <strong>SET_COUNT</strong> omettent au moins une constante de template. Ces anomalies recoupent les causes principales.</p>
<p><a href="RAPPORT_777.md">Rapport détaillé</a> · <a href="occurrences_777.csv">777 occurrences CSV</a> · <a href="frequences_commandes.csv">Textes par fréquence</a> · <a href="frequences_regles.csv">Règles par fréquence</a> · <a href="summary.json">Contrôles</a></p></div>
<div class="grid"><section><h2>Par famille</h2><table><thead><tr><th>Famille</th><th>Occurrences</th><th>Fichiers</th></tr></thead><tbody>FAMILIES</tbody></table></section><section><h2>Pourquoi le mapping manque</h2><table><thead><tr><th>Cause principale</th><th>Occurrences</th></tr></thead><tbody>CAUSES</tbody></table><p>Les propositions de champs dans les détails ne sont pas un nouveau schéma. La conservation dans l’arbre n’implique pas la prise en charge complète de la technologie.</p></section></div>
<h2>Explorer chaque occurrence</h2><div class="box filters"><label>Recherche<input id="q" type="search" placeholder="Commande, règle, contexte…"></label><label>Famille<select id="family"><option value="">Toutes les familles</option>FAMILY_OPTIONS</select></label><label>Cause<select id="cause"><option value="">Toutes les causes</option>CAUSE_OPTIONS</select></label><label>Fichier<select id="file"><option value="">Tous les fichiers</option>FILE_OPTIONS</select></label><button id="reset" type="button">Réinitialiser</button></div>
<p id="count" role="status">777 occurrences affichées</p><div class="tablewrap"><table class="commands"><thead><tr><th>Source</th><th>Commande et données</th><th>Famille</th><th>Cause</th></tr></thead><tbody id="data">ROWS</tbody></table></div>
<p>Analyse locale reproductible : <code>.\\.venv\\Scripts\\python.exe tools/analyse_unmapped_777.py</code>. Aucun appel réseau.</p></main>
<script>const rows=[...document.querySelectorAll('#data tr')]; const controls=['q','family','cause','file'].map(x=>document.getElementById(x));
function filter(){const [q,f,c,id]=controls.map(x=>x.value);let n=0;for(const r of rows){const show=(!q||r.textContent.toLocaleLowerCase('fr').includes(q.toLocaleLowerCase('fr')))&&(!f||r.dataset.family===f)&&(!c||r.dataset.cause===c)&&(!id||r.dataset.file===id);r.hidden=!show;if(show)n++;}document.getElementById('count').textContent=n+' occurrence(s) affichée(s) sur 777';}controls.forEach(x=>x.addEventListener('input',filter));document.getElementById('reset').addEventListener('click',()=>{controls.forEach(x=>x.value='');filter();});</script></html>'''
    replacements = dict(EMPTY_COUNT=stats['empty_values'], SET_COUNT=stats['missing_set_constants'], FAMILIES=families, CAUSES=causes,
                        FAMILY_OPTIONS=family_options, CAUSE_OPTIONS=cause_options, FILE_OPTIONS=file_options, ROWS=''.join(tr))
    # Single pass prevents placeholders inside generated data being interpreted.
    content = re.sub('|'.join(re.escape(k) for k in replacements), lambda m: str(replacements[m.group()]), content)
    (OUT / 'RAPPORT_777.html').write_text(content, encoding='utf-8')


def main():
    before = frozen_inputs()
    rows, docs, file_data, manifest = build_rows()
    probes = probe_candidates(rows, docs, file_data)
    OUT.mkdir(parents=True, exist_ok=True)
    causes = {k: sum(r['cause']==k for r in rows) for k in CAUSES}
    stats = dict(total=len(rows), rule_count=len({r['rule'] for r in rows}), file_count=len(manifest),
        exact_command_count=len({r['command'] for r in rows}), causes=causes,
        families=aggregate(rows, 'functional_family'), files=aggregate(rows, 'file_id'), rules=aggregate(rows, 'rule'),
        empty_values=sum(not r['native_values'] for r in rows),
        missing_set_constants=sum(any(f.startswith('constante_set_non_exportee') for f in r['quality_flags']) for r in rows),
        tree_verified=sum(r['tree_verified'] for r in rows), in_memory_probes=len(probes), probes_pydantic_passed=len(probes),
        probes_jsonschema_passed=len(probes), output_configurations_modified=False)
    command_counts = Counter(r['command'] for r in rows)
    frequencies = [dict(command=text, occurrences=count, files=len({r['file_id'] for r in rows if r['command']==text}),
                        locations=[f'{r["file_id"]}:{r["line"]}' for r in rows if r['command']==text]) for text,count in command_counts.most_common()]
    dump('occurrences_777.json', rows)
    dump('probes_v01.json', probes)
    write_csv('occurrences_777.csv', rows)
    write_csv('frequences_commandes.csv', frequencies)
    write_csv('frequences_regles.csv', stats['rules'])
    write_csv('familles.csv', stats['families'])
    write_csv('fichiers.csv', stats['files'])
    write_csv('qualite_captures.csv', [dict(rule=x['name'], occurrences=x['count'],
        empty_values=sum(not r['native_values'] for r in rows if r['rule']==x['name']),
        missing_set_constants=sum(any(f.startswith('constante_set_non_exportee') for f in r['quality_flags']) for r in rows if r['rule']==x['name']))
        for x in stats['rules'] if any(r['rule']==x['name'] and r['quality_flags'] and
            (not r['native_values'] or any(f.startswith('constante_set_non_exportee') for f in r['quality_flags'])) for r in rows)])
    reports(rows, stats, probes, manifest)
    after = frozen_inputs()
    assert before == after, 'An audited input changed during analysis'
    integrity = dict(all_unchanged=True, checked_files=len(before), before=before, after=after,
                     analysis_script_sha256=digest(Path(__file__)))
    dump('integrity.json', integrity)
    assert sum(causes.values()) == sum(x['count'] for x in stats['families']) == sum(x['count'] for x in stats['files']) == 777
    stats['checks'] = dict(exactly_777_unique_source_positions=True, exactly_90_rules=True,
        all_source_texts_and_ancestor_chains_verified=True, no_existing_normalized_paths=True,
        all_777_preserved_in_normalized_unknown_commands=True,
        independent_group_totals_equal_777=True, all_34_in_memory_proposals_validate=True,
        frozen_inputs_unchanged=True, frozen_input_files=len(before))
    dump('summary.json', stats)
    print(json.dumps({k:v for k,v in stats.items() if k not in ('rules','files','families')},ensure_ascii=False,indent=2))
    print('FAMILIES', json.dumps(stats['families'], ensure_ascii=False))


if __name__ == '__main__':
    main()
