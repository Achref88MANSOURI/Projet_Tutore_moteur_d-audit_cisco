"""Assemble the evidence from audit_pipeline.py and its controlled probes."""
from collections import Counter, defaultdict
import ast
import html
import inspect
import json
from pathlib import Path
import re
import sys
from xml.etree import ElementTree

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from audit_pipeline import read, dump, write_csv, protected, sha
from schemas import normalizedconfig as model

OUT=ROOT/'outputs/diagnostic_pipeline'
LABELS={
    'normalization_mapping':'Mapping absent, compatible v0.1',
    'reference_resolution':'Référence à résoudre',
    'normalization_semantic_convention':'Convention de normalisation à définir',
    'extraction_context_classification':'Mauvais concept de capture',
    'normalized_schema_structure':'Structure insuffisante du contrat',
    'normalized_schema_field':'Champ métier absent du contrat',
    'no_matching_current_template':'Aucun motif correspondant au catalogue',
    'template_variant_missing':'Variante syntaxique non couverte',
    'family_dispatch_gap':'Aiguillage vers le mauvais catalogue',
    'other_scope_pattern_match_not_reusable_as_is':'Motif d’un autre contexte, non réutilisable tel quel',
    'candidate_rejected_or_not_selected':'Candidat filtré ou non retenu',
}


def table(headers,rows):
    def cell(x):return str(x).replace('|','\\|').replace('\n',' ')
    return '\n'.join(['| '+' | '.join(headers)+' |','| '+' | '.join('---' for _ in headers)+' |']+
        ['| '+' | '.join(cell(v) for v in row)+' |' for row in rows])


def source_ref(file,name):
    tree=ast.parse((ROOT/file).read_text(encoding='utf-8'))
    node=next(n for n in ast.walk(tree) if isinstance(n,(ast.ClassDef,ast.FunctionDef)) and n.name==name)
    return f'[{file}, ligne {node.lineno}](../../{file})'


def main():
    summary=read(OUT/'summary.json');tests=read(OUT/'test_rule_execution.json')
    probes=read(OUT/'controlled_probes.json');rows=read(OUT/'diagnostic_occurrences_1359.json')
    constants=read(OUT/'constant_fields.json');catalogue=read(OUT/'rules_272.json')
    old777={(r['file_id'],r['line']):r for r in read(ROOT/'outputs/analysis_777/occurrences_777.json')}
    by_position=defaultdict(list)
    for item in constants:
        if not item['present']:by_position[(item['file_id'],item['line'])].append(item)
    changes=read(OUT/'native_export_changes.json');changes_by_pos=defaultdict(list)
    for item in changes:changes_by_pos[(item['file_id'],item['line'])].append(item)
    for row in rows:
        key=(row['file_id'],row['line'])
        row['missing_constant_fields']=[dict(field=c['field'],expected=c['expected']) for c in by_position[key]]
        row['secondary_failure_stages']=[]
        if row['missing_constant_fields']:row['secondary_failure_stages'].append('native_constant_materialization')
        if changes_by_pos[key]:row['secondary_failure_stages'].append('native_export_redaction')
        if key in old777:
            row['mapper_reference']=old777[key]['mapper_reference']
            row['contract_reference']=old777[key]['contract_reference']
        else:
            row['mapper_reference']='parser/run_ttp.py:46'
            row['contract_reference']=None
    dump('diagnostic_occurrences_1359.json',rows);write_csv('diagnostic_occurrences_1359.csv',rows)
    # Every generated group must match exactly its catalogue declaration; only
    # parse template text here, never execute the template generator.
    groups={}
    for path in (ROOT/'templates/cisco_ios').glob('*.ttp'):
        text=path.read_text(encoding='utf-8')
        for match in re.finditer(r'<group name="([^"]+)\*" method="table">\s*(.*?)\s*</group>',text,re.S):
            rule=match[1];assert rule not in groups
            groups[rule]=dict(path=path.relative_to(ROOT).as_posix(),body=html.unescape(match[2]).strip())
    assert len(groups)==len(catalogue)==272
    for rule in catalogue:
        assert groups[rule['id']]['body']=='{{ source_line | DIGIT | to_int }} '+rule['pattern']
        rule.update(template_file=groups[rule['id']]['path'],catalogue_pattern_matches_template=True,
            selected_during_existing_tests=rule['id'] in tests['selected_rule_occurrences'],
            test_selection_occurrences=tests['selected_rule_occurrences'].get(rule['id'],0),
            test_literal_reference=rule['id'] in tests['literal_rule_ids_in_test_code'])
    dump('rules_272.json',catalogue);write_csv('rules_272.csv',catalogue)
    schema=[]
    for name,cls in vars(model).items():
        if inspect.isclass(cls) and issubclass(cls,model.Contract):
            schema.append(dict(model=name,fields={k:str(f.annotation) for k,f in cls.model_fields.items()}))
    dump('schema_field_inventory.json',schema)
    assert not {'speed','duplex','negotiation','media'} & model.Interface.model_fields.keys()
    assert not {'address_families','update_source'} & model.BGPNeighbor.model_fields.keys()
    assert 'description' not in model.NetworkInstance.model_fields
    assert set(model.PrefixSet.model_fields)=={'name','prefixes'}
    assert set(model.QoS.model_fields)=={'policy_names','attachments'}
    # Explain overlap and structural categories using archived observations.
    position_status={};structural=Counter();structural_no_capture=Counter();empty=Counter()
    per_file=[];per_file_old={r['file_id']:r for r in read(OUT/'replay_files.json')}
    rule_by_position={}
    for folder in sorted((ROOT/'outputs/corpus_20').glob('F*')):
        coverage=read(folder/'coverage_report.json');native=read(folder/'parsed_native.json')
        records={r['source_line']:r for r in native['records']}
        for r in coverage['commands']:
            position_status[(folder.name,r['line'])]=r['status']
            if r['status']=='structure_or_metadata':
                if r['line'] in records:structural[records[r['line']]['rule']]+=1
                else:structural_no_capture[r['text']]+=1
        for r in native['records']:
            rule_by_position[(folder.name,r['source_line'])]=r['rule']
            if not r['values']:empty[position_status[(folder.name,r['source_line'])]]+=1
        subset=[r for r in rows if r['file_id']==folder.name]
        per_file.append(dict(file_id=folder.name,diagnostic_occurrences=len(subset),
            extracted_unmapped=sum(r['coverage_status']=='extracted_unmapped' for r in subset),
            uninterpreted=sum(r['coverage_status']=='preserved_uninterpreted' for r in subset),
            missing_constant_fields=sum(len(by_position[(folder.name,r['source_line'])]) for r in native['records']),
            source_native_normalized_replay_identical=per_file_old[folder.name]['normalized_replay_identical']))
    write_csv('files.csv',per_file)
    raw=read(OUT/'raw_candidates.json');candidates=defaultdict(list)
    definitions={r['id']:r for r in catalogue}
    for item in raw:candidates[(item['file_id'],item['line'])].append(item)
    collisions=[]
    for key,items in candidates.items():
        assert rule_by_position[key] in {r['rule'] for r in items}
        if len(items)>1:
            collisions.append(dict(file_id=key[0],line=key[1],selected_rule=rule_by_position[key],
                raw_rules=[r['rule'] for r in items],selection_mechanism='Literal keyword score, ORPHRASE penalty, port/distance/sequence bonuses, route guards and lexical rule-id tie-break. Not a semantic proof.'))
    dump('candidate_collisions.json',collisions);write_csv('candidate_collisions.csv',collisions)
    stages=Counter(r['failure_stage'] for r in rows)
    boolean_missing=sum(isinstance(r['expected'],bool) and not r['present'] for r in constants)
    string_missing=sum(isinstance(r['expected'],str) and not r['present'] for r in constants)
    unmapped_constants=[c for c in constants if position_status[(c['file_id'],c['line'])]=='extracted_unmapped']
    summary.update(diagnostic_failure_stages=dict(stages),constant_missing_by_status=dict(Counter(position_status[(r['file_id'],r['line'])] for r in constants if not r['present'])),
        boolean_constants_missing=boolean_missing,string_constants_missing=string_missing,
        unmapped_constant_fields_missing=len(unmapped_constants),
        unmapped_boolean_constants_missing=sum(isinstance(c['expected'],bool) for c in unmapped_constants),
        records_with_empty_values=dict(empty),structural_captured_rules=dict(structural),structural_without_capture=dict(structural_no_capture),
        raw_candidate_occurrences=len(raw),positions_with_competing_candidates=len(collisions),
        rules_never_raw=len([r for r in catalogue if not r['observed_raw']]),rules_raw_but_never_selected=len([r for r in catalogue if r['observed_raw'] and not r['observed_selected']]),
        rules_selected_during_tests=tests['selected_distinct_rules'],controlled_probes=len(probes),existing_regression_tests=54,
        templates_with_orphrase=sum(bool(r['orphrase_variables']) for r in catalogue),templates_with_set=sum(bool(r['set_variables']) for r in catalogue),
        template_catalogue_consistency=True,original_contract_sha256=sha(ROOT/'schemas/normalizedconfig.py'))
    # Original sources must still match the audit's pre-run snapshot after all probes.
    integrity=read(OUT/'integrity.json')
    assert all(sha(ROOT/path)==value for path,value in integrity['before'].items())
    integrity['verified_after_controlled_probes_and_report']=True
    dump('integrity.json',integrity);dump('summary.json',summary)
    report(summary,rows,catalogue,per_file,stages,probes)
    report_html(summary,rows,catalogue,stages)
    print(json.dumps({k:summary[k] for k in ('boolean_constants_missing','string_constants_missing','unmapped_constant_fields_missing','hierarchy_checks_failed','raw_candidate_occurrences','positions_with_competing_candidates','rules_never_raw','rules_raw_but_never_selected','rules_selected_during_tests','controlled_probes')},indent=2))


def report(s,rows,rules,files,stages,probes):
    prior=read(ROOT/'outputs/analysis_777/summary.json')
    u=[r for r in rows if r['coverage_status']=='preserved_uninterpreted']
    opaque=read(OUT/'opaque_blocks.json')
    fam=Counter(r['functional_family'] for r in u)
    rule_fam=Counter(r['family'] for r in rules)
    refs=' · '.join(source_ref(file,name) for file,name in [('parser/inventory.py','root_family'),('parser/run_ttp.py','extract'),('parser/coverage.py','build_coverage'),('normalizer/mapping.py','interface'),('normalizer/mapping.py','routing_bgp'),('normalizer/mapping.py','finish_links')])
    parts=[
        '# Diagnostic de la chaîne TTP : extraction, modèle, mapping et compteurs\n',
        '**Conclusion : les résultats ne démontrent pas un échec du moteur TTP.** Ils montrent des limites confirmées de notre contrat, des mappings absents, un défaut de construction des templates et de vraies lacunes du catalogue. Changer de moteur ne résoudrait pas les 737 occurrences dont la signification n’a pas de champ ou de structure adéquate dans v0.1.\n',
        '**Audit sans correction de production** : configurations, templates, parseur, normaliseur, schéma et résultats archivés inchangés. Les 20 extractions natives et les 20 JSON normalisés ont été reproduits **en mémoire**, à l’identique. Les 54 tests existants passent et 13 observations contrôlées supplémentaires sont confirmées. Ces vérifications ne constituent pas une mesure exhaustive de précision sémantique.\n',
        '## Les six contrôles demandés\n',
        table(['Contrôle','Constat vérifié'],[
            ('777 occurrences extraites non mappées','737 limites de contrat, 30 mappings directs possibles, 1 résolution de référence, 3 conventions, 6 captures de login mal classées. Les défauts de constantes recoupent ces causes.'),
            ('582 non interprétées','110 textes distincts : 566 sans motif correspondant, 6 variantes LDP, 1 aiguillage de famille, 9 homonymes/motifs d’autre contexte non utilisables tels quels.'),
            ('272 règles','272 groupes cohérents avec le catalogue ; 171 produisent un candidat, 166 sont retenus sur le corpus. Les règles ne sont pas toutes validées sémantiquement.'),
            ('Contrat v0.1','Champs Ethernet, BGP par AF, OSPFv3, listes de filtrage ordonnées, QoS et PKI insuffisamment représentés ; inventaire des modèles joint.'),
            ('Hiérarchie','876 contrôles d’identité d’objet/de portée sans anomalie sur les rattachements examinés ; gardes de contexte confirmés sur cas contrôlés.'),
            ('Compteurs','1 995 = 1 148 normalisées + 777 non mappées + 70 structures/métadonnées capturées. Aucun reliquat de 70 captures inexpliquées.')]),
        '\n## 1. Réconcilier les compteurs\n',
        'La référence historique contient **3 051 positions**. La somme est exacte :\n\n```text\n1 148 normalisées\n+ 777 extraites non mappées\n+ 582 non interprétées\n+ 440 positions de corps opaques\n+  84 structures / métadonnées\n+  20 enveloppes d’export\n= 3 051 positions historiques\n```\n',
        '**Les 1 995 captures sélectionnées comprennent 70 éléments structurels** : 32 `exit-address-family` BGP, 20 versions IOS/IOS-XE, 9 en-têtes AF VRF et 9 sorties AF VRF. Les 14 autres éléments structurels sont des `quit` de certificats, traités par l’inventaire sans règle TTP. Ainsi : `1 995 = 1 148 + 777 + 70`.\n',
        'Il existe également **2 041 candidats bruts TTP**, avant les gardes et le choix du meilleur motif : 46 positions ont plusieurs candidats. Ce compteur ne doit pas être confondu avec les 1 995 records retenus. [Détail des concurrences](candidate_collisions.csv).\n',
        table(['Statut','Positions historiques','Objets de l’inventaire actuel'],[(k,v,s['actual_inventory_statuses'][k]) for k,v in s['legacy_statuses'].items()]),
        '\nL’inventaire actuel compte 2 653 objets : les 440 lignes opaques deviennent 22 blocs ; il inclut aussi les 20 `end` finaux, absents du dénominateur historique. Les 40 export_wrapper actuels regroupent 20 enveloppes et 20 fins de configuration. Ces univers n’ont donc pas la même taille et ne doivent pas être mélangés.\n',
        '## 2. Les 777 : corriger le diagnostic de responsabilité\n',
        table(['Cause principale','Occurrences','Conséquence'],[
            ('Champ métier absent',601,'Enrichir le contrat avant mapping fidèle'),
            ('Structure / portée insuffisante',136,'Préserver AF, groupes, versions et ordre des filtres'),
            ('Mapping direct compatible v0.1',30,'29 no ip address et 1 destination de tunnel'),
            ('Résolution de référence',1,'Source de tunnel Loopback0, sous condition de résolution non ambiguë'),
            ('Convention non définie',3,'transport input all'),
            ('Concept de capture incorrect',6,'login on-success log global capturé comme méthode de login')]),
        '\nCes causes principales sont exclusives ; les défauts de capture/export peuvent s’y ajouter. Les 737 limites de contrat ne certifient pas que chaque capture est parfaite. Par exemple, **176 champs de constante manquent dans ce groupe** : les **165 booléens** déjà identifiés, plus **11 options littérales** `send-community` non matérialisées.\n',
        'Les 30 mappings directs et la résolution du tunnel ont été vérifiés lors de l’audit précédent ; les mêmes sources et le même contrat sont inchangés. Les propositions ne sont pas appliquées. Les listes d’adresses vides doivent recevoir une preuve explicite, sans déduire « IPv4 désactivé ». Le tunnel peut rester de technologie inconnue. `all` passe le type list[str], mais sa convention canonique reste à définir. [Audit précédent](../analysis_777/RAPPORT_777.md).\n',
        '### Ce que le contrat ne sait pas représenter fidèlement\n',
        table(['Domaine','Contrat actuel','Limite confirmée'],[
            ('Ethernet','Interface : adresses, état, MTU, VLAN…','Pas de speed, duplex, negotiation ou media'),
            ('BGP','Voisin avec enabled et politiques globales ; liste de noms de groupes','Pas de propriétés du voisin/groupe structurées par AF ni update_source'),
            ('OSPF','OSPFProcess sans version','Ne permet pas de distinguer proprement v2 et v3'),
            ('Prefix-lists','PrefixSet(name, prefixes)','Pas de deny, ge/le ou entrées ordonnées de filtre'),
            ('QoS','Noms de policies et attachements','Pas de classifiers ni d’actions détaillées'),
            ('PKI','Security : ensembles et attachements ACL','Pas de trustpoint, enrollment ou métadonnées de certificats'),
            ('VRF','NetworkInstance : nom, RD/RT, interfaces','Pas de description')]),
        '\nUn champ générique de routing_policy ne doit pas servir à stocker arbitrairement un paramètre Ethernet ou QoS. On parle ici d’un emplacement sémantiquement adéquat, pas seulement de la possibilité d’insérer une chaîne dans un JSON. [Inventaire complet des champs](schema_field_inventory.json).\n',
        '## 3. Défaut confirmé : constantes absentes des records natifs\n',
        f'**{s["set_fields_missing"]} champs attendus par les expressions set() sont absents**, soit {s["boolean_constants_missing"]} booléens et {s["string_constants_missing"]} options littérales, dans les captures sélectionnées du corpus. Les 34 règles qui emploient set() ne sont pas toutes exercées par ces fichiers. Répartition des occurrences touchées :\n',
        table(['Statut de la commande','Champs de constante absents'],s['constant_missing_by_status'].items()),
        '\nLe comparatif minimal produit réellement :\n',
        table(['Template testé en mémoire','Résultat observé'],[
            ('shutdown avec enabled | set(False), sans numéro ajouté','enabled=false'),
            ('source_line + shutdown avec enabled | set(False), variante actuelle','source_line=1 ; enabled absent'),
            ('source_line + shutdown avec set au niveau du groupe, contrôle alternatif','source_line=1 ; enabled=false')]),
        '\nLe `set` au niveau du match s’appuie sur le texte littéral de la ligne. Ajouter une autre variable pour le numéro de source change cette comparaison. **C’est notre combinaison de variables et de set(), pas une incapacité générale de TTP à produire un booléen.** Le contrôle alternatif prouve une possibilité, sans remplacer aucun template du projet. [Cas et résultats exacts](controlled_probes.json).\n',
        'Les 142 commandes normalisées concernées ne sont pas automatiquement erronées : le mapper reconstruit certaines valeurs à partir du nom de règle (`if_shutdown`, `if_no_shutdown`, HTTP…). Cela explique pourquoi les tests peuvent passer alors que l’export natif manque de champs. Il y a aussi **275 records à values={}** : 142 normalisés, 92 non mappés, 41 structurels. Un record créé n’est donc pas nécessairement un ensemble de paramètres extraits.\n',
        'Deux autres changements apparaissent lors de l’export natif : `credential_type="secret"`, qui est un nom de type et non la valeur du secret, est masqué dans F0057:111 et F0059:104. La politique de masquage textuel est trop large pour ce champ de métadonnée. Le mapping utilise encore la valeur en mémoire avant cet export. Les valeurs de secrets restent exclues des rapports. [Différences d’export](native_export_changes.json).\n',
        '## 4. Les 582 non interprétées\n',
        'Chaque position a été comparée à sa ligne originale, à sa famille d’inventaire, aux sorties brutes des groupes et aux records retenus. Aucune de ces 582 positions ne possède un candidat dans sa famille assignée. Un essai transversal avec les **motifs existants inchangés** permet de distinguer :\n',
        table(['Cause','Occurrences','Preuve / interprétation'],[
            ('Aucun motif correspondant',566,'Ni candidat dans la famille ni correspondance dans l’essai transversal ; pas une preuve que toutes ces commandes méritent un champ normalisé'),
            ('Variante LDP sans option',6,'advanced_mpls_ldp impose interface + option ; mpls ldp router-id Loopback0 n’a pas ce dernier token'),
            ('Aiguillage de famille',1,'F0344:203 : bridge-domain 100 sous service instance ; motif advanced_l2_bridge existe mais seul interfaces est utilisé'),
            ('Motif d’un autre contexte',9,'3 shutdown de gatekeeper et 6 commandes PIM globales ; les motifs interface ne doivent pas être repris comme interprétation valide')]),
        '\nRépartition fonctionnelle de ces 582 positions (classification analytique, distincte des familles techniques du dispatcher) :\n',
        table(['Famille','Occurrences'],fam.most_common()),
        '\nLes plus fréquentes comprennent `no mop enabled` (32), `no mop sysid` (32), `stopbits 1` (28), `logging synchronous` (24), les timestamps debug/log (20 chacun) et les marqueurs boot-start/boot-end (20 chacun). Les **40 marqueurs de démarrage** pourraient légitimement être classés comme structure, après définition de la politique de comptage ; ce ne serait pas un gain de données sémantiques.\n',
        'Des fonctions utiles à l’audit restent aussi absentes : communautés BGP, réglages globaux BGP, source-route, lookup DNS, NetFlow et certains services de gestion. Prioriser selon les données attendues, au lieu d’ajouter 566 motifs pour augmenter un compteur. Corriger la variante LDP ou l’aiguillage ne fournirait pas à lui seul les champs de normalisation MPLS/L2 absents du contrat.\n',
        '[582 fiches JSON](uninterpreted_582.json) · [582 fiches CSV](uninterpreted_582.csv) · [Fréquences des 110 textes](uninterpreted_command_frequencies.csv) · [Familles et fichiers](uninterpreted_families.csv).\n',
        '## 5. Audit des 272 règles complémentaires\n',
        table(['Famille technique','Règles'],rule_fam.items()),
        '\n- **272/272 groupes correspondent exactement au catalogue** ; pas de dérive du générateur détectée.\n'
        '- **171 règles produisent au moins un candidat** sur les 20 fichiers ; **166 sont sélectionnées**, 5 ne sont que des alternatives non retenues et **101 ne produisent aucun candidat**. Les 106 règles jamais retenues ne sont donc pas toutes inactives.\n'
        '- **155 règles sont exécutées pendant les 54 tests existants**. Exécution ne signifie pas validation indépendante de chaque paramètre. Les faits relus indépendamment sont limités à 14 attentes sur 5 fichiers.\n'
        '- **43 règles utilisent ORPHRASE**, et de nombreuses variables sont de simples tokens sans domaine de valeurs. Cela convient à des descriptions, mais ne valide pas par exemple une vitesse Cisco ou une direction BGP.\n'
        '- Les groupes sont plats et traitent des lignes désindentées et numérotées. Les relations viennent du lexer/inventaire Python et du mapper ; elles ne sont pas construites par des groupes TTP hiérarchiques dans ces extensions. TTP sait exécuter d’autres organisations de templates ; ce résultat caractérise notre architecture locale.\n'
        '- Les 4 templates officiels tournent séparément sur l’entrée entière ; 84 usages documentés de champs officiels alimentent le mapping. Ils ne représentent pas une bibliothèque couvrant automatiquement toutes les fonctions Cisco.\n',
        'La sélection privilégie les mots-clés fixes, pénalise ORPHRASE, favorise certains ports/distances/séquences, applique des gardes sur les routes puis tranche par nom de règle en cas d’égalité. Ce mécanisme est cohérent avec les résultats rejoués, mais n’est pas une preuve de fidélité sémantique. Les [46 concurrences](candidate_collisions.csv) et le [catalogue annoté des 272 règles](rules_272.csv) sont joints.\n',
        'Deux cas synthétiques montrent les limites de précision à ne pas confondre avec des erreurs réelles du corpus : `speed potato` est capturé comme token sans être normalisé ; un protocole ACL arbitraire passe le template et le champ ouvert protocol:str du contrat. À l’inverse, `mtu 1` est capturé puis rejeté par la validation de plage. Les validations sont donc réparties et incomplètes selon le champ.\n',
        '## 6. Rattachements hiérarchiques et sens du statut normalisé\n',
        'Les **876 contrôles d’identité et de portée examinés passent** : 435 preuves d’interface, 211 de clause route-map, 158 de voisin/groupe BGP et VRF, 70 d’ACL et 2 contrôles de non-élargissement de portée AF. Les adresses IPv6 sont comparées comme adresses, pour ne pas confondre casse ou compression avec un autre voisin. Ce sont des contrôles de rattachement des preuves ciblées, pas 876 faits métier indépendants ni une certification exhaustive des relations.\n',
        'Les contrôles supplémentaires confirment que les paramètres de service-instance ne remplacent pas ceux de l’interface physique, que deux VRF peuvent conserver le même voisin avec des AS distincts, que les clauses d’ACL/route-map restent séparées et que les politiques BGP par AF sont conservées nativement sans être élargies à un champ global. Une commande inconnue d’interface ne casse pas la capture de l’adresse suivante dans le cas testé. L’inventaire dépend toutefois de l’indentation et de règles de familles explicites.\n',
        '**normalized_values signifie au moins un champ mappé, pas commande entièrement interprétée.** Un contrôle hors corpus avec une direction BGP arbitraire montre que le mapper peut prouver le voisin, ignorer la direction non admise et créditer malgré tout la ligne comme normalisée. Les 1 148 positions ne doivent donc pas être présentées comme 1 148 commandes sémantiquement complètes. Ce cas n’est pas attribué aux fichiers réels.\n',
        '[Contrôles de rattachement](hierarchy_checks.json) · [13 observations contrôlées](controlled_probes.json) · [Exécution des règles pendant les tests](test_rule_execution.json).\n',
        '## 7. Les 440 positions opaques sont-elles un défaut ?\n',
        'Elles correspondent à **22 blocs réels : 14 corps de certificats PKI (364 lignes) et 8 corps de bannières (76 lignes)**. Les 22 empreintes de contenu sont vérifiées contre le fichier original. Les en-têtes de trustpoint/chaîne/certificat sont séparés et capturés ; 92 déclarations ou métadonnées PKI restent parmi les 777 faute de modèle normalisé adapté. Les `quit` ferment les certificats dans l’inventaire.\n',
        'Traiter ces corps en objets opaques est cohérent avec l’objectif d’audit et évite d’interpréter des mots d’une bannière comme des commandes. Il faut mesurer leur conservation et leurs métadonnées, pas les transformer en 440 échecs d’extraction de paramètres. Une analyse X.509 pourrait constituer une fonction distincte si elle devient nécessaire ; elle n’est pas réalisée ici. [Inventaire des blocs](opaque_blocks.csv).\n',
        '## 8. Fiches de diagnostic et répartition par fichier\n',
        'Les **1 359 fiches** couvrent 777 positions extraites non mappées et 582 positions sans extraction retenue. Chaque fiche contient commande source, règle éventuelle, paramètres exportés, contexte, champ normalisé éventuel, étape de défaillance, cause, constantes manquantes et statut de vérification de trace. La fidélité de chaque paramètre n’est pas certifiée par un oracle indépendant ; ce statut est explicite.\n',
        table(['Fichier','Extraites non mappées','Non interprétées','Constantes absentes dans toutes ses captures'],[(r['file_id'],r['extracted_unmapped'],r['uninterpreted'],r['missing_constant_fields']) for r in files]),
        '\n[Rapport HTML filtrable](RAPPORT_DIAGNOSTIC.html) · [1 359 fiches JSON](diagnostic_occurrences_1359.json) · [1 359 fiches CSV](diagnostic_occurrences_1359.csv). Les champs de constante sont un défaut secondaire qui recoupe plusieurs statuts ; ne pas ajouter leurs 359 occurrences aux 1 359 fiches.\n',
        '## 9. Ordre de travail recommandé, sans l’appliquer ici\n',
        '1. Corriger la matérialisation des constantes dans les templates numérotés ; rendre le masquage de l’export natif sensible aux types de champs ; séparer le login logging global. Tester la fidélité native indépendamment du mapper.\n'
        '2. Conserver des compteurs distincts : candidat brut, record retenu, paramètres validés, champs mappés, commande partielle et blocs opaques. Éviter un unique pourcentage de « couverture » présenté comme précision.\n'
        '3. Ajouter les mappings déjà compatibles avec v0.1, avec preuves explicites, puis définir une révision du contrat pour les fonctions effectivement nécessaires à l’audit.\n'
        '4. Développer les variantes et templates manquants après tri fonctionnel des 582 positions ; contrôler les contextes et les conflits de motifs avec des attentes indépendantes.\n'
        '5. Réévaluer ensuite TTP sur ces mêmes configurations. Rien dans cet audit ne justifie de remplacer le moteur pour résoudre des champs ou des relations absents du modèle. Cela ne garantit pas non plus qu’un catalogue de templates couvrira tout Cisco sans travail supplémentaire.\n',
        '## Reproduction et sources\n',
        'Depuis le sous-projet :\n\n```powershell\n.\\.venv\\Scripts\\python.exe tools/audit_pipeline.py\n.\\.venv\\Scripts\\python.exe tools/probe_pipeline_diagnostics.py\n.\\.venv\\Scripts\\python.exe tools/report_pipeline_diagnostic.py\n```\n',
        'Ces scripts d’analyse écrivent uniquement dans `outputs/diagnostic_pipeline`, hors caches Python/TTP. Ils n’exécutent pas le générateur de templates et ne réécrivent aucun résultat de corpus. [Empreintes avant/après](integrity.json) · [Synthèse vérifiable](summary.json) · [Résultats pytest](regression_tests.xml).\n',
        refs+'\n',
    ]
    (OUT/'RAPPORT_DIAGNOSTIC.md').write_text('\n'.join(parts),encoding='utf-8')


def report_html(s,rows,rules,stages):
    esc=lambda x:html.escape(str(x),quote=True)
    stage_table=''.join(f'<tr><td>{esc(LABELS[k])}</td><td>{v}</td></tr>' for k,v in stages.most_common())
    options=''.join(f'<option value="{esc(k)}">{esc(LABELS[k])} ({v})</option>' for k,v in stages.most_common())
    files=sorted({r['file_id'] for r in rows});file_options=''.join(f'<option>{f}</option>' for f in files)
    dataset=json.dumps(dict(rows=rows,rules=rules,labels=LABELS),ensure_ascii=False).replace('<','\\u003c').replace('\u2028','\\u2028').replace('\u2029','\\u2029')
    page=r'''<!doctype html><html lang="fr"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Diagnostic de la chaîne TTP</title>
<style>body{margin:0;background:#f3f6fa;color:#16283e;font:16px/1.55 system-ui,sans-serif}main{max-width:1450px;padding:32px;margin:auto}h1{line-height:1.2}h2{margin-top:2em}.box{background:white;padding:20px;border:1px solid #d7e0eb;border-radius:12px;margin:18px 0}.metrics{display:flex;gap:12px;flex-wrap:wrap}.metrics div{background:#173655;color:white;border-radius:10px;padding:16px;flex:1;min-width:150px}.metrics b{font-size:30px;display:block}table{border-collapse:collapse;width:100%;background:white}th,td{padding:11px;border-bottom:1px solid #dbe3ed;vertical-align:top;text-align:left}th{background:#e7eef7}code,pre{font:13px/1.5 ui-monospace,Consolas,monospace;white-space:pre-wrap;overflow-wrap:anywhere}pre{background:#f0f4f9;padding:12px}.wrap{overflow-x:auto}.filters{display:flex;gap:12px;flex-wrap:wrap;align-items:end}.filters label{display:flex;flex-direction:column;flex:1;min-width:175px}input,select,button{font:inherit;padding:9px;border:1px solid #b6c6d9;border-radius:6px;max-width:100%}summary{cursor:pointer;color:#185c99}details{margin-top:9px}a{color:#165b9c}.toolbar{display:flex;gap:12px;align-items:center;flex-wrap:wrap}small{color:#53677e}.grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}@media(max-width:900px){main{padding:16px}.grid{grid-template-columns:1fr}}</style>
<main><h1>Diagnostic de notre chaîne TTP</h1><p>Inspection des sources, captures natives, mappings et JSON finaux. <strong>Aucune correction de production appliquée.</strong></p>
<div class="metrics"><div><b>20/20</b>sorties natives et normalisées reproduites à l’identique</div><div><b>1 359</b>fiches : 777 extraites + 582 non interprétées</div><div><b>359</b>constantes absentes des captures</div><div><b>54 + 13</b>tests existants et observations contrôlées confirmées</div></div>
<section class="box"><h2 style="margin-top:0">Le moteur TTP n’est pas démontré en échec</h2><p>Le contrat ne représente pas fidèlement 737 occurrences. Des mappings restent à écrire, mais il existe aussi un défaut local de template : le <code>set()</code> de match perd sa constante quand on ajoute le champ de numéro de ligne. Le même moteur fournit correctement la constante avec les templates de contrôle.</p><p><strong>Les compteurs se réconcilient :</strong> 1 995 captures = 1 148 normalisées + 777 non mappées + 70 structures/métadonnées capturées.</p><p>Les 440 positions opaques correspondent à 22 blocs (14 certificats, 8 bannières) dont les empreintes sont vérifiées. Elles ne constituent pas 440 commandes métier échouées.</p><p><a href="RAPPORT_DIAGNOSTIC.md">Rapport complet et preuves</a> · <a href="diagnostic_occurrences_1359.csv">1 359 fiches CSV</a> · <a href="rules_272.csv">272 règles CSV</a> · <a href="controlled_probes.json">Observations contrôlées</a> · <a href="summary.json">Synthèse des contrôles</a></p></section>
<div class="grid"><section><h2>Causes principales des 1 359 positions</h2><table><thead><tr><th>Cause</th><th>Occurrences</th></tr></thead><tbody>STAGE_TABLE</tbody></table></section><section class="box"><h2 style="margin-top:0">Ce que ces résultats prouvent</h2><p>Les fichiers et traces correspondent aux résultats archivés. Les 876 contrôles ciblés de rattachement passent. Ils ne certifient pas tous les paramètres ni toutes les relations.</p><p><code>normalized_values</code> veut dire « au moins un champ mappé », pas « commande entièrement interprétée ». Les défauts de constantes recoupent plusieurs statuts : ne pas ajouter 359 aux 1 359 occurrences.</p><p>Sur les 272 règles : 171 produisent un candidat, 166 sont retenues, 101 n’ont aucun candidat. 155 sont exécutées pendant les tests, ce qui n’équivaut pas à une validation de chacun de leurs paramètres.</p><p><strong>Priorité :</strong> corriger l’export natif et les constantes, clarifier le modèle et les mappings, puis compléter le catalogue selon les besoins d’audit.</p></section></div>
<h2>Explorer les fiches de diagnostic</h2><div class="box filters"><label>Recherche<input id="q" type="search" placeholder="Commande, règle, contexte…"></label><label>Cause<select id="cause"><option value="">Toutes les causes</option>CAUSE_OPTIONS</select></label><label>Fichier<select id="file"><option value="">Tous les fichiers</option>FILE_OPTIONS</select></label><label>Statut<select id="status"><option value="">Les deux groupes</option><option value="extracted_unmapped">Extraites non mappées (777)</option><option value="preserved_uninterpreted">Non interprétées (582)</option></select></label><button id="reset">Réinitialiser</button></div>
<div class="toolbar"><span id="count" role="status"></span><button id="prev">Précédent</button><button id="next">Suivant</button><label>Par page <select id="size"><option>25</option><option selected>50</option><option>100</option></select></label></div><div class="wrap"><table><thead><tr><th>Source</th><th>Commande, capture et contexte</th><th>Étape principale</th></tr></thead><tbody id="rows"></tbody></table></div>
<h2>Les 272 règles : précision et exercice observé</h2><p>Les patterns sont affichés tels qu’ils existent. Un champ libre ou ORPHRASE n’est pas forcément incorrect, mais son sens doit être contrôlé ailleurs. La sélection dans un test ne garantit pas une attente indépendante sur tous les champs.</p><label>Filtrer les règles <input id="ruleq" type="search" placeholder="Identifiant, famille ou pattern"></label><div class="wrap"><table><thead><tr><th>Règle / famille</th><th>Pattern existant</th><th>Candidats / retenues</th><th>Exécutée pendant les tests</th></tr></thead><tbody id="rules"></tbody></table></div>
<p>Rapport reproductible par les trois scripts indiqués dans le rapport Markdown. Sources, templates et contrat sont inchangés.</p></main><script id="dataset" type="application/json">DATASET</script>
<script>
const data=JSON.parse(document.getElementById('dataset').textContent), all=data.rows; let page=0;
const $=id=>document.getElementById(id), el=(name,text)=>{const n=document.createElement(name);if(text!==undefined)n.textContent=text;return n;};
const searches=all.map(r=>JSON.stringify(r).toLocaleLowerCase('fr'));
function render(){const q=$('q').value.toLocaleLowerCase('fr'),cause=$('cause').value,file=$('file').value,status=$('status').value;const filtered=all.filter((r,i)=>(!q||searches[i].includes(q))&&(!cause||r.failure_stage===cause)&&(!file||r.file_id===file)&&(!status||r.coverage_status===status));const size=Number($('size').value);page=Math.min(page,Math.max(0,Math.ceil(filtered.length/size)-1));$('rows').replaceChildren();
for(const r of filtered.slice(page*size,(page+1)*size)){const tr=el('tr'),src=el('td'),a=el('a',r.file_id);a.href='../../'+r.config_file;src.append(a,el('div','Ligne '+r.line));const body=el('td');body.append(el('code',r.source_command),el('div',r.ttp_rule||'Aucune règle retenue'));const detail=el('details');detail.append(el('summary','Capture, contexte et diagnostic'),el('h4','Extraction native exportée'),el('pre',r.native_extraction===null?'Aucune capture retenue':JSON.stringify(r.native_extraction,null,2)),el('h4','Contexte source'),el('pre',r.context.length?r.context.map(c=>'L'+c.line+' '+c.text).join('\n'):'Global'),el('h4','Diagnostic'),el('p',r.diagnosis),el('h4','Champ normalisé / cible'),el('pre',r.normalized_field?JSON.stringify(r.normalized_field):'Aucun champ normalisé à cette position'),el('p',r.target||'Champ à définir selon le besoin d’audit'),el('h4','Constantes attendues mais absentes'),el('pre',JSON.stringify(r.missing_constant_fields,null,2)));if(r.other_family_pattern_matches&&r.other_family_pattern_matches.length)detail.append(el('h4','Motifs d’autres familles : non adoptés'),el('pre',JSON.stringify(r.other_family_pattern_matches,null,2)));detail.append(el('small','Trace source/native/mapping vérifiée ; fidélité sémantique exhaustive non certifiée.'));body.append(detail);tr.append(src,body,el('td',data.labels[r.failure_stage]));$('rows').append(tr);}
$('count').textContent=filtered.length+' occurrence(s) · page '+(filtered.length?page+1:0)+' / '+Math.ceil(filtered.length/size);$('prev').disabled=page===0;$('next').disabled=(page+1)*size>=filtered.length;}
for(const id of ['q','cause','file','status','size'])$(id).addEventListener('input',()=>{page=0;render();});$('reset').addEventListener('click',()=>{for(const id of ['q','cause','file','status'])$(id).value='';page=0;render();});$('prev').addEventListener('click',()=>{page--;render();});$('next').addEventListener('click',()=>{page++;render();});
function renderRules(){const q=$('ruleq').value.toLocaleLowerCase('fr');$('rules').replaceChildren();for(const r of data.rules){if(q&&!JSON.stringify(r).toLocaleLowerCase('fr').includes(q))continue;const tr=el('tr'),pattern=el('td');pattern.append(el('code',r.pattern));const flags=[];if(r.set_variables.length)flags.push('set() : matérialisation à corriger');if(r.orphrase_variables.length)flags.push('ORPHRASE : texte libre');if(r.untyped_variables.length)flags.push('variables sans validation de domaine');pattern.append(el('div',flags.join(' · ')));tr.append(el('td',r.id+' / '+r.family),pattern,el('td',r.raw_candidate_occurrences+' / '+r.selected_occurrences),el('td',r.selected_during_existing_tests?'oui — pas une preuve exhaustive':'non observée'));$('rules').append(tr);}}$('ruleq').addEventListener('input',renderRules);render();renderRules();
</script></html>'''
    values=dict(STAGE_TABLE=stage_table,CAUSE_OPTIONS=options,FILE_OPTIONS=file_options,DATASET=dataset)
    page=re.sub('|'.join(values),lambda m:values[m.group()],page)
    (OUT/'RAPPORT_DIAGNOSTIC.html').write_text(page,encoding='utf-8')


if __name__=='__main__':main()
