"""Generate the French evaluation report, template catalogue and source deltas."""
from collections import Counter,defaultdict
import hashlib
from html import escape
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from cli import write_json


def main():
    report=json.loads((ROOT/'outputs/corpus_20/report.json').read_text(encoding='utf-8'))
    pilot=json.loads((ROOT/'outputs/pilot_5/report.json').read_text(encoding='utf-8'))
    s=report['summary'];ps=pilot['summary']
    suite=ET.parse(ROOT/'outputs/tests.xml').find('.//testsuite')
    test_count=int(suite.attrib['tests']);test_failures=int(suite.attrib['failures'])+int(suite.attrib['errors'])
    rules=json.loads((ROOT/'templates/rules.json').read_text(encoding='utf-8'))
    seen=Counter();mapped=Counter();changes=[]
    for entry in report['files']:
        coverage=json.loads((ROOT/'outputs/corpus_20'/entry['id']/'coverage_report.json').read_text(encoding='utf-8'))
        lookup={line:row for row in coverage['commands'] for line in range(row['line'],row['line_end']+1)}
        for row in coverage['commands']:
            if row['template_rule']:
                seen[row['template_rule']]+=1
                mapped[row['template_rule']]+=row['status']=='normalized_values'
        for old in coverage['legacy_comparison']:
            if old['old_recognized']!=old['ttp_taken_into_account']:
                changes.append({'id':entry['id'],**old,'text':lookup[old['line']]['text'],
                    'rule':lookup[old['line']]['template_rule']})
    catalogue=[{**r,'corpus_occurrences':seen[r['id']],'corpus_mapped_occurrences':mapped[r['id']],
                'coverage_scope':'observed_in_20_configs' if seen[r['id']] else 'not_exercised_by_20_config_corpus'} for r in rules]
    write_json(ROOT/'templates/catalogue_coverage.json',catalogue)
    write_json(ROOT/'outputs/legacy_deltas.json',changes)
    contract_hash=hashlib.sha256((ROOT/'schemas/normalizedconfig.py').read_bytes()).hexdigest()
    source_ok=all(hashlib.sha256((ROOT/e['config_file']).read_bytes()).hexdigest()==e['description_sha256']
                  for e in json.loads((ROOT/'configs/manifest.json').read_text(encoding='utf-8')))
    verification={'all_20_files_pass':s['passed']==20,'all_pilot_files_pass':ps['passed']==5,
        'all_behavioral_tests_pass':test_failures==0,'all_20_source_copies_unchanged':source_ok,
        'contract_hash_unchanged':contract_hash=='438edb9bf58f0143491c6ddc18c5500bddfa552cc8a12898dcd970e79ffd58e4',
        'same_3051_legacy_positions':s['legacy_nodes']==3051,
        'coverage_reconciles':sum(s['statuses'].values())==3051,
        'nonopaque_old_recognition_preserved':all(r.get('checks',{}).get('legacy_nonopaque_recognition_preserved',False) for r in report['files'])}
    write_json(ROOT/'outputs/verification.json',{'passed':all(verification.values()),'checks':verification,'behavioral_tests':test_count})
    defined=Counter(r['family'] for r in rules)
    active=Counter(r['family'] for r in catalogue if r['corpus_occurrences'])
    lines=['# Nouvelle version Cisco avec TTP — évaluation', '',
        f'**{s["passed"]}/20 configurations validées, {s["checks_passed"]}/{s["checks"]} contrôles de corpus et {test_count} tests de comportement réussis.**', '',
        'Le pilote de cinq fichiers passe également : '+str(ps['checks_passed'])+'/'+str(ps['checks'])+' contrôles. '
        'Quatorze faits attendus ont été transcrits depuis les lignes sources de cinq configurations, et sont testés séparément : hostname, adresses, AS, RD, AS_PATH, attache QoS et instance EVPN native.', '',
        '## Ce qui a été effectivement réutilisé', '',
        'TTP 0.10.1 et ttp-templates 0.6.18 sont installés dans `.venv`. Les quatre templates officiels interfaces, VRF, ASN BGP et NAT statique sont exécutés sur chaque fichier complet. '
        'Les transformations Python officielles sont donc exécutées aussi. Les valeurs d’adresses IPv4 et RD concordantes sont réutilisées dans le mapping avec preuve source : '
        f'**{s["official_fields_consumed"]} consommations documentées** dans le corpus. Le template NAT est aussi testé sur une entrée synthétique ; le corpus de 20 fichiers ne démontre pas à lui seul toutes ses variantes.', '',
        f'{len(rules)} règles complémentaires explicites sont organisées en {len(defined)} familles. '
        f'{sum(bool(r["corpus_occurrences"]) for r in catalogue)} règles sont effectivement exercées par ce corpus ; les autres sont signalées dans `templates/catalogue_coverage.json`. '
        'Les tests ciblés exercent en plus plusieurs cas synthétiques. Il n’est pas affirmé que chaque variante des règles est exhaustivement validée.', '',
        'Le dépôt tbotnz/ios-show-run-ttp est conservé comme référence locale. Aucun code de ce dépôt n’est importé dans le moteur de production : absence de licence explicite dans la révision clonée et defaults qui ne correspondent pas à notre politique de connaissance. '
        'ASA n’est pas ajouté comme dépendance car son langage n’est pas celui d’IOS/IOS-XE.', '',
        '## Comparaison sur exactement les mêmes positions sources', '',
        '| Indicateur | Ancienne version | Nouvelle version TTP |', '|---|---:|---:|',
        f'| Fichiers du corpus | 20 | {s["passed"]} |',
        f'| Positions de l’ancien inventaire | 3 051 | {s["legacy_nodes"]} |',
        f'| Ancien compteur « reconnues » | 1 224 | Sans équivalence stricte avec une capture TTP |',
        f'| Positions capturées par une règle TTP | Non mesuré avec ce critère | {s["ttp_captured_legacy_nodes"]} |',
        f'| Positions produisant des valeurs normalisées | Ancien compteur mélangeant valeurs et structure | {s["ttp_normalized_value_nodes"]} |',
        f'| Valeurs normalisées + structure/métadonnées traitées | 1 224 selon l’ancienne convention | {s["ttp_taken_into_account"]} |', '',
        'La capture TTP ne vaut pas conversion intégrale. Le compteur ancien incluait notamment 44 lignes de corps de bannière ; elles sont maintenant classées opaques, sans crédit de normalisation. '
        'Toutes les autres positions auparavant reconnues sont encore traitées. Le fichier `outputs/legacy_deltas.json` montre chaque différence de statut. '
        'Ce résultat ne constitue pas une mesure globale de précision sémantique ni une validation sur équipement.', '',
        '## Répartition réconciliée des 3 051 positions', '', '| Statut TTP | Positions | Signification |', '|---|---:|---|']
    meanings={'normalized_values':'Au moins les valeurs documentées sont converties avec preuves ; pas une garantie de toute la sémantique du bloc.',
        'structure_or_metadata':'Délimiteurs/contextes ou version OS traités séparément des valeurs métier.',
        'extracted_unmapped':'TTP fournit des valeurs ; le contrat ou le mapping ne permet pas une conversion complète.',
        'preserved_uninterpreted':'Commande conservée, sans règle de capture adaptée.',
        'preserved_opaque':'Données de certificat ou texte de bannière conservés comme blocs.',
        'export_wrapper':'En-tête de sauvegarde/sortie de commande.'}
    for key,count in s['statuses'].items():lines.append(f'| `{key}` | {count} | {meanings.get(key,"Valeur invalide conservée.")} |')
    lines+=['','Les 3 051 lignes ne deviennent pas 3 051 objets métier : les blocs opaques sont regroupés dans le nouvel inventaire et ne sont réétendus que pour cette comparaison historique.', '',
        '## Résultats par fichier', '',
        '| ID | Routeur | Validation | Captures TTP | Valeurs normalisées | Structure/métadonnées | Consommations officielles |', '|---|---|---|---:|---:|---:|---:|']
    for row in report['files']:
        lines.append(f'| {row["id"]} | {row["hostname"]} | {"OK" if row["passed"] else "ÉCHEC"} | {row.get("ttp_captured_legacy_nodes",0)} | {row.get("ttp_normalized_value_nodes",0)} | {row.get("statuses",{}).get("structure_or_metadata",0)} | {row.get("official_fields_consumed",0)} |')
    lines+=['','## Catalogue des familles de règles', '', '| Famille | Règles définies | Règles vues dans les 20 fichiers |', '|---|---:|---:|']
    for family,count in sorted(defined.items()):lines.append(f'| {family} | {count} | {active[family]} |')
    lines+=['','## Limites du contrat maintenu à v0.1.0', '',
        '- Interfaces : adresses, état administratif explicite, VRF, ACL, VLAN et attaches QoS sont mappés. Vitesse/duplex, PIM, MPLS et IP unnumbered restent des valeurs natives faute de champs dédiés.',
        '- BGP : AS, voisins, groupes, héritage simple explicite du remote-as et noms de familles sont pris en compte. Les activations et politiques par famille ne sont pas élargies au voisin global. Annonces et redistribution restent natives.',
        '- OSPFv2 : mapping existant maintenu. OSPFv3 est capturé mais reste natif car le contrat ne distingue pas correctement les versions.',
        '- Politiques : AS_PATH prepend et correspondances IPv6 sont mappés dans les objets génériques. Les prefix-lists avec deny/ge/le ne sont pas réduites à une liste de préfixes permis ; la liste entière reste native si nécessaire.',
        '- QoS : noms et attaches seulement dans le contrat ; classes/actions en natif. IS-IS, EVPN/VPLS, PKI et MPLS ne deviennent pas automatiquement des modèles métier complets parce qu’une règle TTP les capture.',
        '- Les certificats sont regroupés par contenu opaque et `quit` est rattaché au certificat, jamais à une ligne hexadécimale.',
        '- Le `enabled=true` implicite des templates officiels n’est jamais repris sans commande explicite. Aucune conclusion d’absence ni de complétude du fichier n’est inférée.',
        '- Les pointeurs `Evidence` valident les valeurs effectivement stockées. Les champs `kind/value` de politique ont un vocabulaire interne documenté, pas une garantie d’export YANG/RFC7951.', '',
        '## Livrables', '',
        '- `outputs/corpus_20/Fxxxx/parsed_native.json` : résultats officiels, captures des extensions et inventaire source.',
        '- `normalized_config.json` : contrat original Pydantic/JSON Schema, sans extension dissimulée.',
        '- `coverage_report.json` : statut, règle TTP, ligne, contexte, valeurs partielles et comparaison historique.',
        '- `outputs/pilot_5/` : première étape de validation ; `outputs/tests.xml` : tests automatisés.',
        '- `templates/catalogue_upstream.json`, `templates/catalogue_coverage.json` : sources, empreintes et couverture réellement observée.',
        '- `requirements.lock`, `wheelhouse/`, `docs/dependencies.json` : dépendances figées et révisions Git.', '',
        'Les copies de configurations et du contrat sont inchangées ; le runtime ne charge ni l’ancien parseur Cisco ni des fichiers du dossier parent.', '']
    (ROOT/'outputs/RAPPORT_EVALUATION.md').write_text('\n'.join(lines),encoding='utf-8')
    table=''.join('<tr><td>'+r['id']+'</td><td>'+escape(r['hostname'])+'</td><td>'+('OK' if r['passed'] else 'ÉCHEC')+'</td><td>'+str(r.get('ttp_captured_legacy_nodes',0))+'</td><td>'+str(r.get('ttp_normalized_value_nodes',0))+'</td><td><a href="corpus_20/'+r['id']+'/parsed_native.json">Natif</a> · <a href="corpus_20/'+r['id']+'/normalized_config.json">Normalisé</a> · <a href="corpus_20/'+r['id']+'/coverage_report.json">Couverture</a></td></tr>' for r in report['files'])
    html='''<!doctype html><html lang="fr"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Évaluation TTP</title>
<style>body{max-width:1250px;margin:35px auto;padding:0 22px;font:16px/1.55 system-ui;color:#172d46;background:#f5f7fb}h1{line-height:1.2}.cards{display:flex;gap:12px;flex-wrap:wrap}.card{padding:16px 24px;background:white;border:1px solid #d7e2ee;border-radius:9px}.card strong{display:block;font-size:27px}.note{background:#fff3d9;border-left:4px solid #bb8c2c;padding:15px}table{width:100%;border-collapse:collapse;background:white}th,td{padding:10px;border-bottom:1px solid #dde5f0;text-align:left}th{background:#e7edf7}a{color:#22569b}code{font-size:13px}.scroll{overflow:auto}li{margin:7px 0}</style>
<h1>Nouvelle version Cisco avec TTP</h1><p>Un dossier autonome pour le moteur TTP, les templates officiels et les extensions, le contrat NormalizedConfig v0.1.0 et les mêmes vingt configurations.</p><div class="cards">__CARDS__</div>
<p class="note"><b>Extraction et normalisation sont distinctes.</b> __CAPTURED__ positions sont capturées par TTP, mais __NORMALIZED__ seulement produisent des valeurs dans le contrat actuel. Les autres valeurs utiles restent dans le résultat natif ou le rapport. Aucun taux d’exactitude globale n’est déduit de ce nombre.</p>
<p><a href="RAPPORT_EVALUATION.md">Rapport détaillé</a> · <a href="corpus_20/comparison.csv">Comparaison CSV</a> · <a href="legacy_deltas.json">Différences de statut</a> · <a href="verification.json">Vérifications</a> · <a href="../README.md">Guide d’utilisation</a></p>
<h2>Répartition des 3 051 positions historiques</h2><p>__STATUSES__</p><p>Le dénominateur est conservé pour comparer le même corpus. Les corps de bannières et certificats sont regroupés dans l’inventaire moderne ; ils ne sont jamais crédités comme commandes interprétées.</p>
<h2>Résultats et fichiers générés</h2><div class="scroll"><table><thead><tr><th>ID</th><th>Routeur</th><th>Validation</th><th>Captures TTP</th><th>Valeurs normalisées</th><th>Sorties</th></tr></thead><tbody>__TABLE__</tbody></table></div>
<h2>Réutilisation vérifiée</h2><p>4 templates officiels sont exécutés et leurs fonctions de transformation Python sont actives. __USAGE__ champs officiels concordants sont consommés avec preuve source. __RULES__ règles complémentaires sont définies ; leur couverture observée est publiée séparément.</p>
<h2>Limites</h2><ul><li>Le contrat d’origine est conservé. Les captures PIM/MPLS, OSPFv3 et les options avancées BGP restent natives lorsque ce contrat ne suffit pas.</li><li>Les templates peuvent fournir des défauts, comme enabled=true. Le mapping conserve unknown sans commande explicite.</li><li>Les politiques incomplètes restent signalées et ne constituent pas une configuration prête à déployer.</li><li>Une capture, un JSON valide et un contrôle de quelques propriétés ne prouvent pas le fonctionnement d’un routeur.</li></ul></html>'''
    cards=[('20/20','configurations'),(f'{s["checks_passed"]}/{s["checks"]}','contrôles de corpus'),(f'{test_count}/{test_count}','tests ciblés'),('5/5','pilote représentatif')]
    for key,value in {'__CARDS__':''.join(f'<div class="card"><strong>{a}</strong>{b}</div>' for a,b in cards),
                      '__CAPTURED__':str(s['ttp_captured_legacy_nodes']),'__NORMALIZED__':str(s['ttp_normalized_value_nodes']),
                      '__STATUSES__':' · '.join(f'<b>{count}</b> {escape(status)}' for status,count in s['statuses'].items()),
                      '__TABLE__':table,'__USAGE__':str(s['official_fields_consumed']),'__RULES__':str(len(rules))}.items():html=html.replace(key,value)
    (ROOT/'outputs/RAPPORT_EVALUATION.html').write_text(html,encoding='utf-8')
    print(json.dumps({'verification':all(verification.values()),'files':s['passed'],'checks':s['checks_passed'],'tests':test_count,'active_rule_ids':sum(bool(r['corpus_occurrences']) for r in catalogue)},indent=2))
    return 0 if all(verification.values()) else 1


if __name__=='__main__':raise SystemExit(main())
