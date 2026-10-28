"""Build redacted local deliverables and aggregate-only versioned documentation."""
from collections import Counter,defaultdict
import csv
import json
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tools.catalogue_audit import OUT,CORPUS,discover,write
from parser.inventory import redacted


def md(name,content):
    (OUT/name).write_text(content+'\n',encoding='utf-8')


def main():
    load=lambda name:json.loads((OUT/name).read_text(encoding='utf-8'))
    manifest=load('CORPUS_MANIFEST.json');base=load('BASELINE_COVERAGE.json');final=load('FINAL_COVERAGE.json')
    before=load('BASELINE_OCCURRENCES.json');after=load('FINAL_OCCURRENCES.json');verify=load('INDEPENDENT_VERIFICATION.json')
    assert [(r['file'],r['sha256']) for r in discover()]==[(r['file'],r['sha256']) for r in manifest]
    assert not base['failures'] and not final['failures'] and not verify['failures'] and not final['official_template_errors']
    protected=['docs/cisco-command-inventory','docs/deferred','tests/oracle_v02.py','tests/reviewed_source_facts.json','tests/source_oracle.py','schemas']
    subprocess.run(['git','diff','--exit-code','0a94e30','--',*protected],cwd=ROOT,check=True,capture_output=True)
    tests=ET.parse(OUT/'final_tests.xml').getroot().find('testsuite').attrib
    assert int(tests['failures'])==int(tests['errors'])==0
    branch=subprocess.check_output(['git','branch','--show-current'],cwd=ROOT,text=True).strip()
    old_rules={r['id']:r for r in json.loads(subprocess.check_output(['git','show','0a94e30:templates/rules.json'],cwd=ROOT))}
    rules={r['id']:r for r in json.loads((ROOT/'templates/rules.json').read_text())}
    additions=rules.keys()-old_rules.keys()
    deferred=json.loads((ROOT/'docs/deferred/reliability_rules.json').read_text())
    by_key={(r['file'],r['line']):r for r in after};ids={r['file']:r['id'] for r in manifest}
    frequencies=Counter((r['family'],r['command']) for r in before if r['category'] not in ('correctly_normalized','opaque_or_structural'))
    def reason(r):
        if r['category']=='unrecognized':return 'logging synchronous global : aucun parent line ; ne pas inventer un contexte.'
        if r['category']=='partially_normalized':return 'Expression Cisco expanded-regex conservée exactement avec son dialecte ; validation de sa sémantique non implémentée.'
        if r['rule'] in ('bgp_no_sync','bgp_no_auto_summary'):return 'Option locale à une address-family : le schéma ne possède ce champ typé qu’au niveau processus ; conservation native avec parents.'
        if r['category']=='captured_unmapped':return 'Paramètres et parents conservés dans cisco.observations ; mapping typé ou validation sémantique complète absent.'
        if r['category']=='opaque_or_structural':return 'Marqueur d’export ou bloc opaque ; exclu des commandes métier.'
        return 'Capture validée et mapping typé avec preuve de source.'
    with (OUT/'MISSING_COMMANDS.csv').open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.writer(f);w.writerow(['file','line','line_end','parent_context','observed_syntax_redacted','frequency','initial_status','active_ttp_rule','final_status','justification'])
        for row in before:
            if row['category'] in ('correctly_normalized','opaque_or_structural'):continue
            now=by_key[(row['file'],row['line'])]
            w.writerow([row['file'],row['line'],row['line_end'],' > '.join(now['context']),redacted(row['command']),frequencies[(row['family'],row['command'])],row['category'],now['rule'],now['category'],reason(now)])
    versions=Counter(r['version_token'] or 'non imprimée' for r in manifest if r['status']=='included');platforms=Counter()
    for r in manifest:
        if r['status']!='included':continue
        text=(CORPUS/r['file']).read_text(encoding='utf-8-sig')
        for match in re.finditer(r'^license udi pid (\S+)',text,re.M):platforms[match[1]]+=1
    inventory=[f'# Inventaire du corpus\n\n174 fichiers lus récursivement, sans filtre d’extension : 85 configurations IOS/IOS-XE retenues, 64 IOS-XR exclues, 25 documents exclus. Aucun fichier ambigu restant selon les signatures observées. Les exclusions XR incluent les exports sans bannière explicite, identifiés par leur syntaxe native. Aucun commutateur exclusif, NX-OS ou ASA identifié dans ce corpus.\n',
        'Les signatures ne constituent pas une preuve de compatibilité matérielle. Les numéros version sont ceux imprimés par les exports ; les trains/releases et licences complets ne sont pas toujours présents. Aucune validation sur équipement.\n',
        'Versions imprimées : '+json.dumps(dict(versions),ensure_ascii=False)+'.\n',
        'PID explicitement imprimés (sans numéro de série) : '+json.dumps(dict(platforms),ensure_ascii=False)+'. Les autres plateformes restent non attestées ; ne pas déduire une couverture ISR/ASR/Catalyst 8000 complète.\n',
        'Familles d’inventaire, incluant les nœuds structuraux : '+json.dumps(final['families'],ensure_ascii=False)+'. Les fonctionnalités absentes ne reçoivent aucune garantie de couverture.\n',
        '| ID | Fichier relatif à catalogue | Statut | Version | SHA-256 | Justification |','|---|---|---|---|---|---|']
    for r in manifest:inventory.append(f"| {r['id']} | {r['file']} | {r['status']} | {r['version_token'] or 'inconnue'} | {r['sha256']} | {r['reason']} |")
    md('CORPUS_INVENTORY.md','\n'.join(inventory))
    comparable=Counter(r['category'] for r in before if by_key[(r['file'],r['line'])]['category']!='opaque_or_structural')
    business=sum(v for k,v in final['counts'].items() if k!='opaque_or_structural')
    stats=dict(branch=branch,baseline_commit='0a94e30',files=174,included=85,excluded_iosxr=64,excluded_documents=25,physical_lines=16719,inventory_nodes=8263,business_commands=business,
        baseline_original_counts=base['counts'],baseline_comparable_counts=dict(comparable),final_counts=final['counts'],baseline_active_rules=len(old_rules),final_active_rules=len(rules),new_rules=len(additions),reactivated_rules=len(deferred),new_written_rules=len(additions)-len(deferred),modified_family_templates=4,new_template_files=0,
        tests_passed=int(tests['tests']),tests_failed=0,independent_verification=verify['counts'],reviewed_rules_observed=len(verify['reviewed_rule_occurrences']),original_corpus_unchanged=True,documentary_inventories_unchanged=True,schema_unchanged=True)
    write(OUT/'SUMMARY.json',stats)
    lines=['# Fidélité finale du corpus',f'\nBranche `{branch}` ; base préservée `0a94e30`. Sources et inventaires documentaires inchangés.\n',
        f'85 configurations ; 16 719 lignes physiques ; 8 263 nœuds d’inventaire. Décompte final : {business} commandes métier et 754 nœuds opaques/structuraux/métadonnées. Chaque ligne physique appartient à un nœud, à son bloc opaque, à un commentaire ou à une ligne vide.\n',
        '| Catégorie | Avant brut (8 263 nœuds) | Avant comparable (7 509 commandes) | Après (7 509 commandes) |','|---|---:|---:|---:|']
    for category in ['correctly_normalized','partially_normalized','incorrectly_normalized','captured_unmapped','unrecognized']:
        lines.append(f"| {category} | {base['counts'].get(category,0)} | {comparable.get(category,0)} | {final['counts'].get(category,0)} |")
    lines += [f'\n170 marqueurs auparavant comptés comme inconnus sont reclassés structurels ; cette correction du dénominateur ne constitue pas une capture de commande. Les 2 049 nouvelles captures ont un oracle de paramètres et de parents indépendant des templates de production.\n',
        f"Reconnaissance : {(business-final['counts']['unrecognized'])/business:.4%}. Normalisation complète selon les paramètres source contrôlés : {final['counts']['correctly_normalized']/business:.4%}. Les 1 324 captures natives et 22 cas partiels ne sont pas crédités comme complètement normalisés.\n",
        'Validation : 482 tests réussis, aucun échec ; 85 sorties vérifiées contre le schéma JSON versionné ; 20 configurations historiques converties par la CLI avec les quatre templates amont et validées contre ce schéma. Aucun changement des oracles de faits existants. Trois faits historiquement différés rejoignent les assertions de valeurs exactes sans changer les attentes de ces faits.\n',
        'Non-régression : 5 238 captures auparavant correctes identiques et toujours correctement classées ; 11 830 valeurs sémantiques préexistantes comparées aux sorties de référence ; aucun écart. Les coordonnées/parents de 2 049 nouvelles captures contrôlés depuis les sources. Tous les hashes du corpus inchangés.\n',
        'Le bilan initial utilisait les règles du projet seules ; le bilan final exécute aussi les quatre templates amont gelés, sans erreur. Les comparaisons indépendantes rejouent les règles du projet et contrôlent les sorties typées ; le parcours CLI complet est également vérifié sur le corpus historique.\n',
        'Anomalies corrigées pendant la mission : détection erronée de plateforme sur de l’hexadécimal de certificat ; signatures XR sans en-tête ; correspondances de préfixe ignorant un suffixe ; constantes TTP ; options BGP locales à une AF élargies au processus ; secrets natifs/numéros de série et bannières sur une ligne dans les exports publics. Deux tests qui imposaient l’ancien report de fonctionnalités ont été remplacés par des assertions positives plus précises ; aucune valeur d’oracle n’a été changée.\n',
        '**Décision : le moteur couvre toutes les syntaxes valides identifiées par une capture explicite ou une conservation native contextualisée, mais ne normalise pas entièrement le corpus. Trois lignes mal contextualisées restent inconnues. Aucune affirmation d’exhaustivité Cisco IOS/IOS-XE, ni d’équivalence sémantique complète des captures natives.**\n']
    md('FINAL_FIDELITY_REPORT.md','\n'.join(lines))
    implementation=['# Implémentation TTP',
        '\n374 règles explicites actives contre 273 à la base : 101 règles ajoutées, dont 30 règles préexistantes auparavant différées et 71 nouvelles règles écrites. Aucun nouveau fichier de template de famille ; 4 fichiers modifiés sur les 11 chargés : services, interfaces, bgp, advanced. Quatre templates amont restent gelés et inchangés.\n',
        'Ordre effectif : inventaire de source et blocs opaques → regroupement par famille avec numéros de ligne → TTP → garde de ligne entière, choix de domaine et contexte → classement par spécificité/ambiguïté → rattachement aux parents originaux → templates amont gelés → validation des champs → normaliseur v0.2 avec rollback en cas d’échec → extensions natives pour paramètres restants.\n',
        'Les règles ne servent pas de capture générique de ligne. Les champs libres sont limités à des commandes nommées : alias exec, expressions de communauté, options de timestamps, transports. Le suffixe complet reste capturé ; une réussite par simple préfixe est rejetée.\n',
        'Mappings activés : CDP/MOP, service instances Ethernet avec encapsulation/bridge-domain, LDP router-id sans force, timestamps et paramètres de terminal, options globales de service, authentification HTTP locale, NetFlow global, flags BGP au niveau processus. Les flags BGP locaux à une AF restent natifs, car le contrat v0.2 ne possède pas les champs correspondants dans l’AF. Les nouvelles commandes RIP/call-home/CEF/MMI/cache NetFlow/PIM/MSDP/plateforme/DHCP/BGP sont conservées dans les domaines natifs appropriés lorsque le contrat ne possède pas leur représentation typée.\n',
        'Aucune migration de schéma. Aucune valeur implicite inventée pour un secret sans format imprimé ; credential_format=not_specified. Les secrets, mots de passe, communautés SNMP et numéros de série suivent le masquage ; bannières et certificats sont conservés par coordonnées et SHA-256, dans les sources originales inchangées. Les sorties ne constituent donc pas une sauvegarde autonome des octets opaques : conserver les sources pour les reconstruire.\n',
        'Sources Cisco pour les ambiguïtés de contexte : [auto-summary BGP](https://www.cisco.com/c/en/us/td/docs/ios/iproute_bgp/command/reference/irg_book/irg_bgp1.html), [synchronization](https://www.cisco.com/c/en/us/td/docs/ios/iproute_bgp/command/reference/irg_book/irg_bgp5.html), [exemples BGP IOS-XE 16.7](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_bgp/configuration/xe-16-7/irg-xe-16-7-book.pdf), [authentification HTTP IOS-XE 17](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/https/configuration/xe-17/https-xe-17-book/HTTP_1-1_Web_Server_and_Client.html). Les autres ajouts transcrivent les syntaxes réellement observées, sans prétendre établir leur compatibilité sur d’autres releases.\n',
        '| Règle active ajoutée | Famille | Syntaxe TTP |','|---|---|---|']
    for rule in sorted(additions):implementation.append('| '+rule+' | '+rules[rule]['family']+' | '+rules[rule]['pattern'].replace('|','&#124;')+' |')
    md('TTP_IMPLEMENTATION_REPORT.md','\n'.join(implementation))
    groups=defaultdict(list)
    for row in after:
        if row['category'] not in ('correctly_normalized','opaque_or_structural'):groups[(row['category'],row['rule'])].append(row)
    gaps=['# Lacunes restantes',
        '\n1 349 occurrences restent sans normalisation sémantique complète : 1 324 captures natives contextualisées, 22 expressions de communauté partiellement validées, 3 commandes sans contexte valide. Aucun cas classé incorrectly_normalized dans les contrôles exécutés ; cela ne prouve pas l’absence de tout défaut possible.\n',
        'La liste ci-dessous couvre chaque occurrence restante par ID de fichier et ligne. CORPUS_INVENTORY.md résout les ID ; MISSING_COMMANDS.csv fournit les positions/contextes avant-après. Les domaines natifs préservent les paramètres exacts sans leur prêter un sens commun au-delà du contrat. Les regex Cisco sont conservées avec leur dialecte, sans validation de leur langage.\n',
        'Lacunes de généralisation : pas de preuve de toutes les releases/plateformes ISR, ASR 1000 ou Catalyst 8000 ; versions d’exports incomplètes ; fonctionnalités/variantes absentes du corpus non validées ; pas de configuration active ni de vérification sur routeur ; classification par signatures, sans vérité matérielle externe ; audit indépendant exhaustif des paramètres pour les nouvelles règles observées et sous-ensembles contrôlés pour les anciennes règles, pas de preuve formelle de tous leurs comportements.\n']
    gaps.append('Contexte des trois lignes inconnues : Cisco définit [logging synchronous en mode line](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/fundamentals/command/cf_command_ref/L_through_mode.html). Leur export les place au niveau global ; aucun parent line n’est inventé.\n')
    for (category,rule),rows in sorted(groups.items(),key=lambda k:(k[0][0],str(k[0][1]))):
        gaps += [f'## {rule or "aucune règle"} — {category} — {len(rows)} occurrences\n',reason(rows[0])+'\n',
            'Paramètres capturés : '+', '.join(sorted({f for r in rows for f in r['fields']}))+'.\n',
            'Exemple masqué : `'+redacted(rows[0]['command']).replace('`','')+'`.\n',
            'Preuves : '+', '.join(f"{ids[r['file']]}:L{r['line']}" for r in rows)+'.\n']
    md('REMAINING_GAPS.md','\n'.join(gaps))
    # Commit aggregates only; private source filenames, addresses and per-command
    # outputs remain local. Never stage outputs/ or the original corpus.
    versioned=ROOT/'docs/catalogue-ttp-completion';versioned.mkdir(parents=True,exist_ok=True)
    write(versioned/'summary.json',stats)
    (versioned/'README.md').write_text('# Finalisation du parseur sur catalogue\n\n'+
        '\n'.join(lines[1:])+ '\n\n'+ '\n'.join(implementation[:7])+ '\n\n'+
        '## Reproduction\n\nLes sources privées doivent être présentes dans le dossier frère catalogue, et les 20 fixtures historiques dans configs/. Les règles générées sont versionnées. Exécuter avec le Python du projet :\n\n'+
        '```text\npython tools/build_templates.py\npython -m pytest tests -q --junitxml=outputs/catalogue_ttp_completion/final_tests.xml\npython tools/catalogue_audit.py final\npython tools/catalogue_verify.py\npython tools/catalogue_report.py\n```\n\n'+
        'La référence initiale est immuable : ne pas relancer baseline sur les règles corrigées. Pour la reconstituer dans un environnement neuf, utiliser le commit 0a94e30 avec les outils d’audit, sans copier de nouveau code du parseur dans cette référence. Les livrables détaillés locaux sont dans outputs/catalogue_ttp_completion/ ; ils ne sont pas committés car ils indexent le corpus privé. Les métriques agrégées et les contrôles sont versionnés ici.\n',encoding='utf-8')
    print(json.dumps(stats,ensure_ascii=False),flush=True)


if __name__=='__main__':main()
