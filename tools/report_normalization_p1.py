"""Produce the three versioned delivery reports from the immutable audit."""
from collections import Counter,defaultdict
import json
from pathlib import Path
import re
import subprocess
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'outputs/cisco_normalization_p1'
DOCS=ROOT/'docs/cisco-normalization-p1'


def main():
    after=json.loads((OUT/'AFTER_COVERAGE.json').read_text())
    before=json.loads((OUT/'BEFORE_REFERENCE.json').read_text())
    rows=json.loads((OUT/'AFTER_OCCURRENCES.json').read_text())
    decisions={r['family_id']:r for r in json.loads((DOCS/'decisions.json').read_text())}
    tests=ET.parse(OUT/'tests.xml').getroot().find('testsuite').attrib
    assert not after['failures'] and int(tests['failures'])==int(tests['errors'])==0
    protected=['templates','parser','schemas/normalizedconfig.py','schemas/normalizedconfig_v0_2.schema.json',
               'tests/oracle_v02.py','tests/reviewed_source_facts.json','tests/source_oracle.py','docs/cisco-command-inventory']
    subprocess.run(['git','diff','--exit-code','a528053','--',*protected],cwd=ROOT,check=True,capture_output=True)
    branch=subprocess.check_output(['git','branch','--show-current'],cwd=ROOT,text=True).strip()
    p1={k:v for k,v in decisions.items() if v['priority']=='P1' and v['decision']=='EXTEND_MODEL'}
    assert len(p1)==40 and all(k in after['promoted_rules'] for k in p1)
    assert sum(after['promoted_rules'][k] for k in p1)==466
    target={r['rule']:r['normalized_paths'] for r in rows if r['before_category']=='captured_unmapped' and r['category']=='correctly_normalized'}
    implementation=[
      '# Implémentation de la normalisation Cisco P1',
      f'\nBranche `{branch}`, base `a528053`. Les travaux de feature/catalogue-ttp-completion et les références précédentes sont conservés.\n',
      '40 familles P1 EXTEND_MODEL implémentées : 466 occurrences promues. Les 7 familles MAP_EXISTING ont été examinées : 6 familles et 94 occurrences promues, dont 93 route-maps déjà représentées génériquement et 1 network BGP. Les 16 match community de la septième famille restent natifs car leurs dépendances de regex Cisco ne sont pas validées. Total : 46 familles avec gain, 560 occurrences nouvelles correctement normalisées.\n',
      'Les templates TTP, règles de sélection et captures ne changent pas. Les mappings supplémentaires vivent dans normalizer/audit_p1.py et sont activés par le normaliseur v0.2. Le contrat des ajouts est publié sous **0.2.1**, avec schéma JSON distinct ; le fichier 0.2.0 est gelé.\n',
      '## Champs et relations ajoutés\n',
      '- Interfaces : ipv4_assignment_method=dhcp, pim_bsr_border et sap_listen_enabled. Aucun bail, adresse DHCP, état opérationnel ou mode PIM inventé. Les combinaisons DHCP/statique incompatibles restent non normalisées.\n',
      '- BGP : auto_summary et synchronization dans BGPAddressFamily ; additional_paths_advertise_selection et allowas_in dans BGPPeerOptions. Le nombre omis de allowas-in reste null, aucun défaut 3 ne devient explicite. Pair/groupe, AFI/SAFI et VRF restent distincts.\n',
      '- RIP : processus déclaré, réseaux de participation globaux et locaux à AF/VRF, auto-summary et redistribution BGP avec ASN et métrique RIP. Pas de numéro de processus ou de version par défaut inventé.\n',
      '- AAA : password_policy.minimum_length ; archive : déclaration, déclaration log config et hidekeys. La présence de log config ne prouve pas une commande logging enable absente.\n',
      '- Services Cisco : Call Home avec déclaration, activation globale et profils actifs/transports ; DNS avec vue par VRF et interface source ; client TFTP avec interface source ; services virtuels déclarés ; registre de configuration conservé comme hexadécimal sans décodage matériel supposé. Les guillemets délimitant un nom de profil sont retirés dans son identité typée ; la forme source reste dans les preuves et captures.\n',
      '- IP : CEF IPv4/IPv6, limiteur ICMP unreachable, attente TCP SYN et sélection de Network Disk pour relais de broadcast. Aucun état de FIB, désactivation globale IPv6 ou relais réellement actif ne sont inférés.\n',
      '- Multicast : Auto-RP, candidats BSR/RP par interface, SSM comme sélecteur, pair MSDP avec connect-source ; propriétés SAP et BSR-border orthogonales au mode PIM. Pas de RP élu ou appris déduit.\n',
      '- L2VPN : bridge_domain sur la VFI parente. NetFlow : destination/port sous le cache agrégé as. Ce dernier utilise une identité parent issue de la commande P2 comme dépendance indispensable ; les paramètres P2 de ce cache ne sont ni consommés ni reclassés.\n',
      '## Mappings existants\n',
      'Aucun objet route-map supplémentaire n’est ajouté. La validation vérifie les noms et familles des références ACL/prefix-lists, les ASN ordonnés et répétés, les membres AA:NN et la présence de additive. La valeur générique et son kind existants restent identiques ; additive demeure explicitement dans la grammaire de value. Le choix du plan de créer des kinds community_add/community_replace n’était pas nécessaire pour représenter fidèlement les formes observées et aurait modifié les consommateurs. La classification change seulement après validation et contrôle de la représentation déjà produite. Cela ne simule pas exécution complète de politiques.\n',
      'Pour BGP network sans masque imprimé, seuls les réseaux IPv4 alignés sur leur masque naturel documenté sont dérivés, avec basis dans la preuve. Les adresses non alignées, loopback, multicast et formes spéciales ne reçoivent aucun préfixe arbitraire. Aucune présence en RIB ni annonce effective ne sont déduites.\n',
      '## Version et compatibilité\n',
      'La CLI utilise 0.2.1 par défaut. --schema-version 0.2.0 désactive les mappings P1, conserve leurs données natives et exporte un document validé contre le schéma 0.2.0 gelé. --schema-version 0.1.0 conserve le parcours historique. Le modèle Python accepte les marqueurs de version historiques pour lecture interne ; utiliser upgrade_v020 pour migrer et project_v020 pour sérialiser vers le contrat gelé. La projection refuse toute propriété nouvelle renseignée au lieu de la supprimer. migrate_v01 cible désormais 0.2.1.\n',
      'Les nouveaux champs sont additifs et optionnels. Les objets déclarés gardent une indication explicite distincte d’une activation ou d’un état observé. Les nouvelles correspondances refusent les sous-modes intermédiaires inconnus. Les secrets et UDI restent masqués ; aucun champ nouveau ne contient de mot de passe ou clé.\n',
      '## Familles examinées et destinations\n',
      '| Famille | Décision | Occurrences initiales | Promues | Destination représentative |',
      '|---|---|---:|---:|---|',
    ]
    for rule,d in sorted(decisions.items()):
        if rule not in p1 and d['decision']!='MAP_EXISTING':continue
        paths=', '.join(re.sub(r'/\d+(?=/|$)','/[]',p) for p in target.get(rule,[])) or 'Conservation native : dépendance non validée'
        implementation.append(f"| {rule} | {d['decision']} | {d['occurrences']} | {after['promoted_rules'].get(rule,0)} | {paths} |")
    implementation += [
      '\n## Sources Cisco et limites de qualification\n',
      '- [BGP network et masque naturel](https://www.cisco.com/c/en/us/support/docs/ip/border-gateway-protocol-bgp/19345-bgp-noad.html).\n',
      '- [BGP auto-summary](https://www.cisco.com/c/en/us/td/docs/ios/iproute_bgp/command/reference/irg_book/irg_bgp1.html), [synchronization](https://www.cisco.com/c/en/us/td/docs/ios/iproute_bgp/command/reference/irg_book/irg_bgp5.html), [allowas-in](https://www.cisco.com/c/en/us/support/docs/ip/border-gateway-protocol-bgp/112236-allowas-in-bgp-config-example.html).\n',
      '- [Route-maps et additive](https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/ip-routing/b-ip-routing/m_irg-external-sp-0.html), [Call Home IOS](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/csa/configuration/15-mt/csa-15-mt-book/csa-call-home-v2.html). Le token transport http peut aussi utiliser HTTPS.\n',
      '- [ip forward-protocol : nd = Network Disk](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipapp/iap-cr-book/iap-i1.html), [synwait 5 à 300 secondes](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipapp/iap-cr-book/iap-i2.pdf).\n',
      '- [Mot de passe minimal](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/s1/sec-s1-cr-book/sec-cr-s1.html), [commandes de redistribution](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_pi/command/iri-cr-book/iri-cr-a1.html), [multicast SAP/SDP](https://www.cisco.com/c/en/us/support/docs/ip/ip-multicast/218004-secure-ip-multicast-deployments.pdf).\n',
      'Les autres propriétés sont des faits de configuration directement imprimés et contrôlés contre les sources du corpus. La mission ne prouve pas leur compatibilité sur toutes releases ou plateformes. Les valeurs effectives, héritages complets et conformité de chaque politique nécessitent des contrôles supplémentaires.\n',
      '## Reproduction\n\nLes fixtures privées catalogue, configs et les résultats de la mission précédente doivent être présents. Les décisions sans données sensibles sont versionnées dans decisions.json. Les sorties détaillées restent locales.\n',
      '```text\npython tools/build_schema_v021.py\npython -m pytest tests -q --basetemp=cache/p1-replay-tests --junitxml=outputs/cisco_normalization_p1/tests.xml\npython tools/audit_normalization_p1.py\npython tools/report_normalization_p1.py\n```\n',
      'La référence BEFORE_REFERENCE.json enregistre le commit a528053 et les empreintes des sorties actuelles avant modifications ; ne pas la reconstruire depuis les nouvelles sorties.\n',
    ]
    fidelity=['# Fidélité avant/après P1',
      f'\nBranche `{branch}`, référence a528053. 85 configurations IOS/IOS-XE ; 16 719 lignes physiques ; 8 263 nœuds dont 754 opaques/structuraux. Dénominateur métier inchangé : **7 509 commandes**.\n',
      '| Statut métier | Avant | Après |','|---|---:|---:|']
    for k in ('correctly_normalized','captured_unmapped','partially_normalized','incorrectly_normalized','unrecognized'):
        fidelity.append(f"| {k} | {before['counts'].get(k,0)} | {after['counts'].get(k,0)} |")
    fidelity += [
      f"\nNormalisation complète : 82,03 % avant, **{after['counts']['correctly_normalized']/7509*100:.2f} % après**. Gain réel : 560 occurrences, soit 7,46 points. Reconnaissance inchangée : 7 506 / 7 509 (99,96 %). Les captures natives ne sont pas créditées comme normalisation complète.\n",
      f"**Tests : {tests['tests']} réussis, {tests['failures']} échec, {tests['errors']} erreur.** Les 482 tests existants ont été rejoués, avec 74 tests supplémentaires. Trois tests imposant l’ancien statut différé ont été remplacés par des assertions de valeurs exactes pour les nouvelles capacités. Les oracles historiques de faits, valeurs et sources restent inchangés.\n",
      'Audit indépendant : tous les paramètres TTP et coordonnées comparés à la référence ; valeurs nouvellement promues contrôlées depuis les lignes source par un oracle distinct du mapping. Les anciennes représentations génériques des route-maps ne sont ni dupliquées ni réécrites pour améliorer les statistiques.\n',
      '| Vérification | Nombre | Résultat |','|---|---:|---|']
    for k,v in after['checks'].items():fidelity.append(f'| {k} | {v} | Aucun écart |')
    fidelity += [
      '\nLes 6 160 captures initialement correctes restent correctement classées ; 13 633 valeurs préexistantes vérifiées sans écart. Les 8 263 jeux de paramètres TTP et 1 324 contextes natifs restent identiques. 560 promotions ont un contrôle de valeur et de relation fondé sur la source. Les 748 occurrences explicitement différées gardent leur statut, ainsi que les 22 lignes partielles et 3 inconnues.\n',
      'Les 85 sorties utilisent les quatre templates amont et sont validées contre le schéma JSON 0.2.1 versionné. Les 20 configurations historiques passent également par la CLI avec templates amont et schéma 0.2.1. Les hashes des 174 fichiers du catalogue et des 89 références de résultats restent inchangés.\n',
      'Les tests couvrent les scopes BGP/VRF, les groupes déclarés ou non, les sous-modes intermédiaires inconnus, les paramètres invalides, les conflits DHCP/statique, les références de policy absentes, les communautés additive/remplacement, l’ordre des ASN et la migration/refus de perte. Les tests de confidentialité et blocs opaques existants restent réussis.\n',
      '**Décision : livraison fonctionnelle validée sur le corpus, sans régression détectée. La couverture de normalisation reste partielle.** Ce taux ne mesure ni la conformité de sécurité ni un état opérationnel et ne prouve pas l’exhaustivité Cisco. Aucun équipement n’a été configuré.\n',
    ]
    remaining=defaultdict(list)
    for r in rows:
        if r['category'] not in ('correctly_normalized','opaque_or_structural'):remaining[(r['category'],r['rule'])].append(r)
    reasons={
      'KEEP_NATIVE':'Conservation native suffisante dans le profil courant ; ne vaut pas normalisation complète.',
      'NEEDS_REVIEW':'Sémantique/source non établie : maintien natif selon la décision initiale.',
      'EXTEND_MODEL':'P2 différé explicitement par la mission. Seule identité du cache parent utilisée si indispensable au collecteur P1.',
      'MAP_EXISTING':'Référence de communauté conservée, mais dépendance de regex Cisco non validée. Pas de promotion automatique.',
    }
    gaps=['# Lacunes de normalisation restantes',
      '\n764 commandes natives (38 familles), 22 commandes partielles, 3 inconnues : **789 occurrences** sans normalisation complète. La totalité est indexée ci-dessous. Les coordonnées Cxxxx:Lnn se résolvent dans le CORPUS_MANIFEST.json de la mission précédente.\n',
      '| Décision du périmètre natif restant | Familles | Occurrences |','|---|---:|---:|',
      '| KEEP_NATIVE | 17 | 490 |','| NEEDS_REVIEW | 7 | 177 |','| EXTEND_MODEL P2 | 13 | 81 |','| MAP_EXISTING bloqué par dépendance | 1 | 16 |',
      '\nAucune famille P1 EXTEND_MODEL du plan ne reste sans implémentation. Les 40 familles et leurs 466 occurrences sont traitées. Les paramètres P2 ne sont pas consommés sous prétexte de partager une structure avec P1.\n',
      'Les deux cas AAA restent en revue : négation antérieure suivie d’une activation explicite dans le même export et commande authentication login privilege-mode sans méthode IOS démontrée. Les 140 occurrences MMI et 35 IOAM gardent leurs valeurs natives. Ni correction de syntaxe, ni valeur de méthode, ni activation de service ne sont inventées.\n',
      'Les 16 match community dépendent des 22 lignes de regex Cisco partiellement normalisées. La liste et son expression restent conservées sans certification de son langage. Les trois logging synchronous globaux restent inconnus, sans parent line inventé.\n',
      'Limites générales : absence d’état RIB/FIB ou négocié, références hors export et sources incomplètes possibles, pas de validation sur toutes releases/plateformes, pas de moteur complet d’évaluation de route-maps. Le registre est conservé sans décodage non attesté ; http Call Home ne prouve pas absence de TLS. Un verdict de conformité doit tenir compte de ces inconnues.\n',
    ]
    for (state,rule),items in sorted(remaining.items(),key=lambda x:(x[0][0],str(x[0][1]))):
        d=decisions.get(rule,{})
        reason=reasons.get(d.get('decision'),'Expression Cisco non entièrement validée.' if state=='partially_normalized' else 'Commande globale sans contexte line valide.')
        gaps += [f"## {rule or 'sans règle : logging synchronous global'} — {state} — {len(items)} occurrences\n",
                 f"Décision : {d.get('decision','hors captures natives initiales')} ; priorité : {d.get('priority','statut préservé')}. {reason}\n",
                 'Preuves : '+', '.join(f"{r['id']}:L{r['line']}" for r in items)+'.\n']
    for name,parts in [('IMPLEMENTATION_REPORT.md',implementation),('FIDELITY_BEFORE_AFTER.md',fidelity),('REMAINING_NORMALIZATION_GAPS.md',gaps)]:
        (DOCS/name).write_text('\n'.join(parts).rstrip()+'\n',encoding='utf-8')
    print('Three versioned reports written; no private corpus data staged.')


if __name__=='__main__':main()
