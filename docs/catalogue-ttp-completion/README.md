# Finalisation du parseur sur catalogue

> Résultats historiques. La maintenance actuelle des templates est décrite dans
> [le guide des templates](../../templates/README.md) et ne comporte aucune génération préalable.

Branche `feature/catalogue-ttp-completion` ; base préservée `0a94e30`. Sources et inventaires documentaires inchangés.

85 configurations ; 16 719 lignes physiques ; 8 263 nœuds d’inventaire. Décompte final : 7509 commandes métier et 754 nœuds opaques/structuraux/métadonnées. Chaque ligne physique appartient à un nœud, à son bloc opaque, à un commentaire ou à une ligne vide.

| Catégorie | Avant brut (8 263 nœuds) | Avant comparable (7 509 commandes) | Après (7 509 commandes) |
|---|---:|---:|---:|
| correctly_normalized | 5238 | 5238 | 6160 |
| partially_normalized | 94 | 94 | 22 |
| incorrectly_normalized | 0 | 0 | 0 |
| captured_unmapped | 125 | 125 | 1324 |
| unrecognized | 2222 | 2052 | 3 |

170 marqueurs auparavant comptés comme inconnus sont reclassés structurels ; cette correction du dénominateur ne constitue pas une capture de commande. Les 2 049 nouvelles captures ont un oracle de paramètres et de parents indépendant des templates de production.

Reconnaissance : 99.9600%. Normalisation complète selon les paramètres source contrôlés : 82.0349%. Les 1 324 captures natives et 22 cas partiels ne sont pas crédités comme complètement normalisés.

Validation : 482 tests réussis, aucun échec ; 85 sorties vérifiées contre le schéma JSON versionné ; 20 configurations historiques converties par la CLI avec les quatre templates amont et validées contre ce schéma. Aucun changement des oracles de faits existants. Trois faits historiquement différés rejoignent les assertions de valeurs exactes sans changer les attentes de ces faits.

Non-régression : 5 238 captures auparavant correctes identiques et toujours correctement classées ; 11 830 valeurs sémantiques préexistantes comparées aux sorties de référence ; aucun écart. Les coordonnées/parents de 2 049 nouvelles captures contrôlés depuis les sources. Tous les hashes du corpus inchangés.

Le bilan initial utilisait les règles du projet seules ; le bilan final exécute aussi les quatre templates amont gelés, sans erreur. Les comparaisons indépendantes rejouent les règles du projet et contrôlent les sorties typées ; le parcours CLI complet est également vérifié sur le corpus historique.

Anomalies corrigées pendant la mission : détection erronée de plateforme sur de l’hexadécimal de certificat ; signatures XR sans en-tête ; correspondances de préfixe ignorant un suffixe ; constantes TTP ; options BGP locales à une AF élargies au processus ; secrets natifs/numéros de série et bannières sur une ligne dans les exports publics. Deux tests qui imposaient l’ancien report de fonctionnalités ont été remplacés par des assertions positives plus précises ; aucune valeur d’oracle n’a été changée.

**Décision : le moteur couvre toutes les syntaxes valides identifiées par une capture explicite ou une conservation native contextualisée, mais ne normalise pas entièrement le corpus. Trois lignes mal contextualisées restent inconnues. Aucune affirmation d’exhaustivité Cisco IOS/IOS-XE, ni d’équivalence sémantique complète des captures natives.**


# Implémentation TTP

374 règles explicites actives contre 273 à la base : 101 règles ajoutées, dont 30 règles préexistantes auparavant différées et 71 nouvelles règles écrites. Aucun nouveau fichier de template de famille ; 4 fichiers modifiés sur les 11 chargés : services, interfaces, bgp, advanced. Quatre templates amont restent gelés et inchangés.

Ordre effectif : inventaire de source et blocs opaques → regroupement par famille avec numéros de ligne → TTP → garde de ligne entière, choix de domaine et contexte → classement par spécificité/ambiguïté → rattachement aux parents originaux → templates amont gelés → validation des champs → normaliseur v0.2 avec rollback en cas d’échec → extensions natives pour paramètres restants.

Les règles ne servent pas de capture générique de ligne. Les champs libres sont limités à des commandes nommées : alias exec, expressions de communauté, options de timestamps, transports. Le suffixe complet reste capturé ; une réussite par simple préfixe est rejetée.

Mappings activés : CDP/MOP, service instances Ethernet avec encapsulation/bridge-domain, LDP router-id sans force, timestamps et paramètres de terminal, options globales de service, authentification HTTP locale, NetFlow global, flags BGP au niveau processus. Les flags BGP locaux à une AF restent natifs, car le contrat v0.2 ne possède pas les champs correspondants dans l’AF. Les nouvelles commandes RIP/call-home/CEF/MMI/cache NetFlow/PIM/MSDP/plateforme/DHCP/BGP sont conservées dans les domaines natifs appropriés lorsque le contrat ne possède pas leur représentation typée.

Aucune migration de schéma. Aucune valeur implicite inventée pour un secret sans format imprimé ; credential_format=not_specified. Les secrets, mots de passe, communautés SNMP et numéros de série suivent le masquage ; bannières et certificats sont conservés par coordonnées et SHA-256, dans les sources originales inchangées. Les sorties ne constituent donc pas une sauvegarde autonome des octets opaques : conserver les sources pour les reconstruire.

Sources Cisco pour les ambiguïtés de contexte : [auto-summary BGP](https://www.cisco.com/c/en/us/td/docs/ios/iproute_bgp/command/reference/irg_book/irg_bgp1.html), [synchronization](https://www.cisco.com/c/en/us/td/docs/ios/iproute_bgp/command/reference/irg_book/irg_bgp5.html), [exemples BGP IOS-XE 16.7](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_bgp/configuration/xe-16-7/irg-xe-16-7-book.pdf), [authentification HTTP IOS-XE 17](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/https/configuration/xe-17/https-xe-17-book/HTTP_1-1_Web_Server_and_Client.html). Les autres ajouts transcrivent les syntaxes réellement observées, sans prétendre établir leur compatibilité sur d’autres releases.


## Maintenance et vérification actuelles

Les sources privées doivent être présentes dans le dossier frère catalogue, et les fixtures historiques dans configs/. Les règles se maintiennent directement dans les `.ttp`, avec leurs restrictions dans `rule_metadata.json`. La vérification courante utilise dix configurations représentatives :

```text
python -B tools/validate_normalized.py
python -B -m pytest tests/test_ttp_loading.py tests/test_catalogue_completion.py -q -p no:cacheprovider --basetemp=outputs/pytest_ttp
```

La référence initiale est immuable : ne pas relancer baseline sur les règles corrigées. Pour la reconstituer dans un environnement neuf, utiliser le commit 0a94e30 avec les outils d’audit, sans copier de nouveau code du parseur dans cette référence. Les livrables détaillés locaux sont dans outputs/catalogue_ttp_completion/ ; ils ne sont pas committés car ils indexent le corpus privé. Les métriques agrégées et les contrôles sont versionnés ici.
