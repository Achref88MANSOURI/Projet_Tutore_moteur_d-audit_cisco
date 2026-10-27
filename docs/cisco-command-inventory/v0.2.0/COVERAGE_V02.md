# Couverture documentaire 0.2.0

Aucun taux global d'exhaustivité Cisco n'est calculé. La frontière est ouverte et les versions des documents ne constituent pas un univers fermé de commandes.

## Familles technologiques

| Technologie (classement lexical de navigation) | Confirmé | Documenté | Incertain | Exclu |
|---|---:|---:|---:|---:|
| 504c9866bd53 | 0 | 0 | 1 | 0 |
| 65c1357a8383 | 0 | 0 | 1 | 0 |
| 67d6e1d52808 | 0 | 0 | 74 | 0 |
| Cisco IOS Asynchronous Transfer Mode Command Reference | 0 | 0 | 166 | 0 |
| Cisco IOS Basic System Management Command Reference | 0 | 0 | 27 | 0 |
| Cisco IOS Broadband Access Aggregation and DSL Command Reference | 0 | 0 | 99 | 0 |
| Cisco IOS Carrier Ethernet Command Reference | 0 | 0 | 146 | 0 |
| Cisco IOS Configuration Fundamentals Command Reference | 0 | 0 | 175 | 1 |
| Cisco IOS Dynamic Application Policy Routing Command Reference | 0 | 0 | 14 | 0 |
| Cisco IOS First Hop Redundancy Protocols Command Reference | 0 | 0 | 54 | 0 |
| Cisco IOS High Availability Command Reference | 0 | 0 | 53 | 0 |
| Cisco IOS IP Addressing Services Command Reference | 0 | 0 | 346 | 0 |
| Cisco IOS IP Application Services Command Reference | 0 | 0 | 71 | 0 |
| Cisco IOS IP Mobility Command Reference | 0 | 0 | 134 | 0 |
| Cisco IOS IP Routing OSPF Command Reference | 0 | 0 | 43 | 0 |
| Cisco IOS IP Routing: BGP Command Reference | 0 | 0 | 69 | 0 |
| Cisco IOS IP Routing: EIGRP Command Reference | 0 | 0 | 28 | 0 |
| Cisco IOS IP Routing: ISIS Command Reference | 0 | 0 | 36 | 0 |
| Cisco IOS IP Routing: LISP Command Reference | 0 | 0 | 67 | 0 |
| Cisco IOS IP Routing: Protocol-Independent Command Reference | 0 | 0 | 68 | 0 |
| Cisco IOS IP Routing: RIP Command Reference | 0 | 0 | 7 | 0 |
| Cisco IOS IP SLAs Command Reference | 0 | 0 | 209 | 0 |
| Cisco IOS IP Switching Command Reference | 0 | 0 | 34 | 0 |
| Cisco IOS IPv6 Command Reference | 0 | 0 | 292 | 0 |
| Cisco IOS Intelligent Services Gateway Command Reference | 0 | 0 | 91 | 0 |
| Cisco IOS Interface and Hardware Component Command Reference | 0 | 1 | 505 | 0 |
| Cisco IOS LAN Switching Command Reference | 0 | 0 | 118 | 0 |
| Cisco IOS Multiprotocol Label Switching Command Reference | 0 | 0 | 106 | 0 |
| Cisco IOS Performance Routing Command Reference | 0 | 0 | 93 | 0 |
| Cisco IOS Performance Routing Version 3 Command Reference | 0 | 0 | 19 | 0 |
| Cisco IOS Quality of Service Solutions Command Reference | 0 | 0 | 328 | 0 |
| Cisco IOS Security Command Reference: Commands A to C | 0 | 0 | 190 | 0 |
| Cisco IOS Security Command Reference: Commands D to L | 0 | 0 | 414 | 0 |
| Cisco IOS Security Command Reference: Commands M to R | 0 | 0 | 315 | 0 |
| Cisco IOS Security Command Reference: Commands S to Z | 0 | 0 | 216 | 0 |
| Cisco IOS Software Activation Command Reference | 0 | 0 | 12 | 0 |
| Cisco IOS VPDN Command Reference | 0 | 0 | 95 | 0 |
| Cisco IOS Wide-Area Networking Command Reference | 0 | 0 | 284 | 0 |
| Configuration fundamentals | 0 | 0 | 175 | 1 |
| EEM | 0 | 0 | 106 | 0 |
| Flexible NetFlow | 0 | 0 | 20 | 0 |
| MPLS/VPN | 8 | 1 | 275 | 0 |
| NetFlow | 0 | 0 | 93 | 0 |
| Programmability Command Reference, Cisco IOS XE 17.18.x | 0 | 0 | 41 | 1 |
| Programmability Command Reference, Cisco IOS XE Dublin 17.12.x | 0 | 0 | 41 | 1 |
| QoS | 0 | 0 | 100 | 0 |
| SNMP | 0 | 4 | 60 | 0 |
| administration | 18 | 2 | 207 | 0 |
| d5d0e9a6f452 | 0 | 0 | 1 | 0 |
| db75ad88e928 | 0 | 0 | 1 | 0 |
| interfaces | 13 | 5 | 248 | 0 |
| multicast/PIM | 1 | 0 | 60 | 0 |
| other | 20 | 3 | 1 | 0 |
| routing | 4 | 0 | 484 | 0 |
| security/VPN | 6 | 3 | 358 | 0 |
| telemetry | 0 | 2 | 36 | 0 |

Ce classement sert à stratifier l'étude ; il ne prouve pas la prise en charge d'une technologie sur une plateforme.

## Plateformes

| Périmètre | Preuves ajoutées ou relues | Lacune |
|---|---|---|
| ISR 800 | Running-config explicitement présenté pour Cisco 881W ; AES Cisco 836 sous image IP plus ; exemples SNMP du guide de commutation intégrée | Pas d'extension à tous les 8xx, modules, images ou releases |
| ISR 1900/2900/3900 | Exemples du guide commun relus | PID non identifié ; exemple historique version 12.4 non transformé en matrice de support G2 |
| ISR 1000 | Exemples dont une configuration identifie C1111-8PLTELA par UDI | Pas de validation de tous les modèles ni des options |
| ISR 4000 | Exemple running-config et chapitre de plateforme ajoutés | Version de configuration 15.3 distincte de la release IOS-XE ; PID exact inconnu |
| ASR 1000 | Exemples broadband relus ; claims scoped protected, strict et WebEx SPA | Conditions RP/ESP/SPA/images et variantes incomplètes |
| Catalyst 8200/8300 | Extraits du guide commun relus | Exemple ne distingue pas les deux plateformes ; aucun support universel affirmé |
| Catalyst 8500/8500L | Sortie running-config vrf ; procédures de gestion et breakout relues | Modèle exact non identifié dans la sortie VRF ; breakout limité aux conditions du guide |
| Catalyst 8000V | Références initiales conservées | Aucune nouvelle fixture ciblée 8000V validée en phase 2 |

## Frontière et références restantes

Les 1 142 documents de la frontière initiale sont conservés, dédupliqués par URL et classés en pertinence. Les paires HTML/PDF de même localisateur sont regroupées pour navigation sans supposer leur équivalence de contenu. Les releases différentes restent distinctes. Voir FRONTIER_RELEVANCE.json.

Les chapitres EEM ont été ajoutés comme références syntaxiques. Le guide PIM et des exemples Flexible NetFlow ont été consultés, mais leurs exemples génériques restent incertains tant que leur applicabilité à une plateforme ciblée n'est pas établie. La télémétrie distingue dial-in dynamique et dial-out configuré ; une procédure CLI ne suffit pas pour confirmed_config.

Restent prioritaires : résolution des stubs et des modes absents, références SNMP complètes, paramètres/options par plateforme et release, VPN/sécurité, MPLS/SR, QoS imbriquée, EEM par image, 8000V, variantes historiques et fixtures de startup-config. Les PDF et contenus soumis à authentification n'ont pas été dépouillés systématiquement.

## Localisateurs inaccessibles

- [https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipmulti/command/imc-cr-book.html](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipmulti/command/imc-cr-book.html) — generic_support_redirect.
- [https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipmulti/command/imc-cr-book/imc_i4.html](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipmulti/command/imc-cr-book/imc_i4.html) — generic_support_redirect.
- [https://www.cisco.com/c/en/us/support/routers/1900-series-integrated-services-routers/products-command-reference-list.html](https://www.cisco.com/c/en/us/support/routers/1900-series-integrated-services-routers/products-command-reference-list.html) — HTTP Error 404: Not Found.
- [https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/mcl/allreleasemcl/all-book.html](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/mcl/allreleasemcl/all-book.html) — generic_support_redirect.
- [https://www.cisco.com/c/en/us/td/docs/routers/cloud_edge/c8300/software_config/cat8300swcfg-xe-17-book.html](https://www.cisco.com/c/en/us/td/docs/routers/cloud_edge/c8300/software_config/cat8300swcfg-xe-17-book.html) — HTTP Error 404: Not Found.

## Triage des anomalies

| Disposition | Occurrences |
|---|---:|
| documentation_redirect_stub_retained_for_resolution | 20 |
| excluded_operational_article | 79 |
| non_cli_serialization_marker | 4 |
| non_command_document_section | 11 |
| recovered_candidate_needs_router_qualification | 4 |
| resolved_duplicate_already_deduplicated | 7 |
| uncertain_missing_structured_syntax_or_mode | 136 |
