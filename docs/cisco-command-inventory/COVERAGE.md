# Couverture et lacunes — snapshot du 27 octobre 2026

**Inventaire non exhaustif. Aucun pourcentage global de commandes de routeurs couvertes n'est établi.**

7296 occurrences candidates ; 6502 intitulés distincts ; 6569 groupes de syntaxe/mode strictement identiques après regroupement. Ces nombres ne sont pas des nombres de commandes routeur certifiées.

43 livres découverts ; 281 chapitres tentés sur 281 repérés dans les livres sélectionnés. 3854 articles exclus, 261 anomalies d'extraction. L'accès à un chapitre ne prouve pas l'extraction complète de ses articles.

339 URL distinctes récupérées avec succès, sur 344 URL tentées. Le registre peut décrire plusieurs rôles pour une même URL.

Échantillon relu : 48 entrées, dont 43 présentes dans une sortie running-config publiée par Cisco et 5 issues uniquement d'une procédure CLI. Aucun essai sur équipement/image Cisco n'a été réalisé.

10 exemples relus n'ont pas de correspondance exacte d'intitulé dans les candidats. Ils restent des preuves d'exemples observés, sans grammaire complète déduite. Les correspondances par titre existantes ne prouvent pas non plus une équivalence de mode ou de variante.

## Plateformes et releases

| Famille | Recherche effectuée | Limite restante |
|---|---|---|
| ISR 1000 | Index de références et guides ; exemple de running-config portant version 16.6 | Pas de matrice par PID, module, licence et release ; exemples du guide parfois incohérents |
| ISR 4000 | Index de références et guides | Pas de preuve de sérialisation relue propre à cette famille |
| ASR 1000 | Références par technologie et guide broadband XE 3S avec running-config | Exemple sans release exacte ; pas de validation par RP/ESP/SPA/feature set |
| Catalyst 8200/8300 Edge | Index et guide de plateforme ; procédure CLI et extrait running-config EIGRP | Release exacte absente dans l'extrait ; aucune extension automatique à 8500/8000V |
| Catalyst 8500 / 8000V | Index de références explorés | Pas d'exemple sauvegardé relu propre à chaque famille ; images et fonctions différentes |
| IOS historique | Index IOS et ISR G2 ; exemple 1900/2900/3900 portant version 12.4 ; références multi-releases | Pas d'inventaire de tous les trains 12.x/15.x, modules et anciennes plateformes |

La version imprimée dans un exemple n'est pas une release minimale ni la preuve qu'une plateforme donnée exécute cette release. Le guide ISR G2 reprend notamment un exemple portant version 12.4 : ce texte n'établit pas une compatibilité ISR G2/12.4. Les dates des guides ne prouvent pas la prise en charge de chaque commande. Les références de programmabilité 17.12.x et 17.18.x ont été sélectionnées ; les autres releases, dont les nouvelles familles 26.x, ne sont pas traitées systématiquement.

## Extraction par livre

| Livre | Candidats | Anomalies |
|---|---:|---:|
| [Cisco IOS Asynchronous Transfer Mode Command Reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/atm/command/atm-cr-book.html) | 182 | 4 |
| [Cisco IOS Broadband Access Aggregation and DSL Command Reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/bbdsl/command/bba-cr-book.html) | 121 | 1 |
| [Cisco IOS Basic System Management Command Reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/bsm/command/bsm-cr-book.html) | 57 | 0 |
| [Cisco IOS Carrier Ethernet Command Reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/cether/command/ce-cr-book.html) | 187 | 3 |
| [Cisco IOS Software Activation Command Reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/csa/command/csa-cr-book.html) | 14 | 3 |
| [Cisco IOS Embedded Syslog Manager Command Reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/esm/command/esm-cr-book.html) | 30 | 1 |
| [flexible-netflow](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/fnetflow/command/fnf-cr-book.html) | 101 | 0 |
| [Cisco IOS Configuration Fundamentals Command Reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/fundamentals/command/Cisco_IOS_Configuration_Fundamentals_Command_Reference.html) | 233 | 22 |
| [fundamentals](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/fundamentals/command/cf_command_ref.html) | 233 | 22 |
| [Cisco IOS High Availability Command Reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ha/command/ha-cr-book.html) | 65 | 2 |
| [Cisco IOS Interface and Hardware Component Command Reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/interface/command/ir-cr-book.html) | 608 | 72 |
| [Cisco IOS IP Addressing Services Command Reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipaddr/command/ipaddr-cr-book.html) | 405 | 7 |
| [Cisco IOS IP Application Services Command Reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipapp/command/iap-cr-book.html) | 77 | 6 |
| [Cisco IOS First Hop Redundancy Protocols Command Reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipapp_fhrp/command/fhp-cr-book.html) | 59 | 1 |
| [Cisco IOS IP Mobility Command Reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipmobility/command/imo-cr-book.html) | 160 | 0 |
| [ipv4-multicast](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipmulti/command/imc-cr-book.html) | 0 | 0 |
| [Cisco IOS IP Routing: BGP Command Reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_bgp/command/irg-cr-book.html) | 223 | 9 |
| [Cisco IOS IP Routing: EIGRP Command Reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_eigrp/command/ire-cr-book.html) | 91 | 0 |
| [Cisco IOS IP Routing: ISIS Command Reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_isis/command/irs-cr-book.html) | 71 | 0 |
| [Cisco IOS IP Routing: LISP Command Reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_lisp/command/ip-lisp-cr-book.html) | 74 | 0 |
| [Cisco IOS IP Routing OSPF Command Reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_ospf/command/iro-cr-book.html) | 108 | 1 |
| [Cisco IOS IP Routing: Protocol-Independent Command Reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_pi/command/iri-cr-book.html) | 93 | 0 |
| [Cisco IOS IP Routing: RIP Command Reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_rip/command/irr-cr-book.html) | 28 | 3 |
| [Cisco IOS IP SLAs Command Reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipsla/command/sla-cr-book.html) | 236 | 3 |
| [Cisco IOS IP Switching Command Reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipswitch/command/isw-cr-book.html) | 39 | 24 |
| [Cisco IOS IPv6 Command Reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipv6/command/ipv6-cr-book.html) | 474 | 1 |
| [Cisco IOS Intelligent Services Gateway Command Reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/isg/command/isg-cr-book.html) | 126 | 1 |
| [Cisco IOS LAN Switching Command Reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/lanswitch/command/lsw-cr-book.html) | 136 | 11 |
| [Cisco IOS Multiprotocol Label Switching Command Reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/mpls/command/mp-cr-book.html) | 365 | 0 |
| [Cisco IOS Performance Routing Command Reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/pfr/command/pfr-cr-book.html) | 111 | 4 |
| [Cisco IOS Performance Routing Version 3 Command Reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/pfrv3/command/pfrv3-cr-book.html) | 32 | 0 |
| [Programmability Command Reference, Cisco IOS XE Dublin 17.12.x](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/prog/command/1712/b_1712_programmability_cr.html) | 63 | 0 |
| [Programmability Command Reference, Cisco IOS XE 17.18.x](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/prog/command/1718/b_1718_programmability_cr.html) | 65 | 0 |
| [Cisco IOS Quality of Service Solutions Command Reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/qos/command/qos-cr-book.html) | 404 | 21 |
| [Cisco IOS Security Command Reference: Commands A to C](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/a1/sec-a1-cr-book.html) | 435 | 5 |
| [Cisco IOS Security Command Reference: Commands D to L](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/d1/sec-d1-cr-book.html) | 486 | 6 |
| [Cisco IOS Security Command Reference: Commands M to R](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/m1/sec-m1-cr-book.html) | 359 | 8 |
| [Cisco IOS Security Command Reference: Commands S to Z](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/s1/sec-s1-cr-book.html) | 256 | 9 |
| [Cisco IOS VPDN Command Reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/vpdn/command/vpd-cr-book.html) | 115 | 2 |
| [Cisco IOS Wide-Area Networking Command Reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/wan/command/wan-cr-book.html) | 357 | 9 |
| [Cisco IOS Dynamic Application Policy Routing Command Reference](https://www.cisco.com/c/en/us/td/docs/ios/dapr/command/reference/dapr-cr-book.html) | 17 | 0 |
| [Cisco IOS ISO CLNS Command Reference](https://www.cisco.com/c/en/us/td/docs/ios/isoclns/command/reference/iso_book.html) | 0 | 0 |
| [Cisco Unified Border Element (SP Edition) Command Reference: Unified Model](https://www.cisco.com/c/en/us/td/docs/ios/sbc/command/reference/sbcu_book.html) | 0 | 0 |

## Sources en échec ou redirigées

- [ios-master-historical](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/mcl/allreleasemcl/all-book.html) : `redirected_to_support` ; https://www.cisco.com/c/en/us/support/index.html.
- [isr1900](https://www.cisco.com/c/en/us/support/routers/1900-series-integrated-services-routers/products-command-reference-list.html) : `fetch_failed` ; HTTP Error 404: Not Found.
- [evidence-c8200-c8300-old](https://www.cisco.com/c/en/us/td/docs/routers/cloud_edge/c8300/software_config/cat8300swcfg-xe-17-book.html) : `fetch_failed` ; HTTP Error 404: Not Found.
- [ipv4-multicast](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipmulti/command/imc-cr-book.html) : `redirected_to_support` ; https://www.cisco.com/c/en/us/support/index.html.
- [ipv4-multicast-chapter-fallback](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipmulti/command/imc-cr-book/imc_i4.html) : `redirected_to_support` ; https://www.cisco.com/c/en/us/support/index.html.
- [ipv4-multicast](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipmulti/command/imc-cr-book.html) : `redirected_to_support` ; https://www.cisco.com/c/en/us/support/index.html.
- [ip rgmp through ipv6 multicast-routing (explicit chapter fallback for unavailable book TOC)](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipmulti/command/imc-cr-book/imc_i4.html) : `redirected_to_support` ; https://www.cisco.com/c/en/us/support/index.html.

47 chapitres accessibles ne contiennent aucun article de commande reconnu par l'extracteur (préambule, aide, format différent ou absence de commandes). Ils sont signalés dans `sources.json`.

## Lacunes documentaires et de couverture

- La Master Command List historique redirige vers Cisco Support au moment de cette collecte ; son contenu indexé par un moteur de recherche ne vaut pas contenu récupéré. Le PDF historique et le Command Lookup Tool authentifié ne sont pas dépouillés.
- `frontier.json` conserve les références non sélectionnées, les guides non dépouillés et les PDF repérés. Une frontière vide de chapitres sélectionnés ne signifierait pas que toute la documentation Cisco est couverte.
- Le corpus se concentre sur la CLI IOS/IOS-XE classique, notamment en mode autonome. Les références SD-Routing repérées sont différées ; les variantes SD-WAN/controller-managed, configurations générées et feature templates ne sont pas inventoriés systématiquement.
- Les livres partagés IOS contiennent des syntaxes de commutateurs, équipements anciens et fonctions non disponibles sur toutes les plateformes. Tous les candidats restent en quarantaine documentaire ; aucune liste de support routeur n'est affirmée à partir du seul livre.
- Multicast IPv4/PIM, Flexible NetFlow, EEM, SNMP/gestion avancée, télémétrie, VRF/address-families imbriquées, sécurité/VPN, QoS hiérarchique, MPLS/SR, broadband, voix/CUBE, modules cellulaires et services applicatifs nécessitent des croisements supplémentaires. Certains sont partiellement représentés dans les livres collectés ; leur complétude n'est pas établie.
- Les formes no/default publiées indiquent des syntaxes acceptées, pas leur persistance. Une commande par défaut peut être absente de show running-config et visible avec une autre forme d'affichage. Les différences running/startup/all, réécritures, alias, ordres et commandes générées ne sont pas validés.
- Bannières, chaînes de certificats, clés, blocs multilignes, menus, macros, délimiteurs et lignes de version/boot demandent une modélisation propre. Le contenu opaque ne doit pas être interprété ligne par ligne comme commande indépendante.
- Les sous-modes et la hiérarchie complète ne sont pas reconstruits pour les candidats automatiques. Les homonymes et différences par mode/release doivent être relus avant toute utilisation par un parseur.
- Les schémas HTML non reconnus et les articles sans syntaxe/mode sont conservés dans les anomalies. Une extraction sans anomalie détectée ne prouve pas l'absence de perte.

## Incohérences constatées dans les exemples Cisco

Dans les guides de base ISR 1000 et Catalyst 8200/8300, certains exemples IPv6 contiennent `2001.db8::ffff:1/128`, et une étape de loopback omet même `ipv6 address`. Des extraits de routage utilisent des valeurs IPv6 après `ip route`, ou un prompt global pour une commande network EIGRP. Ces lignes ne sont pas promues comme syntaxe valide dans l'échantillon relu. La référence OSPF imprime également `distance ospf commanddistance ospf` dans une syntaxe : cette transcription est conservée comme candidat à relire, sans correction inventée. Les articles HTML strictement dupliqués sont dédupliqués et consignés dans les anomalies. Ces observations montrent pourquoi une source officielle demande aussi une lecture critique.

## Travail restant pour étendre la confiance

1. Traiter les anomalies et les technologies absentes à partir des chapitres de référence spécifiques ; enrichir la frontière de façon versionnée.
2. Résoudre le support par PID, OS, release, licence/module et mode, avec Feature Information, release notes, guides de plateforme et outil Cisco lorsque disponible.
3. Sur des images/appareils autorisés, vérifier entrée → running-config → sauvegarde → startup-config ; conserver des fixtures expurgées et la version exacte.
4. Définir un univers documentaire fermé et auditable avant de calculer une couverture ; faire relire les groupes de syntaxes, sans activer de templates dans cette tâche.
