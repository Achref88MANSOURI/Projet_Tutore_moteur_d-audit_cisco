# Implémentation de la normalisation Cisco P1

Branche `feature/cisco-normalization-p1`, base `a528053`. Les travaux de feature/catalogue-ttp-completion et les références précédentes sont conservés.

40 familles P1 EXTEND_MODEL implémentées : 466 occurrences promues. Les 7 familles MAP_EXISTING ont été examinées : 6 familles et 94 occurrences promues, dont 93 route-maps déjà représentées génériquement et 1 network BGP. Les 16 match community de la septième famille restent natifs car leurs dépendances de regex Cisco ne sont pas validées. Total : 46 familles avec gain, 560 occurrences nouvelles correctement normalisées.

Les templates TTP, règles de sélection et captures ne changent pas. Les mappings supplémentaires vivent dans normalizer/audit_p1.py et sont activés par le normaliseur v0.2. Le contrat des ajouts est publié sous **0.2.1**, avec schéma JSON distinct ; le fichier 0.2.0 est gelé.

## Champs et relations ajoutés

- Interfaces : ipv4_assignment_method=dhcp, pim_bsr_border et sap_listen_enabled. Aucun bail, adresse DHCP, état opérationnel ou mode PIM inventé. Les combinaisons DHCP/statique incompatibles restent non normalisées.

- BGP : auto_summary et synchronization dans BGPAddressFamily ; additional_paths_advertise_selection et allowas_in dans BGPPeerOptions. Le nombre omis de allowas-in reste null, aucun défaut 3 ne devient explicite. Pair/groupe, AFI/SAFI et VRF restent distincts.

- RIP : processus déclaré, réseaux de participation globaux et locaux à AF/VRF, auto-summary et redistribution BGP avec ASN et métrique RIP. Pas de numéro de processus ou de version par défaut inventé.

- AAA : password_policy.minimum_length ; archive : déclaration, déclaration log config et hidekeys. La présence de log config ne prouve pas une commande logging enable absente.

- Services Cisco : Call Home avec déclaration, activation globale et profils actifs/transports ; DNS avec vue par VRF et interface source ; client TFTP avec interface source ; services virtuels déclarés ; registre de configuration conservé comme hexadécimal sans décodage matériel supposé. Les guillemets délimitant un nom de profil sont retirés dans son identité typée ; la forme source reste dans les preuves et captures.

- IP : CEF IPv4/IPv6, limiteur ICMP unreachable, attente TCP SYN et sélection de Network Disk pour relais de broadcast. Aucun état de FIB, désactivation globale IPv6 ou relais réellement actif ne sont inférés.

- Multicast : Auto-RP, candidats BSR/RP par interface, SSM comme sélecteur, pair MSDP avec connect-source ; propriétés SAP et BSR-border orthogonales au mode PIM. Pas de RP élu ou appris déduit.

- L2VPN : bridge_domain sur la VFI parente. NetFlow : destination/port sous le cache agrégé as. Ce dernier utilise une identité parent issue de la commande P2 comme dépendance indispensable ; les paramètres P2 de ce cache ne sont ni consommés ni reclassés.

## Mappings existants

Aucun objet route-map supplémentaire n’est ajouté. La validation vérifie les noms et familles des références ACL/prefix-lists, les ASN ordonnés et répétés, les membres AA:NN et la présence de additive. La valeur générique et son kind existants restent identiques ; additive demeure explicitement dans la grammaire de value. Le choix du plan de créer des kinds community_add/community_replace n’était pas nécessaire pour représenter fidèlement les formes observées et aurait modifié les consommateurs. La classification change seulement après validation et contrôle de la représentation déjà produite. Cela ne simule pas exécution complète de politiques.

Pour BGP network sans masque imprimé, seuls les réseaux IPv4 alignés sur leur masque naturel documenté sont dérivés, avec basis dans la preuve. Les adresses non alignées, loopback, multicast et formes spéciales ne reçoivent aucun préfixe arbitraire. Aucune présence en RIB ni annonce effective ne sont déduites.

## Version et compatibilité

La CLI utilise 0.2.1 par défaut. --schema-version 0.2.0 désactive les mappings P1, conserve leurs données natives et exporte un document validé contre le schéma 0.2.0 gelé. --schema-version 0.1.0 conserve le parcours historique. Le modèle Python accepte les marqueurs de version historiques pour lecture interne ; utiliser upgrade_v020 pour migrer et project_v020 pour sérialiser vers le contrat gelé. La projection refuse toute propriété nouvelle renseignée au lieu de la supprimer. migrate_v01 cible désormais 0.2.1.

Les nouveaux champs sont additifs et optionnels. Les objets déclarés gardent une indication explicite distincte d’une activation ou d’un état observé. Les nouvelles correspondances refusent les sous-modes intermédiaires inconnus. Les secrets et UDI restent masqués ; aucun champ nouveau ne contient de mot de passe ou clé.

## Familles examinées et destinations

| Famille | Décision | Occurrences initiales | Promues | Destination représentative |
|---|---|---:|---:|---|
| advanced_l2_bridge | EXTEND_MODEL | 3 | 3 | /configuration/cisco/l2vpn/vfis/[]/bridge_domain |
| bgp_advertise_additional | EXTEND_MODEL | 11 | 11 | /configuration/routing/bgp/[]/family_options/[]/peers/[]/additional_paths_advertise_selection |
| bgp_network | MAP_EXISTING | 1 | 1 | /configuration/routing/bgp/[]/networks |
| bgp_no_auto_summary | EXTEND_MODEL | 3 | 3 | /configuration/routing/bgp/[]/family_options/[]/auto_summary |
| bgp_no_sync | EXTEND_MODEL | 4 | 4 | /configuration/routing/bgp/[]/family_options/[]/synchronization |
| catalogue_allowas | EXTEND_MODEL | 2 | 2 | /configuration/routing/bgp/[]/family_options/[]/peers/[]/allowas_in |
| catalogue_archive | EXTEND_MODEL | 2 | 2 | /configuration/cisco/config_archive/declared |
| catalogue_archive_hide | EXTEND_MODEL | 2 | 2 | /configuration/cisco/config_archive/config_logging/hidekeys |
| catalogue_archive_log | EXTEND_MODEL | 2 | 2 | /configuration/cisco/config_archive/config_logging/declared |
| catalogue_cache_export | EXTEND_MODEL | 2 | 2 | /configuration/cisco/netflow/aggregation_caches/[]/destinations |
| catalogue_call_home | EXTEND_MODEL | 21 | 21 | /configuration/cisco/call_home/declared |
| catalogue_call_home_active | EXTEND_MODEL | 21 | 21 | /configuration/cisco/call_home/profiles/[]/active |
| catalogue_call_home_destination | EXTEND_MODEL | 21 | 21 | /configuration/cisco/call_home/profiles/[]/transport_methods |
| catalogue_call_home_on | EXTEND_MODEL | 15 | 15 | /configuration/cisco/call_home/enabled |
| catalogue_call_home_profile | EXTEND_MODEL | 21 | 21 | /configuration/cisco/call_home/profiles/[]/name |
| catalogue_cef | EXTEND_MODEL | 57 | 57 | /configuration/cisco/ip_services/cef_ipv4_enabled |
| catalogue_cef6 | EXTEND_MODEL | 10 | 10 | /configuration/cisco/ip_services/cef_ipv6_enabled |
| catalogue_config_register | EXTEND_MODEL | 2 | 2 | /configuration/cisco/boot/configuration_register |
| catalogue_dhcp4 | EXTEND_MODEL | 20 | 20 | /configuration/interfaces/[]/ipv4_assignment_method |
| catalogue_dns_view | EXTEND_MODEL | 20 | 20 | /configuration/cisco/dns/views |
| catalogue_domain_source | EXTEND_MODEL | 1 | 1 | /configuration/cisco/dns/lookup_source_interface |
| catalogue_forward_protocol | EXTEND_MODEL | 83 | 83 | /configuration/cisco/ip_services/broadcast_forwarding_protocols |
| catalogue_icmp_no_limit | EXTEND_MODEL | 24 | 24 | /configuration/cisco/ip_services/icmp_unreachable_rate_limit_enabled |
| catalogue_msdp_peer | EXTEND_MODEL | 1 | 1 | /configuration/cisco/multicast/msdp/peers |
| catalogue_no_cef6 | EXTEND_MODEL | 47 | 47 | /configuration/cisco/ip_services/cef_ipv6_enabled |
| catalogue_password_minimum | EXTEND_MODEL | 2 | 2 | /configuration/system/aaa/password_policy/minimum_length |
| catalogue_pim_autorp | EXTEND_MODEL | 2 | 2 | /configuration/cisco/multicast/auto_rp/listener_configured |
| catalogue_pim_bsr | EXTEND_MODEL | 1 | 1 | /configuration/cisco/multicast/bsr_candidates |
| catalogue_pim_discovery | EXTEND_MODEL | 1 | 1 | /configuration/cisco/multicast/auto_rp/discovery_scope |
| catalogue_pim_rp_candidate | EXTEND_MODEL | 1 | 1 | /configuration/cisco/multicast/rp_candidates |
| catalogue_pim_ssm | EXTEND_MODEL | 1 | 1 | /configuration/cisco/multicast/ssm/range_selector |
| catalogue_rip | EXTEND_MODEL | 2 | 2 | /configuration/routing/rip/[]/declared |
| catalogue_rip_family | EXTEND_MODEL | 1 | 1 | /configuration/routing/rip/[]/address_families/[] |
| catalogue_rip_network | EXTEND_MODEL | 3 | 3 | /configuration/routing/rip/[]/address_families/[]/network_statements |
| catalogue_rip_no_summary | EXTEND_MODEL | 1 | 1 | /configuration/routing/rip/[]/address_families/[]/auto_summary |
| catalogue_rip_redistribute | EXTEND_MODEL | 1 | 1 | /configuration/routing/rip/[]/address_families/[]/redistributions |
| catalogue_sap | EXTEND_MODEL | 1 | 1 | /configuration/interfaces/[]/sap_listen_enabled |
| catalogue_synwait | EXTEND_MODEL | 24 | 24 | /configuration/cisco/ip_services/tcp_synwait_seconds |
| catalogue_tftp_source | EXTEND_MODEL | 22 | 22 | /configuration/cisco/file_transfer/tftp/source_interface |
| catalogue_virtual_service | EXTEND_MODEL | 7 | 7 | /configuration/cisco/virtual_services |
| if_pim | EXTEND_MODEL | 1 | 1 | /configuration/interfaces/[]/pim_bsr_border |
| policy_match_acl | MAP_EXISTING | 23 | 23 | /configuration/routing/routing_policies/[]/statements/[]/matches/[] |
| policy_match_community | MAP_EXISTING | 16 | 0 | Conservation native : dépendance non validée |
| policy_match_prefix4 | MAP_EXISTING | 19 | 19 | /configuration/routing/routing_policies/[]/statements/[]/matches/[] |
| policy_match_prefix6 | MAP_EXISTING | 6 | 6 | /configuration/routing/routing_policies/[]/statements/[]/matches/[] |
| policy_set_aspath | MAP_EXISTING | 5 | 5 | /configuration/routing/routing_policies/[]/statements/[]/actions/[] |
| policy_set_community | MAP_EXISTING | 40 | 40 | /configuration/routing/routing_policies/[]/statements/[]/actions/[] |

## Sources Cisco et limites de qualification

- [BGP network et masque naturel](https://www.cisco.com/c/en/us/support/docs/ip/border-gateway-protocol-bgp/19345-bgp-noad.html).

- [BGP auto-summary](https://www.cisco.com/c/en/us/td/docs/ios/iproute_bgp/command/reference/irg_book/irg_bgp1.html), [synchronization](https://www.cisco.com/c/en/us/td/docs/ios/iproute_bgp/command/reference/irg_book/irg_bgp5.html), [allowas-in](https://www.cisco.com/c/en/us/support/docs/ip/border-gateway-protocol-bgp/112236-allowas-in-bgp-config-example.html).

- [Route-maps et additive](https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/ip-routing/b-ip-routing/m_irg-external-sp-0.html), [Call Home IOS](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/csa/configuration/15-mt/csa-15-mt-book/csa-call-home-v2.html). Le token transport http peut aussi utiliser HTTPS.

- [ip forward-protocol : nd = Network Disk](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipapp/iap-cr-book/iap-i1.html), [synwait 5 à 300 secondes](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipapp/iap-cr-book/iap-i2.pdf).

- [Mot de passe minimal](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/s1/sec-s1-cr-book/sec-cr-s1.html), [commandes de redistribution](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_pi/command/iri-cr-book/iri-cr-a1.html), [multicast SAP/SDP](https://www.cisco.com/c/en/us/support/docs/ip/ip-multicast/218004-secure-ip-multicast-deployments.pdf).

Les autres propriétés sont des faits de configuration directement imprimés et contrôlés contre les sources du corpus. La mission ne prouve pas leur compatibilité sur toutes releases ou plateformes. Les valeurs effectives, héritages complets et conformité de chaque politique nécessitent des contrôles supplémentaires.

## Reproduction

Les fixtures privées catalogue, configs et les résultats de la mission précédente doivent être présents. Les décisions sans données sensibles sont versionnées dans decisions.json. Les sorties détaillées restent locales.

```text
python tools/build_schema_v021.py
python -m pytest tests -q --basetemp=cache/p1-replay-tests --junitxml=outputs/cisco_normalization_p1/tests.xml
python tools/audit_normalization_p1.py
python tools/report_normalization_p1.py
```

La référence BEFORE_REFERENCE.json enregistre le commit a528053 et les empreintes des sorties actuelles avant modifications ; ne pas la reconstruire depuis les nouvelles sorties.
