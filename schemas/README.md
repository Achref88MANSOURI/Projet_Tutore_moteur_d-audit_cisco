# Contrat canonique actif

`router_contract_v1.py` définit le modèle unique `RouterContractV1` et ses
sous-modèles. Le moteur et les modules métier construisent directement ces objets.
Aucun modèle historique, convertisseur ou export alternatif n'est utilisé.

`router_contract_v1.schema.json` est généré depuis Pydantic par
`tools/build_router_contract_v1_schema.py`. Le contrat impose la version `1.0.0`
et conserve ses domaines racines, les nulls et les négations explicites.

Les collections absentes restent null. Une collection vide nécessite une preuve
locale explicite ou la confirmation conjointe de source complète et de couverture
du domaine. Les types définis mais non extraits restent indéterminés.
Les contraintes entre champs restent vérifiées par Pydantic avant export.

Les fonctions L2 de commutation et l'authentification d'accès PPP/802.1X sont
exclues. Les LAG, sous-interfaces L3 et encapsulations routées restent incluses.
Le schéma ne contient ni secret ni résultat d'audit.

## Extension EIGRP

`routing.eigrp` contient les processus classiques ou nommés ; les sous-modèles
conservent AF, VRF, topologies, réglages d'af-interface et références de politiques.
`routing.eigrp_interfaces` conserve les réglages classiques identifiés explicitement
par interface, AFI et AS, sans création automatique d'un processus.

Les ASN EIGRP sont limités à 1–65535, distincts des ASN BGP. Les métriques composites
sont typées et conservent leurs unités. L'action de route-map `eigrp_metric` reste
distincte de l'action scalaire `metric`. Les paramètres communs d'interface
`bandwidth_kbps` et `delay_tens_of_microseconds` représentent des valeurs configurées.

Les champs `removed_settings` et marqueurs locaux expriment des resets sans injecter
de défauts. Les clés et mots de passe ne font pas partie des modèles. Le contrat
conserve son nom/version V1 ; son schéma généré doit être actualisé pour accepter
les nouveaux champs, y compris lorsqu'ils sont indéterminés.

Voir [la couverture EIGRP et les sources](../docs/eigrp/README.md).

## Champs ajoutés pour la fidélité Cisco

- `ACLEntry.tcp_established` : critère TCP ACK ou RST, sans supposer un état de session.
- `RoutingPolicyMatch.exact_match` : qualification explicite de `match community ... exact`.
- `QoSMatch.address_family` : distingue `match ip precedence` (IPv4) et `match precedence` (IPv4/IPv6).
- `Boot.images` : emplacements d'images ordonnés et périphériques explicitement identifiés.
- `AggregationCache` : capacité, activation et timers propres au cache, distincts du réglage global.
- `SNMP.ifindex_persistent`, `CallHome.contact_email` et options Cisco structurées de scheduler, CDP, FPD, IOAM et format de communautés.

Les autres champs restent indéterminés lorsqu'ils ne sont pas établis. La version
logicielle et le PID alimentent des champs `device` déjà existants ; le numéro de
série n'est pas exporté. La présence d'un texte de bannière est représentée sans
son contenu. Les contrôles des références retirées appartiennent au moteur et ne
prétendent pas rendre toute référence littérale obligatoire dans le contrat.

Voir le [bilan et les limites](../docs/diagnostic_17_tests/CORRECTIONS_ET_VALIDATION.md).

## Réserves IOS 15 / IOS-XE 17

Les extensions Cisco conservent désormais `qfp_utilization_monitor_load` et
`punt_keepalive_kernel_core_disabled` lorsqu’ils sont explicitement configurés.
Voir la [convention de compatibilité](COMPATIBILITE.md) pour identifier le schéma
exact, et le [bilan des réserves](../docs/diagnostic_17_tests/SUIVI_VERIFICATIONS_IOS15_IOSXE17.md).
