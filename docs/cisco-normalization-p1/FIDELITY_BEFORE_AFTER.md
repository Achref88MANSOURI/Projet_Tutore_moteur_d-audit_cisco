# Fidélité avant/après P1

Branche `feature/cisco-normalization-p1`, référence a528053. 85 configurations IOS/IOS-XE ; 16 719 lignes physiques ; 8 263 nœuds dont 754 opaques/structuraux. Dénominateur métier inchangé : **7 509 commandes**.

| Statut métier | Avant | Après |
|---|---:|---:|
| correctly_normalized | 6160 | 6720 |
| captured_unmapped | 1324 | 764 |
| partially_normalized | 22 | 22 |
| incorrectly_normalized | 0 | 0 |
| unrecognized | 3 | 3 |

Normalisation complète : 82,03 % avant, **89.49 % après**. Gain réel : 560 occurrences, soit 7,46 points. Reconnaissance inchangée : 7 506 / 7 509 (99,96 %). Les captures natives ne sont pas créditées comme normalisation complète.

**Tests : 556 réussis, 0 échec, 0 erreur.** Les 482 tests existants ont été rejoués, avec 74 tests supplémentaires. Trois tests imposant l’ancien statut différé ont été remplacés par des assertions de valeurs exactes pour les nouvelles capacités. Les oracles historiques de faits, valeurs et sources restent inchangés.

Audit indépendant : tous les paramètres TTP et coordonnées comparés à la référence ; valeurs nouvellement promues contrôlées depuis les lignes source par un oracle distinct du mapping. Les anciennes représentations génériques des route-maps ne sont ni dupliquées ni réécrites pour améliorer les statistiques.

| Vérification | Nombre | Résultat |
|---|---:|---|
| original_hash | 174 | Aucun écart |
| versioned_schema | 85 | Aucun écart |
| official_templates | 85 | Aucun écart |
| source_hostname | 85 | Aucun écart |
| source_interfaces_admin | 85 | Aucun écart |
| source_ipv4 | 85 | Aucun écart |
| source_ipv6 | 85 | Aucun écart |
| unchanged_native_values | 8263 | Aucun écart |
| baseline_correct_status | 6160 | Aucun écart |
| baseline_semantic_value | 13633 | Aucun écart |
| unchanged_parent | 1324 | Aucun écart |
| independent_promoted_source | 560 | Aucun écart |
| deferred_scope_unchanged | 748 | Aucun écart |
| partial_unknown_unchanged | 25 | Aucun écart |
| historical_official | 20 | Aucun écart |
| historical_schema | 20 | Aucun écart |
| historical_files | 20 | Aucun écart |

Les 6 160 captures initialement correctes restent correctement classées ; 13 633 valeurs préexistantes vérifiées sans écart. Les 8 263 jeux de paramètres TTP et 1 324 contextes natifs restent identiques. 560 promotions ont un contrôle de valeur et de relation fondé sur la source. Les 748 occurrences explicitement différées gardent leur statut, ainsi que les 22 lignes partielles et 3 inconnues.

Les 85 sorties utilisent les quatre templates amont et sont validées contre le schéma JSON 0.2.1 versionné. Les 20 configurations historiques passent également par la CLI avec templates amont et schéma 0.2.1. Les hashes des 174 fichiers du catalogue et des 89 références de résultats restent inchangés.

Les tests couvrent les scopes BGP/VRF, les groupes déclarés ou non, les sous-modes intermédiaires inconnus, les paramètres invalides, les conflits DHCP/statique, les références de policy absentes, les communautés additive/remplacement, l’ordre des ASN et la migration/refus de perte. Les tests de confidentialité et blocs opaques existants restent réussis.

**Décision : livraison fonctionnelle validée sur le corpus, sans régression détectée. La couverture de normalisation reste partielle.** Ce taux ne mesure ni la conformité de sécurité ni un état opérationnel et ne prouve pas l’exhaustivité Cisco. Aucun équipement n’a été configuré.
