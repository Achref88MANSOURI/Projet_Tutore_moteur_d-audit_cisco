# Mission Codex — Phase 2 : Qualification de l'inventaire Cisco IOS/IOS-XE

## 1. Objectif

Poursuivre le travail de recherche effectué dans la branche `research/cisco-ios-iosxe-config-inventory`, à partir du snapshot documentaire `0.1.0`.

**Objectif final : construire un catalogue aussi complet, fiable et traçable que possible des commandes et variantes de configuration pouvant apparaître dans les fichiers `running-config` et `startup-config` des routeurs Cisco IOS/IOS-XE.**

Ne pas repartir de zéro. Réutiliser les sources, données, scripts et résultats déjà produits.

## 2. Périmètre strict

Inclure uniquement :

- Routeurs Cisco IOS historiques : notamment ISR 800, 1900, 2900, 3900.
- Routeurs Cisco IOS-XE : ISR 1000/4000, ASR 1000, Catalyst 8200/8300/8500 Edge et 8000V.
- Commandes de configuration persistante susceptibles d'apparaître dans `running-config` ou `startup-config`.
- Commandes et sous-commandes des différents modes : configuration globale, interface, routeur, address-family, line, ACL, route-map, class-map, policy-map, VPN, etc.
- Variantes syntaxiques, arguments, options et formes `no`/`default` lorsqu'elles sont documentées et pertinentes pour une configuration sauvegardée.

Exclure les commandes exclusivement opérationnelles (`show`, `debug`, `clear`, `copy`, etc.) et les commandes propres à IOS XR, NX-OS, ASA ou aux commutateurs.

Une commande commune aux routeurs et aux commutateurs peut être conservée si son applicabilité à au moins une plateforme routeur est établie.

**Ne jamais considérer qu'une commande est applicable à tous les routeurs simplement parce qu'elle figure dans une référence Cisco IOS.**

## 3. Qualification des candidats existants

Examiner les 7 296 occurrences candidates du snapshot `0.1.0`, correspondant à 6 502 intitulés distincts.

Pour chaque entrée, établir :

1. La syntaxe documentée et ses paramètres.
2. Le mode de configuration et son contexte hiérarchique.
3. Son applicabilité aux routeurs Cisco ciblés.
4. Les plateformes et releases confirmées par les sources.
5. Sa possibilité d'apparaître dans une configuration sauvegardée.
6. Les variantes documentées, sans inventer d'options.
7. Une référence Cisco officielle précise.
8. Le niveau de confiance des conclusions.

**Ne pas confondre syntaxe acceptée en CLI et syntaxe réellement sérialisée par IOS/IOS-XE.**

Dédupliquer les entrées tout en conservant les différences de syntaxe, mode, plateforme et release. Une commande homonyme dans deux contextes distincts ne doit pas être fusionnée abusivement.

## 4. Classification obligatoire

Attribuer à chaque entrée l'un des statuts suivants :

| Statut | Condition |
|---|---|
| `confirmed_config` | Forme observée dans une configuration de routeur Cisco officiellement publiée ou sur un équipement identifié |
| `documented_config` | Commande documentée pour une plateforme routeur dans un mode de configuration, mais sérialisation non confirmée |
| `uncertain` | Mode, applicabilité routeur ou persistance insuffisamment établis |
| `excluded` | Commande opérationnelle, propre à une autre famille d'équipements ou clairement hors périmètre |

Une commande ne doit pas être considérée comme confirmée uniquement parce qu'elle apparaît dans un exemple de saisie CLI.

Pour chaque exclusion ou incertitude, conserver une justification et sa source.

Ne pas supprimer les candidats incertains.

## 5. Poursuite de la recherche officielle Cisco

Réexaminer `COVERAGE.md`, `frontier.json`, `sources.json` et le journal des anomalies du snapshot `0.1.0`.

Traiter en priorité :

- Les 261 anomalies de collecte.
- Les sources récupérées mais partiellement exploitées.
- Les 1 142 documents découverts mais non dépouillés, après déduplication et classement de pertinence.
- Les références ayant échoué, redirigé ou changé d'emplacement.
- Les technologies insuffisamment couvertes : IPv4 multicast/PIM, SNMP, NetFlow, télémétrie, EEM, VPN, sécurité, MPLS, QoS, routage et services d'administration.

Rechercher dans les références officielles Cisco les informations permettant de confirmer plateformes, releases, modes et variantes.

Ne pas utiliser des listes communautaires comme preuve principale de compatibilité.

Ne pas déduire la prise en charge d'une commande de la seule date d'un guide, de la section `Command History` ou de l'existence d'un article IOS générique.

Si une source ne peut être consultée, conserver son statut `inaccessible` ou `not_reviewed` plutôt que supposer son contenu.

## 6. Contrôle de qualité du catalogue

Vérifier particulièrement :

- Les commandes globales et leurs sous-commandes.
- Les structures imbriquées et changements de contexte.
- Les commandes partageant un même mot-clé mais ayant des significations différentes.
- Les paramètres facultatifs et formes syntaxiques alternatives.
- Les négations explicites.
- Les valeurs par défaut et leur éventuelle omission dans `running-config`.
- Les commandes multilignes : banners, certificats, clés, menus et blocs natifs.

Corriger les erreurs d'extraction documentaire uniquement lorsque la source permet de justifier la correction.

**Ne pas générer automatiquement des syntaxes supposées à partir de conventions Cisco.**

## 7. Validation et preuves

Définir une stratégie reproductible de validation documentaire.

Pour les entrées confirmées, enregistrer la ligne ou le bloc de configuration source, avec URL, plateforme, release si disponible et contexte.

Pour les commandes documentées sans exemple de `running-config`, conserver cette limite explicite.

Vérifier un échantillon stratifié couvrant les différentes familles technologiques, plateformes et statuts. Ne pas présenter la validation de cet échantillon comme une vérification exhaustive de toutes les entrées.

Mesurer séparément :

- Les candidats examinés.
- Les candidats qualifiés.
- Les commandes confirmées.
- Les commandes seulement documentées.
- Les candidats incertains.
- Les exclusions justifiées.
- Les sources restant à examiner.

Aucun pourcentage global d'exhaustivité des commandes Cisco ne doit être annoncé sans univers documentaire fermé et dénominateur justifié.

## 8. Livrables attendus

Créer une nouvelle version documentaire `0.2.0` dans le dossier de recherche existant, sans écraser le snapshot `0.1.0`.

Produire :

1. **`router_config_commands.jsonl`** : catalogue qualifié, avec syntaxe, paramètres, mode, contexte, statut, plateformes, releases, URL Cisco et preuves.
2. **`QUALIFICATION_REPORT.md`** : méthode, résultats, chiffres et qualité des preuves.
3. **`COVERAGE_V02.md`** : couverture documentaire par technologie et plateforme, zones inconnues et sources restant à traiter.
4. **`EXCLUSIONS_AND_UNCERTAINTIES.csv`** : exclusions et candidats non confirmés avec justification.
5. **`SOURCE_REGISTRY.json`** : références officielles consultées et leurs statuts.
6. **`VALIDATION_SAMPLES.md`** : échantillon de vérification et preuves associées.
7. Scripts permettant de reconstruire et de valider le catalogue à partir des sources conservées.

Conserver les identifiants permettant de relier chaque entrée au snapshot `0.1.0`.

## 9. Contraintes de développement

**Cette mission est exclusivement documentaire.**

Interdictions :

- Ne pas modifier le moteur TTP.
- Ne pas créer, activer ou modifier de templates TTP.
- Ne pas modifier `NormalizedConfig v0.1/v0.2`.
- Ne pas modifier les mappings ou règles de normalisation.
- Ne pas traiter les 582 commandes non reconnues du corpus.
- Ne pas comparer encore l'inventaire avec les templates TTP.
- Ne pas écraser les résultats des audits de fidélité.
- Ne pas modifier les travaux concurrents d'autres branches.

Vérifier l'état Git avant toute intervention. Travailler sur la branche de recherche existante ou une branche de qualification dérivée, sans intégrer les modifications concurrentes du normaliseur.

## 10. Critères de réussite et point d'arrêt

La phase sera considérée terminée lorsque :

- Chaque candidat du snapshot `0.1.0` aura été qualifié ou explicitement conservé comme non vérifié.
- Les nouveaux candidats collectés auront une source traçable.
- Les doublons et collisions de contexte auront été traités sans perte des variantes.
- Les plateformes et releases seront renseignées uniquement lorsqu'il existe des preuves suffisantes.
- Les incertitudes, anomalies et sources restantes seront documentées.
- Le catalogue sera reproductible, cohérent et validé par des contrôles automatiques et un échantillon indépendant.

**Ne pas affirmer que le catalogue est exhaustif si les preuves ne le permettent pas.**

À la fin, fournir un bilan chiffré, les fichiers produits, les sources non couvertes et une décision sur l'aptitude de l'inventaire à servir de référence pour une future comparaison avec TTP.

**Arrêter le travail après cette qualification. Aucune extension du parseur n'est autorisée.**