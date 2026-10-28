# Contrat actuel : NormalizedConfig 0.2.1

La mission P1 autorisée publie les ajouts sous 0.2.1. La CLI utilise cette version
par défaut ; `--schema-version 0.2.0` conserve le parcours historique sans les
mappings P1 et produit le schéma 0.2.0 gelé. Le modèle v0.1 reste inchangé.
Voir [la livraison P1](cisco-normalization-p1/IMPLEMENTATION_REPORT.md) pour les
champs, limites, tests et fonctions de migration. `upgrade_v020` valide le
document historique avant migration ; `project_v020` refuse de supprimer des
propriétés 0.2.1 renseignées. Les valeurs nulles ne sont pas des valeurs false.

## Archive du point de contrôle 0.2.0

Le texte ci-dessous décrit le point de contrôle historique, avant les missions
de complétion et P1 ; ses métriques et son ancienne valeur par défaut sont archivées.

Point de contrôle demandé par l’utilisateur : arrêter ici avant tout ajout de
prise en charge de nouvelles commandes Cisco. Toute extension du catalogue
requiert désormais son accord explicite.

## Fichiers

- Modèle Pydantic : `schemas/normalizedconfig_v02.py`.
- Schéma JSON correspondant : `schemas/normalizedconfig_v0_2.schema.json`.
- Contrat historique inchangé : `schemas/normalizedconfig.py` (0.1.0).
- La CLI utilise 0.2.0 par défaut ; `--schema-version 0.1.0` sélectionne le
  contrat historique.

Le modèle est un contrat interne au vocabulaire aligné sur OpenConfig, pas un
document JSON natif RFC7951/OpenConfig. Les structures spécifiques sont placées
dans `configuration.cisco`, avec leur provenance. Un champ présent dans le
contrat ne constitue pas une promesse que toutes les commandes correspondantes
sont implémentées.

## Données et contraintes

Les extensions concernent Ethernet, encapsulation et paramètres IP d’interface,
groupes et voisins BGP par famille d’adresses, OSPF versionné, prefix-lists
ordonnées, QoS, métadonnées PKI et structures natives Cisco.

La version OSPF est obligatoire. Les vitesses fixes ont une valeur positive en
bit/s ; le mode auto ne comporte aucune vitesse numérique supposée. Les VLAN,
longueurs de préfixe, pourcentages et identifiants disposent de contraintes.
Les options BGP inscrites sous une AF restent sous cette AF.

Les observations natives conservent des paramètres encore non normalisés et
leur contexte. Elles sont explicitement partielles et ne suffisent jamais à
attribuer le statut `fully_normalized`. Les blocs opaques conservent leurs
positions et empreintes sans exposer le corps des certificats ou bannières dans
le modèle normalisé. Les commandes inconnues restent dans les sorties.

## Migration

`migrate_v01(document, ospf_version=None)` valide d’abord le contrat v0.1 et
produit une copie v0.2. Les attributs nouveaux restent inconnus ou vides.
Pour OSPF, le mapper TTP historique est identifié comme producteur d’OSPFv2 ;
un document d’une autre origine doit fournir une version justifiée explicitement.
La migration ne transforme pas les commandes précédemment inconnues en faits.

`project_v01(document)` est une projection explicitement réductrice qui retire
les extensions et leurs preuves non représentables. Elle refuse de faire passer
un processus OSPFv3 pour un processus OSPFv2. Elle ne constitue pas une garantie
d’équivalence fonctionnelle entre les deux versions.

## Validation au point d’arrêt

- Schéma JSON identique à celui généré par le modèle Pydantic actuel.
- Empreinte du modèle v0.1 conservée :
  `438edb9bf58f0143491c6ddc18c5500bddfa552cc8a12898dcd970e79ffd58e4`.
- Migration et refus de projection ambiguë couverts par les tests.
- Suite active : 169 tests réussis, rapport `outputs/reliability/phase6/tests.xml`.

Ces tests ne certifient pas une précision sémantique exhaustive sur toutes les
syntaxes IOS/IOS-XE. Aucune décision finale Go/No-Go n’est prononcée à ce point
d’arrêt.
