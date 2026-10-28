> Document historique. Le pipeline et le contrat actifs sont décrits dans le README à la racine.

# Arrêt demandé après fixation du contrat

La dernière instruction de l’utilisateur prévaut sur la mission initiale :
ne pas résoudre toutes les commandes et ne pas commencer l’ajout de nouvelles
commandes sans son approbation explicite.

Le travail est arrêté au point de contrôle du contrat 0.2.0. Ne pas reprendre
automatiquement les phases suivantes ni compléter les commandes non reconnues.

## État conservé

- Référence initiale restaurable : `baseline/fiabilisation_v01`.
- Sources des phases 1 et 2 : `baseline/reliability_phase1` et
  `baseline/reliability_phase2` ; leurs résultats sont sous
  `outputs/reliability/phase1` et `phase2`.
- Modèle et schéma v0.2 présents ; v0.1 conservé inchangé.
- Corrections de fidélité de l’extraction et des mappings déjà compatibles
  réalisées. Les autres modifications existantes restent consultables ; elles
  ne doivent pas être assimilées à une validation complète de l’auditeur.
- Les 30 propositions pour des commandes supplémentaires et leurs cas de test
  ont été retirés du catalogue et de la suite actifs ; elles sont archivées dans
  `docs/deferred`.
- Le catalogue actif comprend les 272 règles originales et la correction de
  concept `services_login_logging`, qui concerne six commandes déjà capturées
  auparavant. Aucune des 30 propositions n’est active.
- Les 582 positions auparavant non interprétées restent non interprétées dans
  la dernière exécution limitée. Aucun ajout n’a été utilisé pour gonfler ce
  compteur.
- La suite active s’achève avec 169 tests réussis.

`outputs/reliability/phase5` correspond à une tentative d’élargissement antérieure
au recentrage de l’utilisateur ; ses résultats sont abandonnés et ne décrivent
pas le catalogue actif. Les résultats intermédiaires sous phase4 et phase7 ne
constituent pas un rapport final Go/No-Go.

La documentation du contrat retenu est `docs/CONTRAT_V02.md`. Toute reprise ou
extension du périmètre attend une nouvelle instruction explicite de l’utilisateur.
