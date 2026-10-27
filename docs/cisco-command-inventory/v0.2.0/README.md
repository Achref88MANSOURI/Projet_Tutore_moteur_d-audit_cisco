# Qualification Cisco routeurs — version documentaire 0.2.0

Lire d'abord `QUALIFICATION_REPORT.md`, puis `COVERAGE_V02.md`. Le catalogue reste
non exhaustif. Les milliers de familles syntaxiques non vérifiées sont conservées
avec le statut `uncertain`, pas présentées comme prises en charge par les routeurs.

## Unités et statuts

- Une `documented_syntax_family` conserve les variantes effectivement imprimées
  par Cisco. Ses paramètres proviennent du balisage HTML ; leur liste peut être
  incomplète. Les types/plages non transcrits restent inconnus.
- Une `observed_instance` est une forme **littérale** séparée. La preuve de
  `hostname Router` n'établit pas toutes les valeurs ou options de `hostname`.
- `confirmed_config` : forme effectivement observée dans une sortie running-config
  Cisco identifiée. Ce n'est pas une validation sur appareil ou une preuve de
  sérialisation universelle. Aucun exemple CLI seul n'obtient ce statut.
- `documented_config` : applicabilité documentaire conditionnelle à un routeur,
  ou exemple CLI dans un guide de plateforme, sans sortie sauvegardée attestée.
- `uncertain` : preuve de plateforme, mode, variante ou persistance insuffisante.
- `excluded` : exclusion explicitement justifiée pour cette syntaxe et ce contexte,
  par exemple `do` ou `enable` en contexte App Hosting limité aux Catalyst 9410.

`platforms_confirmed` est toujours limité par `platform_conditions`, la preuve et
le contexte. Les noms regroupés d'un guide commun n'affirment pas une compatibilité
avec chacun de ses modèles. Le PID C1111 vient de l'UDI de l'exemple ; le Cisco
881W est nommé par le guide. Les tokens `version` des configurations ne sont pas
convertis en releases IOS-XE. Aucun intervalle de support continu n'est inféré.

Les `release_history_not_support` et `document_release_scope_not_support` restent
des métadonnées. Les assertions concernant un mot-clé particulier (par exemple
`strict`, IOS-XE 3.10) sont isolées dans `scoped_applicability_claims` et ne qualifient
pas toutes les variantes de la commande.

Les extraits de preuve sélectionnent la ligne et ses en-têtes de contexte ; ils
ne sont pas nécessairement contigus dans l'original. Les sélecteurs et empreintes
du bloc source permettent de retrouver leur emplacement sans fabriquer une
nouvelle configuration exécutable.

## Fichiers de livraison

| Fichier | Usage |
|---|---|
| `router_config_commands.jsonl` | Catalogue et preuves par entrée |
| `QUALIFICATION_REPORT.md` | Méthode, chiffres, limites, décision pour TTP |
| `COVERAGE_V02.md` | Couverture par technologie et plateforme, sources restantes |
| `EXCLUSIONS_AND_UNCERTAINTIES.csv` | Toutes les entrées non confirmées, motifs et sources |
| `SOURCE_REGISTRY.json`, `FRONTIER_RELEVANCE.json` | Accès, portée de lecture et pertinence documentaire |
| `VALIDATION_SAMPLES.md`, `SAMPLE_EXPECTATIONS.json` | Échantillon fixé séparément des règles de classement |
| `LEGACY_LINKS.jsonl`, `BASELINE_MANIFEST.json` | Rattachement aux 7 296 occurrences et intégrité du snapshot |
| `ARTICLE_FACTS.jsonl`, `NEW_CANDIDATES.jsonl` | Faits structurés relus automatiquement, paramètres, locateurs |
| `ANOMALY_TRIAGE.jsonl`, `PAGE_AUDIT.json` | Triage des 261 anomalies et relevé des pages exploitées |
| `CONFIGURATION_PROOFS.jsonl`, `SCOPED_EVIDENCE.json` | Extraits factuels et claims vérifiés, sans abstraction de grammaire |
| `EVIDENCE_SELECTIONS.json`, `SCOPED_CLAIMS.json` | Sélections fixes et conditions de portée |
| `RESEARCH_FETCHES.json`, `research_sources.json` | Lectures supplémentaires, échecs et liens découverts |
| `SUMMARY.json`, `VALIDATION.json` | Comptages séparés et résultats des contrôles |

## Reproduction hors ligne du catalogue

Les scripts utilisent uniquement Python 3.12 et sa bibliothèque standard.
Depuis la racine du projet :

```powershell
.\.venv\Scripts\python.exe docs/cisco-command-inventory/v0.2.0/build_catalog.py
.\.venv\Scripts\python.exe docs/cisco-command-inventory/v0.2.0/validate_catalog.py
.\.venv\Scripts\python.exe docs/cisco-command-inventory/v0.2.0/check_reproducibility.py
.\.venv\Scripts\python.exe -m unittest discover -s docs/cisco-command-inventory/v0.2.0 -p 'test_*.py'
```

La reconstruction normale utilise les fichiers de faits/preuves versionnés et
les entrées du snapshot 0.1.0. Elle n'a besoin ni du réseau ni des caches HTML.
Elle reproduit un snapshot documentaire ; elle ne valide pas indépendamment la
vérité d'une page absente. Les URLs, empreintes des octets reçus et sélecteurs de
preuves servent à refaire l'audit de provenance.

Pour réextraire les preuves depuis les pages conservées localement :

```powershell
.\.venv\Scripts\python.exe docs/cisco-command-inventory/v0.2.0/prepare_evidence.py
.\.venv\Scripts\python.exe docs/cisco-command-inventory/v0.2.0/curate_evidence.py
.\.venv\Scripts\python.exe docs/cisco-command-inventory/v0.2.0/build_catalog.py
.\.venv\Scripts\python.exe docs/cisco-command-inventory/v0.2.0/validate_catalog.py --verify-cache
```

Les caches `cache/cisco-command-inventory/` et `cache/cisco-qualification-v02/`
contiennent les octets HTML originaux et restent hors Git. Leur absence empêche
une réextraction, mais pas la reconstruction à partir des faits versionnés.
Les pages complètes Cisco ne sont pas redistribuées dans le catalogue.

`collect_sources.py` effectue une collecte réseau explicite, avec trois lectures
simultanées au maximum, en écrivant uniquement dans le cache de phase 2. Les
anciennes sources ne sont pas modifiées. Il dépouille tous les chapitres de la
référence EEM sélectionnée et au plus trois chapitres par guide de configuration
sélectionné ; les autres liens restent dans le registre comme non relus.

Le tri de pertinence par URL/titre n'est pas une preuve du contenu d'un document.
L'échantillon fixe et son validateur sont distincts des règles de classement ;
ils ne constituent pas une expertise humaine externe ni une validation exhaustive.

Cette version ne lit ni ne compare les templates TTP et ne modifie aucun moteur,
mapping, contrat métier ou audit de fidélité. Les fichiers de travail concurrents
hors de ce sous-dossier sont préservés et exclus des commits de cette mission.
