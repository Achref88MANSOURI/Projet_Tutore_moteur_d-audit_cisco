# Inventaire documentaire Cisco IOS / IOS-XE — routeurs

Cet inventaire est un **outil de recherche versionné**, indépendant du parseur.
Il n'est ni une grammaire complète, ni une liste de commandes validées sur
tous les routeurs. Aucun de ses fichiers n'est chargé par le runtime TTP.

## Périmètre et méthode

1. Partir des catalogues Cisco de références pour ISR 1000/4000, ASR 1000,
   Catalyst 8200/8300/8500 et 8000V, puis consulter les index historiques et
   guides de configuration. Les URL initiales sont dans `seeds.json`.
2. Sélectionner les références par technologie proposées par ces catalogues,
   hors livres de debug et SD-Routing. Pour la programmabilité, sélectionner
   explicitement 17.12.x et 17.18.x ; les autres releases restent visibles dans
   la frontière documentaire. Les guides indexés ne sont pas tous dépouillés.
   Des références complémentaires multicast IPv4 et Flexible NetFlow ont été
   ajoutées à partir de la recherche officielle Cisco.
3. Suivre les chapitres HTML du même répertoire de livre, hors index/préfaces.
   La collecte n'est pas un parcours récursif de tout Cisco.com.
4. Extraire les articles structurés de référence : nom, paragraphes de syntaxe,
   modes, labels de releases et types de changements de Command History.
   Conserver chaque occurrence par source : deux commandes homonymes dans
   deux modes ne sont pas fusionnées automatiquement.
5. Mettre dans `inventory.jsonl` les candidats dont le mode mentionne la
   configuration ; journaliser les commandes d'exploitation dans `excluded.jsonl`
   et les articles incomplets dans `anomalies.jsonl`.
6. Relire un échantillon contre des exemples Cisco de configuration. L'échantillon
   relu reste distinct des milliers d'articles extraits automatiquement.

Les syntaxes sont des transcriptions lisibles de la notation Cisco, avec espaces
normalisés. Les accolades, crochets et alternatives restent présents. Les
italiques HTML ne sont pas conservées : il faut consulter la référence pour
distinguer précisément chaque argument et mot-clé. Ce format **ne doit pas être
compilé automatiquement en template ou en commande à exécuter**.

## Lire les preuves et la confiance

- `source` : URL avec ancre d'article, livre, date UTC et SHA-256 des octets HTML
  réellement reçus. La date de collecte n'est pas une date de sortie logicielle.
- `modes` : libellés Cisco publiés ; `context_path: null` signifie que la hiérarchie
  complète des sous-modes n'a pas été établie. L'indentation d'une config ne suffit
  pas à la déduire pour toutes les technologies.
- `documented_forms` : seulement les formes positive/no/default imprimées dans
  la section syntaxe. On n'ajoute pas automatiquement `no` ou `default`.
- `os_families_document_scope` : périmètre du corpus de références IOS/IOS-XE,
  **pas une preuve du support de chaque entrée dans les deux OS**.
- `platform_mentions` : noms repérés dans l'article, pas une matrice de support.
  `platform_support: unverified_per_command` empêche cette interprétation.
- `release_history_labels` et `release_history` : événements historiques documentés.
  Une intégration ou modification à une release ne prouve ni un support continu,
  ni l'absence sur les autres trains ; les variantes ne sont pas automatiquement
  associées à une plage de releases.
- `configuration_presence` : candidat issu d'un mode de configuration documenté.
  `serialization` reste non vérifiée sans preuve supplémentaire. Une commande
  interactive en mode configuration n'est pas nécessairement une ligne sauvegardée.
- `confidence` : dimensions indépendantes (syntaxe, mode, support, persistance).
  `medium_automatic_extraction` signale une extraction mécanique à relire.
  `unknown` est une lacune explicite, jamais une absence de support.

Les références communes contiennent aussi des commandes propres à des
commutateurs ou à du matériel ancien. **Un candidat extrait d'un livre lié depuis
la page ASR n'est pas pour autant une commande ASR confirmée.** Le rapport détaille
cette limite. IOS XR, NX-OS et ASA sont hors périmètre ; Cisco 8000 sous IOS XR
ne doit pas être confondu avec Catalyst 8000 Edge sous IOS-XE.

## Fichiers

| Fichier | Rôle |
|---|---|
| `TASK.md` | Tâche locale Codex, contraintes et critères |
| `seeds.json`, `books.json` | Points de départ et livres découverts |
| `sources.json` | Registre d'accès et empreintes des sources |
| `inventory.jsonl`, `inventory.csv` | Candidats documentaires et variantes |
| `reviewed.jsonl`, `review_specs.json` | Échantillon relu et sélections de preuves |
| `syntax_groups.jsonl` | Regroupement exact des syntaxes/modes identiques, sans fusion sémantique |
| `excluded.jsonl` | Commandes rejetées et motif |
| `anomalies.jsonl` | Articles nécessitant une autre extraction/relecture |
| `frontier.json` | Documents découverts mais non dépouillés |
| `summary.json`, `COVERAGE.md` | Comptages et lacunes, sans taux global inventé |
| `schema.json` | Contrat de données de l'inventaire |
| `validation.json`, `CHANGELOG.md` | Contrôles du snapshot et historique de l'inventaire |
| `collect.py`, `review.py`, `validate.py`, `test_collect.py` | Outils locaux indépendants |

## Reproduction

Depuis la racine du projet, avec Python 3.12 et sa bibliothèque standard :

```powershell
.\.venv\Scripts\python.exe docs/cisco-command-inventory/collect.py
.\.venv\Scripts\python.exe docs/cisco-command-inventory/review.py
.\.venv\Scripts\python.exe docs/cisco-command-inventory/validate.py
.\.venv\Scripts\python.exe -m unittest discover -s docs/cisco-command-inventory -p 'test_*.py'
```

La collecte utilise au plus trois lectures HTTP simultanées, uniquement sur les
URL publiques `www.cisco.com`. Elle n'utilise ni compte Cisco, ni appareil réseau,
ni CLI du routeur. Le cache HTML dans `cache/cisco-command-inventory/` est ignoré
par Git ; les pages complètes ne sont pas redistribuées dans l'inventaire.

`collect.py --offline` reconstruit les données avec le cache local, après vérification
des empreintes. Sans cache, les fichiers versionnés restent lisibles et
`validate.py` contrôle leur cohérence ; il ne recrée pas les preuves absentes.
Ne pas utiliser `--offline` dans un clone neuf pour écraser une collecte existante.
`--limit N` permet une collecte partielle explicite et journalise la frontière.
Pour actualiser une source déjà cachée, déplacer sa paire de fichiers de cache
hors de ce dossier, puis relancer la collecte. Les pages peuvent évoluer : une
nouvelle collecte ne doit pas être présentée comme identique à ce snapshot.

Le droit d'auteur des pages Cisco reste à Cisco. Seules les métadonnées et les
syntaxes factuelles utiles à l'étude sont versionnées. L'inventaire n'accorde
aucune licence sur la documentation source ni sur les logiciels Cisco.
