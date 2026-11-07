# Validation Phase 6A.1 — Dashboard Cisco CIS

**Date de validation :** 2026-11-07
**Périmètre :** réparations ciblées frontend/backend, routes existantes, profil CIS, sécurité de rendu, diagnostic VTY.
**Copie examinée/modifiée :** `C:\Users\achre\AppData\Local\Temp\network-config-normalizer-ttp-phase6a1`
**Miroir source :** `C:\Users\achre\.codex\.chatgpt-projects\g-p-6ac119134e18819194cd3163ddeeb560\network-config-normalizer-ttp` (aucun fichier modifié).

## 1. Résumé de validation

| Domaine | Résultat vérifié |
|---|---|
| Syntaxe du JavaScript inline | Réussie avec `node --check` |
| Catalogue et manifeste | HTTP mémoire 200; 90 contrôles chacun; aucun ID manquant |
| Registre CIS | 63 IDs enregistrés, réellement lus dans le registre |
| Profils | Level 1 : 53 findings; Level 2 cumulatif : 90 findings |
| Tests Web + frontend | 38 passés, 1 xfailed strictement attendu |
| TTP/VTY | Perte reproduite dans la normalisation; test de non-régression documenté en xfail strict |
| Parcours navigateur E2E | Non exécuté : sockets locaux interdits par la sandbox (WinError 10013) |
| Suite globale | Baseline préexistante : 67 erreurs de collection sur `pytest -q`; `pytest tests` : 112 échecs et 1125 réussites avant correction |

La validation ne signifie pas que tout le dépôt est vert. Les échecs globaux existaient avant les changements; ils portent largement sur des corpus/tests parser-normalizer hors périmètre. Ils ne sont ni masqués ni corrigés ici.

## 2. État initial et défauts reproduits

- Le script inline échouait à l'analyse Node sur `escapeHtml`, à cause d'un littéral apostrophe mal fermé dans `.replace(/'/g,''')`.
- `/api/catalog` renvoyait HTTP 500 : le worker concaténait une boucle `for` et des `if` compound après des points-virgules dans une chaîne `python -c` ; Python interdit cette forme.
- Le changement de profil ne faisait que modifier le badge, sans nouveau POST `/api/audit` ni invalidation du rapport visible.
- Le chargement du manifeste/catalogue appelait `response.json()` sans vérifier `response.ok`, puis avalait les erreurs.
- L'interface remplaçait des Findings réels par `UNKNOWN` à partir de métadonnées statiques du manifeste, y compris `tested`; ceci pouvait faire diverger table/KPI des statuts retournés par le moteur.
- Le score affichait 0 % si aucun PASS/FAIL n'était déterminable.
- Les diff par ID étaient fictifs et indépendants de la configuration; balises HTML retournées puis placées comme texte. Ils ne démontraient aucune correction contextualisée.
- Les tests Web antérieurs (29 passés) ne couvraient ni le catalogue ni le POST audit de manière suffisante.
- Aucun E2E navigateur n'était possible faute d'écoute socket locale.

## 3. Fichiers modifiés dans la copie indépendante

- `webapp.py`
- `web/index.html`
- `tests/test_webapp.py`
- `tests/test_web_frontend.py` (nouveau)
- `tests/test_phase6a1_vty_diagnostic.py` (nouveau)
- `docs/dashboard/USER_GUIDE.md`
- `docs/dashboard/PHASE6A1_VALIDATION.md` (ce document)

Aucun changement à RouterContractV1, au parser, au normaliseur, aux templates TTP, au moteur historique, aux évaluateurs CIS ou au dépôt externe de référence.

## 4. Corrections et raisons

### Backend

`get_catalog_metadata()` importe directement `CISIOS15Catalog` et `_build_evaluator_registry()`, calcule les nombres/familles avec du Python normal, expose la liste des contrôles utiles à l'interface, et expose les IDs du registre réel. Une comparaison additive donne `catalog_count=90`, `manifest_count=90` et des listes d'IDs manquants vides. `tested` et `mapping_verified` ne sont pas utilisés comme preuve d'exécution.

`POST /api/audit` valide le type exact de `profile_level` (un booléen ne peut plus se faire passer pour `1`), le type `include_lower`, l'objet `evidence` et le RouterContractV1. Les erreurs de validation du document sont ramenées à un message contrôlé et ne réémettent pas les valeurs reçues (qui pourraient contenir un secret).

### Frontend

- Échappement HTML complet corrigé, y compris apostrophe.
- Helper `fetchJson` vérifie les statuts HTTP, les corps JSON invalides et les erreurs réseau avec messages compréhensibles.
- Profil modifié : le rapport est invalidé, les résultats/détails effacés, puis nouvel audit sur le document normalisé conservé en mémoire. Les jetons de version et d'exécution ignorent les réponses tardives d'un ancien fichier/profil.
- Import fichier invalide/trop grand : le document précédent et ses résultats ne restent pas affichés comme s'ils correspondaient au fichier courant.
- Les statuts présentés sont ceux du rapport CIS réel. Les évaluateurs disponibles/sans évaluateur sont une métrique séparée provenant du registre runtime, pas un état de conformité.
- Le score utilise uniquement `PASS / (PASS + FAIL)`, indique le dénominateur et affiche « Non déterminable (0/0) » à défaut. La couverture d'évaluateurs est séparée.
- Les métadonnées de détail CIS viennent du catalogue; le texte utilisateur est placé via `textContent` ou échappé avant insertion de fragments contrôlés.
- Les exemples de diff codés en dur sont supprimés. Le panneau FAIL explique qu'aucun diff contextuel n'est disponible avant SourceMap. Aucune commande n'est exécutée.
- Export CSV protège les cellules commençant par des caractères de formule; les valeurs exportées sont citées/échappées.

## 5. Routes et tests effectués

Tests en mémoire, avec le vrai Handler et le vrai pipeline CLI/audit, sans socket :

- `GET /api/health` : couvert par les tests Web historiques.
- `GET /api/catalog` : 200, 90 contrôles, 63 évaluateurs, famille/profils, liste de contrôles, cohérence manifeste.
- `GET /api/manifest` : 200, 90 règles.
- `POST /api/normalize` : parcours réel déjà couvert par la suite existante, dont IOS/IOS-XE, entrées malformées, BOM/secrets, tailles et plateforme.
- `POST /api/audit` : rapports réels Level 1/Level 2 avec 53/90 findings; entrées invalide booléen, `include_lower`, evidence, contrat rejetées sans écho du canari sensible.

Commande exécutée :

```powershell
$py = 'C:\Users\achre\.codex\.chatgpt-projects\g-p-6ac119134e18819194cd3163ddeeb560\network-config-normalizer-ttp\.venv\Scripts\python.exe'
$env:PYTHONDONTWRITEBYTECODE = '1'
& $py -B -m pytest -p no:cacheprovider --basetemp='C:\Users\achre\AppData\Local\Temp\phase6a1-pytest' tests/test_webapp.py tests/test_web_frontend.py tests/test_phase6a1_vty_diagnostic.py -q --tb=short
```

Résultat exact : **38 passed, 1 xfailed in 21.71s**. Le test JavaScript extrait le script inline et passe `node --check`. Un test ciblé antérieur a détecté que Pydantic incluait l'entrée rejetée dans son message d'erreur; le backend a été corrigé pour renvoyer un message générique, puis la suite a repassé.

## 6. Diagnostic VTY/TTP reproduit

Configuration minimale testée :

```cisco
hostname LAB
line vty 0 4
 transport input ssh telnet
!
```

Chemin vérifié :

1. `parser.inventory` conserve la ligne `transport input ssh telnet`, numéro de source 3, racine `line vty 0 4`.
2. `parser.run_ttp.extract` émet une capture `services_transport`, avec valeur `ssh telnet`, `source_line=3`, `root_line=2`, et le contexte VTY.
3. `parser.validation.validate_record` accepte la capture.
4. Le dispatcher de `normalizer/engine.py` ne consomme pas cette capture. La résolution observée reste vide; le contrat sort `system.management.lines: null` au lieu d'une ligne avec `allowed_transports`.
5. `normalizer/domains/services.py` traite les variantes `services_transport_output` et `services_transport_output_remove`, mais pas l'identifiant `services_transport` pour cette commande `transport input`.

**Conclusion :** la perte se situe dans le dispatch/mapping de normalisation des captures, pas dans le template TTP, la création de contexte ou la validation de capture. Une fixture n'est pas la cause : le test passe une vraie configuration brute au pipeline. Le test de diagnostic exige les transports attendus et est `xfail(strict=True)`; c'est un défaut connu explicite, pas une réussite masquée. Correctif minimal futur : reconnaître `services_transport` dans le domaine services, rattacher la capture à la ligne VTY et préserver les sémantiques IOS/negation; à traiter dans une mission distincte avec tests dédiés. Aucun audit CIS ne relit ici la CLI brute.

## 7. Non vérifié et limitations

- Le rendu visuel, le glisser-déposer dans un navigateur, la navigation Code/Tree avec DOM réel, la bascule profil côté interface en navigateur et le téléchargement n'ont pas été testés par navigateur. Node vérifie la syntaxe et les tests vérifient les points de sécurité structurels; cela ne remplace pas un E2E.
- La sandbox rejette la création d'un serveur local (Windows 10013), empêchant une vérification HTTP sur socket.
- Le test source testifie le rendu textuel/échappé du contenu hostile, mais ne constitue pas une analyse dynamique navigateur complète.
- Il n'existe pas de SourceMap reliant Finding → JSON Pointer → objet normalisé → bloc CLI → ligne source. Le tableau de preuves peut afficher les JSON Pointers retournés par les évaluateurs, mais pas naviguer jusqu'au fichier Cisco.
- Les suggestions contextuelles et commandes de remédiation sont volontairement absentes; les données catalogue peuvent documenter la remédiation, mais elles ne prouvent pas qu'un changement CLI est sûr pour un appareil précis.
- L'isolation complète multi-analyse a des garde-fous de version frontaux; le navigateur réel n'a pas été disponible pour vérifier les interactions concurrentes.

## 8. Limites des suites globales préexistantes

Baseline enregistrée avant modification dans la copie indépendante :

- `pytest -q` : 67 erreurs de collection à cause de duplications de tests archivés sous `docs/` et `baseline/`/conflits de noms de modules.
- `pytest tests` : 112 échecs, 1125 réussites sur 1237 tests, avant les changements Phase 6A.1.
- `pytest tests/test_webapp.py` : 29 réussites avant les ajouts.
- `node --check` : échec initial sur `escapeHtml`.

Les échecs historiques ne sont ni imputés aux changements Web ni traités dans cette phase. Ils doivent être triés indépendamment avant de déclarer une suite totale verte.

## 9. Environnement Git et stratégie de travail

Le miroir source est synchronisé et interdit à la modification par `AGENTS.md`; il est resté intact. Avant copie, son état contenait six modifications suivies préexistantes, plus de 6 000 fichiers non suivis et des milliers ignorés; un clone seul aurait perdu ces travaux. Le contenu pertinent et l'historique Git ont donc été recopiés vers une copie indépendante, sans environnements virtuels, caches ni dossier vendor, et avec les changements suivis/non suivis pertinents conservés.

Le chemin demandé `C:\workspace\network-config-normalizer-ttp-phase6` n'était pas créable dans cet environnement : Windows renvoyait Access denied sur `C:\workspace`. Un essai de clone local par Git a aussi échoué sur la création d'objets nommés Git for Windows. La copie de travail utilisée est donc dans `%LOCALAPPDATA%\Temp`, accessible en écriture, mais temporaire. Avant une suite de travaux durable, recopier cette copie (y compris `.git` et les changements utiles) vers un dossier local autorisé hors synchronisation, puis vérifier `git status`; ne pas reprendre le miroir comme workspace d'écriture.

Aucun changement n'a été écrit dans `sources/` ou le miroir, aucun fichier du dépôt de référence externe n'a été touché, et aucun push n'a été fait.
