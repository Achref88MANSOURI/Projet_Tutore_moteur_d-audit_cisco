# Patch Config Studio — liaison frontend ↔ moteur local

L’interface utilise `cli.normalize` dans un processus isolé et restitue exclusivement
`RouterContractV1`. Le parsing TTP et les mappings métier sont ceux du pipeline
de production. Aucune dépendance externe supplémentaire n’est nécessaire.

## Installation
1. Avant de copier, sauvegarder votre éventuel `webapp.py` et votre HTML existants.
2. Copier `webapp.py` à la RACINE du dépôt `network-config-normalizer-ttp`, au même niveau que `cli.py`.
3. Copier `web/index.html` dans le sous-dossier `web` du même dépôt.

## Lancement dans PowerShell (Windows)
```powershell
cd "C:\Users\achre\.codex\.chatgpt-projects\g-p-6ac119134e18819194cd3163ddeeb560\network-config-normalizer-ttp"
.\.venv\Scripts\python.exe .\webapp.py
```
Le lanceur `.\run_ui.ps1` utilise également l’environnement Python du dépôt.
Si l'environnement .venv n'existe pas, utilisez l'interpréteur Python avec lequel le CLI fonctionne déjà.

Ouvrir dans Chrome/Edge : http://127.0.0.1:8000
NE PAS utiliser `file:///.../index.html`, Live Server ou l'aperçu ChatGPT :
la route relative `/api/normalize` doit être servie depuis la MÊME origine HTTP.

## Tests simples
```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/health
```
Doit renvoyer status `ok`, ready `True` et contract `RouterContractV1`.

```powershell
$body = @{ configuration = "hostname LAB-R01`ninterface Loopback0`n ip address 192.0.2.1 255.255.255.255`n!"; os_family = 'ios' } | ConvertTo-Json
Invoke-RestMethod -Uri http://127.0.0.1:8000/api/normalize -Method Post -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($body))
```
Doit renvoyer `normalized` et `duration_ms`.

Dans la page, « Charger un exemple » permet de tester les interfaces, AAA, SSH,
l’authentification d’aire OSPF et les valeurs `null`, `false` et `[]`.
Les vues Code et Arborescence, la copie et le téléchargement conservent le même
contrat V1. Le téléchargement s’appelle `normalized.json`.

## Si erreur
- 404 `/api/normalize` : l'interface n'est pas ouverte depuis le serveur Python de ce patch.
- Connection refused : le script n'est pas en cours d'exécution, ou le port est occupé.
- 422 : la configuration correspond à une plateforme non prise en charge.
- 429 : une autre normalisation est en cours ; réessayer après son achèvement.
- 500 : exécuter séparément `cli.py` pour diagnostiquer la configuration ; les détails internes ne sont pas renvoyés par le Web.
- 504 : le parseur a dépassé la limite de 120 s.
- Ne fermez pas la fenêtre PowerShell pendant que vous utilisez l'interface.

`webapp.py` écoute UNIQUEMENT sur 127.0.0.1 (pas d'exposition Internet).
La configuration et le résultat transitent en mémoire, sans fichier temporaire.
Les requêtes du navigateur doivent venir de la même origine locale.

Tests Web uniquement :
```powershell
.\.venv\Scripts\python.exe -m pytest -q --tb=short --basetemp .pytest_cache/web-check tests/test_webapp.py
```

## EIGRP dans le pipeline canonique

Le dépôt original comprend le parsing et le mapping EIGRP classique IPv4/IPv6 et
nommé, avec portées AF/VRF, af-interface et topologies. Les métriques composites,
références de politiques, paramètres d'interface et authentification reconnus
alimentent directement `RouterContractV1`.

La [documentation EIGRP](docs/eigrp/README.md) contient les sources Cisco officielles,
la matrice des règles, les décisions de modélisation, les limites et les commandes
de vérification. Exemple synthétique à importer dans le Web ou à exécuter en CLI :

```powershell
.\.venv\Scripts\python.exe cli.py tests/fixtures/eigrp/named_dualstack.cfg --output outputs/eigrp-demo --os-family iosxe
```

Le JSON Schema est régénéré ; les consommateurs utilisant un ancien schéma fermé
doivent l'actualiser. Le dossier `à exporter` n'est pas synchronisé par cette
intervention. Un serveur Web déjà lancé doit être redémarré pour charger les modèles
Python mis à jour.

## Stabilisation après le diagnostic Cisco

Les corrections des pertes démontrées (conditions `match community`, ACL TCP
`established`, variantes QoS de précédence, métadonnées, NetFlow et aires OSPF)
sont décrites dans le [bilan de correction](docs/diagnostic_17_tests/CORRECTIONS_ET_VALIDATION.md).
Une définition reconnue puis retirée comme incomplète ne peut plus rester la cible
d'une référence publiée : le pipeline refuse alors l'export. Une référence externe
dont la définition n'est pas fournie reste conservée, sans objet inventé.

Le JSON Schema a été actualisé avec les champs typés nécessaires. Le contrat
conserve son nom et sa version `RouterContractV1` / `1.0.0` ; les consommateurs
utilisant une copie antérieure du schéma doivent adopter le schéma généré courant.
Le dossier `à exporter` reste inchangé par cette stabilisation.
