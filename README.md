# Normalisation Cisco avec TTP

**Version du pipeline : 0.2.0. Contrat de sortie conservé : NormalizedConfig 0.1.0.**

Ce dossier contient une nouvelle implémentation indépendante du précédent
`cisco_config_parser`. Le moteur est **TTP** — c'est le nom utilisé dans le
document de référence, et non « TDP ».

## Démarrage immédiat

L'environnement est déjà installé dans `.venv`, pour Windows x64 / Python 3.12.
Depuis ce dossier :

```powershell
.\.venv\Scripts\python.exe cli.py configs\01_F0456_rt1.bsqmk.cfg --output outputs\mon_essai --os-family ios
```

Trois fichiers sont produits :

- `parsed_native.json` : templates officiels, captures complémentaires et inventaire avec numéros de lignes ;
- `normalized_config.json` : le contrat Pydantic/JSON Schema original ;
- `coverage_report.json` : chaque commande, son contexte, son extracteur et son statut de conversion.

Le fichier d'entrée reste inchangé. `--strict` retourne un code 2 lorsque des
commandes n'ont pas de mapping complet, même si les sorties sont écrites.

Pour relancer le pilote, les 20 fichiers, les tests et le rapport :

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\run_all.ps1
```

Ou lancer directement les étapes Python :

```powershell
.\.venv\Scripts\python.exe tools\evaluate_twenty.py --pilot
.\.venv\Scripts\python.exe tools\evaluate_twenty.py
.\.venv\Scripts\python.exe -m pytest tests -q -p no:cacheprovider --junitxml=outputs/tests.xml
.\.venv\Scripts\python.exe tools\build_report.py
```

Ouvrir ensuite **`outputs/RAPPORT_EVALUATION.html`** ou
`outputs/RAPPORT_EVALUATION.md`.

## Organisation

```text
network-config-normalizer-ttp/
├── .venv/                 environnement Python installé
├── wheelhouse/            paquets figés pour réinstallation hors ligne
├── requirements.lock      versions exactes des bibliothèques
├── configs/               copies identiques des 20 configurations et manifeste
├── templates/
│   ├── upstream/          quatre templates officiels utilisés, inchangés
│   ├── cisco_ios/         extensions TTP par famille
│   ├── rules.json         règles déclarées et patterns
│   └── catalogue_*.json   origine, empreintes et couverture observée
├── parser/                inventaire de source, moteur TTP et couverture
├── normalizer/            mapping des captures, validation du contrat
├── schemas/               copie inchangée du contrat et de son schéma
├── baseline/              résultats historiques et 3 051 coordonnées sources
├── tests/                 cas synthétiques et faits relevés dans les sources
├── outputs/               pilote, corpus, trois sorties par fichier et rapports
├── vendor/                dépôts Git clonés pour référence et traçabilité
├── tools/                 génération des templates, évaluation, rapports
└── docs/                  approche demandée, dépendances, licences et catalogue
```

Les originaux du dossier parent n'ont été ni déplacés ni modifiés. Les copies
dans `configs/` sont contrôlées par SHA-256. Aucun fichier parent n'est nécessaire
pour exécuter le parseur ou les tests ; `prepare_local_inputs.py` est seulement
le script historique d'import initial.

## Ce qui fonctionne dans cette version

- Les quatre templates officiels de **ttp_templates 0.6.18** — interfaces, VRF,
  ASN BGP et NAT statique — sont exécutés sur le texte complet. Les fonctions
  Python officielles de transformation sont exécutées avec eux.
- Des valeurs d'adresses IPv4 et de RD issues de ces résultats sont consommées
  lorsqu'elles concordent avec les captures sourcées. Les défauts automatiques
  comme `enabled=true` sont ignorés sans commande explicite.
- Les extensions utilisent de véritables règles TTP pour extraire les champs.
  L'inventaire Python fournit les lignes et le contexte ; il ne remplace pas
  TTP par l'ancien parseur. Un test vérifie que changer une capture TTP change
  effectivement la valeur normalisée.
- Les interfaces, VRF, routes statiques, BGP de base, OSPFv2, ACL, paramètres de
  gestion, politiques simples et attaches QoS sont convertis dans les limites
  du contrat existant. L'héritage simple explicite du remote-as et les actions
  AS_PATH prepend sont également couverts par des tests.
- Plusieurs propriétés avancées sont capturées en natif sans être forcées dans
  un champ inadéquat : PIM, MPLS, OSPFv3, paramètres physiques, classes QoS,
  EVPN/VPLS, PKI et options BGP par famille.
- Les blocs de certificats et de bannières sont regroupés comme contenus opaques.
  Le terminateur PKI `quit` appartient au certificat, jamais à sa dernière ligne
  hexadécimale. Les contenus restent accessibles dans les fichiers d'entrée
  copiés ; les exports donnent leurs empreintes et leurs positions.

**Une capture TTP ne signifie pas que toute sa sémantique est normalisée.**
Consulter les rapports pour les nombres mesurés, les limites et les différences
avec l'ancien compteur « commandes reconnues ».

Les modèles système ne déduisent ni la complétude du fichier ni les défauts
constructeur. `transport input ssh` ne prouve pas qu'un service SSH fonctionne.
Une prefix-list avec `deny` ou `ge/le` n'est pas réduite à une liste de préfixes
permis qui changerait son sens. Les politiques incomplètes restent signalées.

## Réinstallation et portabilité

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\setup.ps1
```

`setup.ps1` installe uniquement dans `.venv`, à partir des roues de `wheelhouse`.
Ces roues binaires sont préparées pour **Windows x64 / CPython 3.12**.
L'interpréteur Python de base reste un prérequis système ; un environnement
virtuel n'est pas une distribution complète et portable de Python.

Pour une autre plateforme, installer Python compatible puis utiliser
`python -m pip install -r requirements.lock` avec un accès au dépôt de paquets.
Le fichier `docs/dependencies.json` donne les versions installées et les
révisions Git. Les dépendances de référence sont TTP 0.10.1, ttp-templates
0.6.18 et Pydantic 2.14.1.

## Sources et réutilisation

- [dmulyalin/ttp](https://github.com/dmulyalin/ttp) : moteur, licence MIT.
- [dmulyalin/ttp_templates](https://github.com/dmulyalin/ttp_templates) : collection
  officielle et utilitaires, licence MIT ; quatre templates actifs figés ici.
- [tbotnz/ios-show-run-ttp](https://github.com/tbotnz/ios-show-run-ttp) : référence
  locale étudiée ; aucun code importé dans le runtime. Sans licence explicite
  dans la révision clonée, cette copie n'est pas incluse dans l'archive de livraison.
- Le dépôt ASA n'est pas une dépendance de ce parseur IOS/IOS-XE.

Le modèle métier reste celui du projet, aligné sur OpenConfig. Aucun modèle
IETF ne remplace le contrat et aucun export YANG/RFC7951 complet n'est annoncé.
