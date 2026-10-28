# Normalisation Cisco avec TTP

Le moteur produit uniquement `normalized.json`, une configuration métier alignée
sur les concepts OpenConfig, avec des extensions Cisco explicites. Le contrat
unique est `schemas/normalized_config.py` ; son schéma public est
`schemas/normalized_export_v1.schema.json`.

## Exécution

```powershell
.\.venv\Scripts\python.exe cli.py configs\01_F0456_rt1.bsqmk.cfg --output outputs\mon_routeur --os-family ios
```

```python
from cli import normalize, convert_file
configuration = normalize(texte_cisco)
configuration = convert_file("routeur.cfg", "outputs/routeur", os_family="ios")
```

Ces fonctions retournent un dictionnaire métier. `export_file` est un alias de
`convert_file`. Le fichier produit est un JSON compact. Les anciennes options
`--legacy`, `--output-format`, `--schema-version` et `--strict` restent retirées.

## Architecture active

Lecture et identification → inventaire structurel → captures TTP → moteur unique
→ modèle métier validé → sérialisation JSON.

- `parser/` lit directement les identifiants et motifs des 28 fichiers `.ttp`.
  `templates/rule_metadata.json` porte uniquement les restrictions `scope` et
  `choices`. Les quatre templates officiels figés restent disponibles pour les
  captures concordantes. Les templates se maintiennent directement, sans
  génération préalable.
- `normalizer/engine.py` valide les captures et leurs contextes, établit les
  identités, appelle le domaine propriétaire et résout les références différées.
  Une affectation échouée est annulée avant la commande suivante.
- `normalizer/domains/` construit directement les objets métier : interfaces,
  VLAN, ACL, politiques, services, NAT, VPN, QoS, PKI et extensions Cisco.
  Le sous-dossier `routing/` contient BGP, OSPF, RIP, routes statiques, VRF
  et prefix-lists. Chaque capture possède un seul domaine propriétaire.
- `normalizer/common/` contient les conversions et contextes partagés, la
  validation du contrat et la sélection des valeurs explicitement configurées.
  Les associations temporaires portent seulement un champ et un indice de capture.
- `schemas/normalized_config.py` définit un seul modèle actif, sans héritage
  de versions historiques. BGP utilise directement voisins, groupes et familles
  d'adresses ; les ACL et actions de politiques sont typées dès leur construction.
- `normalizer/serialization.py` transforme le modèle final en dictionnaire ou
  JSON. Il ne connaît ni les captures TTP ni les commandes Cisco.

Les valeurs `false`, `0` et les listes explicitement vides sont conservées.
Les défauts de constructeurs et les valeurs inconnues sont omis. Les secrets
restent masqués. Une ACL, prefix-list ou politique ordonnée incomplète et ses
dépendances ne sont pas publiées comme une configuration exploitable complète.
L'absence d'une propriété ne prouve pas son absence sur le routeur.

Aucun moteur historique, export de preuves ou diagnostics n'est conservé dans
le pipeline. Les archives `baseline/`, anciens résultats `outputs/` et documents
historiques ne sont pas des points d'entrée actifs et ne sont pas empaquetés.

## Vérification

```powershell
.\.venv\Scripts\python.exe -B tools\validate_normalized.py --ids C0001 F0456 F0057
.\.venv\Scripts\python.exe -B -m pytest tests -q -p no:cacheprovider --basetemp=outputs\pytest_local
```

Sans `--ids`, la validation traite dix configurations représentatives.
`--all` permet de demander explicitement les 105 configurations disponibles. Le manifeste et les attentes indépendantes sont conservés sous
`tests/fixtures/`, sans dépendance aux anciens rapports. Les tests comparent
les dix sorties sélectionnées à leur référence avant refactorisation et vérifient les
corrections explicites d'anciens artefacts de projection.

`run_all.ps1` lance la validation des dix équipements et les tests. Le validateur écrit
un bilan JSON et une sortie `normalized.json` par équipement, aucun rapport Markdown.
`tools/build_export_schemas.py` régénère le schéma public depuis le modèle unique.

## Réinstallation

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\setup.ps1
```

L'installation locale utilise `.venv` et les roues figées de `wheelhouse`
(Windows x64 / CPython 3.12). Python de base reste un prérequis système.
Pour une autre plateforme, utiliser un Python compatible et `requirements.lock`.
Les versions et licences sont documentées sous `docs/`.

TTP et ttp-templates restent les dépendances de parsing. Le modèle métier
s'inspire d'OpenConfig ; il ne représente pas une instance YANG/RFC7951 complète.
