# NormalizedConfig v0.1.0 — Contrat de sortie multi-constructeur

**Statut : prototype de contrat validable.** Modèle de configuration réseau *aligné sur les concepts OpenConfig*. Ce n'est **pas** une instance native conforme au codage JSON YANG/OpenConfig. Aucun modèle IETF n'a été utilisé comme *schéma métier* : les modules réseau référencés sont exclusivement ceux du dépôt OpenConfig.

## 1. Livrables

| Fichier | Rôle |
|---|---|
| `normalizedconfig.py` | Contrat typé Pydantic 2.x et validations métiers |
| `normalizedconfig_v0_1.schema.json` | JSON Schema Draft 2020-12 généré du contrat Pydantic |
| `field_mapping_openconfig.csv` | Dictionnaire **60 correspondances** entre nos champs, OpenConfig, netconv, Netcanon et SecurityBaselineModel |
| `sample_cisco_ios.conf` | Entrée Cisco IOS synthétique destinée à valider le contrat |
| `sample_cisco_ios.normalized.json` | Résultat normalisé *construit manuellement* (pas produit par un parseur testé) |
| `sample_junos_set.conf` | Entrée Junos synthétique équivalente sur plusieurs propriétés |
| `sample_junos_set.normalized.json` | Résultat normalisé *construit manuellement* |
| `test_contract.py` | Tests automatiques : validité, validation des contraintes, invariants, comparaison sémantique |
| `build_contract_artifacts.py` | Script de génération des exemples et du dictionnaire de correspondance |

**Important :** ce livrable spécifie le **contrat de sortie** et vérifie des exemples. Il **n'implémente pas encore** l'extraction des configurations ; remplacer le constructeur manuel des exemples par des parseurs Cisco/Junos est l'étape suivante.

## 2. Vue globale

```text
NormalizedConfig
├── schema_version = "0.1.0"
├── metadata                     # constructeur, OS, provenance, complétude
├── configuration
│   ├── system                   # identité, DNS, NTP, syslog, AAA, SNMP, management
│   ├── interfaces[]             # interfaces, adresses IPv4/6, L2/L3, ACL, VRF
│   ├── layer2                   # VLAN, LAG/LACP, STP
│   ├── network_instances[]      # VRF / instances
│   ├── routing                  # statique, BGP, OSPF, prefix-sets, politiques
│   ├── security                 # ACL ordonnées et points d'application
│   ├── nat[]                    # sous-ensemble générique
│   ├── vpn_tunnels[]            # identification des tunnels (pas crypto complète)
│   └── qos                     # noms et associations des politiques (pas QoS complète)
├── evidence[]                  # faits, sources, état de connaissance, justification
└── parsing                     # couverture, commandes inconnues, diagnostics
```

Le modèle inclut **la configuration déclarée**, pas l'état opérationnel réel observé sur les équipements. Les `source_file` exemples correspondent à des extraits **synthétiques et partiels** ; ni l'absence d'une commande ni un fichier se terminant par `end` ne prouvent la complétude.

## 3. Correspondance avec OpenConfig

OpenConfig constitue la référence de **signification métier** des données. Le fichier CSV contient 60 entrées avec l'emplacement interne, le type, le module OpenConfig, un chemin conceptuel, la règle de normalisation et les équivalents connus dans les projets de référence.

| Famille du contrat | Référence OpenConfig | Champs typiques |
|---|---|---|
| `system` | [`openconfig-system`](https://github.com/openconfig/public/blob/master/release/models/system/openconfig-system.yang) et modules système | hostname, domaine, NTP, DNS, AAA, SNMP, syslog |
| `interfaces` | [`openconfig-interfaces`](https://github.com/openconfig/public/blob/master/release/models/interfaces/openconfig-interfaces.yang), [`openconfig-if-ip`](https://github.com/openconfig/public/blob/master/release/models/interfaces/openconfig-if-ip.yang) | nom, description, enabled, mtu, IPv4, IPv6 |
| `layer2` | [`openconfig-vlan`](https://github.com/openconfig/public/blob/master/release/models/vlan/openconfig-vlan.yang), [`openconfig-if-aggregate`](https://github.com/openconfig/public/blob/master/release/models/interfaces/openconfig-if-aggregate.yang) | VLAN, LAG, port membership |
| `network_instances` | [`openconfig-network-instance`](https://github.com/openconfig/public/blob/master/release/models/network-instance/openconfig-network-instance.yang) | VRF, route targets |
| `routing` | [`openconfig-network-instance-static`](https://github.com/openconfig/public/blob/master/release/models/network-instance/openconfig-network-instance-static.yang), [`openconfig-bgp`](https://github.com/openconfig/public/blob/master/release/models/bgp/openconfig-bgp.yang), [`openconfig-ospfv2`](https://github.com/openconfig/public/blob/master/release/models/ospf/openconfig-ospfv2.yang), [`openconfig-routing-policy`](https://github.com/openconfig/public/blob/master/release/models/policy/openconfig-routing-policy.yang) | statique, BGP, OSPF, politiques |
| `security` | [`openconfig-acl`](https://github.com/openconfig/public/blob/master/release/models/acl/openconfig-acl.yang) | ACL et associations aux interfaces |
| `nat`, `vpn_tunnels`, `qos` | [`openconfig-nat`](https://github.com/openconfig/public/blob/master/release/models/nat/openconfig-nat.yang), [`openconfig-if-tunnel`](https://github.com/openconfig/public/blob/master/release/models/interfaces/openconfig-if-tunnel.yang), [`openconfig-qos`](https://github.com/openconfig/public/blob/master/release/models/qos/openconfig-qos.yang) | Modèles partiels dans **notre** contrat |

**Attention :** dans le CSV, les chemins `openconfig_concept_path` sont des **références de correspondance conceptuelle**, pas des chemins YANG exécutables garantis pour chaque champ. Les marqueurs `direct`, `adapted`, `conceptual`, `extension` ou `internal` qualifient le mapping. Les valeurs `extension` / `internal` ne sont **pas** des champs OpenConfig natifs. Pour générer une véritable instance RFC7951, il faudra un exportateur séparé, avec validation contre des versions figées de modules OpenConfig, leurs augmentations et leurs types.

## 4. Sémantique des valeurs et absence de faux défauts

Dans `configuration`, `null` veut dire « valeur non renseignée dans le modèle ». Cela **n'affirme pas** que la fonctionnalité est désactivée. Une liste vide `[]` veut dire « aucun objet enregistré dans la sortie », et non nécessairement « aucun objet configuré sur le périphérique ». Pour décider de la portée de ces absences, il faut consulter `evidence[]` et `parsing.feature_coverage[]`.

| Statut de preuve (`Evidence.status`) | Sémantique |
|---|---|
| `explicit` | Valeur extraite d'une commande présente et localisée dans le fichier |
| `inferred_default` | Valeur déduite d'un défaut documenté ; nécessite OS/version et justification |
| `absent` | Absence conclusive, limitée aux fichiers dont la complétude est attestée et motivée |
| `unknown` | Données insuffisantes ou indéterminées |
| `unsupported` | Fonctionnalité non interprétée par l'adaptateur |
| `not_applicable` | Concept non applicable au type d'équipement considéré |

Les validations Pydantic refusent les affirmations `absent` issues d'un fichier marqué `partial`/`unknown`, refusent `inferred_default` sans `os_version`, et exigent une ligne source pour toute observation `explicit`. Pour `explicit` et `inferred_default`, le JSON Pointer désigné doit correspondre à une valeur non nulle. Une inférence fondée sur la simple absence d'une ligne est interdite dans le contrat sans justification.

Les attributs `source_completeness`, `coverage` et `confidence` doivent être considérés séparément : *un parseur supportant un champ* n'implique pas que *ce champ a été observé*, et *un fichier complet* n'implique pas que *tous ses attributs ont été normalisés*.

## 5. Invariants supplémentaires et limites du v0.1

1. **Interfaces :** conserver le nom natif (`GigabitEthernet0/0` ≠ `ge-0/0/0`). Les comparaisons multi-constructeurs portent sur des propriétés, pas sur une identité physique supposée.
2. **IPv4/IPv6 :** adresse + longueur de préfixe, avec vérification des bornes (`0..32`, `0..128`). Convertir les masques Cisco uniquement lorsqu'ils sont valides. Les wildcards ACL non convertibles restent sous forme `wildcard`.
3. **ACL :** respecter l'ordre des règles ; une ACL référencée doit être associée au bon nom et à la direction ingress/egress. La validation des références est disponible via `semantic_warnings()` (avertissement et non suppression).
4. **Routage statique :** chaque route doit avoir au moins un next-hop ou une interface de sortie. La famille de la passerelle doit correspondre à la famille du préfixe.
5. **BGP/OSPF :** les structures globales et les voisins/aires sont couverts ; les sémantiques avancées (héritage complet, politiques arbitraires, redistribution et convergence) restent hors du périmètre v0.1.
6. **NAT, VPN, QoS :** formes génériques minimales uniquement ; **ne pas** les interpréter comme des modèles exhaustifs de sécurité ou de politique.
7. **Non-perte :** préserver les commandes non reconnues via `parsing.unknown_commands[]` et conserver si possible un arbre natif externe indiqué par `parsing.native_tree_file`.
8. **Sensible :** les configurations peuvent contenir des secrets, des communautés SNMP et des clés. Les fichiers originaux et les champs `raw_command` doivent rester protégés ; masquer les secrets avant tout export partageable. Le drapeau `redacted_secrets` ne réalise lui-même aucune censure.
9. **Versions :** versionner le contrat, les règles de mapping et les versions des modules OpenConfig choisis ; les URLs `master` du CSV sont des pointeurs de recherche, pas des dépendances figées.

## 6. Validation et utilisation

```bash
python -m pip install 'pydantic>=2,<3' 'jsonschema>=4' 'pytest>=8'
python test_contract.py
```

Pour charger une sortie déjà normalisée :

```python
import json
from pathlib import Path
from normalizedconfig import NormalizedConfig

raw = json.loads(Path('sample_cisco_ios.normalized.json').read_text(encoding='utf-8'))
model = NormalizedConfig.model_validate(raw)
print(model.configuration.system.hostname)
print(model.configuration.interfaces[0].ipv4_addresses[0].prefix_length)
print(model.semantic_warnings())
```

Pour adapter un parseur existant :

```text
config native
  -> parsing syntaxique (CiscoConfParse2 / parser Junos / autre)
  -> NativeConfig (arbre brut et numéros de lignes)
  -> extracteurs par constructeur
  -> normalisation vers les champs OpenConfig-aligned
  -> NormalizedConfig.model_validate(data)
  -> NormalizedConfig v0.1.0 + rapports
```

**À ne pas confondre :** le fichier `build_contract_artifacts.py` construit des sorties d'exemple par codage explicite des faits connus, afin de **tester le contrat** ; il ne prétend pas parser automatiquement les `.conf`. La prochaine expérimentation devra réellement implémenter les adaptateurs et mesurer leur précision sur une vérité terrain.

## 7. Sources de conception

- OpenConfig : https://github.com/openconfig/public/tree/master/release/models
- Netcanon : https://github.com/netcanon/netcanon/blob/main/netcanon/migration/canonical/intent.py
- netconv : https://github.com/casablanque-code/netconv/blob/main/crates/netconv-core/src/ir.rs
- Security Compliance Auditor (Observations) : https://github.com/Sivaguru-2008/network-compliance/blob/main/auditor/models/observation.py
- Batfish, architecture et support de parsing : https://github.com/batfish/batfish/blob/master/docs/parsing/README.md
