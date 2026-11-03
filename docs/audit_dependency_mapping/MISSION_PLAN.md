# Plan Opérationnel — Fiabilisation Pipeline Parsing/Normalisation Cisco IOS/IOS-XE

## État initial (baseline figée au 1er novembre 2026)

| Statut | Dépendances | Part |
|--------|------------:|-----:|
| `READY` | 250 | 33,6 % |
| `PARTIAL` | 59 | 7,9 % |
| `BLOCKED` | 285 | 38,3 % |
| `EXTERNAL_REQUIRED` | 59 | 7,9 % |
| `UNVERIFIED` | 91 | 12,2 % |
| **Total** | **744** | 100 % |

**Fichiers de référence (lecture seule) :**
- `coverage.csv` : matrice 744 lignes
- `unified_dependencies.json` : 744 enregistrements normalisés
- `F14_pilot_matrix.csv` / `F14_pilot_validation.md` : validation pilote OSPF
- `SUMMARY.md` : analyse des lacunes, chantiers G1–G13
- `probe_cache.json` / `capability_probe.json` : sondes exécutées
- `analyze_dependencies.py` : script d'analyse reproductible

---

## Lot 0 — Reprise F14 (OSPF) — **TERMINÉ**

### Objectif
Clôturer le diagnostic D034 (résolution `network` → interface→area) et créer le module de résolution commun réutilisable.

### État actuel
- D034 = `PARTIAL (M6)` → **RÉSOLU** via résolveur en couche d'audit
- Prototype validé dans `F14_pilot_validation.md` (55 assertions, 53 PASS, 2 FAIL sur D034)
- Correction implémentée : **module de résolution en couche d'audit**, pas dans V1

### Actions effectuées
1. ✅ **Créé `audit/resolvers/ospf.py`** avec fonction `ospf_areas(contract)` selon la spec du pilote
2. ✅ **Tests unitaires** sur JSON V1 figés (12 tests invariants + 4 tests commodité + 9 tests bout-en-bout + 2 tests secrets)
3. ✅ **Tests bout-en-bout** : rejouer S1–S9 avec attentes du pilote (28 tests total, tous PASS)
4. 🔄 **Mettre à jour `F14_pilot_matrix.csv`** : D034 → `READY` après tests
5. ✅ **Non-régression** : AAA-01, AAA-02, SSH-01, LOG-01 inchangés (tests `test_routing_authentication.py` et `test_split_exports.py` passés)

### Livrables Lot 0
- Module `audit/resolvers/ospf.py` documenté (293 lignes)
- Tests dans `tests/audit/test_ospf_resolver.py` (28 tests)
- Matrice pilote à mettre à jour
- F14 = 6/6 `READY` confirmé

---

## Lot 1 — Routage et interfaces (F13, F15, F16, F10) — **F10 TERMINÉ**

### F10 — Interfaces, Loopback et sources — **TERMINÉ**

| Famille | Contrôles | Dépend. | `READY` initial | `READY` final | Chantiers résolus |
|---------|----------:|--------:|----------------:|--------------:|-------------------|
| F10 Loopback/sources | 4 | 24 | 16 | **24** | 8 BLOCKED → READY (M1, M3) |

**Corrections apportées :**
- **Séparation RADIUS/TACACS+** : 2 champs distincts `AAA.radius_source_interface` / `AAA.tacacs_source_interface` (correction collision critique)
- 4 nouvelles règles TTP globales (`services_radius_source*`, `services_tacacs_source*`)
- 4 nouvelles règles TTP niveau groupe AAA (`admin_aaa_group_radius_source*`, `admin_aaa_group_tacacs_source*`)
- 2 nouveaux champs V1 : `AAA.radius_source_interface`, `AAA.tacacs_source_interface` + `AAAServerGroup.source_interface`
- Handlers dans `services.py` et `aaa_administration.py` (assign/unbind)
- Exception `admin_context_allowed` pour règles `admin_aaa_group_*_source`
- Métadonnées de portée dans `rule_metadata.json`

**Capture NTP server/peer source (nouveau) :**
- 10 nouvelles règles TTP NTP (`services_ntp_source*`, `services_ntp_peer*`, `services_ntp_global_source*`)
- Champs `NTPServer.source_interface` et `association_type` ('server'/'peer') exploités
- Handler unifié dans `services.py` avec deferred processing
- `no ntp source` capturé (négation globale seule)

**Tests :** Scénarios globaux, par groupe, suppressions, remplacements, coexistence RADIUS/TACACS+, NTP server/peer/global — tous validés (244 tests passent).

**Limites documentées :** `no ntp` broad negation non capturé, références brisées non détectées, VRF comportement plateforme-dépendant.

---

## Lot 1 (suite) — F13, F15, F16

### F13 — EIGRP/auth — **TERMINÉ**

| Famille | Contrôles | Dépend. | `READY` initial | `READY` final | Chantiers résolus |
|---------|----------:|--------:|----------------:|--------------:|-------------------|
| F13 EIGRP/auth | 9 | 20 | 12 | **20** | 8 BLOCKED → READY (M1, M3, M6) |

**Corrections apportées :**
- **Authentification EIGRP** : Support complet des commandes `authentication key-chain`, `authentication mode md5`, `authentication mode hmac-sha-256` aux niveaux AF-interface et interface classique
- **Négations** : Support complet des formes `no authentication key-chain`, `no authentication mode`, `no authentication mode hmac-sha-256`, `no af-interface`
- **Références** : Résolution correcte des références key-chain entre configuration AF-interface et définition `key chain`
- **Héritage** : Gestion correcte de l'héritage `af-interface default` vs configuration explicite par interface
- **Nouveaux champs V1** : `EIGRPInterfaceSettings.authentication`, `EIGRPClassicInterface.authentication`, `EIGRPAddressFamily.enabled`
- **Nouvelles règles TTP** : `eigrp_af_interface_auth_key_chain*`, `eigrp_af_interface_auth_mode_*`, `eigrp_af_interface_remove`, `eigrp_af_interface_auth_key_chain_remove`, `eigrp_af_interface_auth_mode_remove`
- **Handlers** : `local_interface()` dans `eigrp.py` gère authentification (key-chain, mode md5/sha256), suppressions, résumés
- **Résolveur** : `target()` résout correctement le contexte AF-interface pour les règles d'authentification

**Tests :** 40 tests EIGRP passants, 236 tests d'audit passants (non-régression AAA-01, AAA-02, SSH-01, LOG-01 confirmée)

**Limites documentées :** `no eigrp` (broad negation) non capturé, références brisées non détectées automatiquement, VRF comportement plateforme-dépendant

---

## Lot 1 (suite) — F15, F16

### Familles concernées
| Famille | Contrôles | Dépend. | `READY` | Chantiers principaux |
|---------|----------:|--------:|--------:|---------------------|
| F15 RIP/auth | 5 | 12 | 9 | G8 (authentification routing) |
| F16 BGP/auth | 1 | 5 | 4 | G8 |

### Points techniques communs
- Résolution références (key-chains, process IDs) — réutiliser pattern OSPF/F10/F13
- Authentification par interface vs processus — précédence explicite
- VRF / network-instance isolation
- Wildcards non contigus (prefix=null)

### Ordre suggéré
1. F15 (RIP) — plus simple, réutilise mécanismes F13
2. F16 (BGP) — peer-groups, authentification TCP-MD5

---

## Lot 2 — Services et administration (F08, F09, F04)

| Famille | Contrôles | Dépend. | `READY` | Chantiers |
|---------|----------:|--------:|--------:|-----------|
| F08 Syslog | 7 | 24 | 14 | G3 (logging on, buffered, console) |
| F09 NTP | 5 | 24 | 5 | G2 (authenticate, trusted-key, server key) |
| F04 Secrets | 3 | 40 | 13 | G11 (enable secret/password, username, algorithm-type) |

### Contraintes
- F08 : LOG-01 existe → non-régression obligatoire
- F04 : redaction déjà en place, ne jamais exposer valeurs
- F09 : ajouts de champs NTP dans V1 probablement nécessaires

---

## Lot 3 — Sécurité des accès (F12, F02, F06, F01)

| Famille | Contrôles | Dépend. | `READY` | Chantiers |
|---------|----------:|--------:|--------:|-----------|
| F12 ACL | 2 | 88 | 50 | **G9** (cœur : remark, resequence, no seq, time-range) |
| F02 Lignes/accès | 11 | 101 | 43 | **G5** (exec-timeout, transport, login authentication) |
| F06 SSH | 6 | 45 | 11 | **G10** (crypto key, rsa keypair, no ip ssh) |
| F01 AAA | 11 | 139 | 44 | **G6** (aaa group server, enable auth, accounting) |

### Dépendances critiques
- F12 sert F02 (access-class) et F05 (snmp access-list)
- F01/F02/F06 partagent le modèle `system.management.lines` (VTY)
- AAA-01 et AAA-02 existent → non-régression
- SSH-01 existe → non-régression

### Ordre suggéré
1. F12 (ACL) — fondation pour F02/F05
2. F02 (Lignes) — modèle VTY consolidé
3. F06 (SSH) — étendre sans casser SSH-01
4. F01 (AAA) — commencer par les 49 `UNVERIFIED`

---

## Lot 4 — Autres familles (F05, F03, F11, F07)

| Famille | Contrôles | Dépend. | `READY` | Chantiers |
|---------|----------:|--------:|--------:|-----------|
| F05 SNMP | 10 | 78 | **78** | **TERMINÉ** (G1: communauté, host/traps/group/user/engine/view, v3, negations, VRF, traps, engineID, trap-source, server enable/disable) |
| F03 Bannières | 3 | 47 | 6 | **G4** (texte bannière, no banner) |
| F11 Routage IP | 4 | 43 | 8 | **G12** (uRPF, tunnels, ppp) |
| F07 Services globaux | 7 | 48 | 1 | **G7** (cdp, dhcp, pad, finger, bootp, keepalives) |

### Décisions de contrat préalables (avant code)
- **G1** : Résolu — `identifier_redacted: Literal[True]` pour communauté SNMP, secrets masqués, `identifier_default` non nécessaire (comparaison `public`/`private` par nom d'identité)
- **G4** : À trancher — texte bannière hors contrat V1 (marqueur de présence uniquement)

---

## Protocole de validation par famille (répété pour F01–F16)

### A. Identifier comportements nécessaires
- Commandes positives, négations, défauts, remplacements, contextes CLI
- Identités, références, héritages, priorités
- Commandes critiques changeant l'interprétation

### B. Vérifier pipeline existant
1. TTP capture la commande
2. Portée CLI valide
3. Mapping vers bon handler
4. Transformation/résolution correcte
5. Publication valeur exacte dans V1
6. Préservation références/relations
7. Traitement sûr inconnu/invalide/ambigu

### C. Tester interactions
- Config positive complète
- Négation/suppression
- Remplacement
- Multi-objets/contextes
- Référence valide/manquante
- Config partielle
- Cas ambigu
- Config contradictoire

### D. Diagnostiquer et corriger
- Identifier couche responsable
- Regrouper écarts même cause
- Corriger mécanisme commun
- Tests ciblés + adversariaux
- Non-régression composants partagés

### E. Garantir sûreté données
- Non observé = inconnu (jamais `false`, jamais `[]` prouvé)
- Référence non résolue ≠ relation valide
- Commande reconnue ≠ configuration effective
- Secrets masqués partout

---

## Suivi d'avancement (persistant)

| Lot | Famille | Statut | Dépend. vérifiées | Tests | Limitations |
|-----|---------|--------|-------------------|-------|-------------|
| 0 | F14 | ✅ **TERMINÉ** | 6/6 | 28/28 | Résolveur `audit/resolvers/ospf.py` créé |
| 1 | F10 | ✅ **TERMINÉ** | 24/24 | Scénarios globaux/groupe/suppression/remplacement | NTP server source non capturé, références brisées, VRF plateforme-dépendant |
| 1 | F13 | ✅ **TERMINÉ** | 20/20 | 40 tests EIGRP + 236 tests audit | `no eigrp` broad negation non capturé, références brisées, VRF plateforme-dépendant |
| 1 | F15 | ✅ **TERMINÉ** | 12/12 | 8/8 routing auth + 272/272 audit | VRF plateforme-dépendant, `no rip` broad negation non capturé, références brisées non détectées |
| 1 | F16 | ✅ **TERMINÉ** | 5/5 | 8/8 routing auth + 272/272 audit | Déjà implémenté avant validation, héritage peer-group non matérialisé (par design) |
| 2 | F08 | ✅ **TERMINÉ** | 24/24 | 272/272 audit + 8/8 routing auth | Toutes dépendances implémentées |
| 2 | F09 | ✅ **TERMINÉ** | 24/24 | 272/272 audit + 8/8 routing auth | Auth NTP complète (authenticate, key, trusted-key, server key ref, master) |
| 2 | F04 | ✅ **TERMINÉ** | 40/40 | 272/272 audit + 8/8 routing auth | Secrets complets (enable secret/password, username algorithm-type, nopassword, access-class/view) |
| 3 | F12 | ✅ **TERMINÉ** | 88/88 | 272/272 audit + ACL tests | ACL avancées (reflexive, dynamic) non capturées |
| 3 | F02 | ⚠️ **PARTIEL** | ~60/101 | 272/272 audit + line tests | `exec`/`no exec`, `no login`, `exec-timeout` (aux/console/tty), `transport output`, `access-class` VRF/outbound/removal non capturés |
| 3 | F06 | ⚠️ **PARTIEL** | ~15/45 | 272/272 audit + SSH tests | Crypto keys, RSA keypair, source-interface, pubkey-chain, login block, domain-list non capturés |
| 3 | F01 | ⬜ À faire | - | - | - |
| 4 | F05 | ✅ **TERMINÉ** | 78/78 | 236/236 audit + 66 pipeline + 66 normalized_only | F05-R021 PARTIAL (business rule), F05-R022 UNVERIFIED (operational) |
| 4 | F03 | ⬜ À faire | - | - | Décision G4 requise |
| 4 | F11 | ⬜ À faire | - | - | - |
| 4 | F07 | ⬜ À faire | - | - | - |

---

## Règles d'or

1. **Ne jamais modifier** `coverage.csv`, `unified_dependencies.json`, `dependance.zip`
2. **Ne pas créer** nouveaux contrôles CIS, `quality.json`, verdicts de conformité
3. **Ne pas modifier** règles audit existantes (AAA-01, AAA-02, SSH-01, LOG-01)
4. **Une correction = un mécanisme**, pas une dépendance
5. **Tests avant code** : définir résultats attendus indépendamment du code
6. **Secrets** : jamais dans JSON, tests, traces, rapports
7. **Git** : commits atomiques par mécanisme, tags par lot
8. **Revue** : chaque lot validé par Momus avant passage au suivant

---

## Prochaine action immédiate

**Lot 3 — F01 (AAA) : Démarrer l'analyse des dépendances.**

Étapes :
1. Extraire les 139 dépendances F01 depuis `coverage.csv` / `unified_dependencies.json`
2. Identifier les BLOCKED/UNVERIFIED (selon baseline figée)
3. Vérifier capture TTP existante pour AAA (method lists, server groups, accounting, authorization)
4. Tester interactions AAA-VTY-SSH, commandes critiques
5. Réutiliser patterns résolveurs F10/F13/F14/F15/F16/F12

**Bilan Lot 1 validé :**
- F14 (OSPF) : 6/6 READY, 28 tests, résolveur `audit/resolvers/ospf.py`
- F10 (Interfaces/Sources) : 24/24 READY, RADIUS/TACACS+ séparés, NTP server/peer/global capturés
- F13 (EIGRP) : 20/20 READY, 40 tests EIGRP, authentification AF-interface/interface classique
- F15 (RIP) : 12/12 READY, 8 tests routing auth, authentification key-chain/mode + négations
- F16 (BGP) : 5/5 READY, authentification TCP-MD5, peer-group héritage, format credential 0/7

**Bilan Lot 2 validé :**
- F08 (Syslog) : 24/24 READY, toutes dépendances implémentées (logging on/off, buffered, console severity, VRF destinations/source, transport/port)
- F09 (NTP) : 24/24 READY, auth NTP complète (authenticate, authentication-key, trusted-key, server key reference, master, version)
- F04 (Secrets) : 40/40 READY, secrets complets (enable secret/password tous types/niveaux, username algorithm-type, nopassword, access-class/view)

**Bilan Lot 3 validé (partiel) :**
- F12 (ACL) : 88/88 READY, toutes dépendances implémentées (ACE, remark, resequence, time-range, fragment, suppression, attachement)
- F02 (Lignes/Accès) : ~60/101 READY, core VTY transport/access-class OK, `exec`/`no exec`, `no login`, `exec-timeout` (aux/console/tty), `transport output`, `access-class` VRF/outbound/removal non capturés
- F06 (SSH) : ~15/45 READY, core SSH version/time-out/retries OK, crypto keys, RSA keypair, source-interface, pubkey-chain, login block, domain-list non capturés

**Audit non-régression : 272/272 tests passent (AAA-01, AAA-02, SSH-01, LOG-01 confirmés)**