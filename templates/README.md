# Catalogue des templates

`upstream/` contient quatre copies inchangées de templates distribués dans
ttp-templates 0.6.18. Le moteur les résout par l'API officielle `get_template` et
vérifie leur empreinte contre ces copies avant exécution. Leurs macros Python
appellent les utilitaires du paquet installé dans `.venv`.

`catalogue_upstream.json` précise la portée réelle de chacun : le template ASN
BGP ne doit pas être présenté comme un parseur BGP complet ; les interfaces
officielles fournissent des défauts qui ne sont pas adoptés automatiquement.

`cisco_ios/` contient les extensions du projet. Elles prennent un inventaire
annoté sous la forme `numéro_de_ligne commande_désindentée`. Le contexte
hiérarchique et les positions sont conservés séparément par `parser/inventory.py`.
Les 28 fichiers `.ttp` sont la source de vérité des 374 règles actives.
`parser/run_ttp.py` lit directement les identifiants des groupes et leur motif
de capture, après retrait du préfixe technique `source_line`. Le même texte de
template est ensuite exécuté par TTP, qui applique les constantes et conversions.

`rule_metadata.json` contient uniquement les restrictions `scope` et `choices`,
indexées par identifiant : 73 entrées, dont 71 avec `scope` et 3 avec `choices`
(une règle possède les deux). Les restrictions absentes restent absentes.
Le chargeur refuse les identifiants dupliqués, les métadonnées orphelines ou
invalides et les groupes ne respectant pas le format actuel : groupe plat
`method="table"`, nom terminé par `*`, une seule ligne de capture numérotée.

Le chargement découvre récursivement les `.ttp` sous `cisco_ios/` et les trie
par chemin relatif, avec `/` comme séparateur. Une famille peut posséder
plusieurs fichiers, y compris des fichiers de même nom dans des sous-dossiers
distincts. Chaque source conserve son chemin et ses identifiants de groupes ;
les métadonnées restent associées par identifiant, sans changement de format.

L'association à une famille de commandes suit une convention explicite :
le dossier parent de famille connu le plus proche est prioritaire ; à défaut,
le nom du fichier sans extension doit être une famille connue. Par exemple,
`routing/bgp/neighbors.ttp` et `routing/bgp/address_families.ttp` appartiennent
à `bgp`, tandis que `security/acl_standard.ttp` appartient à `acl_standard`.
Les familles sont celles de l'inventaire actuel : `interfaces`, `bgp`, `ospf`,
`vrf`, `acl_standard`, `acl_extended`, `policies`, `prefix`, `routes`, `advanced`
et `services`. Un fichier sans association est refusé explicitement.

Exception d'organisation : `routing/rip.ttp` conserve explicitement le dispatch
`services`, car l'inventaire classe toujours `router rip` et ses descendants dans
cette famille. Ce fichier reçoit exactement les mêmes lignes que les fichiers de `services/`.
Il contient uniquement les cinq groupes `catalogue_rip*`, déplacés sans changement
de contenu ni d'ordre relatif ; les 117 autres groupes sont répartis dans `services/`.

Chaque fichier est exécuté séparément sur les lignes de sa famille : ses
variables et fonctions TTP ne sont pas fusionnées avec celles des autres fichiers.
Les captures candidates sont ensuite réunies avant le classement existant.
Un identifiant dupliqué, même entre sous-dossiers, provoque une erreur.
Les sous-dossiers organisent les fichiers sans changer les familles de lignes.
Les 42 groupes de l'ancien `advanced.ttp` sont répartis sans changement de contenu
dans `advanced/mpls.ttp` (3), `advanced/isis.ttp` (3), `advanced/multicast.ttp` (7),
`advanced/qos.ttp` (11), `advanced/layer2.ttp` (11) et `advanced/pki.ttp` (7).
Le dossier parent conserve le dispatch `advanced` pour ces six fichiers, sans
association supplémentaire. Leur ordre de chargement suit le tri des chemins ;
l'ordre relatif des groupes dans chaque domaine est conservé. Les cinq règles
`catalogue_pim_*` conservent leur restriction `scope: global`.

Les 117 groupes de l'ancien `services.ttp` sont répartis dans douze fichiers :
`services/system.ttp` (19), `services/administration.ttp` (21), `services/aaa.ttp` (12),
`services/dns.ttp` (6), `services/ntp.ttp` (5), `services/logging.ttp` (9),
`services/snmp.ttp` (5), `services/flow_telemetry.ttp` (9), `services/network.ttp` (16),
`services/call_home.ttp` (6), `services/wan_access.ttp` (6) et `services/voice.ttp` (3).
Le dossier parent conserve le dispatch `services`, sans nouvelle association.
Le contenu des groupes et leur ordre relatif dans chaque domaine sont conservés.
Les deux règles MSDP restent dans `services/network.ttp`. Les restrictions de
métadonnées (57 `scope`, deux `choices`) et les contrôles supplémentaires du
chargeur restent inchangés ; le découpage n'ajoute aucun contexte implicite.

Les expressions ACL sont définies dans des variables TTP pour que le caractère
`|` d'une alternative regex ne soit pas interprété comme un séparateur de filtres.
Les variantes qui capturent explicitement des ports priment sur une capture
générique d'options. Une option non prise en charge ne doit jamais produire une
règle permit plus large.

La maintenance courante se fait directement dans les `.ttp`, avec une entrée
dans `rule_metadata.json` lorsqu'une restriction est nécessaire. Les identifiants,
constantes et conversions doivent rester cohérents avec les consommateurs.
Le contrôle de ligne complète, les scores, le départage des règles et les
ambiguïtés sont conservés dans `run_ttp.py` ; la hiérarchie reste dans l'inventaire.

Il n'existe aucune étape de génération préalable. Les 30 règles historiquement
réintégrées restent présentes dans les templates et possèdent des exemples de
capture indépendants. Leurs identifiants sont conservés dans une fixture de test,
sans dupliquer leurs motifs ou leurs constantes.

`catalogue_coverage.json` reste une référence historique et n'est pas chargé par
le parseur. Les quatre templates officiels restent indépendants de ce document
et des métadonnées des extensions du projet.

## EIGRP

`cisco_ios/routing/eigrp.ttp` appartient à la famille `eigrp` ajoutée à l'inventaire
et au loader. `cisco_ios/interfaces/eigrp.ttp` appartient à la famille `interfaces`.
La règle de métrique composite des route-maps est dans `cisco_ios/policies.ttp`.

`parser/eigrp_context.py` et `parser/eigrp_commands.py` vérifient portée immédiate et
opérandes. Une même syntaxe ne s'applique pas indifféremment au processus, à l'AF,
à la topologie ou à l'interface.

La [matrice et les références Cisco](../docs/eigrp/README.md) décrivent les 129 règles
ajoutées et les syntaxes volontairement non prises en charge. Les anciens templates
amont restent inchangés.

## Correction des lacunes Cisco

La règle `advanced_qos_match_precedence_both` reconnaît `match precedence` sans
le mot-clé `ip`, sous une class-map. Le mapping conserve la distinction de famille
avec la règle existante `match ip precedence`. L'inventaire est désormais de
580 règles dans 31 fichiers et 12 familles ; les 173 associations de métadonnées
comprennent 145 restrictions de portée et 48 ensembles de valeurs autorisées.

Les pertes `match community`, `established`, version, boot et cache NetFlow
reposaient sur des captures déjà présentes : elles ont été corrigées dans les
mappings et les modèles, sans dupliquer les templates. Les bannières transmettent
au parsing un en-tête sûr et un indicateur interne de présence, sans leur texte.

La règle globale `services_password_encryption_on` complète désormais la forme
`no service password-encryption`, sans collecter de credential.
