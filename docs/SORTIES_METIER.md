# Sortie canonique unique

Le pipeline actif est : configuration Cisco → TTP existant → modules métier →
`RouterContractV1` → sérialisation → `normalized.json`.

Le contrat est `schemas/router_contract_v1.py` et son schéma public est
`schemas/router_contract_v1.schema.json`. Les modèles historiques et leur schéma
ont été retirés. Aucun convertisseur ni moteur parallèle n'est conservé.

`normalize(texte)` retourne le dictionnaire canonique sans écriture de fichier.
`convert_file(source, dossier)` et `export_file` écrivent uniquement
`normalized.json`. La sérialisation revalide le graphe Pydantic et conserve les
sections racines, null, false, zéro et les collections dont le vide est justifié.

Les bindings internes servent à sélectionner les faits configurés; ils ne sont
pas exportés. `normalizer/common/absence.py` centralise les preuves de collection
vide. Le moteur n'infère pas la complétude d'un fichier à partir du seul marqueur
`end`. Sans preuve de source complète et de couverture, une collection absente
reste null. Les commandes négatives ou sélections explicitement vides peuvent
établir une absence locale, par exemple `no ip address` et `transport input none`.

Les paramètres NTP/Syslog globaux restent globaux. BGP conserve les portées
globale/AF/VRF et les références d'héritage. OSPF conserve les wildcards natifs,
les défauts passifs et leurs exceptions déjà reconnus par TTP. Les politiques
incomplètes et leurs dépendances restent bloquées; les références non résolues
ne créent aucun objet fictif. log et log-input sont distincts.

Les secrets et les corps de certificats ne sont pas exportés. Les fonctions
prévues mais non extraites restent null. Aucun résultat d'audit n'est ajouté.

## EIGRP

Les processus EIGRP alimentent `routing.eigrp`, avec séparation des modes classique
et nommé, AF/VRF, topologies et af-interface. Les réglages classiques d'interface
restent dans `routing.eigrp_interfaces`, identifiés par interface, AFI, AS et VRF
connue. Aucun processus ou défaut hérité n'est fabriqué pour les résoudre.

Les interfaces conservent aussi bandwidth/delay configurés. Les resets scalaires
et d'authentification sont distingués d'une désactivation booléenne. L'action de
politique `eigrp_metric` préserve le vecteur, sans fusion avec `metric`.

Les nouvelles clés peuvent être présentes à null dans le JSON. Le schéma public
doit être actualisé chez les consommateurs. Voir [la couverture EIGRP](eigrp/README.md).
