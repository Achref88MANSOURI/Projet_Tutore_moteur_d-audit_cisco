# Contrat de configuration actif

`normalized_config.py` définit le modèle métier unique et ses contraintes.
Il ne dépend d'aucun modèle v0.1/v0.2 ni d'une fonction de migration.
Le document public contient directement les domaines configurés, sans enveloppe
`configuration`, version historique, provenance, preuves ou diagnostics.

`normalized_export_v1.schema.json` est généré par `tools/build_export_schemas.py`.
Le numéro du schéma public identifie son contrat JSON ; il ne sélectionne pas
un ancien moteur. La génération n'applique aucun mapping Cisco supplémentaire.

Les types distinguent hôte, préfixe, wildcard et object-group ACL ; les actions
de route-map possèdent des paramètres typés. Les familles BGP et les VRF restent
des scopes distincts. Les extensions Cisco sont regroupées sous `cisco`.
Les contraintes métier (VLAN, ASN, ports, préfixes, OSPF versionné, QoS, identités)
sont conservées dans les modèles. Aucun champ ne contient une valeur de secret.

Le moteur ne retient que les propriétés explicitement établies. La sérialisation
omet les propriétés non renseignées et préserve `false`, `0` et les listes vides
explicitement configurées. Le schéma public ne permet pas les valeurs nulles.

Les deux fichiers `.conf` présents restent des entrées de référence historiques ;
ils ne constituent pas des exemples de sortie publique ni une annonce de support Junos.
