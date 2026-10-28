# Sortie métier unique

Le moteur écrit uniquement `normalized.json`. Aucun export de preuves ou de
diagnostics n'est construit par le pipeline actif.

Le contrat unique est `schemas/normalized_config.py`. Son schéma public,
`schemas/normalized_export_v1.schema.json`, est généré par
`tools/build_export_schemas.py`. Les domaines métier apparaissent directement
à la racine, sans enveloppe technique ni commande CLI brute.

`normalize(texte)` retourne le dictionnaire métier sans écrire de fichier.
`convert_file(source, dossier)` et son alias `export_file` écrivent uniquement
le JSON compact et retournent ce même dictionnaire.

`normalizer/engine.py` valide les captures, les contextes et les ambiguïtés.
Chaque domaine construit directement ses objets typés. Les associations de
champs sont temporaires : chemin du champ et indice de capture. Elles servent
à distinguer les affectations explicites des défauts de constructeur et ne sont
jamais sérialisées. Les relations différées sont résolues avant publication.

`normalizer/serialization.py` ne réalise aucun mapping métier. Il conserve
`false`, `0` et les listes explicitement vides, et omet les propriétés absentes
ou inconnues. Les secrets restent masqués. Une politique ordonnée incomplète
et ses dépendances ne sont pas publiées comme une configuration complète.

Les ACL conservent la distinction entre hôte, préfixe, wildcard et object-group.
Les voisins et groupes BGP sont uniques dans leur scope ; les propriétés d'une
famille d'adresses restent dans cette famille. Les actions de route-map sont
typées lors du mapping, sans conversion tardive de commandes dans le sérialiseur.

L'absence d'une propriété ne prouve pas son absence sur le routeur. Les archives
historiques restent consultables sans participer au moteur actuel.
