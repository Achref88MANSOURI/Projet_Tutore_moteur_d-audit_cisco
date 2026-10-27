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
Les champs de commande sont capturés par TTP, puis les types métier sont validés
par `normalizer/mapping.py` et le contrat original.

Les expressions ACL sont définies dans des variables TTP pour que le caractère
`|` d'une alternative regex ne soit pas interprété comme un séparateur de filtres.
Les variantes qui capturent explicitement des ports priment sur une capture
générique d'options. Une option non prise en charge ne doit jamais produire une
règle permit plus large.

Modifier `tools/build_templates.py`, puis exécuter :

```powershell
.\.venv\Scripts\python.exe tools\build_templates.py
```

`rules.json` décrit les règles déclarées. `catalogue_coverage.json` indique celles
effectivement rencontrées dans les vingt configurations, sans prétendre que les
autres variantes sont couvertes par ce corpus. Les tests synthétiques complètent
ce contrôle ; les règles et le normaliseur doivent évoluer ensemble.
