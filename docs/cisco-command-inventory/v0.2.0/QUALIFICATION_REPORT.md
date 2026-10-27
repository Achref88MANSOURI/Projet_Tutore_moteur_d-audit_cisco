# Qualification documentaire Cisco IOS/IOS-XE — 0.2.0

Le snapshot 0.1.0 reste inchangé. Cette version est un catalogue documentaire, pas une grammaire exhaustive de routeurs ni une matrice universelle de support.

## Résultats et unité de comptage

Les 7296 occurrences initiales ont toutes été réexaminées automatiquement et reliées à une disposition explicite. Cette mesure ne signifie pas 7 296 relectures humaines ni 7 296 commandes confirmées.

Après déduplication documentaire conservatrice : 6687 familles de syntaxe issues du snapshot ; 609 occurrences alias regroupées. 185 autres articles ont été récupérés/collectés avec une source précise.

| Statut du catalogue | Enregistrements |
|---|---:|
| `confirmed_config` | 70 |
| `documented_config` | 21 |
| `uncertain` | 6875 |
| `excluded` | 3 |

Total : 6969 enregistrements. Les familles de syntaxe et les instances littérales sont comptées séparément dans les données. 70 instances sont confirmées dans des sorties running-config officielles ; **aucune grammaire paramétrée complète n'est certifiée**.

Les familles génériques ne sont pas promues sur la seule base d'un exemple : un enregistrement distinct représente la forme littérale observée, avec son contexte et sa portée. `related_legacy_candidate_ids` est un lien par titre, jamais une preuve d'équivalence de variante.

## Méthode et confiance

1. Empreintes du snapshot initial figées ; lecture des octets HTML cachés dont les empreintes correspondent à la source de chaque candidat.
2. Extraction des noms de paramètres marqués dans le HTML et conservation de la notation syntaxique imprimée. Les plages, types et contraintes non transcrits restent inconnus ; aucune option no/default n'est créée.
3. Relecture structurale des articles et tri des anomalies. Les stubs renvoyant à une autre commande restent traçables ; ils ne sont pas assimilés à une commande disparue du logiciel.
4. Les mentions de plateformes dans Command History ne qualifient pas le support. Même une phrase hors historique peut concerner un mot-clé ou une image : les quatre cas relus sont conservés avec leurs conditions dans SCOPED_EVIDENCE.json.
5. Les formes en sortie running-config sont distinguées des procédures CLI. Les exemples publiés sans identification suffisante d'une plateforme cible restent uncertain, même s'ils ressemblent à une configuration valide.
6. Déduplication seulement si contenu d'article, syntaxe, paramètres, modes, portée d'édition, historique et qualification concordent. Les homonymes à contexte inconnu ne sont pas fusionnés par leur nom.

Les identifiants originaux sont conservés dans LEGACY_LINKS.jsonl. Les sources fusionnées restent toutes présentes. `releases_confirmed` demeure vide lorsque la source ne permet pas d'établir un support précis de la variante ; les événements de mot-clé sont conservés séparément.

Le token `version` d'une configuration n'est pas une release IOS-XE complète. Le guide ISR 4000 peut montrer `version 15.3` ; le guide ISR G2 peut reprendre un exemple `version 12.4`. Aucune compatibilité de plateforme avec ces releases n'est extrapolée.

## Qualité et limites

Les 261 anomalies initiales ont une disposition explicite ; les cas non résolus restent conservés. Il ne s'agit pas de 261 erreurs toutes corrigées.

Les balises boot-start-marker/boot-end-marker sont signalées comme marqueurs de sérialisation non CLI à partir du texte Cisco. Les bannières, certificats, clés et menus gardent un indicateur de bloc opaque ; l'absence de fixture complète et de terminateur validé reste une lacune. Les chaînes hexadécimales ne deviennent pas des commandes autonomes.

Des coquilles Cisco, dont `commanddistance` dans une syntaxe OSPF et des exemples IPv6 incohérents, restent signalées. Les corrections de mise en page documentaire ne remplacent pas une correction sémantique non prouvée.

28 localisateurs ont été consultés en phase 2, dont les cinq anciens localisateurs distincts en échec/redirection. Les détails d'accès et les contenus non relus figurent dans SOURCE_REGISTRY.json. Il reste 1519 sources non relues, au sens de lecture documentaire ciblée complète/partielle, et 5 sources inaccessibles.

## Décision pour une future comparaison avec TTP

**Apte comme index documentaire traçable et comme jeu de cas limités aux formes confirmées. Inapte, à ce stade, comme référence exhaustive, grammaire de production ou oracle automatique de couverture TTP.**

Une comparaison future doit maintenir les statuts et les contextes, distinguer instance littérale et famille syntaxique, puis résoudre les preuves de plateforme/release et les blocs opaques manquants. Aucun template, mapping, audit de fidélité ou moteur TTP n'a été consulté pour une comparaison ni modifié par cette phase. Aucun appareil/image Cisco n'a été utilisé. Le travail s'arrête à la qualification documentaire.
