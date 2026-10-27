# Tâche Codex — inventaire documentaire des configurations Cisco routeurs

Date : 27 octobre 2026. Travail local demandé par l'utilisateur.
Branche : `research/cisco-ios-iosxe-config-inventory`.
Base : `main`, photographie initiale du projet local (aucun dépôt distant).
Le commit initial conserve le code, les schémas, templates et documents existants.
Les corpus de configurations, résultats, environnements et dépendances volumineuses
préexistants restent sur disque ; ils ne font pas partie de ce commit initial.
Les modifications concurrentes du répertoire de travail hors recherche ne sont
ni annulées, ni incluses dans la livraison. Le contrôle Git porte sur les commits
et fichiers préparés pour cette tâche ; les écarts externes sont signalés séparément.

## Objectif

Rechercher systématiquement les références officielles Cisco IOS/IOS-XE afin
de recenser les syntaxes susceptibles d'apparaître dans running-config et
startup-config des routeurs ISR, ASR 1000, Catalyst 8000 Edge et IOS historique.
L'inventaire constitue une base documentaire indépendante du moteur TTP.

## Contraintes

- Ne modifier ni parseur, ni normaliseur, ni schéma métier, ni règle/template actif.
- Aucune activation automatique à partir de cet inventaire.
- Exclure IOS XR, NX-OS, ASA et les références propres aux commutateurs.
- Les références IOS communes peuvent contenir des commandes de commutateurs :
  leur présence dans une référence liée depuis un routeur n'atteste pas leur
  disponibilité sur ce routeur. Conserver cette incertitude à chaque entrée.
- Distinguer commande de configuration, procédure interactive, délimiteur de
  contexte et ligne réellement sérialisée. Ne pas inventer de formes no/default.
- Ne pas déduire une matrice de support de la seule table Command History.
- Ne pas prétendre à l'exhaustivité. Conserver les échecs, anomalies et sources
  découvertes non traitées ; ne pas calculer de pourcentage de couverture de
  l'ensemble des commandes Cisco sans dénominateur documenté.
- Les fichiers de `sources/` du projet ChatGPT sont des références en lecture seule.

## Livrables et critères de réception

- [x] Registre des sources officielles : URL demandée/résolue, date de collecte,
      empreinte des octets, état d'accès et liens découverts.
- [x] Inventaire JSONL versionné : syntaxe, variantes imprimées, mode,
      contexte connu/inconnu, plateformes/releases avec limites de preuve,
      référence précise et confiance par dimension.
- [x] Échantillon relu et preuves de présence dans des exemples Cisco de config.
- [x] Journal des exclusions, anomalies et frontière de collecte.
- [x] Matrice de couverture et lacunes par plateforme/technologie/release.
- [x] Procédure de reproduction et validation hors ligne.
- [x] Vérification finale du périmètre Git : seuls les livrables documentaires
      et outils de recherche de ce dossier diffèrent de la base.

## Suite nécessitant des preuves supplémentaires

La validation sur images/appareils Cisco, les différences de sérialisation par
release et l'élargissement aux archives ou contenus soumis à authentification
doivent rester identifiés comme travaux ouverts lorsqu'ils ne sont pas réalisés.
La création ou modification de templates fera l'objet d'une autre tâche.

## Résultat de la collecte 0.1.0

Collecte initiale livrée : 7 296 occurrences candidates, 6 502 intitulés distincts,
48 exemples relus (43 issus de sorties running-config et 5 de procédures CLI),
261 anomalies conservées et 1 142 autres documents découverts non dépouillés.
Les 12 tests de l'extracteur et le contrôle de cohérence des données passent.
La reconstruction hors ligne avec les empreintes du cache a été réalisée.

Ce statut clôt la production de ce snapshot documentaire, pas les lacunes de
couverture ou la validation sur routeur. Consulter `COVERAGE.md` avant réutilisation.
Le fichier `normalizer/v02.py`, modifié par un travail concurrent pendant la
collecte, est préservé dans le répertoire de travail et exclu de cette livraison.
