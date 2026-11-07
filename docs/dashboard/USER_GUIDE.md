# Guide utilisateur — Dashboard Cisco CIS

## Prérequis

- Windows 10/11 et Python 3.11 ou plus récent.
- Node.js recommandé pour vérifier la syntaxe JavaScript.
- Une copie de développement indépendante du miroir synchronisé. Pour cette validation, la copie est située dans `C:\Users\achre\AppData\Local\Temp\network-config-normalizer-ttp-phase6a1` ; ce chemin temporaire n'est pas un emplacement durable.

## Installation locale

Dans PowerShell, depuis la copie indépendante :

```powershell
Set-Location 'C:\Users\achre\AppData\Local\Temp\network-config-normalizer-ttp-phase6a1'
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.lock
```

L'installation nécessite que les dépendances soient disponibles via l'index pip configuré ou le wheelhouse du projet. Si un accès réseau n'est pas autorisé, installer depuis les wheels compatibles présents dans `wheelhouse` selon les options pip de votre environnement.

## Démarrer le dashboard

```powershell
Set-Location 'C:\Users\achre\AppData\Local\Temp\network-config-normalizer-ttp-phase6a1'
$env:CONFIG_STUDIO_PORT = '8000'
.\.venv\Scripts\python.exe .\webapp.py
```

Ouvrir `http://127.0.0.1:8000`. Garder la console ouverte. Le serveur écoute uniquement sur l'interface loopback. Arrêt : `Ctrl+C`.

## Parcours

1. Déposer un fichier IOS/IOS-XE texte UTF-8 (2 Mio maximum), le sélectionner, ou coller le contenu dans la zone de configuration.
2. Choisir IOS/IOS-XE et cliquer **Normaliser**. Le backend appelle le parser et le normaliseur existants puis affiche le RouterContractV1 réel en Code ou Arborescence.
3. Choisir **Level 1** (53 contrôles) ou **Level 2** cumulatif (90 contrôles). Le changement invalide le rapport précédent et relance l'audit à partir du document normalisé en mémoire, sans reparsing.
4. Filtrer par statut, famille, niveau ou texte. Ouvrir un contrôle pour consulter verdict, justification, preuves/JSON Pointer, classification CIS, exigence catalogue et limitations disponibles.
5. Télécharger le RouterContractV1, le rapport ou les Findings CSV avec les boutons d'export.

Le score déterminable est `PASS / (PASS + FAIL)` et affiche son dénominateur. Il indique « Non déterminable » lorsqu'aucun contrôle n'a produit PASS ou FAIL. La couverture des évaluateurs est séparée des verdicts ; la présence d'un évaluateur n'est pas une preuve de conformité ni de qualité de test.

## Limites fonctionnelles connues

- Les contrôles sans évaluateur restent visibles avec le verdict du moteur (souvent NEEDS_REVIEW) et sont comptés à part ; les métadonnées `tested`/`mapping_verified` ne sont pas présentées comme une validation indépendante.
- Les références à la configuration source et les diffs contextuels ne sont pas encore disponibles. Le panneau l'indique explicitement ; aucune commande n'est appliquée.
- Le diagnostic reproduit de `transport input ssh telnet` montre une perte dans la normalisation des lignes VTY. Consulter `PHASE6A1_VALIDATION.md`; le parser, le normaliseur et le contrat n'ont pas été modifiés ici.
- Les navigateurs et les sockets locaux étaient bloqués par la sandbox lors de cette validation. Les parcours HTTP ont donc été exercés avec le transport mémoire des tests ; la validation manuelle navigateur doit être réalisée dans un environnement local autorisant l'écoute loopback.

## Vérifications développeur

```powershell
.\.venv\Scripts\python.exe -m pytest -p no:cacheprovider tests\test_webapp.py tests\test_web_frontend.py tests\test_phase6a1_vty_diagnostic.py -q
```

Le test VTY est volontairement `xfail(strict=True)` jusqu'à une mission dédiée au normaliseur : une résolution accidentelle de cette lacune fera échouer le test (XPASS strict) pour signaler qu'il faut réévaluer le diagnostic.
