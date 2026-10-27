"""Human-readable documentary qualification reports, generated from the catalogue."""
import collections
from common import ROOT, read, rows


def select_sample(catalogue, spec):
    if "legacy_id" in spec:
        return [r for r in catalogue if spec["legacy_id"] in r["legacy_candidate_ids"]]
    return [r for r in catalogue if r["record_kind"] == "observed_instance" and spec["literal"] in r["syntaxes"] and
            (not spec.get("platform_contains") or any(spec["platform_contains"] in p for p in r["platforms_confirmed"]))]


def render(catalogue, registry, summary):
    counts = summary["catalogue_status_counts"]
    report = ["# Qualification documentaire Cisco IOS/IOS-XE — 0.2.0", "",
        "Le snapshot 0.1.0 reste inchangé. Cette version est un catalogue documentaire, pas une grammaire exhaustive de routeurs ni une matrice universelle de support.", "",
        "## Résultats et unité de comptage", "",
        f"Les {summary['baseline_candidates_examined_automatically']} occurrences initiales ont toutes été réexaminées automatiquement et reliées à une disposition explicite. Cette mesure ne signifie pas 7 296 relectures humaines ni 7 296 commandes confirmées.", "",
        f"Après déduplication documentaire conservatrice : {summary['baseline_documentary_entries_after_deduplication']} familles de syntaxe issues du snapshot ; {summary['baseline_alias_occurrences_merged']} occurrences alias regroupées. {summary['new_or_recovered_candidate_occurrences']} autres articles ont été récupérés/collectés avec une source précise.", "",
        "| Statut du catalogue | Enregistrements |", "|---|---:|"]
    report += [f"| `{status}` | {counts.get(status, 0)} |" for status in ["confirmed_config", "documented_config", "uncertain", "excluded"]]
    report += ["", f"Total : {summary['catalogue_records']} enregistrements. Les familles de syntaxe et les instances littérales sont comptées séparément dans les données. {summary['confirmed_literal_instances']} instances sont confirmées dans des sorties running-config officielles ; **aucune grammaire paramétrée complète n'est certifiée**.", "",
        "Les familles génériques ne sont pas promues sur la seule base d'un exemple : un enregistrement distinct représente la forme littérale observée, avec son contexte et sa portée. `related_legacy_candidate_ids` est un lien par titre, jamais une preuve d'équivalence de variante.", "",
        "## Méthode et confiance", "",
        "1. Empreintes du snapshot initial figées ; lecture des octets HTML cachés dont les empreintes correspondent à la source de chaque candidat.",
        "2. Extraction des noms de paramètres marqués dans le HTML et conservation de la notation syntaxique imprimée. Les plages, types et contraintes non transcrits restent inconnus ; aucune option no/default n'est créée.",
        "3. Relecture structurale des articles et tri des anomalies. Les stubs renvoyant à une autre commande restent traçables ; ils ne sont pas assimilés à une commande disparue du logiciel.",
        "4. Les mentions de plateformes dans Command History ne qualifient pas le support. Même une phrase hors historique peut concerner un mot-clé ou une image : les quatre cas relus sont conservés avec leurs conditions dans SCOPED_EVIDENCE.json.",
        "5. Les formes en sortie running-config sont distinguées des procédures CLI. Les exemples publiés sans identification suffisante d'une plateforme cible restent uncertain, même s'ils ressemblent à une configuration valide.",
        "6. Déduplication seulement si contenu d'article, syntaxe, paramètres, modes, portée d'édition, historique et qualification concordent. Les homonymes à contexte inconnu ne sont pas fusionnés par leur nom.", "",
        "Les identifiants originaux sont conservés dans LEGACY_LINKS.jsonl. Les sources fusionnées restent toutes présentes. `releases_confirmed` demeure vide lorsque la source ne permet pas d'établir un support précis de la variante ; les événements de mot-clé sont conservés séparément.", "",
        "Le token `version` d'une configuration n'est pas une release IOS-XE complète. Le guide ISR 4000 peut montrer `version 15.3` ; le guide ISR G2 peut reprendre un exemple `version 12.4`. Aucune compatibilité de plateforme avec ces releases n'est extrapolée.", "",
        "## Qualité et limites", "",
        f"Les {summary['anomalies_triaged']} anomalies initiales ont une disposition explicite ; les cas non résolus restent conservés. Il ne s'agit pas de {summary['anomalies_triaged']} erreurs toutes corrigées.", "",
        "Les balises boot-start-marker/boot-end-marker sont signalées comme marqueurs de sérialisation non CLI à partir du texte Cisco. Les bannières, certificats, clés et menus gardent un indicateur de bloc opaque ; l'absence de fixture complète et de terminateur validé reste une lacune. Les chaînes hexadécimales ne deviennent pas des commandes autonomes.", "",
        "Des coquilles Cisco, dont `commanddistance` dans une syntaxe OSPF et des exemples IPv6 incohérents, restent signalées. Les corrections de mise en page documentaire ne remplacent pas une correction sémantique non prouvée.", "",
        f"{summary['phase_2_http_attempts']} localisateurs ont été consultés en phase 2, dont les cinq anciens localisateurs distincts en échec/redirection. Les détails d'accès et les contenus non relus figurent dans SOURCE_REGISTRY.json. Il reste {summary['sources_not_reviewed']} sources non relues, au sens de lecture documentaire ciblée complète/partielle, et {summary['inaccessible_sources']} sources inaccessibles.", "",
        "## Décision pour une future comparaison avec TTP", "",
        "**Apte comme index documentaire traçable et comme jeu de cas limités aux formes confirmées. Inapte, à ce stade, comme référence exhaustive, grammaire de production ou oracle automatique de couverture TTP.**", "",
        "Une comparaison future doit maintenir les statuts et les contextes, distinguer instance littérale et famille syntaxique, puis résoudre les preuves de plateforme/release et les blocs opaques manquants. Aucun template, mapping, audit de fidélité ou moteur TTP n'a été consulté pour une comparaison ni modifié par cette phase. Aucun appareil/image Cisco n'a été utilisé. Le travail s'arrête à la qualification documentaire.", ""]
    (ROOT / "QUALIFICATION_REPORT.md").write_text("\n".join(report), encoding="utf-8")
    tech = collections.defaultdict(collections.Counter)
    for r in catalogue:
        for t in r["technologies"]:
            tech[t][r["status"]] += 1
    coverage = ["# Couverture documentaire 0.2.0", "", "Aucun taux global d'exhaustivité Cisco n'est calculé. La frontière est ouverte et les versions des documents ne constituent pas un univers fermé de commandes.", "",
        "## Familles technologiques", "", "| Technologie (classement lexical de navigation) | Confirmé | Documenté | Incertain | Exclu |", "|---|---:|---:|---:|---:|"]
    for t, values in sorted(tech.items()):
        coverage.append(f"| {t} | {values['confirmed_config']} | {values['documented_config']} | {values['uncertain']} | {values['excluded']} |")
    coverage += ["", "Ce classement sert à stratifier l'étude ; il ne prouve pas la prise en charge d'une technologie sur une plateforme.", "",
        "## Plateformes", "", "| Périmètre | Preuves ajoutées ou relues | Lacune |", "|---|---|---|",
        "| ISR 800 | Running-config explicitement présenté pour Cisco 881W ; AES Cisco 836 sous image IP plus ; exemples SNMP du guide de commutation intégrée | Pas d'extension à tous les 8xx, modules, images ou releases |",
        "| ISR 1900/2900/3900 | Exemples du guide commun relus | PID non identifié ; exemple historique version 12.4 non transformé en matrice de support G2 |",
        "| ISR 1000 | Exemples dont une configuration identifie C1111-8PLTELA par UDI | Pas de validation de tous les modèles ni des options |",
        "| ISR 4000 | Exemple running-config et chapitre de plateforme ajoutés | Version de configuration 15.3 distincte de la release IOS-XE ; PID exact inconnu |",
        "| ASR 1000 | Exemples broadband relus ; claims scoped protected, strict et WebEx SPA | Conditions RP/ESP/SPA/images et variantes incomplètes |",
        "| Catalyst 8200/8300 | Extraits du guide commun relus | Exemple ne distingue pas les deux plateformes ; aucun support universel affirmé |",
        "| Catalyst 8500/8500L | Sortie running-config vrf ; procédures de gestion et breakout relues | Modèle exact non identifié dans la sortie VRF ; breakout limité aux conditions du guide |",
        "| Catalyst 8000V | Références initiales conservées | Aucune nouvelle fixture ciblée 8000V validée en phase 2 |", "",
        "## Frontière et références restantes", "",
        "Les 1 142 documents de la frontière initiale sont conservés, dédupliqués par URL et classés en pertinence. Les paires HTML/PDF de même localisateur sont regroupées pour navigation sans supposer leur équivalence de contenu. Les releases différentes restent distinctes. Voir FRONTIER_RELEVANCE.json.", "",
        "Les chapitres EEM ont été ajoutés comme références syntaxiques. Le guide PIM et des exemples Flexible NetFlow ont été consultés, mais leurs exemples génériques restent incertains tant que leur applicabilité à une plateforme ciblée n'est pas établie. La télémétrie distingue dial-in dynamique et dial-out configuré ; une procédure CLI ne suffit pas pour confirmed_config.", "",
        "Restent prioritaires : résolution des stubs et des modes absents, références SNMP complètes, paramètres/options par plateforme et release, VPN/sécurité, MPLS/SR, QoS imbriquée, EEM par image, 8000V, variantes historiques et fixtures de startup-config. Les PDF et contenus soumis à authentification n'ont pas été dépouillés systématiquement.", "",
        "## Localisateurs inaccessibles", ""]
    coverage += [f"- [{s['url']}]({s['url']}) — {s['versions'][-1].get('access_detail', s['versions'][-1].get('error', 'inaccessible'))}." for s in registry if s["access_status"] == "inaccessible"]
    coverage += ["", "## Triage des anomalies", "", "| Disposition | Occurrences |", "|---|---:|"]
    coverage += [f"| {key} | {value} |" for key, value in sorted(summary["anomaly_dispositions"].items())]
    (ROOT / "COVERAGE_V02.md").write_text("\n".join(coverage) + "\n", encoding="utf-8")
    proofs = {p["id"]: p for p in rows("CONFIGURATION_PROOFS.jsonl")}
    sample = ["# Vérification stratifiée — sélections fixes 0.2.0", "",
        "Les attentes sont écrites séparément des règles de classification dans SAMPLE_EXPECTATIONS.json. Ce contrôle utilise un validateur distinct et des preuves Cisco sélectionnées ; il ne constitue ni une relecture par un autre humain ni une validation exhaustive des milliers d'entrées.", "",
        "L'échantillon couvre les quatre statuts, les frontières entre exploitation et configuration, les variantes conditionnelles, les familles de plateformes disposant de preuves et les principales technologies. L'absence de fixture 8000V et de startup-config est une lacune, pas une strate faussement validée.", ""]
    for spec in read("SAMPLE_EXPECTATIONS.json"):
        matches = select_sample(catalogue, spec)
        passed = bool(matches) and all(r["status"] == spec["expected"] for r in matches)
        sample += [f"## {spec['id']} — {spec['stratum']}", "", f"Attendu : `{spec['expected']}`. Résultat : {'PASS' if passed else 'FAIL'}. {spec['rationale']}", ""]
        for r in matches:
            sample.append(f"- `{r['id']}` : `{r['syntaxes'][0]}` ; modes : {', '.join(r['modes']) or 'inconnus'}.")
            sample.append(f"  Source : [Cisco]({r['sources'][0]['url']}).")
            for pid in r["evidence_ids"]:
                p = proofs[pid]
                sample.append(f"  Preuve `{pid}` : contexte {p['context_path'] or 'global'} ; extrait `{p['literal_form']}` ; type `{p['kind']}`.")
        sample.append("")
    (ROOT / "VALIDATION_SAMPLES.md").write_text("\n".join(sample), encoding="utf-8")
