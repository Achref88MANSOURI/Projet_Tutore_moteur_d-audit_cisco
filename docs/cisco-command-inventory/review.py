"""Validate selected documentary evidence, group exact duplicates, export CSV/report."""
import csv
import hashlib
import json
from collections import Counter, defaultdict

from collect import ROOT, clean, dump, fetch, jsonl


def load_rows(name):
    return [json.loads(line) for line in (ROOT / name).read_text(encoding="utf-8").splitlines() if line]


def evidence_window(text, spec):
    text = clean(text)
    offset = 0
    while True:
        start = text.casefold().find(spec["start_marker"].casefold(), offset)
        if start < 0:
            raise ValueError("No evidence window contains every reviewed example: " + spec["source_id"])
        end = text.casefold().find(spec["end_marker"].casefold(), start + len(spec["start_marker"]))
        if end >= 0:
            window = text[start:end + len(spec["end_marker"])]
            if all(clean(entry["example"]) in window for entry in spec["entries"]):
                return window
        offset = start + 1


def run():
    inventory = load_rows("inventory.jsonl")
    sources = json.loads((ROOT / "sources.json").read_text(encoding="utf-8"))
    source_by_id = {s["id"]: s for s in sources if "id" in s}
    seeds = {s["id"]: s for s in json.loads((ROOT / "seeds.json").read_text(encoding="utf-8"))}
    specs = json.loads((ROOT / "review_specs.json").read_text(encoding="utf-8"))
    by_command = defaultdict(list)
    for row in inventory:
        by_command[row["command"].lower()].append(row)
    reviewed = []
    for spec in specs:
        # Read the exact cached bytes whose digest was recorded during collection.
        source = source_by_id[spec["source_id"]]
        dom, cached = fetch(source["url"], offline=True)
        if dom is None or cached.get("sha256") != source.get("sha256"):
            raise ValueError("Missing or changed evidence cache: " + spec["source_id"])
        window = evidence_window(dom.raw_text(), spec)
        for entry in spec["entries"]:
            # Context order is checked, but is not presented as automated mode inference.
            cursor = 0
            for context in entry["context"]:
                found = window.find(context, cursor)
                if found < 0:
                    raise ValueError("Reviewed context absent: " + context)
                cursor = found + len(context)
            if window.find(clean(entry["example"]), cursor) < 0:
                raise ValueError("Example not found after reviewed context: " + entry["example"])
            matches = by_command[entry["command"].lower()]
            presence = spec["evidence_kind"] == "running_config_output"
            reviewed.append({
                "id": hashlib.sha256((spec["source_id"] + "|" + json.dumps(entry, sort_keys=True)).encode()).hexdigest()[:16],
                "command": entry["command"], "observed_example": entry["example"],
                "mode": entry["mode"], "context_path": entry["context"],
                "platform_scope": seeds[spec["source_id"]]["platform_scope"],
                "example_release": spec["example_release"],
                "release_support": "example_scope_only_no_minimum_or_maximum_inferred",
                "evidence_kind": spec["evidence_kind"],
                "evidence_window": {"start_marker": spec["start_marker"], "end_marker": spec["end_marker"], "sha256": hashlib.sha256(window.encode()).hexdigest()},
                "source": {"url": source["url"], "sha256": source["sha256"], "retrieved_at": source["retrieved_at"], "source_id": spec["source_id"]},
                "candidate_ids": [m["id"] for m in matches],
                "candidate_link_policy": "title_match_only_not_a_mode_or_variant_equivalence_proof",
                "full_grammar_verified": False,
                "serialization": "documented_running_config_example_no_device_validation" if presence else "unverified_cli_example_only",
                "confidence": {"example_transcription": "high_documentary_example_checked", "mode_context": "medium_reviewed_example", "persistence": "medium_documentary_example" if presence else "unknown", "universal_platform_release_support": "unknown"},
                "note": entry.get("note", "Example is documentary evidence, not a configuration recommendation."),
            })
    jsonl(ROOT / "reviewed.jsonl", reviewed)
    groups = defaultdict(list)
    for row in inventory:
        signature = json.dumps([row["command"], row["modes"], row["syntaxes"]], sort_keys=True)
        groups[signature].append(row["id"])
    jsonl(ROOT / "syntax_groups.jsonl", [{"signature": hashlib.sha256(key.encode()).hexdigest()[:16], "occurrence_ids": sorted(ids)} for key, ids in sorted(groups.items())])
    with (ROOT / "inventory.csv").open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["id", "command", "syntaxes", "modes", "forms", "platform_mentions_NOT_support", "release_history_NOT_support", "platform_support", "persistence", "confidence", "source"])
        for r in inventory:
            writer.writerow([r["id"], r["command"], " || ".join(r["syntaxes"]), " | ".join(r["modes"]), " | ".join(r["documented_forms"]), " | ".join(r["platform_mentions"]), " | ".join(r["release_history_labels"]), r["platform_support"], r["serialization"], r["confidence"]["syntax"], r["source"]["url"]])
    summary = json.loads((ROOT / "summary.json").read_text(encoding="utf-8"))
    summary.update({"exact_syntax_mode_groups": len(groups), "reviewed_example_records": len(reviewed),
                    "reviewed_running_config_examples": sum(r["evidence_kind"] == "running_config_output" for r in reviewed),
                    "reviewed_cli_only_examples": sum(r["evidence_kind"] == "cli_configuration_example" for r in reviewed),
                    "reviewed_without_title_match_in_candidates": sum(not r["candidate_ids"] for r in reviewed)})
    dump(ROOT / "summary.json", summary)
    build_report(summary, sources, inventory, reviewed)
    print(json.dumps(summary, ensure_ascii=False))


def build_report(summary, sources, inventory, reviewed):
    books = json.loads((ROOT / "books.json").read_text(encoding="utf-8"))
    anomalies = load_rows("anomalies.jsonl")
    book_counts = Counter(r["source"]["book_id"] for r in inventory)
    anomaly_counts = Counter(r["book_id"] for r in anomalies)
    lines = ["# Couverture et lacunes — snapshot du 27 octobre 2026", "",
             "**Inventaire non exhaustif. Aucun pourcentage global de commandes de routeurs couvertes n'est établi.**", "",
             f"{summary['candidate_records']} occurrences candidates ; {summary['unique_command_titles']} intitulés distincts ; {summary['exact_syntax_mode_groups']} groupes de syntaxe/mode strictement identiques après regroupement. Ces nombres ne sont pas des nombres de commandes routeur certifiées.", "",
             f"{summary['books_discovered']} livres découverts ; {summary['chapters_attempted']} chapitres tentés sur {summary['chapters_discovered']} repérés dans les livres sélectionnés. {summary['excluded_records']} articles exclus, {summary['anomalies']} anomalies d'extraction. L'accès à un chapitre ne prouve pas l'extraction complète de ses articles.", "",
             f"{summary.get('unique_successful_urls', 'voir sources.json')} URL distinctes récupérées avec succès, sur {summary.get('unique_source_urls', 'voir sources.json')} URL tentées. Le registre peut décrire plusieurs rôles pour une même URL.", "",
             f"Échantillon relu : {len(reviewed)} entrées, dont {summary['reviewed_running_config_examples']} présentes dans une sortie running-config publiée par Cisco et {summary['reviewed_cli_only_examples']} issues uniquement d'une procédure CLI. Aucun essai sur équipement/image Cisco n'a été réalisé.", "",
             f"{summary['reviewed_without_title_match_in_candidates']} exemples relus n'ont pas de correspondance exacte d'intitulé dans les candidats. Ils restent des preuves d'exemples observés, sans grammaire complète déduite. Les correspondances par titre existantes ne prouvent pas non plus une équivalence de mode ou de variante.", "",
             "## Plateformes et releases", "",
             "| Famille | Recherche effectuée | Limite restante |", "|---|---|---|",
             "| ISR 1000 | Index de références et guides ; exemple de running-config portant version 16.6 | Pas de matrice par PID, module, licence et release ; exemples du guide parfois incohérents |",
             "| ISR 4000 | Index de références et guides | Pas de preuve de sérialisation relue propre à cette famille |",
             "| ASR 1000 | Références par technologie et guide broadband XE 3S avec running-config | Exemple sans release exacte ; pas de validation par RP/ESP/SPA/feature set |",
             "| Catalyst 8200/8300 Edge | Index et guide de plateforme ; procédure CLI et extrait running-config EIGRP | Release exacte absente dans l'extrait ; aucune extension automatique à 8500/8000V |",
             "| Catalyst 8500 / 8000V | Index de références explorés | Pas d'exemple sauvegardé relu propre à chaque famille ; images et fonctions différentes |",
             "| IOS historique | Index IOS et ISR G2 ; exemple 1900/2900/3900 portant version 12.4 ; références multi-releases | Pas d'inventaire de tous les trains 12.x/15.x, modules et anciennes plateformes |", "",
             "La version imprimée dans un exemple n'est pas une release minimale ni la preuve qu'une plateforme donnée exécute cette release. Le guide ISR G2 reprend notamment un exemple portant version 12.4 : ce texte n'établit pas une compatibilité ISR G2/12.4. Les dates des guides ne prouvent pas la prise en charge de chaque commande. Les références de programmabilité 17.12.x et 17.18.x ont été sélectionnées ; les autres releases, dont les nouvelles familles 26.x, ne sont pas traitées systématiquement.", "",
             "## Extraction par livre", "", "| Livre | Candidats | Anomalies |", "|---|---:|---:|"]
    for book in books:
        lines.append(f"| [{book.get('title', book['id'])}]({book['url']}) | {book_counts[book['id']]} | {anomaly_counts[book['id']]} |")
    lines += ["", "## Sources en échec ou redirigées", ""]
    failures = [s for s in sources if s["status"] != "ok"]
    lines += [f"- [{s.get('id', s.get('discovered_title', s['url']))}]({s['url']}) : `{s['status']}` ; {s.get('error', s.get('resolved_url', 'accès non établi'))}." for s in failures] or ["Aucun échec d'accès dans ce snapshot."]
    no_articles = [s for s in sources if s.get("extraction_status") == "no_structured_command_articles_found"]
    lines += ["", f"{len(no_articles)} chapitres accessibles ne contiennent aucun article de commande reconnu par l'extracteur (préambule, aide, format différent ou absence de commandes). Ils sont signalés dans `sources.json`.", "",
              "## Lacunes documentaires et de couverture", "",
              "- La Master Command List historique redirige vers Cisco Support au moment de cette collecte ; son contenu indexé par un moteur de recherche ne vaut pas contenu récupéré. Le PDF historique et le Command Lookup Tool authentifié ne sont pas dépouillés.",
              "- `frontier.json` conserve les références non sélectionnées, les guides non dépouillés et les PDF repérés. Une frontière vide de chapitres sélectionnés ne signifierait pas que toute la documentation Cisco est couverte.",
              "- Le corpus se concentre sur la CLI IOS/IOS-XE classique, notamment en mode autonome. Les références SD-Routing repérées sont différées ; les variantes SD-WAN/controller-managed, configurations générées et feature templates ne sont pas inventoriés systématiquement.",
              "- Les livres partagés IOS contiennent des syntaxes de commutateurs, équipements anciens et fonctions non disponibles sur toutes les plateformes. Tous les candidats restent en quarantaine documentaire ; aucune liste de support routeur n'est affirmée à partir du seul livre.",
              "- Multicast IPv4/PIM, Flexible NetFlow, EEM, SNMP/gestion avancée, télémétrie, VRF/address-families imbriquées, sécurité/VPN, QoS hiérarchique, MPLS/SR, broadband, voix/CUBE, modules cellulaires et services applicatifs nécessitent des croisements supplémentaires. Certains sont partiellement représentés dans les livres collectés ; leur complétude n'est pas établie.",
              "- Les formes no/default publiées indiquent des syntaxes acceptées, pas leur persistance. Une commande par défaut peut être absente de show running-config et visible avec une autre forme d'affichage. Les différences running/startup/all, réécritures, alias, ordres et commandes générées ne sont pas validés.",
              "- Bannières, chaînes de certificats, clés, blocs multilignes, menus, macros, délimiteurs et lignes de version/boot demandent une modélisation propre. Le contenu opaque ne doit pas être interprété ligne par ligne comme commande indépendante.",
              "- Les sous-modes et la hiérarchie complète ne sont pas reconstruits pour les candidats automatiques. Les homonymes et différences par mode/release doivent être relus avant toute utilisation par un parseur.",
              "- Les schémas HTML non reconnus et les articles sans syntaxe/mode sont conservés dans les anomalies. Une extraction sans anomalie détectée ne prouve pas l'absence de perte.", "",
              "## Incohérences constatées dans les exemples Cisco", "",
              "Dans les guides de base ISR 1000 et Catalyst 8200/8300, certains exemples IPv6 contiennent `2001.db8::ffff:1/128`, et une étape de loopback omet même `ipv6 address`. Des extraits de routage utilisent des valeurs IPv6 après `ip route`, ou un prompt global pour une commande network EIGRP. Ces lignes ne sont pas promues comme syntaxe valide dans l'échantillon relu. La référence OSPF imprime également `distance ospf commanddistance ospf` dans une syntaxe : cette transcription est conservée comme candidat à relire, sans correction inventée. Les articles HTML strictement dupliqués sont dédupliqués et consignés dans les anomalies. Ces observations montrent pourquoi une source officielle demande aussi une lecture critique.", "",
              "## Travail restant pour étendre la confiance", "",
              "1. Traiter les anomalies et les technologies absentes à partir des chapitres de référence spécifiques ; enrichir la frontière de façon versionnée.",
              "2. Résoudre le support par PID, OS, release, licence/module et mode, avec Feature Information, release notes, guides de plateforme et outil Cisco lorsque disponible.",
              "3. Sur des images/appareils autorisés, vérifier entrée → running-config → sauvegarde → startup-config ; conserver des fixtures expurgées et la version exacte.",
              "4. Définir un univers documentaire fermé et auditable avant de calculer une couverture ; faire relire les groupes de syntaxes, sans activer de templates dans cette tâche.", ""]
    (ROOT / "COVERAGE.md").write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    run()
