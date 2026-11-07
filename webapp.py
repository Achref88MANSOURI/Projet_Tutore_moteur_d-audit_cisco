#!/usr/bin/env python3
"""Local HTTP adapter for the network-config-normalizer-ttp with CIS audit dashboard.

- Serves web/index.html from the SAME origin as /api/*
- Reuses the repo's real cli.py and audit modules
- Passes input/output through pipes, without writing uploaded configurations
- Binds to 127.0.0.1; do not expose to the network
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from parser.platform import unsupported_platform
from schemas.router_contract_v1 import RouterContractV1

ROOT = Path(__file__).resolve().parent
INDEX = ROOT / "web" / "index.html"
CLI = ROOT / "cli.py"
MAX_CONFIG_BYTES = 2 * 1024 * 1024
MAX_REQUEST_BYTES = 12 * 1024 * 1024
TIMEOUT_SECONDS = 120


def normalize(configuration: str, *, os_family: str = 'ios') -> dict:
    """Call cli.normalize in an isolated process, with the existing timeout."""
    worker = (
        'import json,sys; from cli import normalize; '
        'request=json.load(sys.stdin); '
        'json.dump(normalize(request["configuration"], os_family=request["os_family"]), sys.stdout)'
    )
    process = subprocess.run(
        [sys.executable, '-c', worker],
        input=json.dumps(dict(configuration=configuration, os_family=os_family)),
        cwd=ROOT, capture_output=True, text=True, encoding='utf-8',
        errors='replace', timeout=TIMEOUT_SECONDS,
    )
    if process.returncode != 0:
        raise RuntimeError('CLI normalization failed')
    document = json.loads(process.stdout)
    return RouterContractV1.model_validate(document).model_dump(mode='json')


def audit_cis(normalized_document: dict, *, profile_level: int = 1, include_lower: bool = True, evidence: dict | None = None) -> dict:
    """Run CIS audit on a normalized document via isolated process."""
    worker = (
        'import json,sys; from audit.cis import audit_cis_normalized; '
        'request=json.load(sys.stdin); '
        'report=audit_cis_normalized(request["document"], profile_level=request["profile_level"], '
        'include_lower=request["include_lower"], evidence=request.get("evidence")); '
        'json.dump(report.model_dump(mode="json"), sys.stdout)'
    )
    process = subprocess.run(
        [sys.executable, '-c', worker],
        input=json.dumps(dict(
            document=normalized_document,
            profile_level=profile_level,
            include_lower=include_lower,
            evidence=evidence,
        )),
        cwd=ROOT, capture_output=True, text=True, encoding='utf-8',
        errors='replace', timeout=TIMEOUT_SECONDS,
    )
    if process.returncode != 0:
        raise RuntimeError('CIS audit failed')
    return json.loads(process.stdout)


def get_catalog_metadata() -> dict:
    """Get CIS catalog metadata for dashboard."""
    from audit.catalog.loader import CISIOS15Catalog
    from audit.cis import _build_evaluator_registry

    catalog = CISIOS15Catalog()
    controls = catalog.controls_for_profile(2)
    families: dict[str, dict[str, int]] = {}
    for control in controls:
        family = control["family"]
        counts = families.setdefault(family, {"count": 0, "level1": 0, "level2": 0})
        counts["count"] += 1
        level = int(control["profile_level"].split()[-1])
        counts["level1"] += int(level == 1)
        counts["level2"] += int(level <= 2)

    # These details are source-derived metadata. Evaluator availability comes
    # from the live registry; manifest flags such as `tested` are not evidence.
    registry = _build_evaluator_registry()
    evaluator_ids = sorted(registry.all_registered())
    manifest_rules = get_manifest().get("rules", [])
    catalog_ids = {item["id"] for item in controls}
    manifest_ids = {item.get("control_id") for item in manifest_rules}
    consistency = {
        "catalog_count": len(catalog_ids),
        "manifest_count": len(manifest_ids),
        "catalog_missing_from_manifest": sorted(catalog_ids - manifest_ids),
        "manifest_missing_from_catalog": sorted(manifest_ids - catalog_ids),
        "evaluator_ids_missing_from_catalog": sorted(set(evaluator_ids) - catalog_ids),
    }
    return {
        "total_controls": len(controls),
        "families": families,
        "catalog_metadata": catalog.metadata,
        "controls": [{key: item.get(key) for key in (
            "id", "title", "family", "profile_level", "assessment", "description",
            "rationale", "audit", "remediation", "remediation_command_templates",
        )} for item in controls],
        "registered_evaluator_ids": evaluator_ids,
        "evaluator_count": len(evaluator_ids),
        "consistency": consistency,
    }


def get_manifest() -> dict:
    """Get the CIS rule manifest."""
    manifest_path = ROOT / "audit" / "catalog" / "cis_ios15_rule_manifest.json"
    return json.loads(manifest_path.read_text(encoding="utf-8"))


class LocalServer(ThreadingHTTPServer):
    def __init__(self, *args, **kwargs):
        self.normalization_lock = threading.Lock()
        self.audit_lock = threading.Lock()
        super().__init__(*args, **kwargs)


class Handler(BaseHTTPRequestHandler):
    def local_request(self) -> bool:
        hosts = {f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}'}
        if self.server.server_port == 80:
            hosts.update(('127.0.0.1', 'localhost'))
        host = self.headers.get('Host', '').lower()
        origin = self.headers.get('Origin')
        return host in hosts and (origin is None or origin == 'http://' + host)

    def send_json(self, status: int, data: dict) -> None:
        encoded = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/api/health":
            self.send_json(200, {"status": "ok", "engine": "cli.normalize", "contract": RouterContractV1.__name__, "ready": CLI.is_file()})
        elif path == "/api/catalog":
            try:
                metadata = get_catalog_metadata()
                self.send_json(200, metadata)
            except Exception:
                self.send_json(500, {"error": "Failed to load catalog metadata"})
        elif path == "/api/manifest":
            try:
                manifest = get_manifest()
                self.send_json(200, manifest)
            except Exception:
                self.send_json(500, {"error": "Failed to load manifest"})
        elif path in ("/", "/index.html"):
            if not INDEX.is_file():
                self.send_json(500, {"error": "web/index.html introuvable."})
                return
            content = INDEX.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(content)
        elif path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
        else:
            self.send_json(404, {"error": "Ressource introuvable."})

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/api/normalize":
            self.handle_normalize()
        elif path == "/api/audit":
            self.handle_audit()
        else:
            self.send_json(404, {"error": "Route API inconnue."})

    def handle_normalize(self) -> None:
        if not self.local_request():
            self.send_json(403, {"error": "Utilisez l'interface depuis le serveur local."})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except (TypeError, ValueError):
            self.send_json(400, {"error": "En-tête Content-Length invalide."})
            return
        if not 0 < length <= MAX_REQUEST_BYTES:
            self.send_json(413, {"error": "Requête trop volumineuse ou vide."})
            return
        if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
            self.send_json(415, {"error": "Content-Type doit être application/json."})
            return
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("Le corps doit être un objet JSON.")
            configuration = payload.get("configuration")
            os_family = payload.get("os_family", "ios")
            if not isinstance(configuration, str) or not configuration.strip():
                raise ValueError("La configuration doit être du texte non vide.")
            configuration = configuration.removeprefix('\ufeff')
            if '\x00' in configuration:
                raise ValueError("La configuration doit être du texte UTF-8 sans octet nul.")
            if len(configuration.encode("utf-8")) > MAX_CONFIG_BYTES:
                self.send_json(413, {"error": "La configuration dépasse 2 Mio."})
                return
            if os_family not in ("ios", "iosxe"):
                raise ValueError("os_family doit être 'ios' ou 'iosxe'.")
        except UnicodeError:
            self.send_json(400, {"error": "La configuration doit être du texte UTF-8 valide."})
            return
        except (json.JSONDecodeError, ValueError) as exc:
            self.send_json(400, {"error": str(exc)})
            return

        if unsupported_platform(configuration):
            self.send_json(422, {"error": "Cette plateforme n'est pas prise en charge. Utilisez une configuration Cisco IOS ou IOS-XE."})
            return

        if not CLI.is_file():
            self.send_json(500, {"error": "cli.py introuvable. Placez webapp.py à la racine du dépôt."})
            return

        started = time.perf_counter()
        lock = self.server.normalization_lock
        if not lock.acquire(blocking=False):
            self.send_json(429, {"error": "Une normalisation est déjà en cours. Réessayez dans quelques instants."})
            return
        try:
            normalized = normalize(configuration, os_family=os_family)
            duration = round((time.perf_counter() - started) * 1000)
            self.send_json(200, {"normalized": normalized, "duration_ms": duration})
            print(f"[OK] {os_family}, {len(configuration)} caractères, {duration} ms")
        except subprocess.TimeoutExpired:
            self.send_json(504, {"error": "Le moteur a dépassé 120 secondes."})
        except Exception:
            self.send_json(500, {"error": "La normalisation a échoué. Vérifiez la configuration et réessayez."})
        finally:
            lock.release()

    def handle_audit(self) -> None:
        if not self.local_request():
            self.send_json(403, {"error": "Utilisez l'interface depuis le serveur local."})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except (TypeError, ValueError):
            self.send_json(400, {"error": "En-tête Content-Length invalide."})
            return
        if not 0 < length <= MAX_REQUEST_BYTES:
            self.send_json(413, {"error": "Requête trop volumineuse ou vide."})
            return
        if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
            self.send_json(415, {"error": "Content-Type doit être application/json."})
            return
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("Le corps doit être un objet JSON.")
            normalized = payload.get("normalized")
            profile_level = payload.get("profile_level", 1)
            include_lower = payload.get("include_lower", True)
            evidence = payload.get("evidence")
            if not isinstance(normalized, dict):
                raise ValueError("Le document normalisé est requis.")
            if type(profile_level) is not int or profile_level not in (1, 2):
                raise ValueError("profile_level doit être 1 ou 2.")
            if not isinstance(include_lower, bool):
                raise ValueError("include_lower doit être un booléen.")
            if evidence is not None and not isinstance(evidence, dict):
                raise ValueError("evidence doit être un objet JSON.")
            try:
                normalized = RouterContractV1.model_validate(normalized).model_dump(mode="json")
            except Exception:
                raise ValueError("Le document normalisé ne respecte pas RouterContractV1.") from None
        except (json.JSONDecodeError, ValueError) as exc:
            self.send_json(400, {"error": str(exc)})
            return

        lock = self.server.audit_lock
        if not lock.acquire(blocking=False):
            self.send_json(429, {"error": "Un audit est déjà en cours. Réessayez dans quelques instants."})
            return
        try:
            report = audit_cis(normalized, profile_level=profile_level, include_lower=include_lower, evidence=evidence)
            self.send_json(200, report)
        except subprocess.TimeoutExpired:
            self.send_json(504, {"error": "L'audit a dépassé 120 secondes."})
        except Exception:
            self.send_json(500, {"error": "L'audit a échoué."})
        finally:
            lock.release()


def main() -> None:
    if not CLI.is_file():
        print("ATTENTION : cli.py introuvable à la racine de :", ROOT, file=sys.stderr)
    try:
        port = int(os.environ.get("CONFIG_STUDIO_PORT", "8000"))
        server = LocalServer(("127.0.0.1", port), Handler)
    except OSError as exc:
        raise SystemExit(f"Impossible d'ouvrir 127.0.0.1:{port} : {exc}") from exc
    print(f"Config Studio : http://127.0.0.1:{port}")
    print("Appuyez sur Ctrl+C pour arrêter le serveur.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nArrêt du serveur.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
