"""Otomatik tehdit modeli: rota envanteri, veri akış diyagramı, STRIDE tehditleri, rapor ve API (13. tur)."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import textwrap
import threading
import unittest
from unittest import mock
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import project_analyzer
from project_analyzer import analyze_project
import scan_scope
import threat_model


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).lstrip("\n"), encoding="utf-8")


FLASK_APP = """
    import os
    import sqlite3
    import requests
    from flask import Flask, request
    from flask_login import login_required

    app = Flask(__name__)
    DB = os.environ.get("DB_PATH", "app.db")

    @app.route("/users", methods=["GET", "POST"])
    def users():
        name = request.args["name"]
        cur = sqlite3.connect(DB).cursor()
        cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
        return "ok"

    @app.get("/status")
    def status():
        return requests.get("https://status.partner-api.io/v1/health").text
"""


class CollectorTests(unittest.TestCase):
    def collect(self, files: dict[str, str]):
        collector = threat_model.ThreatModelCollector("demo")
        for rel, text in files.items():
            collector.add(rel, textwrap.dedent(text).lstrip("\n"), "manifest" if rel.endswith("package.json") else "source")
        return collector

    def test_express_routes_without_local_require(self):
        collector = self.collect({
            "app/routes/index.js": """
                module.exports = function (app, db) {
                    app.get("/", isLoggedIn, sessionHandler.displayWelcomePage);
                    app.post("/login", sessionHandler.handleLoginRequest);
                    router.delete('/notes/:id', (req, res) => res.send('x'));
                    axios.get('/not-a-route');
                    api.get('/also-not-a-route');
                    app.use('/static', serve);
                };
            """,
        })
        routes = {(r["method"], r["path"], r["handler"]) for r in collector.routes}
        self.assertIn(("GET", "/", "sessionHandler.displayWelcomePage"), routes)
        self.assertIn(("POST", "/login", "sessionHandler.handleLoginRequest"), routes)
        self.assertIn(("DELETE", "/notes/:id", "(anonim)"), routes)
        self.assertIn(("USE", "/static", "serve"), routes)
        self.assertFalse(any(r["path"] in {"/not-a-route", "/also-not-a-route"} for r in collector.routes))

    def test_nest_django_falcon_aiohttp_openapi(self):
        collector = self.collect({
            "src/users.controller.ts": """
                import { Controller, Get, Post } from '@nestjs/common';
                @Controller('users')
                export class UsersController {
                  @Get(':id')
                  findOne() {}
                  @Post()
                  async create() {}
                }
            """,
            "shop/urls.py": """
                from django.urls import path, include
                from . import views
                urlpatterns = [path("orders/<int:pk>/", views.order_detail), path("api/", include("api.urls"))]
            """,
            "svc/app.py": """
                import falcon
                from aiohttp import web
                app = falcon.App()
                app.add_route("/items/{id}", ItemResource())
                web_app = web.Application()
                web_app.router.add_get("/health", health)
            """,
            "spec/openapi.yaml": """
                openapi: 3.0.0
                paths:
                  /pets/{id}:
                    get:
                      operationId: pets.get_pet
                    delete:
                      operationId: pets.delete_pet
            """,
        })
        routes = {(r["method"], r["path"], r["handler"], r["framework"]) for r in collector.routes}
        self.assertIn(("GET", "/users/:id", "findOne", "nestjs"), routes)
        self.assertIn(("POST", "/users", "create", "nestjs"), routes)
        self.assertIn(("ANY", "/orders/<int:pk>/", "views.order_detail", "django"), routes)
        self.assertFalse(any(h.startswith("include") for _, _, h, _ in routes))
        self.assertIn(("ANY", "/items/{id}", "ItemResource", "falcon"), routes)
        self.assertIn(("GET", "/health", "health", "aiohttp"), routes)
        self.assertIn(("GET", "/pets/{id}", "pets.get_pet", "openapi"), routes)
        self.assertIn(("DELETE", "/pets/{id}", "pets.delete_pet", "openapi"), routes)

    def test_services_per_manifest_and_static_bundles_ignored(self):
        collector = self.collect({
            "api/package.json": "{}",
            "api/server.js": "const express = require('express'); const app = express(); const { Pool } = require('pg');\napp.get('/a', h);\n",
            "worker/requirements.txt": "celery\n",
            "worker/tasks.py": "import celery\nimport boto3\n",
            "web/static/app.js": "const axios = require('axios'); axios.get('https://cdn.example-cdn.net/x');\n",
        })
        model = collector.build([])
        processes = {n["label"]: n for n in model["nodes"] if n["type"] == "process"}
        self.assertEqual(set(processes), {"api", "worker"})
        node_ids = {n["id"] for n in model["nodes"]}
        self.assertIn("store:sql", node_ids)
        self.assertIn("store:queue", node_ids)
        self.assertIn("external:cloud", node_ids)
        self.assertNotIn("external:http", node_ids)  # istemci paketi sunucu bileşeni sayılmaz

    def test_svg_and_html_escape_untrusted_labels(self):
        collector = self.collect({"<img src=x onerror=alert(1)>/app.js":
                                  "const express=require('express');\napp.get('/<script>alert(1)</script>', h);\n"})
        model = collector.build([])
        svg = threat_model.render_svg(model)
        section = threat_model.render_html_section(model, [])
        for blob in (svg, section):
            self.assertNotIn("<script>", blob)
            self.assertNotIn("<img", blob)
        self.assertTrue(svg.startswith("<svg"))


class AnalyzerIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / "proj"
        _write(self.root, "requirements.txt", "flask\nrequests\nflask-login\n")
        _write(self.root, "app.py", FLASK_APP)

    def analyze(self, **kwargs):
        return analyze_project(str(self.root), allowed_roots=(self.base,), **kwargs)

    def test_model_in_analysis_with_linked_findings(self):
        result = self.analyze()
        model = result["threat_model"]
        self.assertEqual(model["format"], threat_model.MODEL_FORMAT)
        self.assertFalse(model["partial"])
        self.assertEqual({(r["method"], r["path"]) for r in model["routes"]},
                         {("GET", "/users"), ("POST", "/users"), ("GET", "/status")})
        nodes = {n["id"]: n for n in model["nodes"]}
        self.assertIn("external:client", nodes)
        self.assertEqual(nodes["store:sql"]["technologies"], ["SQLite"])
        self.assertIn("status.partner-api.io", nodes["external:http"]["hosts"])
        self.assertIn("store:env", nodes)
        self.assertEqual(model["auth_components"], ["Flask-Login"])
        boundaries = {b["id"] for b in model["boundaries"]}
        self.assertTrue({"B:internet", "B:data", "B:third_party", "B:host"} <= boundaries)
        sql_threat = next(t for t in model["threats"] if t["element"] == "F2" or "SQL" in t["title"])
        self.assertEqual(sql_threat["status"], "finding")
        cwe89 = [i for i, f in enumerate(result["findings"]) if "CWE-89" in str(f.get("reference"))]
        self.assertTrue(cwe89 and set(cwe89) <= set(sql_threat["finding_refs"]))
        flows = {f["to"]: f for f in model["flows"]}
        self.assertTrue(flows["store:sql"]["has_findings"])
        self.assertTrue(any(t["status"] == "review" for t in model["threats"]))
        json.dumps(model)  # özet JSON'a yazılabilir

    def test_skipped_only_marks_partial_and_collector_errors_never_break(self):
        (self.root / "tests").mkdir()
        _write(self.root, "tests/test_app.py", FLASK_APP)
        rest = self.analyze(scope=scan_scope.parse_scope({"preset": "skipped"}))
        self.assertTrue(rest["threat_model"]["partial"])
        with mock.patch.object(threat_model.ThreatModelCollector, "add", side_effect=RuntimeError("x")), \
                mock.patch.object(threat_model.ThreatModelCollector, "build", side_effect=RuntimeError("y")):
            result = self.analyze()
        self.assertIsNone(result["threat_model"])
        self.assertTrue(result["findings"])


class ThreatModelApiTests(unittest.TestCase):
    def setUp(self):
        import server
        from storage import Store

        self.server = server
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / "proj"
        _write(self.root, "app.py", FLASK_APP)
        self.previous_store = server.STORE
        server.STORE = Store(self.base / "data" / "t.db")
        for patch in (mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(self.base / "data")}),
                      mock.patch.object(project_analyzer, "_allowed_roots", return_value=(self.base,))):
            patch.start()
            self.addCleanup(patch.stop)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.server.STORE = self.previous_store

    def get(self, path):
        try:
            with urllib.request.urlopen(self.url + path, timeout=30) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    def test_endpoint_report_and_rebuild_for_old_audits(self):
        audit = self.server.STORE.create_project_audit(analyze_project(str(self.root), allowed_roots=(self.base,)))
        status, body = self.get(f"/api/project-audits/{audit['id']}/threat-model")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertFalse(data["rebuilt_from_disk"])
        self.assertTrue(data["svg"].startswith("<svg"))
        self.assertEqual(data["threat_model"]["route_count"], 3)
        status, html_body = self.get(f"/api/project-audits/{audit['id']}/report.html")
        self.assertEqual(status, 200)
        self.assertIn("Tehdit modeli (STRIDE)", html_body.decode())
        # Eski analiz (modelsiz): klasör varsa yeniden çıkarılır; yoksa 404
        legacy = analyze_project(str(self.root), allowed_roots=(self.base,))
        legacy.pop("threat_model")
        old = self.server.STORE.create_project_audit(legacy)
        status, body = self.get(f"/api/project-audits/{old['id']}/threat-model")
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["rebuilt_from_disk"])
        legacy["project_path"] = str(self.base / "silinmis")
        gone = self.server.STORE.create_project_audit(legacy)
        self.assertEqual(self.get(f"/api/project-audits/{gone['id']}/threat-model")[0], 404)


if __name__ == "__main__":
    unittest.main()
