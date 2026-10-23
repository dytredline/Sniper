"""OpenAPI sözleşmesi ↔ rota envanteri (17. tur W2-API) ve bununla gelen authz_routes kesinlik düzeltmeleri."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import textwrap
import unittest

import api_spec_routes
import authz_routes
import project_analyzer


def _spec(paths: dict, **extra) -> str:
    doc = {"openapi": "3.0.0", "info": {"title": "t", "version": "1"}, "paths": paths}
    doc.update(extra)
    return json.dumps(doc)


def _op(security=None, params=None, op_id=None) -> dict:
    op: dict = {"responses": {"200": {"description": "ok"}}}
    if security is not None:
        op["security"] = security
    if params is not None:
        op["parameters"] = params
    if op_id:
        op["operationId"] = op_id
    return op


EXPRESS = textwrap.dedent("""\
    const express = require('express');
    const router = express.Router();
    const validateToken = require('./auth').validateToken;
    router.get('/v1/items', validateToken, (req, res) => res.json([]));
    router.post('/v1/items', validateToken, (req, res) => res.json({}));
    router.get('/v1/items/:itemId', validateToken, (req, res) => res.json({}));
    router.put('/v1/items/:itemId', (req, res) => res.json({}));
    router.delete('/v1/admin/purge', validateToken, (req, res) => res.json({}));
    router.get('/v1/debug/dump', (req, res) => res.json({}));
    module.exports = router;
""")


def _compare(spec_text: str, sources: list[tuple[str, str]], spec_name: str = "openapi.json") -> dict:
    routes = authz_routes.analyze_sources(sources)["routes"]
    return api_spec_routes.analyze([(spec_name, spec_text)], routes, sources)


class NormalizeTests(unittest.TestCase):
    def test_framework_path_forms(self):
        norm = api_spec_routes.norm_path
        self.assertEqual(norm("/users/{id}"), ("users", "{}"))
        self.assertEqual(norm("/users/:userId"), ("users", "{}"))
        self.assertEqual(norm("/users/<int:pk>/"), ("users", "{}"))
        self.assertEqual(norm(r"^orders/(?P<order_id>\d+)$"), ("orders", "{}"))
        self.assertEqual(norm(r"/service/(?P<vin>[^/]+)/report"), ("service", "{}", "report"))
        self.assertEqual(norm("/Files/*"), ("files", "{}"))

    def test_suffix_match_rules(self):
        match = api_spec_routes._suffix_match
        self.assertEqual(match(("api", "v1", "items"), ("items",)), 2)  # bağlama öneki bilinmiyor
        self.assertIsNone(match(("a", "{}", "items"), ("items",)))  # fazlalıkta parametre: farklı kaynak
        self.assertIsNone(match(("agents", "agents", "{}"), ("{}",)))  # yalnız parametreden oluşan yol eşleşmez
        self.assertIsNone(match(("a", "b", "c", "d", "items"), ("items",)))  # en çok 3 önek bölümü

    def test_spec_detection(self):
        self.assertTrue(api_spec_routes.looks_like_spec("docs/api.json", _spec({})))
        self.assertTrue(api_spec_routes.looks_like_spec("spec/openapi3.yml", "openapi: 3.0.1\ninfo:\n  title: x\npaths: {}\n"))
        self.assertTrue(api_spec_routes.looks_like_spec("swagger.yaml", 'swagger: "2.0"\npaths: {}\n'))
        self.assertFalse(api_spec_routes.looks_like_spec("k8s/deploy.yaml", "apiVersion: v1\nkind: Service\n"))
        self.assertFalse(api_spec_routes.looks_like_spec("x.yaml", "  openapi: 3.0.0\n"))  # üst düzey değil
        self.assertFalse(api_spec_routes.looks_like_spec("app.js", _spec({})))


class CompareTests(unittest.TestCase):
    def test_shadow_missing_auth_mismatch_and_drift(self):
        paths = {
            "/v1/items": {"get": _op(), "post": _op()},
            "/v1/items/{itemId}": {"get": _op(), "put": _op(security=[{"bearer": []}])},
            "/v1/admin/purge": {"delete": _op(security=[])},
            "/v1/legacy/report": {"get": _op()},
        }
        spec = _spec(paths, servers=[{"url": "https://api.example.test/api"}], security=[{"bearer": []}],
                     components={"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}})
        result = _compare(spec, [("routes.js", EXPRESS)])
        s = result["summary"]
        self.assertEqual((s["spec_operations"], s["matched_operations"]), (6, 5))
        self.assertEqual([x["path"] for x in result["shadow"]], ["/v1/debug/dump"])
        self.assertEqual([(m["method"], m["path"]) for m in result["missing"]], [("GET", "/v1/legacy/report")])
        self.assertEqual([(a["method"], a["path"]) for a in result["auth_mismatch"]], [("PUT", "/v1/items/{itemId}")])
        self.assertEqual(s["doc_auth_drift"], 1)  # DELETE /v1/admin/purge: sözleşmede security: [] ama kod korumalı
        titles = {f["title"]: f for f in result["findings"]}
        shadow = titles["Belgelenmemiş (gölge) API uç noktası: sözleşmede yok (gözden geçirme)"]
        self.assertEqual((shadow["severity"], shadow["file"], shadow["category"]), ("medium", "routes.js", "api"))  # debug yolu
        gap = titles["Sözleşme kimlik doğrulama istiyor, kodda denetim görülmedi (gözden geçirme)"]
        self.assertEqual((gap["category"], gap["reference"], gap["line"]), ("authz", "CWE-306", 7))
        self.assertIn("API sözleşmesinde kimlik doğrulama tanımı eksik (kod korumalı; belge sapması)", titles)
        self.assertIn("API sözleşmesindeki uç nokta kodda bulunamadı (eski belge ya da başka servis olabilir)", titles)

    def test_low_coverage_spec_reports_nothing_about_routes(self):
        # Sözleşme başka bir servisi anlatıyor: eşleşme azsa gölge/eksik uç nokta gürültüsü yok.
        spec = _spec({f"/other/r{i}": {"get": _op()} for i in range(10)} | {"/v1/items": {"get": _op()}})
        result = _compare(spec, [("routes.js", EXPRESS)])
        self.assertEqual((result["summary"]["shadow_routes"], result["summary"]["missing_in_code"]), (0, 0))
        self.assertFalse(any("gölge" in f["title"] for f in result["findings"]))

    def test_operation_id_resolution_for_spec_driven_frameworks(self):
        # connexion: rotalar koddan değil sözleşmeden kurulur; operationId projedeki işleve eşlenir.
        spec = "openapi: 3.0.0\ninfo:\n  title: t\n  version: '1'\npaths:\n" + "".join(
            f"  /users/{name}:\n    get:\n      operationId: api_views.users.{name}\n      responses:\n        '200':\n          description: ok\n"
            for name in ("get_all", "get_one", "missing_fn"))
        sources = [("api_views/users.py", "def get_all():\n    return []\n\ndef get_one():\n    return {}\n")]
        result = api_spec_routes.analyze([("openapi_specs/openapi3.yml", spec)], [], sources)
        report = result["specs"][0]
        self.assertEqual((report["matched"], report["matched_by_operation_id"]), (2, 2))
        self.assertEqual([m["path"] for m in result["missing"]], [])  # 2 eşleşme < 3: eksik raporu yok (gürültü sınırı)

    def test_param_gaps_and_duplicate_specs(self):
        paths = {"/a/{id}": {"get": _op(params=[{"name": "q", "in": "query"}])}}
        spec = _spec(paths)
        result = api_spec_routes.analyze([("openapi.json", spec), ("copy/openapi.json", spec)], [], [])
        self.assertEqual(result["summary"]["specs"], 1)  # aynı içerik tek sözleşme
        gaps = [f for f in result["findings"] if f["title"].startswith("API sözleşmesinde parametre şeması eksik")]
        self.assertEqual(len(gaps), 1)
        self.assertIn("yol parametresi 'id' tanımlanmamış", gaps[0]["evidence"])
        self.assertIn("'q' parametresinin türü/şeması yok", gaps[0]["evidence"])

    def test_root_route_is_not_shadow(self):
        app = EXPRESS + "router.get('/', (req, res) => res.send('ok'));\n"
        spec = _spec({"/v1/items": {"get": _op(), "post": _op()}, "/v1/items/{itemId}": {"get": _op(), "put": _op()},
                      "/v1/admin/purge": {"delete": _op()}, "/v1/debug/dump": {"get": _op()}})
        result = _compare(spec, [("routes.js", app)])
        self.assertEqual(result["shadow"], [])

    def test_bad_spec_is_ignored(self):
        self.assertIsNone(api_spec_routes.analyze([("openapi.json", '{"openapi": "3.0.0", "paths": [1]}')], [], []))
        self.assertIsNone(api_spec_routes.analyze([("openapi.yaml", "openapi: 3.0.0\npaths:\n  : : :\n")], [], []))


class AuthzPrecisionTests(unittest.TestCase):
    def test_validate_token_middleware_is_auth_but_validators_are_not(self):
        self.assertTrue(authz_routes._is_auth_name("validateToken"))
        self.assertTrue(authz_routes._is_auth_name("verifyJwtValid"))
        self.assertFalse(authz_routes._is_auth_name("validateBody"))
        self.assertFalse(authz_routes._is_auth_name("csrfTokenValidator"))

    def test_class_view_method_decorators_and_get_permissions(self):
        source = textwrap.dedent("""\
            from django.urls import path
            from rest_framework.views import APIView
            class ProductView(APIView):
                @jwt_auth_required
                def get(self, request, user):
                    return 1
                @jwt_auth_required
                def post(self, request, user):
                    return 1
            class HalfView(APIView):
                @jwt_auth_required
                def put(self, request):
                    return 1
                def get(self, request):
                    return 1
            class SettingsView(APIView):
                def get_permissions(self):
                    return [HasPermission("view_settings")()]
                def get(self, request):
                    return 1
            urlpatterns = [path("products", ProductView.as_view()), path("half", HalfView.as_view()),
                           path("settings", SettingsView.as_view())]
        """)
        routes = {r.handler: r for r in authz_routes.analyze_sources([("shop/views.py", source)])["routes"]}
        self.assertEqual(routes["ProductView"].protection, "method_decorator")
        self.assertIsNone(routes["HalfView"].protection)  # GET korumasız: rota korumasız sayılır
        self.assertEqual(routes["SettingsView"].protection, "get_permissions")

    def test_drf_custom_default_permission(self):
        settings = "REST_FRAMEWORK = {'DEFAULT_PERMISSION_CLASSES': ('app.rbac.permissions.ObjectPermissions',)}\n"
        anon = "REST_FRAMEWORK = {'DEFAULT_PERMISSION_CLASSES': ('rest_framework.permissions.AllowAny',)}\n"
        view = textwrap.dedent("""\
            from django.urls import path
            from rest_framework.views import APIView
            class ItemView(APIView):
                def post(self, request):
                    return 1
            urlpatterns = [path("items", ItemView.as_view())]
        """)
        protected = authz_routes.analyze_sources([("proj/settings.py", settings), ("items/views.py", view)])["routes"]
        self.assertEqual(protected[0].protection, "global")
        open_ = authz_routes.analyze_sources([("proj/settings.py", anon), ("items/views.py", view)])["routes"]
        self.assertIsNone(open_[0].protection)


class ProjectIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "api"
        (self.root / "docs").mkdir(parents=True)
        (self.root / "routes.js").write_text(EXPRESS)
        paths = {"/v1/items": {"get": _op(), "post": _op()}, "/v1/items/{itemId}": {"get": _op(), "put": _op()},
                 "/v1/admin/purge": {"delete": _op()}}
        (self.root / "docs" / "openapi.json").write_text(_spec(paths, servers=[{"url": "/api"}]))

    def test_project_analysis_reports_contract(self):
        result = project_analyzer.analyze_project(str(self.root), allowed_roots=(self.root.parent,))
        contract = result["api_contract"]
        self.assertEqual(contract["summary"]["matched_operations"], 5)
        self.assertEqual([x["path"] for x in contract["shadow"]], ["/v1/debug/dump"])
        check = next(c for c in result["checks"] if c["id"] == "api_contract")
        self.assertEqual(check["status"], "review")
        shadow = [f for f in result["findings"] if f["title"].startswith("Belgelenmemiş (gölge)")]
        self.assertEqual([(f["file"], f["category"]) for f in shadow], [("routes.js", "api")])
        self.assertNotIn("findings", contract)
        json.dumps(result)  # saklanabilir

    def test_no_spec_and_partial_scans_skip(self):
        import scan_scope

        (self.root / "tests").mkdir()
        (self.root / "tests" / "extra.js").write_text("router.get('/v1/test-only', (req, res) => res.json({}));\n")
        partial = project_analyzer.analyze_project(str(self.root), allowed_roots=(self.root.parent,),
                                                   scope=scan_scope.parse_scope({"preset": "skipped"}))
        self.assertIsNone(partial["api_contract"])  # yalnız atlananlar: sözleşme karşılaştırması anlamsız
        (self.root / "docs" / "openapi.json").unlink()
        result = project_analyzer.analyze_project(str(self.root), allowed_roots=(self.root.parent,))
        self.assertIsNone(result["api_contract"])
        self.assertEqual(next(c for c in result["checks"] if c["id"] == "api_contract")["status"], "na")

    def test_ui_wiring(self):
        static = Path(__file__).resolve().parent.parent / "static"
        source = (static / "authz_inventory.js").read_text()
        self.assertIn("renderApiContract", source)
        self.assertIn("api_contract", source)
        self.assertNotIn("innerHTML", source)
        self.assertIn("/authz_inventory.js?v=2", (static / "index.html").read_text())


if __name__ == "__main__":
    unittest.main()
