"""Rota yetki envanteri: korumasız hassas rota (CWE-862) ve IDOR adayı (CWE-639) — statik, kesinlik öncelikli."""
from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import authz_routes as az  # noqa: E402
import project_analyzer  # noqa: E402


def _src(text: str) -> str:
    return textwrap.dedent(text).lstrip("\n")


def run(files: dict[str, str]):
    result = az.analyze_sources([(k, _src(v)) for k, v in files.items()])
    routes = {(r.file, r.path or r.handler, "/".join(r.methods)): r for r in result["routes"]}
    return routes, result["findings"]


def line_of(source: str, needle: str) -> int:
    for number, line in enumerate(_src(source).splitlines(), 1):
        if needle in line:
            return number
    raise AssertionError(needle)


def refs(findings, cwe):
    return sorted((f["file"], f["line"]) for f in findings if f["reference"] == cwe)


FLASK = """
    from flask import Blueprint, request, abort
    from flask_login import login_required, current_user
    bp = Blueprint("notes", __name__)

    @bp.route("/notes/<int:note_id>")
    @login_required
    def show(note_id):
        return Note.query.get_or_404(note_id).body

    @bp.route("/notes/<int:note_id>/delete", methods=["POST"])
    @login_required
    def delete(note_id):
        note = Note.query.filter_by(id=note_id, owner_id=current_user.id).first_or_404()

    @bp.route("/notes/<int:note_id>/edit", methods=["POST"])
    @login_required
    def edit(note_id):
        note = get_own_note(note_id)

    def get_own_note(note_id):
        note = Note.query.get(note_id)
        if note.owner_id != current_user.id:
            abort(403)
        return note

    @bp.route("/notes", methods=["POST"])
    @login_required
    def create():
        pass

    @bp.route("/admin/wipe", methods=["POST"])
    def wipe():
        pass

    @bp.route("/login", methods=["POST"])
    def login():
        pass

    @bp.route("/search", methods=["POST"])
    def search():
        pass
"""


class FlaskTests(unittest.TestCase):
    def test_protection_majority_and_idor(self):
        routes, findings = run({"app/notes.py": FLASK})
        self.assertEqual(routes[("app/notes.py", "/notes/<int:note_id>", "GET")].protection, "decorator:login_required")
        self.assertIsNone(routes[("app/notes.py", "/admin/wipe", "POST")].protection)
        # Korumasız hassas: yalnız /admin/wipe (login açık yol, /search okuma amaçlı POST).
        self.assertEqual(refs(findings, "CWE-862"), [("app/notes.py", line_of(FLASK, "def wipe"))])
        # IDOR: show (note okuma, kişisel kaynak) evet; sahiplik filtresi ve yardımcıda 403 olanlar hayır.
        self.assertEqual(refs(findings, "CWE-639"), [("app/notes.py", line_of(FLASK, "Note.query.get_or_404(note_id)"))])

    def test_blueprint_before_request_protects_routes(self):
        source = """
            from flask import Blueprint, session, redirect
            admin = Blueprint("admin", __name__)

            @admin.before_request
            def guard():
                if not session.get("user_id"):
                    return redirect("/login")

            @admin.route("/admin/users/<int:user_id>/delete", methods=["POST"])
            def delete_user(user_id):
                User.query.filter_by(id=user_id).delete()
        """
        routes, _ = run({"web/admin.py": source})
        self.assertEqual(routes[("web/admin.py", "/admin/users/<int:user_id>/delete", "POST")].protection, "router")

    def test_open_api_without_majority_is_quiet(self):
        source = """
            from flask import Flask
            app = Flask(__name__)
            @app.route("/items", methods=["POST"])
            def a(): pass
            @app.route("/items/<int:item_id>", methods=["DELETE"])
            def b(item_id): Item.query.filter_by(id=item_id).delete()
            @app.route("/admin/reset", methods=["POST"])
            def c(): pass
            @app.route("/x", methods=["PUT"])
            def d(): pass
        """
        _, findings = run({"api/app.py": source})
        self.assertEqual(findings, [])


class FastApiTests(unittest.TestCase):
    def test_depends_and_router_dependencies(self):
        source = """
            from fastapi import APIRouter, Depends
            router = APIRouter()
            secure = APIRouter(dependencies=[Depends(get_current_user)])

            @router.get("/orders/{order_id}")
            def get_order(order_id: int, user=Depends(get_current_user), db=Depends(get_db)):
                return db.query(Order).filter(Order.id == order_id).first()

            @router.get("/mine/{order_id}")
            def get_mine(order_id: int, user=Depends(get_current_user), db=Depends(get_db)):
                return db.query(Order).filter(Order.id == order_id, Order.user_id == user.id).first()

            @secure.delete("/orders/{order_id}")
            def remove(order_id: int, db=Depends(get_db)):
                db.query(Order).filter(Order.id == order_id).delete()

            @router.post("/public-thing")
            def thing(db=Depends(get_db)):
                pass
        """
        routes, findings = run({"svc/orders.py": source})
        self.assertEqual(routes[("svc/orders.py", "/orders/{order_id}", "GET")].protection, "dependency")
        self.assertEqual(routes[("svc/orders.py", "/orders/{order_id}", "DELETE")].protection, "router")
        self.assertIsNone(routes[("svc/orders.py", "/public-thing", "POST")].protection)
        idor = refs(findings, "CWE-639")
        src = source
        self.assertIn(("svc/orders.py", line_of(src, "filter(Order.id == order_id).first()")), idor)  # kullanıcı bağlaması yok
        self.assertNotIn(("svc/orders.py", line_of(src, "Order.user_id == user.id")), idor)
        self.assertIn(("svc/orders.py", line_of(src, "filter(Order.id == order_id).delete()")), idor)  # router düzeyinde korumalı silme


class DjangoTests(unittest.TestCase):
    URLS = """
        from django.urls import path
        from rest_framework.routers import DefaultRouter
        from . import views
        router = DefaultRouter()
        router.register(r"notes", views.NoteViewSet)
        router.register(r"mynotes", views.MyNoteViewSet)
        urlpatterns = [
            path("profile/<int:user_id>/", views.profile),
            path("tasks/<int:pk>/", views.TaskDetail.as_view()),
            path("reports/<int:pk>/", views.ReportDetail.as_view()),
            path("open/", views.open_view),
        ]
    """
    VIEWS = """
        from django.contrib.auth.decorators import login_required
        from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
        from rest_framework import viewsets
        from rest_framework.permissions import IsAuthenticated

        @login_required
        def profile(request, user_id):
            if request.method == "POST":
                User.objects.filter(pk=user_id).update(name=request.POST["name"])

        def helper_not_routed(request, thing):
            if request.method == "POST":
                thing.save()

        def open_view(request):
            return HttpResponse("ok")

        class TaskDetail(LoginRequiredMixin, DetailView):
            model = Task

        class ReportDetail(PermissionRequiredMixin, DetailView):
            permission_required = "reports.view_report"
            model = Report

        class NoteViewSet(viewsets.ModelViewSet):
            permission_classes = [IsAuthenticated]
            queryset = Note.objects.all()

        class MyNoteViewSet(viewsets.ModelViewSet):
            permission_classes = [IsAuthenticated]
            def get_queryset(self):
                return Note.objects.filter(owner=self.request.user)
    """

    def test_routes_from_urlconf_and_idor(self):
        routes, findings = run({"app/urls.py": self.URLS, "app/views.py": self.VIEWS})
        names = {r.handler for r in routes.values()}
        self.assertNotIn("helper_not_routed", names)  # URL tanımında yok
        self.assertEqual(routes[("app/views.py", "/profile/<int:user_id>/", "GET/POST")].protection, "decorator:login_required")
        self.assertEqual(routes[("app/views.py", "/notes", "GET/POST/PUT/PATCH/DELETE")].protection, "permission_classes")
        self.assertEqual(routes[("app/views.py", "/tasks/<int:pk>/", "GET")].protection, "mixin")
        idor = refs(findings, "CWE-639")
        line = lambda needle: ("app/views.py", line_of(self.VIEWS, needle))  # noqa: E731
        self.assertIn(line("User.objects.filter(pk=user_id)"), idor)  # başka kullanıcının profilini güncelleme
        self.assertIn(line("class TaskDetail"), idor)  # model kullanıcıya göre daraltılmamış
        self.assertNotIn(line("class ReportDetail"), idor)  # izin tabanlı (rol)
        self.assertIn(line("class NoteViewSet"), idor)  # queryset=all
        self.assertNotIn(line("class MyNoteViewSet"), idor)  # get_queryset request.user ile daraltılmış
        self.assertEqual(len(idor), 3)
        severities = {f["line"]: f["severity"] for f in findings if f["reference"] == "CWE-639"}
        self.assertEqual(severities[line_of(self.VIEWS, "User.objects.filter(pk=user_id)")], "medium")  # POST ile güncelleme
        self.assertEqual(severities[line_of(self.VIEWS, "class TaskDetail")], "low")  # salt okuma

    def test_inherited_and_urlconf_protection(self):
        files = {
            "site/admin/urls.py": """
                from django.urls import path
                from site.utils import decorate_urlpatterns
                from site.admin.auth import require_admin_access
                from . import views
                urlpatterns = [path("wipe/", views.wipe), path("items/", views.ItemCreate.as_view())]
                urlpatterns = decorate_urlpatterns(urlpatterns, require_admin_access)
            """,
            "site/admin/views.py": """
                def wipe(request):
                    if request.method == "POST":
                        Item.objects.all().delete()
                class ItemCreate(BaseCreate):
                    pass
            """,
            "site/generic.py": """
                class BaseCreate(CreateView):
                    permission_policy = None
            """,
        }
        routes, _ = run(files)
        self.assertEqual(routes[("site/admin/views.py", "/wipe/", "GET/POST")].protection, "urlconf")  # GET + gövdedeki POST
        self.assertEqual(routes[("site/admin/views.py", "/items/", "GET/POST")].protection, "inherited")


EXPRESS = """
    const express = require("express");
    const router = express.Router();
    router.get("/orders/:id", auth, async (req, res) => { res.json(await Order.findById(req.params.id)); });
    router.get("/mine/:id", auth, async (req, res) => { res.json(await Order.findOne({ _id: req.params.id, owner: req.user.id })); });
    router.post("/orders", auth, (req, res) => {});
    router.put("/orders/:id", isLoggedIn, (req, res) => { const { id } = req.params; db.query("UPDATE o SET x=1 WHERE id=" + id); });
    router.delete("/orders/:id", (req, res) => { Order.findByIdAndDelete(req.params.id); });
    router.post("/notes", csrfProtection, (req, res) => {});
    router.post("/login", (req, res) => {});
    module.exports = router;
"""


class ExpressTests(unittest.TestCase):
    def test_middleware_majority_and_idor(self):
        routes, findings = run({"src/routes/orders.js": EXPRESS})
        self.assertEqual(routes[("src/routes/orders.js", "/orders/:id", "GET")].protection, "middleware:auth")
        self.assertIsNone(routes[("src/routes/orders.js", "/notes", "POST")].protection)  # csrf kimlik değil
        line = lambda needle: ("src/routes/orders.js", line_of(EXPRESS, needle))  # noqa: E731
        self.assertEqual(refs(findings, "CWE-862"), sorted([line('router.delete("/orders/:id"'), line('router.post("/notes"')]))
        self.assertEqual(refs(findings, "CWE-639"), sorted([line('router.get("/orders/:id"'), line('router.put("/orders/:id"')]))

    def test_router_use_and_mounting(self):
        files = {
            "src/app.js": """
                const express = require("express");
                const app = express();
                const admin = require("./routes/admin");
                app.use("/admin", requireAuth, admin);
                app.get("/health", (req, res) => res.send("ok"));
            """,
            "src/routes/admin.js": """
                const router = require("express").Router();
                router.post("/users/:id/ban", (req, res) => {});
                module.exports = router;
            """,
            "src/routes/api.js": """
                const router = require("express").Router();
                router.get("/open", (req, res) => {});
                router.use(passport.authenticate("jwt"));
                router.delete("/things/:id", (req, res) => {});
                module.exports = router;
            """,
        }
        routes, _ = run(files)
        self.assertEqual(routes[("src/routes/admin.js", "/users/:id/ban", "POST")].protection, "mounted")
        self.assertIsNone(routes[("src/routes/api.js", "/open", "GET")].protection)
        self.assertEqual(routes[("src/routes/api.js", "/things/:id", "DELETE")].protection, "router.use")


class NestTests(unittest.TestCase):
    def test_guards_and_public(self):
        source = """
            @Controller('cats')
            @UseGuards(AuthGuard('jwt'))
            export class CatsController {
              @Get(':id')
              findOne(@Param('id') id: string) {}
              @Public()
              @Post()
              create(@Body() dto) {}
            }
            @Controller('dogs')
            export class DogsController {
              @Delete(':id')
              remove(@Param('id') id: string) {}
            }
        """
        routes, _ = run({"src/pets.controller.ts": source})
        self.assertEqual(routes[("src/pets.controller.ts", "/cats/:id", "GET")].protection, "guard")
        self.assertTrue(routes[("src/pets.controller.ts", "/cats", "POST")].public_mark)
        self.assertIsNone(routes[("src/pets.controller.ts", "/dogs/:id", "DELETE")].protection)


class AnalyzerIntegrationTests(unittest.TestCase):
    def test_project_analyzer_reports_inventory_and_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "proj"
            (root / "app").mkdir(parents=True)
            (root / "app" / "notes.py").write_text(_src(FLASK))
            result = project_analyzer.analyze_project(str(root), allowed_roots=(root.parent,))
        inventory = result["route_inventory"]
        self.assertEqual(inventory["summary"]["total"], 7)
        self.assertEqual(inventory["summary"]["idor_candidates"], 1)
        authz = [f for f in result["findings"] if f["category"] == "authz"]
        self.assertEqual(sorted(f["reference"] for f in authz), ["CWE-639", "CWE-862"])
        self.assertIn("gözden geçirme", authz[0]["title"])
        check = next(c for c in result["checks"] if c["id"] == "authz")
        self.assertEqual(check["status"], "review")

    def test_list_view_keeps_only_inventory_summary(self):
        from storage import Store

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "proj"
            (root / "app").mkdir(parents=True)
            (root / "app" / "notes.py").write_text(_src(FLASK))
            result = project_analyzer.analyze_project(str(root), allowed_roots=(root.parent,))
            store = Store(Path(tmp) / "data" / "t.db")
            saved = store.create_project_audit(result)
            listed = store.list_project_audits()[0]
            detail = store.get_project_audit(saved["id"])
        self.assertNotIn("routes", listed["route_inventory"])
        self.assertEqual(listed["route_inventory"]["summary"]["total"], 7)
        self.assertEqual(len(detail["route_inventory"]["routes"]), 7)

    def test_ui_wiring(self):
        static = Path(__file__).resolve().parent.parent / "static"
        self.assertIn("/authz_inventory.js", (static / "index.html").read_text())
        self.assertIn("renderRouteInventory", (static / "app.js").read_text())
        self.assertIn("textContent", (static / "authz_inventory.js").read_text())
        self.assertNotIn("innerHTML", (static / "authz_inventory.js").read_text())


if __name__ == "__main__":
    unittest.main()
