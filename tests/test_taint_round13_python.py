"""13. tur Python: kaçışsız şablon çıktısı (Django/Jinja2), Django URLconf parametreleri, QuerySet.extra/RawSQL,
yüklenen dosya adı ve open_resource yolu, çözme sonrası yol aşımı, MongoDB operatör enjeksiyonu (yalnız JSON
kaynaklı), Tornado/Jinja2 şablon enjeksiyonu ve PickleSerializer oturum ayarı."""
from pathlib import Path
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import project_analyzer  # noqa: E402
import taint_flow as tf  # noqa: E402
import taint_py_views  # noqa: E402


def _src(text):
    return textwrap.dedent(text).lstrip("\n")


def _flows(files, templates=None, label="request"):
    results = tf._analyze_python_files_uncached({k: _src(v) for k, v in files.items()}, None, frozenset(),
                                                {k: _src(v) for k, v in (templates or {}).items()})
    out = {}
    for relpath, analysis in results.items():
        out[relpath] = sorted((f.sink_kind, f.line) for f in analysis.flows if label is None or f.source_label == label)
    return out


DJANGO_VIEW = """
    from django.shortcuts import render

    def search(request):
        q = request.GET.get("q", "")
        return render(request, "shop/search.html", {"q": q, "n": 1})
"""


class TemplateParserTests(unittest.TestCase):
    def test_outputs_and_filters(self):
        text = _src("""
            {% extends "base.html" %}
            <p>{{ q|safe }}</p><p>{{ q }}</p><p>{{ q|escape|safe }}</p><p>{{ items|length|safe }}</p>
            {% autoescape off %}{{ raw }}{{ raw|force_escape }}{% endautoescape %}
            {% for c in comments %}{{ c.text | safe }}{% endfor %}
            <a href="{{ link }}">x</a> <img src="{{ url_for('static', filename='a.png') }}">
        """)
        outputs, linked = taint_py_views.parse_template("t.html", text)
        self.assertEqual(linked, ["base.html"])
        shown = [(line, paths, url) for _, line, _, paths, url in outputs]
        self.assertEqual(shown, [
            (2, [("q",)], False), (3, [("raw",)], False), (4, [("comments", "text")], False), (5, [("link",)], True),
        ])

    def test_resolution_prefers_module_ancestor_and_refuses_ambiguity(self):
        inventory = frozenset({"a/templates/index.html", "b/templates/index.html", "shop/templates/shop/x.html"})
        self.assertEqual(taint_py_views.resolve_template("index.html", "a/app.py", inventory), "a/templates/index.html")
        self.assertIsNone(taint_py_views.resolve_template("index.html", "c/app.py", inventory))
        self.assertEqual(taint_py_views.resolve_template("shop/x.html", "shop/views.py", inventory), "shop/templates/shop/x.html")
        self.assertIsNone(taint_py_views.resolve_template("../x.html", "shop/views.py", inventory))


class TemplateFlowTests(unittest.TestCase):
    def test_django_safe_output_is_xss(self):
        flows = _flows({"shop/views.py": DJANGO_VIEW},
                       {"shop/templates/shop/search.html": "<h1>{{ q|safe }}</h1><p>{{ n|safe }}</p>"})
        self.assertEqual(flows["shop/views.py"], [("html", 5)])

    def test_escaped_output_is_clean(self):
        flows = _flows({"shop/views.py": DJANGO_VIEW},
                       {"shop/templates/shop/search.html": "<h1>{{ q }}</h1>{{ q|escape|safe }}"})
        self.assertEqual(flows["shop/views.py"], [])

    def test_flask_autoescape_false_and_url_attribute(self):
        app = """
            from flask import Flask, request, render_template
            app = Flask(__name__)

            @app.route("/a", methods=["POST"])
            def a():
                x = request.form["x"]
                return render_template("index.html", x=x)
        """
        raw = {"lab/templates/index.html": "{% autoescape false %}{{ x }}{% endautoescape %}"}
        self.assertEqual(_flows({"lab/app.py": app}, raw)["lab/app.py"], [("html", 7)])
        url = {"lab/templates/index.html": '<a href="{{ x }}">bağlantı</a>'}
        self.assertEqual(_flows({"lab/app.py": app}, url)["lab/app.py"], [("html", 7)])
        text = {"lab/templates/index.html": "<p>{{ x }}</p>"}
        self.assertEqual(_flows({"lab/app.py": app}, text)["lab/app.py"], [])

    def test_dict_variable_context_and_extends(self):
        view = """
            from django.shortcuts import render

            def page(request):
                env = {"qs": request.GET.get("qs", "")}
                return render(request, "app/page.html", env)
        """
        templates = {
            "app/templates/app/page.html": '{% extends "app/base.html" %}{% block b %}{{ qs }}{% endblock %}',
            "app/templates/app/base.html": "<script>var x = '{{ qs|safe }}';</script>",
        }
        self.assertEqual(_flows({"app/views.py": view}, templates)["app/views.py"], [("html", 5)])

    def test_session_user_name_in_base_template_reported_once(self):
        views = """
            from django.shortcuts import render

            def one(request):
                return render(request, "app/one.html", {})

            def two(request):
                return render(request, "app/two.html", {})
        """
        templates = {
            "app/templates/app/one.html": '{% extends "app/base.html" %}',
            "app/templates/app/two.html": '{% extends "app/base.html" %}',
            "app/templates/app/base.html": "<span>{{ user.username|safe }}</span>{{ user.id|safe }}",
        }
        flows = _flows({"app/views.py": views}, templates, label="stored")
        self.assertEqual(flows["app/views.py"], [("html", 4)])

    def test_ambiguous_template_is_not_guessed(self):
        templates = {"x/templates/shop/search.html": "{{ q|safe }}", "y/templates/shop/search.html": "{{ q|safe }}"}
        self.assertEqual(_flows({"shop/views.py": DJANGO_VIEW}, templates)["shop/views.py"], [])


class DjangoTests(unittest.TestCase):
    URLS = """
        from django.urls import re_path as url, path
        from shop import views

        urlpatterns = [
            url(r"^p/(?P<name>.+)/$", views.by_name),
            url(r"^n/(?P<pk>\\d+)/$", views.by_pk),
            path("s/<slug:slug>/<str:label>/", views.by_slug),
        ]
    """
    VIEWS = """
        from django.db import connection
        from django.http import HttpResponse
        from shop.models import Item

        def by_name(request, name):
            return HttpResponse("<b>" + name + "</b>")

        def by_pk(request, pk):
            return HttpResponse("<b>" + pk + "</b>")

        def by_slug(request, slug, label):
            Item.objects.extra(select={"x": "select 1 where y = '%s'" % slug})
            return Item.objects.extra(where=["label = '%s'" % label], params=[slug])
    """

    def test_urlconf_text_params_are_sources(self):
        flows = _flows({"shop/urls.py": self.URLS, "shop/views.py": self.VIEWS})
        self.assertEqual(flows["shop/views.py"], [("html", 6), ("sql", 13)])

    def test_rawsql(self):
        view = """
            from django.db.models.expressions import RawSQL
            from shop.models import Item

            def list_items(request):
                order = request.GET["o"]
                return Item.objects.annotate(v=RawSQL("select " + order, []))
        """
        self.assertEqual(_flows({"shop/views.py": view})["shop/views.py"], [("sql", 6)])


class FileAndDecodeTests(unittest.TestCase):
    def test_upload_save_after_extension_check(self):
        app = """
            import os
            from flask import Flask, request
            from werkzeug.utils import secure_filename
            app = Flask(__name__)

            def allowed_file(name):
                return "." in name and name.rsplit(".", 1)[1] in {"png"}

            @app.route("/up", methods=["POST"])
            def up():
                f = request.files["file"]
                if f and allowed_file(f.filename):
                    f.save(os.path.join("uploads/", f.filename))
                    f.save(os.path.join("uploads/", secure_filename(f.filename)))
                return "ok"
        """
        self.assertEqual(_flows({"app.py": app})["app.py"], [("path", 13)])

    def test_open_resource_and_decode_after_traversal_check(self):
        app = """
            import urllib
            from flask import Flask, request, current_app
            app = Flask(__name__)

            @app.route("/r", methods=["POST"])
            def r():
                name = urllib.parse.unquote(request.form["f"])
                if "../" not in name:
                    with current_app.open_resource(name) as fh:
                        fh.read()
                    name = urllib.parse.unquote(name)
                    with current_app.open_resource(name) as fh:
                        return fh.read()
                return ""
        """
        self.assertEqual(_flows({"app.py": app})["app.py"], [("path", 12)])


class MongoTests(unittest.TestCase):
    APP = """
        from flask import Flask, request
        from pymongo import MongoClient
        app = Flask(__name__)
        users = MongoClient().db.users

        @app.route("/login", methods=["POST"])
        def login():
            body = request.get_json()
            users.find_one({"name": body["name"], "pw": body["pw"]})
            users.find_one({"name": request.form["name"]})
            users.update_many({"_id": request.json["id"]}, {"$set": {"t": 1}})
            return "ok"
    """

    def test_json_values_reach_query_filter(self):
        self.assertEqual(_flows({"app.py": self.APP})["app.py"], [("nosql", 9), ("nosql", 11)])

    def test_project_without_mongo_driver(self):
        app = self.APP.replace("from pymongo import MongoClient", "from mydb import MongoClient")
        self.assertEqual(_flows({"app.py": app})["app.py"], [])


class SstiTests(unittest.TestCase):
    def test_tornado_template_from_argument(self):
        app = """
            import tornado.template
            import tornado.web

            TMPL = "<p>NAME</p>"

            class Main(tornado.web.RequestHandler):
                def get(self):
                    name = self.get_argument("name", "")
                    t = tornado.template.Template(TMPL.replace("NAME", name))
                    self.write(t.generate(name=name))
        """
        self.assertEqual(_flows({"server.py": app})["server.py"], [("ssti", 9)])

    def test_mako_and_django_template_source(self):
        app = """
            from django.http import HttpResponse
            from django.template import Context, Template
            from mako.template import Template as MakoTemplate

            def page(request):
                MakoTemplate(request.GET["m"]).render()
                body = Template("<p>" + request.GET["d"] + "</p>").render(Context({}))
                return HttpResponse(Template("<p>{{ x }}</p>").render(Context({"x": request.GET["x"]})))
        """
        flows = _flows({"app.py": app})["app.py"]
        self.assertEqual([f for f in flows if f[0] == "ssti"], [("ssti", 6), ("ssti", 7)])


class AnalyzerTests(unittest.TestCase):
    def test_pickle_session_serializer_and_stored_template_note(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "proj"
            (root / "shop" / "templates" / "shop").mkdir(parents=True)
            (root / "settings.py").write_text(
                'SESSION_ENGINE = "django.contrib.sessions.backends.signed_cookies"\n'
                'SESSION_SERIALIZER = "django.contrib.sessions.serializers.PickleSerializer"\n')
            (root / "shop" / "views.py").write_text(_src("""
                from django.shortcuts import render
                from shop.models import Item

                def detail(request, pk):
                    item = Item.objects.get(pk=pk)
                    return render(request, "shop/detail.html", {"item": item})

                def search(request):
                    return render(request, "shop/detail.html", {"item": request.GET["q"]})
            """))
            (root / "shop" / "templates" / "shop" / "detail.html").write_text("<div>{{ item|safe }}</div>")
            result = project_analyzer.analyze_project(str(root), allowed_roots=(root.parent,))
        by_title = {(f["title"], f["file"], f["line"]) for f in result["findings"]}
        self.assertIn(("Django oturumu PickleSerializer ile çözülüyor", "settings.py", 2), by_title)
        notes = [f for f in result["findings"] if f["title"].startswith("Kaçışsız şablon çıktısında kayıtlı veri")]
        self.assertEqual([(f["file"], f["line"], f["severity"], "taint_flow" in f) for f in notes],
                         [("shop/views.py", 6, "low", False)])
        verified = [f for f in result["findings"] if f.get("taint_flow") and f["reference"] == "CWE-79"]
        self.assertEqual([(f["file"], f["line"]) for f in verified], [("shop/views.py", 9)])


if __name__ == "__main__":
    unittest.main()
