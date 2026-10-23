"""Python taint (11. tur): strawberry ``field(resolver=…)`` ve ariadne sözlük haritalarıyla bağlanan çözücüler,
sınıf alanı ``list[X]`` öğe türü, SSRF/yönlendirmede dış sabit önek (modül/sınıf sabiti, Django settings,
ortam değişkeni → belirsiz), aynı köken önekleri ve adres şablonunda sorgu kısmı. Olumlu ve olumsuz örnekler."""
from pathlib import Path
import sys
import textwrap
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import taint_flow as tf  # noqa: E402


def _src(text):
    return textwrap.dedent(text).lstrip("\n")


def _analyze(files):
    return tf._analyze_python_files_uncached({k: _src(v) for k, v in files.items()}, None, frozenset())


def _flows(files):
    return {k: sorted((f.sink_kind, f.line) for f in v.flows if f.source_label == "request")
            for k, v in _analyze(files).items()}


class StrawberryAriadneBindingTests(unittest.TestCase):
    def test_strawberry_resolver_keyword_across_files(self):
        flows = _flows({
            "app/resolvers.py": """
                import os

                def get_report(info, name: str) -> str:
                    return os.popen("cat " + name).read()

                def safe_report(info) -> str:
                    return os.popen("uptime").read()
            """,
            "app/schema.py": """
                import strawberry
                from app.resolvers import get_report, safe_report

                @strawberry.type
                class Query:
                    report: str = strawberry.field(resolver=get_report)
                    uptime: str = strawberry.field(resolver=safe_report)
            """,
        })
        self.assertEqual(flows["app/resolvers.py"], [("command", 4)])

    def test_strawberry_keyword_ignored_without_strawberry(self):
        flows = _flows({
            "app/resolvers.py": """
                import os

                def get_report(info, name):
                    return os.popen("cat " + name).read()
            """,
            "app/schema.py": """
                from dataclasses import field
                from app.resolvers import get_report
                cfg = field(default=None, resolver=get_report)
            """,
        })
        self.assertEqual(flows["app/resolvers.py"], [])

    def test_ariadne_dict_maps(self):
        flows = _flows({
            "api/resolvers.py": """
                import subprocess

                def resolve_ping(obj, info, host):
                    return subprocess.check_output("ping -c1 " + host, shell=True)

                def resolve_echo(obj, info, text):
                    return subprocess.check_output("echo " + text, shell=True)

                def resolve_lookup(obj, info, name):
                    return subprocess.check_output("host " + name, shell=True)

                resolvers = {"Query": {"ping": resolve_ping}}
            """,
            "api/schema.py": """
                from ariadne import ObjectType, make_executable_schema
                from api.resolvers import resolvers, resolve_echo, resolve_lookup

                mutation = ObjectType("Mutation", {"echo": resolve_echo})
                schema = make_executable_schema("type Query { ping: String }", resolvers, {"Subscription": {"lookup": resolve_lookup}})
            """,
        })
        self.assertEqual(flows["api/resolvers.py"], [("command", 4), ("command", 7), ("command", 10)])

    def test_plain_dict_without_ariadne_is_not_entry(self):
        flows = _flows({
            "api/resolvers.py": """
                import subprocess

                def resolve_ping(obj, info, host):
                    return subprocess.check_output("ping -c1 " + host, shell=True)

                resolvers = {"Query": {"ping": resolve_ping}}
            """,
        })
        self.assertEqual(flows["api/resolvers.py"], [])


class ClassFieldElementTypeTests(unittest.TestCase):
    def test_list_annotated_field_resolves_loop_receiver(self):
        # run dört sınıfta tanımlı: ada göre dağıtım (en çok 3 aday) devre dışı; yalnız öğe türü çözer.
        flows = _flows({
            "app/repo.py": """
                import sqlite3

                class Repo:
                    def run(self, name):
                        return sqlite3.connect("x").execute("SELECT * FROM t WHERE n = '" + name + "'")

                class Other:
                    def run(self, name):
                        return sqlite3.connect("x").execute("SELECT * FROM o WHERE n = '" + name + "'")

                class A:
                    def run(self, name):
                        return name

                class B:
                    def run(self, name):
                        return name
            """,
            "app/view.py": """
                from flask import Flask, request
                from app.repo import Repo, Other
                app = Flask(__name__)

                class Service:
                    repos: list[Repo]

                    def __init__(self):
                        self.repos = []
                        self.others: "Sequence[A]" = []  # A modülde içe aktarılmamış: çözülmez

                    def handle(self, name):
                        for repo in self.repos:
                            repo.run(name)
                        for other in self.others:
                            other.run(name)

                @app.route("/q")
                def q():
                    Service().handle(request.args["n"])
                    return "ok"
            """,
        })
        self.assertEqual(flows["app/repo.py"], [("sql", 5)])


class ExternalConstantPrefixTests(unittest.TestCase):
    FILES = {
        "proj/settings.py": """
            import os
            API_BASE = "https://api.example.com/v1/"
            LOGIN_URL = "/accounts/login/"
            SHADOW = "https://shadow.example.com/"
            PARTNER = os.environ.get("PARTNER_URL", "https://p.example.com/")
        """,
        "proj/config.py": """
            class Config:
                UPSTREAM = "https://up.example.com/"
            NO_SLASH = "https://bare.example.com"
        """,
        "proj/views.py": """
            import requests
            from django.conf import settings
            from django.shortcuts import redirect
            from proj import config
            from proj.config import Config

            def a(request):
                return requests.get(settings.API_BASE + request.GET["p"])

            def b(request):
                return requests.get(Config.UPSTREAM + request.GET["p"])

            def c(request):
                return requests.get(f"{config.NO_SLASH}{request.GET['p']}")

            def d(request):
                return requests.get(settings.PARTNER + request.GET["p"])

            def e(request):
                return redirect(settings.LOGIN_URL + "?next=" + request.GET["n"])

            def f(request):
                return requests.get(request.GET["u"] + settings.API_BASE)

            def g(request):
                return requests.get(f"{config.NO_SLASH}/items/{request.GET['p']}")
        """,
    }

    def test_resolved_constant_prefixes(self):
        result = _analyze(self.FILES)["proj/views.py"]
        verified = sorted((f.sink_kind, f.line) for f in result.flows if f.source_label == "request")
        # a, b, e, g güvenli önek; c (eğik çizgisiz ana makine) ve f (girdi önde) bulgu; d ortam değişkeni → belirsiz.
        # a, b, g: ana makine sabit, girdi yolda → ayrı kısmi SSRF sınıfı (12. tur).
        self.assertEqual(verified, [("ssrf", 14), ("ssrf", 23), ("ssrf_partial", 8), ("ssrf_partial", 11), ("ssrf_partial", 26)])

    def test_conflicting_django_settings_are_not_trusted(self):
        files = dict(self.FILES)
        files["proj/settings_prod.py"] = 'API_BASE = "https://other.example.com/"\n'
        result = _analyze(files)["proj/views.py"]
        self.assertIn(("ssrf", 8), sorted((f.sink_kind, f.line) for f in result.flows if f.source_label == "request"))

    def test_env_prefix_is_uncertain_not_verified(self):
        files = {"proj/views.py": """
            import os
            import requests

            def h(request):
                base = os.environ["API"]
                return requests.get(base + request.GET["p"])

            def i(request):
                return requests.get(os.getenv("API") + request.GET["p"])
        """}
        project = tf._PyProject(None, max_steps=200_000)
        import ast
        for k, v in files.items():
            project.add_module(k, ast.parse(_src(v)))
        project.run()
        analysis = project.analysis_for("proj/views.py")
        self.assertEqual([f for f in analysis.flows if f.source_label == "request"], [])
        self.assertEqual(sorted(project.uncertain.get("proj/views.py", set())), [("ssrf", 6), ("ssrf", 9)])


class SameOriginAndQueryTests(unittest.TestCase):
    def test_same_origin_builders(self):
        flows = _flows({"app/views.py": """
            import requests
            from django.shortcuts import redirect

            def a(request):
                return redirect(request.build_absolute_uri("/x/") + request.GET["p"])

            def b(request):
                return redirect(request.scheme + "://" + request.get_host() + "/" + request.GET["p"])

            def c(request):
                return redirect(f"{request.scheme}://{request.get_host()}/{request.GET['p']}")

            def d(request):
                return redirect(request.scheme + "://" + request.GET["h"])

            def e(request):
                u = urlsplit(request.GET["u"])
                return redirect(u.scheme + "://" + u.netloc + "/x")
        """})
        self.assertEqual(flows["app/views.py"], [("redirect", 14), ("redirect", 18)])

    def test_flask_host_url(self):
        flows = _flows({"app/views.py": """
            from flask import Flask, redirect, request
            app = Flask(__name__)

            @app.route("/a")
            def a():
                return redirect(request.host_url + request.args["p"])

            @app.route("/b")
            def b():
                return redirect(request.args["p"])
        """})
        self.assertEqual(flows["app/views.py"], [("redirect", 10)])

    def test_query_part_does_not_choose_destination(self):
        flows = _flows({"app/views.py": """
            from django.shortcuts import redirect
            from django.urls import reverse

            def a(request):
                url = reverse("home")
                return redirect(f"{url}?{request.GET.urlencode()}")

            def b(request):
                return redirect(f"{request.GET['next']}?x=1")

            def c(request):
                return redirect(request.GET["next"] + "#frag")

            def d(request):
                return redirect("/search?q=" + request.GET["q"])
        """})
        self.assertEqual(flows["app/views.py"], [("redirect", 9), ("redirect", 12)])


class ConnexionRequestTests(unittest.TestCase):
    def test_connexion_request_object_forms(self):
        flows = _flows({"api/users.py": """
            import os
            import connexion
            from connexion import request as creq

            def a():
                os.system("echo " + connexion.request.json["x"])

            def b():
                os.system("echo " + creq.args["x"])

            def c():
                os.system("echo " + creq.get_json()["x"])

            def d(config):
                os.system("echo " + config.args["x"])
        """})
        self.assertEqual(flows["api/users.py"], [("command", 6), ("command", 9), ("command", 12)])


class StdlibServerTests(unittest.TestCase):
    def test_http_server_handler_sources(self):
        flows = _flows({"srv/app.py": """
            import os
            import subprocess
            from http.server import BaseHTTPRequestHandler
            from urllib.parse import urlparse, parse_qs

            class Handler(BaseHTTPRequestHandler):
                def do_GET(self):
                    query = parse_qs(urlparse(self.path).query)
                    self.run(query["host"][0])

                def do_POST(self):
                    body = self.rfile.read(int(self.headers["Content-Length"]))
                    subprocess.call("ping " + body.decode(), shell=True)

                def run(self, host):
                    os.system("ping -c1 " + host)

                def unrelated(self):
                    os.system("uptime " + self.server_version)

            class Plain:
                path = "/tmp"

                def go(self):
                    os.system("ls " + self.path)
        """})
        self.assertEqual(flows["srv/app.py"], [("command", 13), ("command", 16)])

    def test_socketserver_and_subclass_chain(self):
        flows = _flows({"srv/tcp.py": """
            import os
            import socketserver

            class Base(socketserver.StreamRequestHandler):
                pass

            class Echo(Base):
                def handle(self):
                    line = self.rfile.readline().strip()
                    os.system("echo " + line.decode())
                    data = self.request.recv(1024)
                    os.system("echo " + data.decode())
        """})
        self.assertEqual(flows["srv/tcp.py"], [("command", 10), ("command", 12)])

    def test_raw_wsgi_environ(self):
        flows = _flows({"srv/wsgi.py": """
            import os

            def application(environ, start_response):
                os.system("echo " + environ["QUERY_STRING"])
                start_response("200 OK", [])
                return [b"ok"]

            def helper(environ, other):
                os.system("echo " + environ["QUERY_STRING"])
        """})
        self.assertEqual(flows["srv/wsgi.py"], [("command", 4)])


if __name__ == "__main__":
    unittest.main()
