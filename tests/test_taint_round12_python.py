"""12. tur Python taint: CodeQL karşılaştırmasında görülen boşluklar.

* Django ``HttpResponse`` / aiohttp ``web.Response(content_type="text/html")`` / Flask ``add_url_rule`` görünümü XSS;
* Falcon kaynak sınıfı yanıtlayıcıları (``on_get(self, req, resp)``) ve HTML ``resp.text``;
* iş parçacığı / yürütücü hedefleri (``Thread(target=f, args=…)``, ``ex.submit(f, …)``);
* kısmi SSRF (sabit ana makine; ayrı ``ssrf_partial`` sınıfı) ve modül düzeyi ``urllib3.PoolManager``;
* üçüncü taraf HTTP yanıtı ikinci derece kaynağı (``remote`` etiketi).
"""
from pathlib import Path
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import project_analyzer  # noqa: E402
import taint_flow as tf  # noqa: E402


def _src(text):
    return textwrap.dedent(text).lstrip("\n")


def _flows(text, label="request"):
    results = tf._analyze_python_files_uncached({"m.py": _src(text)}, None, frozenset())
    return sorted((f.sink_kind, f.line) for f in results["m.py"].flows if label is None or f.source_label == label)


class DjangoAiohttpXssTests(unittest.TestCase):
    def test_django_http_response_reflects_request(self):
        self.assertEqual(_flows("""
            from django.http import HttpResponse, HttpResponseBadRequest, JsonResponse
            from django.utils.html import escape
            import json

            def a(request):
                q = request.GET.get("q", "")
                return HttpResponse("<p>" + q + "</p>")

            def b(request):
                return HttpResponseBadRequest(f"bad {request.POST['x']}")

            def c(request):
                q = request.GET["q"]
                return HttpResponse(f"<p>{escape(q)}</p>")

            def d(request):
                q = request.GET["q"]
                return HttpResponse(json.dumps({"q": q}), content_type="application/json")

            def e(request):
                q = request.GET["q"]
                return HttpResponse(q, "text/plain")

            def f(request):
                return JsonResponse({"q": request.GET["q"]})

            def g(request):
                html = "<ul>"
                html += "<li>" + request.GET["i"] + "</li>"
                return HttpResponse(content=html)
        """), [("html", 7), ("html", 10), ("html", 30)])

    def test_aiohttp_response_only_with_html_content_type(self):
        self.assertEqual(_flows("""
            from aiohttp import web

            async def h1(request):
                q = request.query.get("q", "")
                return web.Response(text="<p>" + q + "</p>", content_type="text/html")

            async def h2(request):
                q = request.query.get("q", "")
                return web.Response(text=q)

            async def h3(request):
                data = await request.post()
                return web.Response(body=data["x"], content_type="text/html")
        """), [("html", 5), ("html", 13)])

    def test_flask_add_url_rule_view_returns_html(self):
        self.assertEqual(_flows("""
            from flask import Blueprint, request

            bp = Blueprint("b", __name__)

            def gen(name):
                def _view():
                    template = open(name + ".html").read()
                    template += "<p>" + request.args.get("u", "") + "</p>"
                    return template
                bp.add_url_rule("/x", "x", _view)

            def other():
                return "<b>" + request.args["a"] + "</b>"

            def helper():
                return "<b>" + request.args["a"] + "</b>"

            bp.add_url_rule("/o", view_func=other)
        """), [("html", 9), ("html", 13)])


class FalconTests(unittest.TestCase):
    def test_responder_sources_and_html_body(self):
        self.assertEqual(_flows("""
            import os
            import falcon

            class Thing:
                def on_get(self, req, resp, item_id):
                    os.system("echo " + (req.get_param("q") or ""))
                    os.system("ls " + item_id)

                def on_post_upload(self, req, resp):
                    os.system("x " + req.media["cmd"])
                    resp.content_type = falcon.MEDIA_HTML
                    resp.text = "<p>" + req.get_header("X-A") + "</p>"

                def on_put(self, req, resp):
                    resp.text = "<p>" + req.get_param("a") + "</p>"
        """), [("command", 6), ("command", 7), ("command", 10), ("html", 12)])

    def test_non_falcon_module_is_not_entry(self):
        self.assertEqual(_flows("""
            import os

            class Thing:
                def on_get(self, req, resp):
                    os.system(req.get_param("q"))
        """), [])


class ThreadTargetTests(unittest.TestCase):
    def test_thread_timer_and_executor_targets(self):
        self.assertEqual(_flows("""
            import os, threading
            from concurrent.futures import ThreadPoolExecutor
            from flask import Flask, request
            app = Flask(__name__)

            def work(cmd):
                os.system("echo " + cmd)

            def work2(a, b):
                os.system(b)

            @app.route("/a")
            def a():
                threading.Thread(target=work, args=(request.args["x"],)).start()
                return "ok"

            @app.route("/b")
            def b():
                with ThreadPoolExecutor() as ex:
                    ex.submit(work2, "sabit", request.args["y"])
                return "ok"

            @app.route("/d")
            def d():
                threading.Thread(target=work, args=("sabit",)).start()
                return "ok"
        """), [("command", 7), ("command", 10)])


class PartialSsrfTests(unittest.TestCase):
    SOURCE = """
        import json, requests, urllib3
        from flask import Flask, request
        app = Flask(__name__)
        HTTP = urllib3.PoolManager()

        def get_list(email):
            url = "https://mail.example.com/api/?login={}&domain={}".format(email.split("@")[0], email.split("@")[1])
            return json.loads(HTTP.request("GET", url).data)

        @app.route("/a")
        def a():
            return str(get_list(request.args["e"]))

        @app.route("/b")
        def b():
            return requests.get("https://api.example.com/users/" + request.args["id"]).text

        @app.route("/c")
        def c():
            return requests.get(request.args["url"]).text

        @app.route("/e")
        def e():
            return requests.get("https://api.example.com/x?id=%d" % int(request.args["n"])).text

        def lambda_handler(event, context):
            return HTTP.request("GET", "https://x.example.com/v?q=" + event["q"]).status
    """

    def test_partial_is_separate_from_full_ssrf(self):
        self.assertEqual(_flows(self.SOURCE), [("ssrf", 20), ("ssrf_partial", 8), ("ssrf_partial", 16), ("ssrf_partial", 27)])

    def test_partial_reported_low_in_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "proj"
            root.mkdir()
            (root / "app.py").write_text(_src(self.SOURCE))
            findings = project_analyzer.analyze_project(str(root), allowed_roots=(root.parent,))["findings"]
        partial = [f for f in findings if (f.get("taint_flow") or {}).get("sink_kind") == "ssrf_partial"]
        full = [f for f in findings if (f.get("taint_flow") or {}).get("sink_kind") == "ssrf"]
        self.assertEqual(sorted(f["line"] for f in partial), [8, 16, 27])
        self.assertTrue(all(f["severity"] == "low" and "kısmi SSRF" in f["title"] for f in partial))
        self.assertEqual([(f["line"], f["severity"]) for f in full], [(20, "high")])


class RemoteSourceTests(unittest.TestCase):
    SOURCE = """
        import os, pickle, requests, urllib.request, httpx

        def a():
            r = requests.get("https://api.example.com/cmd")
            os.system("run " + r.text)

        def b():
            os.system(requests.get("https://api.example.com/x").json()["cmd"])

        def c():
            pickle.loads(urllib.request.urlopen("https://x.example.com").read())

        def d(conn):
            r = httpx.get("https://x.example.com")
            conn.execute("select * from t where a='" + r.json()["a"] + "'")

        def e():
            return "<p>" + requests.get("https://api.example.com/x").text
    """

    def test_http_response_is_remote_source(self):
        self.assertEqual(_flows(self.SOURCE, "remote"), [("command", 5), ("command", 8), ("deserialize", 11), ("sql", 15)])
        self.assertEqual(_flows(self.SOURCE, "request"), [])

    def test_remote_flows_are_low_and_limited_to_execution_sinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "proj"
            root.mkdir()
            (root / "jobs.py").write_text(_src(self.SOURCE))
            findings = project_analyzer.analyze_project(str(root), allowed_roots=(root.parent,))["findings"]
        remote = [f for f in findings if (f.get("taint_flow") or {}).get("source_label") == "remote"]
        self.assertEqual(sorted(f["line"] for f in remote), [5, 8, 11, 15])
        self.assertTrue(all(f["severity"] == "low" and "üçüncü taraf HTTP yanıtı" in f["title"] for f in remote))


if __name__ == "__main__":
    unittest.main()
