"""7. tur (L): global değişkenler, demet/sözlük dönüşleri, callback'ler, sanal çağrı, bağlam duyarlılığı."""
import textwrap
import unittest

from taint_flow import analyze_python, analyze_python_files


def _src(text):
    return textwrap.dedent(text).lstrip("\n")


def _flows(body):
    return sorted((f.sink_kind, f.line, f.source_label) for f in analyze_python("from flask import request\n" + _src(body)).flows)


class GlobalFlowTests(unittest.TestCase):
    def test_global_written_in_one_function_read_in_another(self):
        self.assertEqual(_flows("""
            import os
            CURRENT = "sabit"
            def use():
                os.system("x " + CURRENT)
            @app.post("/a")
            def store():
                global CURRENT
                CURRENT = request.form["c"]
                return "ok"
        """), [("command", 5, "request")])

    def test_unrelated_local_with_same_name_is_not_global(self):
        self.assertEqual(_flows("""
            import os
            CURRENT = "sabit"
            def use():
                CURRENT = "yerel"
                os.system("x " + CURRENT)
            @app.post("/a")
            def store():
                global CURRENT
                CURRENT = request.form["c"]
        """), [])

    def test_module_container_mutation_and_cross_file_import(self):
        files = {
            "app/__init__.py": "",
            "app/config.py": _src("""
                SETTINGS = {}
                def remember(value):
                    SETTINGS["last"] = value
            """),
            "app/views.py": _src("""
                from flask import request
                from app.config import remember
                @app.post("/a")
                def save():
                    remember(request.form["v"])
            """),
            "app/jobs.py": _src("""
                import os
                from app.config import SETTINGS
                def run():
                    os.system(SETTINGS["last"])
            """),
        }
        results = analyze_python_files(files)
        self.assertEqual([(f.sink_kind, f.line, f.source_file) for f in results["app/jobs.py"].flows],
                         [("command", 4, "app/views.py")])


class ReturnShapeTests(unittest.TestCase):
    def test_tuple_and_dict_returns_are_element_sensitive(self):
        self.assertEqual(_flows("""
            import os
            def parse():
                return request.form["cmd"], "sabit"
            def options():
                return {"query": request.args["q"], "mode": "fast"}
            @app.post("/x")
            def view():
                cmd, mode = parse()
                os.system(mode)
                os.system(cmd)
                opts = options()
                os.system(opts["mode"])
                os.system(opts["query"])
                os.system(parse()[1])
                os.system(parse()[0])
        """), [("command", 11, "request"), ("command", 14, "request"), ("command", 16, "request")])

    def test_inconsistent_shapes_fall_back_to_whole_value(self):
        self.assertEqual(_flows("""
            import os
            def maybe(flag):
                if flag:
                    return request.form["a"], "b"
                return "c"
            @app.post("/x")
            def view():
                a, b = maybe(request.args.get("f"))
                os.system(b)
        """), [("command", 10, "request")])


class CallbackTests(unittest.TestCase):
    def test_map_filter_sorted_lambda_and_partial(self):
        self.assertEqual(_flows("""
            import os, functools, shlex
            def runner(prefix, value):
                os.system(prefix + value)
            @app.post("/x")
            def view():
                items = request.form.getlist("i")
                safe = list(map(shlex.quote, items))
                os.system(" ".join(safe))
                raw = list(map(lambda v: v.strip(), items))
                os.system(" ".join(raw))
                numbers = list(map(int, items))
                os.system(str(numbers))
                clean = lambda v: shlex.quote(v)
                os.system(clean(request.form["c"]))
                go = functools.partial(runner, "ls ")
                go(request.form["d"])
                sorted(items, key=lambda v: os.system(v))
        """), [("command", 4, "request"), ("command", 11, "request"), ("command", 18, "request")])

    def test_generators_async_and_decorated_functions(self):
        self.assertEqual(_flows("""
            import os, functools
            def logged(fn):
                @functools.wraps(fn)
                def wrapper(*args, **kwargs):
                    return fn(*args, **kwargs)
                return wrapper
            @logged
            def execute(cmd):
                os.system(cmd)
            def lines(text):
                for line in text.splitlines():
                    yield line.strip()
            async def fetch(value):
                return value
            @app.post("/x")
            async def view():
                execute(request.form["a"])
                for line in lines(request.form["b"]):
                    os.system(line)
                os.system(await fetch(request.form["c"]))
        """), [("command", 10, "request"), ("command", 20, "request"), ("command", 21, "request")])


class VirtualDispatchTests(unittest.TestCase):
    def test_override_and_super(self):
        self.assertEqual(_flows("""
            import os, shlex
            class Base:
                def prepare(self, value):
                    return shlex.quote(value)
                def run(self, value):
                    os.system("x " + self.prepare(value))
            class Unsafe(Base):
                def prepare(self, value):
                    return value
            class Child(Base):
                def __init__(self, value):
                    super().__init__()
                    self.value = value
                def run(self, value):
                    super().run(value)
            @app.post("/x")
            def view():
                obj = Base()
                obj.run(request.form["a"])
        """), [("command", 7, "request")])

    def test_no_override_keeps_sanitized_base(self):
        self.assertEqual(_flows("""
            import os, shlex
            class Base:
                def prepare(self, value):
                    return shlex.quote(value)
                def run(self, value):
                    os.system("x " + self.prepare(value))
            @app.post("/x")
            def view():
                Base().run(request.form["a"])
        """), [])


class ContextSensitivityTests(unittest.TestCase):
    def test_constant_flag_specializes_summary(self):
        self.assertEqual(_flows("""
            import os, shlex
            def run(cmd, safe):
                if safe:
                    cmd = shlex.quote(cmd)
                os.system("ls " + cmd)
            @app.post("/x")
            def view():
                run(request.form["a"], True)
                run(request.form["b"], safe=True)
            @app.post("/y")
            def other():
                run(request.form["c"], False)
        """), [("command", 6, "request")])

    def test_unknown_flag_uses_generic_summary(self):
        flows = analyze_python("from flask import request\n" + _src("""
            import os, shlex
            def run(cmd, safe):
                if safe:
                    cmd = shlex.quote(cmd)
                os.system("ls " + cmd)
            @app.post("/x")
            def view():
                run(request.form["a"], request.args.get("s"))
        """)).flows
        self.assertEqual([(f.sink_kind, f.line, f.source_line) for f in flows], [("command", 6, 9)])


if __name__ == "__main__":
    unittest.main()


class FalsePositiveRegressionTests(unittest.TestCase):
    """Olgun projelerde (FastAPI, Wagtail, healthchecks) görülen yanlış alarm kalıpları."""

    def test_fastapi_method_routes_return_json(self):
        source = _src("""
            from fastapi import FastAPI, Request
            from fastapi.responses import HTMLResponse
            app = FastAPI()
            @app.get("/items/{name}")
            def item(name: str):
                return {"name": name}
            @app.get("/plain/{name}")
            def plain(name: str):
                return f"Merhaba {name}"
            @app.get("/page/{name}", response_class=HTMLResponse)
            def page(name: str):
                return f"<p>{name}</p>"
        """)
        self.assertEqual(sorted((f.sink_kind, f.line) for f in analyze_python(source).flows), [("html", 12)])

    def test_flask_string_name_return_but_not_unknown_shape(self):
        self.assertEqual(_flows("""
            @app.route("/a")
            def a():
                body = ""
                body += request.args["x"]
                return body
            @app.route("/b")
            def b():
                result = build(request.args["x"])
                return result
        """), [("html", 6, "request")])

    def test_redirect_prefix_rule_validator_kwargs_and_urlencode(self):
        self.assertEqual(_flows("""
            from django.shortcuts import redirect
            from django.urls import reverse
            from django.utils.http import url_has_allowed_host_and_scheme
            def view(request):
                nxt = request.GET.get("next")
                url = reverse("home")
                url += "?" + request.GET.urlencode()
                redirect(url)
                redirect(f"{reverse('home')}?{request.GET['q']}")
                redirect("/pet/" + request.GET["id"])
                redirect("//" + request.GET["host"])
                if nxt and url_has_allowed_host_and_scheme(url=nxt, allowed_hosts={"x"}):
                    redirect(nxt)
                if _allow_redirect(nxt):
                    redirect(nxt)
                redirect(nxt)
        """), [("redirect", 12, "request"), ("redirect", 17, "request")])

    def test_side_effect_call_is_not_reevaluated_for_prefix(self):
        self.assertEqual(_flows("""
            from flask import redirect
            @app.route("/a")
            def a():
                items = []
                items.append("/home")
                items.append(request.args["n"])
                first = items.pop(0)
                second = items.pop(0)
                return redirect(second)
        """), [("redirect", 10, "request")])


class UrlBuilderPrefixTests(unittest.TestCase):
    def test_url_builders_are_clean_but_bare_slash_prefix_is_not(self):
        self.assertEqual(_flows("""
            from django.shortcuts import redirect
            from django.urls import reverse
            def v(request):
                url = reverse("d", kwargs={"pk": request.GET["id"]})
                redirect(f"{url}?{request.GET['q']}")
                redirect(reverse("d", args=(request.GET["id"],)))
                redirect("/" + request.GET["p"])
                redirect("/x/" + request.GET["p"])
        """), [("redirect", 8, "request")])

    def test_autoescaping_template_render_is_html_clean(self):
        self.assertEqual(_flows("""
            from django.utils.safestring import mark_safe
            from django.template.loader import render_to_string
            def v(request):
                html = render_to_string("t.html", {"q": request.GET["q"]})
                mark_safe(html)
                mark_safe("<b>%s</b>" % request.GET["q"])
        """), [("html", 7, "request")])


class IncrementalPassTests(unittest.TestCase):
    """Global yeniden geçişi artımlı: yalnız bayat globale bağlı özetler ve modül kodu yeniden çözümlenir."""

    SOURCE = _src("""
        import os
        from flask import request
        CURRENT = "sabit"
        def helper(x):
            return x.strip()
        def use():
            os.system("x " + helper(CURRENT))
        def unrelated(v):
            os.system(helper(v))
        os.system("modul " + CURRENT)
        @app.post("/a")
        def store():
            global CURRENT
            CURRENT = request.form["c"]
            unrelated("sabit")
            return "ok"
    """)

    def _project(self, incremental=True):
        import ast
        import taint_flow
        project = taint_flow._PyProject(None, max_steps=1_000_000)
        project.add_module("m.py", ast.parse(self.SOURCE))
        reused = []
        original = project._invalidate_stale

        def invalidate():
            before = dict(project.summaries)
            original()
            reused.extend(key for key, summary in project.summaries.items() if before.get(key) is summary)
            if not incremental:
                project.summaries = {}
                project._skip_top_level = set()
        project._invalidate_stale = invalidate
        project.run()
        flows = sorted((f.sink_kind, f.line, f.source_label) for f in project.analysis_for("m.py").flows)
        return project, flows, reused

    def test_incremental_equals_full_and_reuses_independent_summaries(self):
        project, flows, reused = self._project()
        _, full_flows, _ = self._project(incremental=False)
        self.assertEqual(project.passes, 2)
        self.assertEqual(flows, full_flows)
        # Modül düzeyi kod (satır 10) içe aktarımda, store() çağrılmadan önce çalışır: sabit değer.
        self.assertEqual(flows, [("command", 7, "request")])
        module = project.modules["m.py"]
        reused_ids = {key for key in reused if not isinstance(key, tuple)}
        self.assertIn(id(module.functions["helper"]), reused_ids)      # globale bağlı değil: korunur
        self.assertIn(id(module.functions["unrelated"]), reused_ids)
        self.assertNotIn(id(module.functions["use"]), reused_ids)      # CURRENT okuyor: yeniden
