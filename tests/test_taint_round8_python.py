"""8. tur (Python taint): parametreye bağlı önek özetleri, tip açıklamasından alıcı türü ve
büyük proje performansı (sonuçlar birebir aynı kalmalı)."""
import ast
import gc
import textwrap
import unittest

import taint_flow
import taint_models
from taint_flow import analyze_python, analyze_python_files


def _flows(body, header="from flask import request, redirect\nimport requests\n"):
    source = header + textwrap.dedent(body).lstrip("\n")
    return sorted((f.sink_kind, f.line, f.source_line) for f in analyze_python(source).flows)


def _structure(node):
    """Alanların (konum öznitelikleri hariç) karşılaştırılabilir gösterimi."""
    if isinstance(node, list):
        return [_structure(item) for item in node]
    if not isinstance(node, ast.AST):
        return node
    return (type(node).__name__, getattr(node, "lineno", None),
            tuple((name, _structure(getattr(node, name, None))) for name in node._fields))


class ParameterPrefixTests(unittest.TestCase):
    def test_helper_returning_safe_prefix_is_clean(self):
        self.assertEqual(_flows("""
            def build(p):
                return "/app/" + p
            def build2(p):
                url = f"/app/{p}"
                return url
            def unsafe(p):
                return p
            @app.get("/x")
            def view():
                target = build(request.args["n"])
                redirect(target)
                redirect(build2(request.args["n"]))
                redirect(unsafe(request.args["n"]))
        """), [("redirect", 15, 15)])

    def test_caller_supplied_prefix_for_returned_value(self):
        self.assertEqual(_flows("""
            def join(base, p):
                return base + p
            @app.get("/x")
            def view():
                redirect(join("/app/", request.args["n"]))
                redirect(join(request.args["b"], "/x"))
                redirect(join("//", request.args["c"]))
        """), [("redirect", 8, 8), ("redirect", 9, 9)])

    def test_sink_inside_callee_uses_call_site_prefix(self):
        flows = _flows("""
            def go(base, p):
                return redirect(base + p)
            @app.get("/x")
            def view():
                go("/app/", request.args["a"])
                go("https://example.com/", request.args["b"])
            @app.get("/y")
            def other():
                go("/", request.args["c"])
        """)
        # Yalnız "/" önekli çağrı ("/" + "/evil.com" → "//evil.com") raporlanır.
        self.assertEqual(flows, [("redirect", 4, 11)])

    def test_ssrf_fixed_host_through_parameter_and_helper(self):
        self.assertEqual(_flows("""
            def fetch(base, path):
                return requests.get(base + path)
            def api(path):
                return "https://api.example.com/v1/" + path
            def relative(path):
                return "/v1/" + path
            @app.get("/x")
            def view():
                fetch("https://api.example.com/", request.args["p"])
                requests.get(api(request.args["q"]))
                requests.get(relative(request.args["r"]))
                fetch(request.args["h"], "/x")
        """), [("ssrf", 4, 14), ("ssrf", 13, 13), ("ssrf_partial", 4, 11), ("ssrf_partial", 12, 12)])  # sabit ana makine: kısmi SSRF

    def test_default_values_and_chained_parameters(self):
        self.assertEqual(_flows("""
            def go(p, base="/home/"):
                return redirect(base + p)
            def mid(prefix, q):
                return go(q, prefix)
            @app.get("/x")
            def view():
                go(request.args["n"])
                mid("/ok/", request.args["m"])
                mid(request.args["h"], "z")
        """), [("redirect", 4, 11)])

    def test_branches_keep_prefix_only_when_all_agree(self):
        self.assertEqual(_flows("""
            def go(base, p):
                if p:
                    url = base + p
                else:
                    url = p
                return redirect(url)
            def go2(base, p):
                if p:
                    url = base + p
                else:
                    url = base + "/"
                return redirect(url)
            def go3(base, p):
                for item in p:
                    base = item
                return redirect(base + "x")
            @app.get("/x")
            def view():
                go("/app/", request.args["n"])
                go2("/app/", request.args["n"])
                go3("/app/", request.args["n"])
        """), [("redirect", 8, 21), ("redirect", 18, 23)])


class AnnotationTypeTests(unittest.TestCase):
    def test_request_annotation_marks_request_root_not_whole_object(self):
        self.assertEqual(_flows("""
            from fastapi import FastAPI, Request
            import os
            app = FastAPI()
            @app.get("/x")
            async def ep(r: Request, q: str):
                body = await r.json()
                os.system(r.query_params["c"])
                eval(body)
                os.system(str(r.app))
                os.system(q)
            def helper(rq: "Request"):
                os.system(rq.headers.get("x"))
            def outbound(rq: requests.Request):
                os.system(rq.url)
            def plain(x: str):
                os.system(x)
        """), [("command", 9, 9), ("command", 12, 7), ("command", 14, 14), ("eval", 10, 8)])

    def test_optional_union_string_and_container_annotations(self):
        header = "from flask import request\nfrom typing import Optional, Union\n"
        self.assertEqual(_flows("""
            class Repo:
                def find(self, q):
                    cursor.execute("select " + q)
            class A:
                def find(self, q): return 1
            class B:
                def find(self, q): return 1
            class C:
                def find(self, q): return 1
            def use(r1: Optional[Repo], r2: "Repo", r3: Repo | None, r4: Union[Repo, None], items: list[Repo], r5: A | Repo):
                r1.find(request.args["a"])
                r2.find(request.args["b"])
                r3.find(request.args["c"])
                r4.find(request.args["d"])
                for it in items:
                    it.find(request.args["e"])
                r5.find(request.args["f"])
        """, header), [("sql", 5, 13), ("sql", 5, 14), ("sql", 5, 15), ("sql", 5, 16), ("sql", 5, 18)])

    def test_dataclass_fields_and_external_models(self):
        header = "from dataclasses import dataclass\nimport requests\nfrom flask import request\n"
        self.assertEqual(_flows("""
            class Repo:
                def find(self, q):
                    cursor.execute("select " + q)
            class A:
                def find(self, q): return 1
            class B:
                def find(self, q): return 1
            class C:
                def find(self, q): return 1
            @dataclass
            class Svc:
                repo: Repo
                http: requests.Session
                def go(self, q):
                    self.repo.find(q)
                    self.http.get(q)
            class Holder:
                def __init__(self):
                    self.client: "requests.Session" = make()
                def run(self, u):
                    self.client.post(u)
            def handler(svc: Svc, h: Holder):
                svc.go(request.args["q"])
                svc.repo.find(request.args["z"])
                h.run(request.args["u"])
        """, header), [("sql", 6, 26), ("sql", 6, 27), ("ssrf", 19, 26), ("ssrf", 24, 28)])

    def test_return_annotations_give_receiver_and_element_types(self):
        header = "import requests\nfrom flask import request\n"
        self.assertEqual(_flows("""
            def session() -> requests.Session:
                return build()
            def sessions() -> "list[requests.Session]":
                return []
            def count() -> int:
                return 1
            @app.get("/x")
            def view():
                s = session()
                s.get(request.args["u"])
                for t in sessions():
                    t.get(request.args["w"])
                n = count()
                n.get(request.args["v"])
        """, header), [("ssrf", 12, 12), ("ssrf", 14, 14)])

    def test_annotation_parser(self):
        cases = {
            "Optional[x.Y]": (False, "x.Y"), "'Cursor'": (False, "Cursor"), "A | None": (False, "A"),
            "Union[None, A]": (False, "A"), "Annotated[A, 1]": (False, "A"), "list[A]": (True, "A"),
            "Sequence['A']": (True, "A"), "tuple[A, ...]": (True, "A"), "tuple[A, B]": None, "A | B": None,
            "dict[str, A]": None, "list[list[A]]": None, "'('": None,
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(taint_flow._annotation_target(ast.parse(text, mode="eval").body), expected)


class PerformanceEquivalenceTests(unittest.TestCase):
    SOURCE = textwrap.dedent("""
        import os
        from flask import request
        class Base:
            def run(self, x: "str | None" = None, *a, k=1, **kw):
                '''belge'''
                return [i for i in x if i] or {k: v for k, v in kw.items()}
        async def f(r):
            async with r as s:
                match s:
                    case {"a": 1} | [2, *_]:
                        pass
                try:
                    os.system(request.args["c"])
                except* ValueError:
                    raise
        lam = lambda q: q + 1
    """)

    def test_slim_tree_preserves_structure_types_and_lines(self):
        original = ast.parse(self.SOURCE)
        slim = taint_flow._slim_tree(ast.parse(self.SOURCE), {})
        self.assertEqual(_structure(slim), _structure(original))
        for a, b in zip(ast.walk(original), ast.walk(slim)):
            self.assertIsInstance(b, type(a))
            self.assertEqual(type(a).__name__, type(b).__name__)
            self.assertEqual(getattr(a, "lineno", None), getattr(b, "lineno", None))
            if type(a)._fields or type(a)._attributes:
                self.assertFalse(hasattr(b, "__dict__") and b.__dict__)
        self.assertEqual(taint_flow._walk_statements.__name__, "_walk_statements")
        statements = [type(n).__name__ for n in ast.walk(original) if isinstance(n, (ast.stmt, ast.excepthandler, ast.match_case))]
        walked = [type(n).__name__ for n in taint_flow._walk_statements(original) if not isinstance(n, ast.Module)]
        self.assertEqual(walked, statements)

    def test_project_results_identical_and_gc_state_restored(self):
        files = {"app/a.py": self.SOURCE, "app/b.py": "from app.a import Base\nimport os\nfrom flask import request\n"
                 "def g():\n    os.system(request.form['x'])\n    Base().run(request.args['y'])\n"}
        enabled = gc.isenabled()
        frozen = gc.get_freeze_count()
        result = taint_flow._analyze_python_files_uncached(files, None)
        self.assertEqual(gc.isenabled(), enabled)
        self.assertEqual(gc.get_freeze_count(), frozen)
        for relpath, text in files.items():
            single = analyze_python(text, filename=relpath)
            if relpath == "app/a.py":
                self.assertEqual(sorted((f.sink_kind, f.line) for f in result[relpath].flows),
                                 sorted((f.sink_kind, f.line) for f in single.flows))
        self.assertEqual(sorted((f.sink_kind, f.line) for f in result["app/b.py"].flows), [("command", 5)])
        self.assertIsNotNone(analyze_python_files(files))

    def test_wildcard_propagator_index_matches_linear_scan(self):
        models = taint_models.LanguageModels(propagators=frozenset({"pkg.sub.*", "solo.*", "exact.name", ".*"}))
        names = ["pkg.sub.f", "pkg.sub.deep.f", "pkg.subx.f", "pkg.f", "solo.f", "solo", "exact.name",
                 "exact.name.x", ".hidden", "x.y", "", "pkg.sub."]
        for name in names:
            linear = bool(name) and (name in models.propagators or any(
                e.endswith(".*") and name.startswith(e[:-1]) for e in models.propagators))
            self.assertEqual(models.propagates(name), linear, name)
        models.propagators = frozenset({"other.*"})
        self.assertTrue(models.propagates("other.x"))
        self.assertFalse(models.propagates("solo.f"))


if __name__ == "__main__":
    unittest.main()
