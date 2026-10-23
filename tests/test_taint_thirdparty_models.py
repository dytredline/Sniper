"""Üçüncü taraf modelleri (typeshed stubs/ → rules/taint/python-thirdparty.json) ve alıcı türü izleme."""
import importlib.util
import tempfile
import textwrap
import unittest
from pathlib import Path

import taint_models
from taint_flow import analyze_python

APP = Path(__file__).resolve().parents[1]


def _flows(body):
    source = "from flask import request\n" + textwrap.dedent(body).lstrip("\n")
    return sorted((f.sink_kind, f.line) for f in analyze_python(source).flows)


def _generator():
    spec = importlib.util.spec_from_file_location("generate_taint_models", APP / "scripts" / "generate_taint_models.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ThirdPartyModelFileTests(unittest.TestCase):
    def test_model_file_loaded_and_allowlist_only(self):
        models = taint_models.models_for("python")
        self.assertEqual(models.errors, [])
        self.assertEqual(models.class_of("requests.Session"), "requests.sessions.Session")
        self.assertEqual(models.class_of("paramiko.SSHClient"), "paramiko.client.SSHClient")
        self.assertTrue(models.propagates("six.ensure_str"))
        kinds = {m.kind for m in models.sinks_for("requests.sessions.Session.get")}
        self.assertEqual(kinds, {"ssrf"})
        # Dize döndüren her metot hedef değildir: yalnız elle doğrulanmış liste.
        self.assertEqual(models.sinks_for("requests.sessions.Session.prepare_request"), [])
        self.assertEqual(models.sinks_for("markdown.markdown"), [])
        self.assertEqual(models.sanitizer_kinds("psycopg2.sql.Literal"), frozenset({"sql"}))


class ReceiverTypeTests(unittest.TestCase):
    def test_typed_receivers_hit_curated_sinks(self):
        self.assertEqual(_flows("""
            import requests, paramiko, peewee
            from pexpect import spawn
            @app.route("/a")
            def a():
                u = request.args["u"]
                s = requests.Session()
                s.get(u)
                with requests.Session() as s2:
                    s2.post(url=u)
                paramiko.SSHClient().exec_command("ls " + u)
                db = peewee.SqliteDatabase("x.db")
                db.execute_sql("SELECT " + u)
                spawn("ssh " + u)
                return "ok"
        """), [("command", 11), ("command", 14), ("sql", 13), ("ssrf", 8), ("ssrf", 10)])

    def test_untyped_or_constant_or_sanitized_are_clean(self):
        self.assertEqual(_flows("""
            import requests, six, pymysql
            from psycopg2 import sql
            @app.route("/a")
            def a():
                u = request.args["u"]
                requests.Session().get("https://sabit.example/")
                other = Other()
                other.get(u)
                s = requests.Session()
                s = Other()
                s.get(u)
                cur.execute(sql.SQL("SELECT {}").format(sql.Literal(u)))
                cur.execute("SELECT '%s'" % pymysql.converters.escape_string(u))
                return "ok"
        """), [])

    def test_thirdparty_propagator_keeps_taint(self):
        self.assertEqual(_flows("""
            import os, six
            @app.route("/a")
            def a():
                os.system(six.ensure_str(request.args["u"]))
                return "ok"
        """), [("command", 5)])


class GeneratorTests(unittest.TestCase):
    def _stubs(self, files):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name) / "stubs"
        for rel, text in files.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(textwrap.dedent(text))
        return _generator()._Stubs(root)

    def test_reexport_inheritance_and_returns(self):
        stubs = self._stubs({
            "paket/paket/__init__.pyi": "from .oturum import Oturum as Oturum, oturum as oturum\nfrom ._ic import gizli\n",
            "paket/paket/oturum.pyi": """
                from typing_extensions import Self
                class Taban:
                    def al(self, url: str) -> str: ...
                class Oturum(Taban):
                    def __enter__(self) -> Self: ...
                    def imleç(self) -> Imlec: ...
                class Imlec:
                    def yurut(self, sorgu: str) -> None: ...
                def oturum() -> Oturum: ...
            """,
            "paket/paket/_ic.pyi": "def gizli(x: str) -> str: ...\n",
            "paket/@tests/x.pyi": "def test_disi(x: str) -> str: ...\n",
        })
        self.assertEqual(stubs.canonical("paket.Oturum"), "paket.oturum.Oturum")
        self.assertEqual(stubs.canonical("paket.Oturum.al"), "paket.oturum.Oturum.al")
        self.assertTrue(stubs.exists("paket.Oturum.al"))          # kalıtılmış metot
        self.assertFalse(stubs.exists("paket.Oturum.yok"))
        self.assertEqual(stubs.method_owner("paket.oturum.Oturum", "al"), "paket.oturum.Taban")
        self.assertIn("paket.Oturum", stubs.aliases()["paket.oturum.Oturum"])
        module = stubs.module_of["paket.oturum.oturum"]
        self.assertEqual(stubs.return_class(module, [stubs.functions["paket.oturum.oturum"]], None), "paket.oturum.Oturum")
        self.assertEqual(stubs.return_class(module, stubs.methods["paket.oturum.Oturum.__enter__"], "paket.oturum.Oturum"),
                         "paket.oturum.Oturum")
        self.assertNotIn("x.test_disi", stubs.functions)

    def test_propagator_rule_excludes_sanitizer_like_names(self):
        gen = _generator()
        import ast
        tree = ast.parse("def birlestir(a: str, b: str) -> str: ...\ndef escape_html(a: str) -> str: ...\n"
                         "def uzunluk(a: str) -> int: ...\n")
        result = [gen._is_propagator(node) for node in tree.body]
        self.assertEqual(result, [True, False, False])


if __name__ == "__main__":
    unittest.main()
