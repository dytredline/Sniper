"""Kullanıcı tanımlı taint kuralları (sniper-taint-rules-v1): doğrulama, derleme, saklama, deneme, HTTP."""
import json
import os
import stat
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import server
import taint_models
import taint_rules_dsl as dsl
from storage import Store

RULE = """
format: sniper-taint-rules-v1
name: sirket-db
language: python
description: Şirket içi ham sorgu yardımcısı
sinks:
  - kind: sql
    calls: [sirket.db.ham_sorgu]
    args: [0]
    cwe: CWE-89
    severity: high
sanitizers:
  - calls: [sirket.db.kacis]
    kinds: [sql]
"""

RULE_JSON = json.dumps({
    "format": "sniper-taint-rules-v1", "name": "js-kural", "language": "javascript",
    "sinks": [{"kind": "command", "calls": ["sirket.calistir"], "args": [0]}],
})

CODE = """
import sirket.db
from flask import request

def ara():
    q = request.args.get("q")
    sirket.db.ham_sorgu("SELECT * FROM t WHERE a = " + q)
"""


class DataDirMixin:
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.env = mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": self.temp.name})
        self.env.start()
        os.environ.pop("SNIPER_TAINT_MODELS", None)

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()
        taint_models._load.cache_clear()


class ValidationTests(unittest.TestCase):
    def test_valid_yaml_and_json(self):
        rule = dsl.load_rule_text(RULE)
        self.assertEqual(rule["name"], "sirket-db")
        self.assertEqual(rule["sinks"][0]["calls"], ["sirket.db.ham_sorgu"])
        self.assertEqual(dsl.load_rule_text(RULE_JSON)["language"], "javascript")

    def test_rejections(self):
        bad = [
            "",
            "format: baska\nname: a\nlanguage: python\nsinks: [{kind: sql, calls: [a.b]}]",
            "format: sniper-taint-rules-v1\nname: '../x'\nlanguage: python\nsinks: [{kind: sql, calls: [a.b]}]",
            "format: sniper-taint-rules-v1\nname: a\nlanguage: ruby\nsinks: [{kind: sql, calls: [a.b]}]",
            "format: sniper-taint-rules-v1\nname: a\nlanguage: python\nsinks: [{kind: yok, calls: [a.b]}]",
            "format: sniper-taint-rules-v1\nname: a\nlanguage: python\nsinks: [{kind: sql, calls: ['a; rm -rf /']}]",
            "format: sniper-taint-rules-v1\nname: a\nlanguage: python\nsinks: [{kind: sql, calls: [a.b], kod: x}]",
            "format: sniper-taint-rules-v1\nname: a\nlanguage: python\nbilinmeyen: 1\nsinks: [{kind: sql, calls: [a.b]}]",
            "format: sniper-taint-rules-v1\nname: a\nlanguage: python",
            "!!python/object/apply:os.system ['id']",
            "x" * (dsl.MAX_RULE_BYTES + 1),
        ]
        for text in bad:
            with self.subTest(text=text[:60]):
                with self.assertRaises(dsl.RuleError):
                    dsl.load_rule_text(text)

    def test_compile_models_and_opengrep(self):
        rule = dsl.load_rule_text(RULE)
        clean = {k: v for k, v in rule.items() if not k.startswith("_")}
        models = dsl.compile_models([clean], "python")
        self.assertEqual(models["format"], "sniper-taint-models-v1")
        self.assertIn("sirket.db.ham_sorgu", json.dumps(models))
        self.assertIn("sirket.db.kacis", json.dumps(models))
        og = dsl.compile_opengrep([clean])
        self.assertEqual(len(og["rules"]), 1)
        og_rule = og["rules"][0]
        self.assertEqual(og_rule["mode"], "taint")
        self.assertIn("python", og_rule["languages"])
        self.assertIn("CWE-89", json.dumps(og_rule))
        self.assertTrue(og_rule["pattern-sources"])
        self.assertTrue(og_rule["pattern-sinks"])


class StorageTests(DataDirMixin, unittest.TestCase):
    def test_save_list_delete_with_safe_permissions(self):
        saved = dsl.save_rule(RULE)
        self.assertEqual(saved["name"], "sirket-db")
        directory = Path(self.temp.name) / "custom-rules"
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        compiled = directory / "compiled" / "python-custom.json"
        self.assertTrue(compiled.is_file())
        self.assertEqual(stat.S_IMODE(compiled.stat().st_mode) & 0o077, 0)
        self.assertEqual([r["name"] for r in dsl.list_rules()], ["sirket-db"])
        self.assertEqual(dsl.custom_model_paths(), [str(compiled)])
        status = dsl.status()
        self.assertTrue(status["available"])
        self.assertNotIn(self.temp.name, json.dumps(status))
        self.assertTrue(dsl.delete_rule("sirket-db"))
        self.assertFalse(dsl.delete_rule("sirket-db"))
        self.assertEqual(dsl.list_rules(), [])
        self.assertFalse(compiled.exists())

    def test_rule_count_limit(self):
        with mock.patch.object(dsl, "MAX_RULES", 1):
            dsl.save_rule(RULE)
            dsl.save_rule(RULE)  # aynı adın üzerine yazmak sınırı aşmaz
            with self.assertRaises(dsl.RuleError):
                dsl.save_rule(RULE_JSON)

    def test_unsafe_directory_rejected(self):
        directory = Path(self.temp.name) / "custom-rules"
        directory.mkdir(mode=0o755)
        os.chmod(directory, 0o755)
        with self.assertRaises(dsl.RuleError):
            dsl.save_rule(RULE)
        self.assertFalse(dsl.status()["available"])

    def test_missing_data_dir(self):
        os.environ.pop("SNIPER_DATA_DIR")
        with self.assertRaises(dsl.RuleError):
            dsl.save_rule(RULE)

    def test_try_rule_reports_new_flow_without_saving(self):
        result = dsl.try_rule(RULE, CODE, "ornek.py")
        self.assertTrue(result["analyzed"])
        self.assertTrue(any(f["sink_kind"] == "sql" and f["sink_line"] == 7 for f in result["new_flows"]), result)
        self.assertEqual(dsl.list_rules(), [])
        with self.assertRaises(dsl.RuleError):
            dsl.try_rule(RULE, "   ")

    def test_compiled_model_drives_engine(self):
        dsl.save_rule(RULE)
        with mock.patch.dict(os.environ, {"SNIPER_TAINT_MODELS": os.pathsep.join(dsl.custom_model_paths())}):
            taint_models._load.cache_clear()
            import taint_flow
            analysis = taint_flow.analyze_source(CODE, "ornek.py")
        self.assertTrue(any(f.sink_kind == "sql" for f in analysis.flows))
        safe = CODE.replace('" + q)', '" + sirket.db.kacis(q))')
        with mock.patch.dict(os.environ, {"SNIPER_TAINT_MODELS": os.pathsep.join(dsl.custom_model_paths())}):
            taint_models._load.cache_clear()
            analysis = taint_flow.analyze_source(safe, "ornek.py")
        self.assertFalse(any(f.sink_kind == "sql" for f in analysis.flows))


class TaintRulesApiTests(DataDirMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.previous_store = server.STORE
        self.store = Store(Path(self.temp.name) / "data" / "sniper.db")
        server.STORE = self.store
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        server.STORE = self.previous_store
        super().tearDown()

    def call(self, path, payload=None):
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = Request(self.base + path, data=data, method="GET" if payload is None else "POST",
                          headers={"Content-Type": "application/json"})
        try:
            with urlopen(request, timeout=60) as response:
                return response.status, json.loads(response.read())
        except HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    def test_save_requires_confirmation_and_logs(self):
        status, body = self.call("/api/taint-rules", {"content": RULE})
        self.assertEqual(status, 400)  # 23. tur: eksik onay = 400
        status, body = self.call("/api/taint-rules", {"content": RULE, "confirm_custom_rules": True})
        self.assertEqual(status, 201, body)
        status, listing = self.call("/api/taint-rules")
        self.assertEqual(status, 200)
        self.assertEqual([r["name"] for r in listing["rules"]], ["sirket-db"])
        status, og = self.call("/api/taint-rules/opengrep")
        self.assertEqual(status, 200)
        self.assertEqual(len(og["rules"]), 1)
        status, _ = self.call("/api/taint-rules/sirket-db/delete", {})
        self.assertEqual(status, 400)
        status, _ = self.call("/api/taint-rules/sirket-db/delete", {"confirm_custom_rules": True})
        self.assertEqual(status, 200)
        events = json.dumps(self.store.recent_audit_log(50), ensure_ascii=False)
        self.assertIn("taint_rule.saved", events)
        self.assertIn("taint_rule.deleted", events)

    def test_invalid_rule_and_extra_fields(self):
        status, body = self.call("/api/taint-rules", {"content": "format: x", "confirm_custom_rules": True})
        self.assertEqual(status, 400)
        status, _ = self.call("/api/taint-rules", {"content": RULE, "confirm_custom_rules": True, "path": "/etc"})
        self.assertEqual(status, 400)

    def test_try_route(self):
        status, body = self.call("/api/taint-rules/try", {"content": RULE, "code": CODE, "filename": "a.py"})
        self.assertEqual(status, 200, body)
        self.assertTrue(body["new_flows"])
        status, _ = self.call("/api/taint-rules/try", {"content": RULE, "code": CODE, "extra": 1})
        self.assertEqual(status, 400)


if __name__ == "__main__":
    unittest.main()
