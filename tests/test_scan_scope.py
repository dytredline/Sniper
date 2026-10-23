"""Tarama kapsamı: varsayılan atlanan dizin/dosyaları isteğe bağlı dahil etme, "yalnız atlananlar" modu,
kalıcı varsayılan kapsam ve API."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock
import urllib.error
import urllib.request

from http.server import ThreadingHTTPServer

import project_analyzer
from project_analyzer import ProjectRejected, analyze_project
import scan_scope
import taint_flow

VULN = 'import os\nfrom flask import request\n\ndef run():\n    os.system("ping " + request.args["h"])\n'


class ScopeParsingTests(unittest.TestCase):
    def test_default_matches_previous_skip_list(self):
        self.assertEqual(len(scan_scope.DEFAULT_SKIP_DIRS), 26)
        self.assertIn("node_modules", project_analyzer.SKIP_DIRS)
        self.assertEqual(frozenset(project_analyzer.SKIP_DIRS), scan_scope.DEFAULT_SKIP_DIRS)
        self.assertIs(scan_scope.parse_scope(None), scan_scope.DEFAULT_SCOPE)

    def test_skip_dirs_view_follows_context(self):
        scope = scan_scope.parse_scope({"include_dirs": ["tests", "packages"]})
        with scan_scope.scan_scope(scope):
            self.assertNotIn("tests", project_analyzer.SKIP_DIRS)
            self.assertNotIn("node_modules", project_analyzer.SKIP_DIRS)
            self.assertIn(".git", project_analyzer.SKIP_DIRS)
            self.assertIn("vendor", frozenset(project_analyzer.SKIP_DIRS))
            self.assertNotIn("tests", project_analyzer.SKIP_DIRS | {"x"})
        self.assertIn("tests", project_analyzer.SKIP_DIRS)

    def test_presets_and_validation(self):
        full = scan_scope.parse_scope({"preset": "all"})
        self.assertEqual(full.public()["max_file_mb"], 20)
        self.assertFalse(full.skipped_only)
        self.assertTrue(scan_scope.parse_scope({"preset": "skipped"}).skipped_only)
        self.assertEqual(scan_scope.parse_scope({"preset": "all", "include_dirs": ["tests"]}).include_dirs, {"tests"})
        for bad in ({"include_dirs": ["etc"]}, {"max_file_mb": 0}, {"max_file_mb": 21}, {"include_generated": 1},
                    {"preset": "x"}, {"unknown": True}, []):
            with self.subTest(bad=bad), self.assertRaises(scan_scope.ScopeError):
                scan_scope.parse_scope(bad)

    def test_persisted_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = {"SNIPER_DATA_DIR": tmp}
            self.assertTrue(scan_scope.load_default(env).is_default)
            saved = scan_scope.save_default(scan_scope.parse_scope({"include_dirs": ["vendor"], "max_total_mb": 500}), env)
            loaded = scan_scope.load_default(env)
            self.assertEqual(loaded, saved)
            self.assertEqual(os.stat(Path(tmp) / scan_scope.FILE_NAME).st_mode & 0o777, 0o600)
            (Path(tmp) / scan_scope.FILE_NAME).write_text("{bozuk")
            self.assertTrue(scan_scope.load_default(env).is_default)


class ProjectScopeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "proj"
        (self.root / "tests").mkdir(parents=True)
        (self.root / "node_modules" / "lib").mkdir(parents=True)
        (self.root / "app.py").write_text(VULN)
        (self.root / "tests" / "test_app.py").write_text(VULN)
        (self.root / "node_modules" / "lib" / "index.js").write_text("module.exports = 1;\n")
        (self.root / "jquery.min.js").write_text("var a=1;")
        (self.root / "latin.py").write_bytes("s = 'café'\n".encode("latin-1"))

    def analyze(self, scope=None, **kwargs):
        return analyze_project(str(self.root), allowed_roots=(self.root.parent,), scope=scope, **kwargs)

    def files(self, result):
        return sorted({f["file"] for f in result["findings"]})

    def test_default_scope_unchanged_and_reports_skipped_dirs(self):
        result = self.analyze()
        self.assertEqual(result["file_count"], 1)
        self.assertEqual(result["skipped_files"]["dir_tests"], 1)
        self.assertEqual(result["skipped_files"]["dir_packages"], 1)
        self.assertTrue(any("test dizini atlandı" in w for w in result["warnings"]))
        self.assertTrue(result["scope"]["include_dirs"] == [] and not result["scope"]["skipped_only"])

    def test_include_everything(self):
        result = self.analyze(scan_scope.parse_scope({"preset": "all"}))
        self.assertEqual(result["file_count"], 5)
        self.assertIn("tests/test_app.py", self.files(result))
        self.assertEqual(result["skipped_files"].get("decoded_lossy"), 1)
        self.assertNotIn("generated", result["skipped_files"])
        self.assertTrue(any("Test dizinleri dahil edildi" in w for w in result["warnings"]))

    def test_skipped_only_scans_just_the_rest(self):
        normal = self.analyze()
        rest = self.analyze(scan_scope.parse_scope({"preset": "skipped"}))
        self.assertEqual(normal["file_count"] + rest["file_count"], 5)
        self.assertEqual(rest["skipped_files"]["already_scanned"], 1)
        self.assertNotIn("app.py", self.files(rest))
        self.assertIn("tests/test_app.py", self.files(rest))
        self.assertTrue(rest["scope"]["skipped_only"])
        self.assertTrue(rest["warnings"][0].startswith("Yalnız atlananlar modu"))

    def test_skipped_only_disables_absence_checks(self):
        (self.root / "tests" / "test_app.py").write_text("import hashlib\npassword = hashlib.md5(b'x')\nlogin = 1\n")
        rest = self.analyze(scan_scope.parse_scope({"preset": "skipped"}))
        titles = " ".join(f["title"] for f in rest["findings"] if not f["file"])
        self.assertNotIn("yok", titles.casefold())

    def test_skipped_only_with_nothing_left(self):
        for path in (self.root / "tests" / "test_app.py", self.root / "node_modules" / "lib" / "index.js",
                     self.root / "jquery.min.js", self.root / "latin.py"):
            path.unlink()
        with self.assertRaises(ProjectRejected) as caught:
            self.analyze(scan_scope.parse_scope({"preset": "skipped"}))
        self.assertIn("Normal taramanın dışında kalan dosya yok", str(caught.exception))

    def test_large_file_limit_option(self):
        (self.root / "big.py").write_text("x = 1\n" * 200_000)
        self.assertEqual(self.analyze()["skipped_files"]["large"], 1)
        result = self.analyze(scan_scope.parse_scope({"max_file_mb": 5}))
        self.assertNotIn("large", result["skipped_files"])

    def test_file_count_limit_can_be_raised(self):
        scope = scan_scope.parse_scope({"preset": "all", "max_files": 20_000})
        self.assertEqual(self.analyze(scope, max_files=20_000)["file_count"], 5)
        with self.assertRaises(ProjectRejected):
            self.analyze(max_files=20_000)  # varsayılan kapsamda üst sınır 10.000

    def test_taint_walk_follows_scope(self):
        roots = []
        with scan_scope.scan_scope(scan_scope.parse_scope({"preset": "skipped"})):
            roots = [p.relative_to(self.root).as_posix() for p in taint_flow._walk_project_files(
                self.root, frozenset(project_analyzer.SKIP_DIRS), taint_flow.PY_SUFFIXES)]
        self.assertEqual(roots, ["tests/test_app.py"])


class ScanScopeApiTests(unittest.TestCase):
    def setUp(self):
        import server
        from storage import Store

        self.server = server
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.data_dir = base / "data"
        self.data_dir.mkdir()
        self.root = base / "proj"
        (self.root / "tests").mkdir(parents=True)
        (self.root / "app.py").write_text(VULN)
        (self.root / "tests" / "test_app.py").write_text(VULN)
        self.previous_store = server.STORE
        server.STORE = Store(self.data_dir / "sniper-test.db")
        patches = [
            mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(self.data_dir)}),
            mock.patch.object(project_analyzer, "_allowed_roots", return_value=(base,)),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base_url = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.server.STORE = self.previous_store

    def call(self, path, body=None):
        request = urllib.request.Request(
            self.base_url + path, method="POST" if body is not None else "GET",
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Content-Type": "application/json"} if body is not None else {},
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    def test_default_scope_round_trip_and_audit_modes(self):
        status, data = self.call("/api/scan-scope")
        self.assertEqual(status, 200)
        self.assertTrue(data["is_default"])
        self.assertIn("tests", data["dir_groups"])

        status, normal = self.call("/api/project-audits", {"project_path": str(self.root)})
        self.assertEqual(status, 201, normal)
        self.assertEqual(normal["file_count"], 1)

        status, rest = self.call("/api/project-audits", {"project_path": str(self.root), "scope": {"preset": "skipped"},
                                                         "base_audit_id": normal["id"]})
        self.assertEqual(status, 201, rest)
        self.assertEqual(rest["file_count"], 1)
        detail = self.call(f"/api/project-audits/{rest['id']}")[1]
        self.assertEqual(detail["base_audit_id"], normal["id"])
        self.assertTrue(detail["scope"]["skipped_only"])

        # Kalıcı varsayılan: testler dahil → kapsamsız istek de testleri tarar.
        self.assertEqual(self.call("/api/scan-scope", {"scope": {"include_dirs": ["tests"]}})[0], 400)  # onaysız
        self.assertEqual(self.call("/api/scan-scope", {"confirm": True, "scope": {"preset": "skipped"}})[0], 400)
        status, saved = self.call("/api/scan-scope", {"confirm": True, "scope": {"include_dirs": ["tests"]}})
        self.assertEqual(status, 200, saved)
        self.assertFalse(saved["is_default"])
        status, widened = self.call("/api/project-audits", {"project_path": str(self.root)})
        self.assertEqual(widened["file_count"], 2)
        self.assertEqual(self.call("/api/project-audits", {"project_path": str(self.root), "scope": {"include_dirs": ["x"]}})[0], 400)
        self.assertEqual(self.call("/api/project-audits", {"project_path": str(self.root), "base_audit_id": "prj_yok"})[0], 404)


if __name__ == "__main__":
    unittest.main()
