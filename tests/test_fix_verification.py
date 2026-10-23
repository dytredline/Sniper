"""Düzeltme doğrulama ve toplu düzeltme: yama geçici kopyada uygulanır, aynı motorla yeniden analiz edilir;
kullanıcının projesine hiçbir şey yazılmaz."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import textwrap
import threading
import unittest
from unittest import mock
import urllib.error
import urllib.request

from http.server import ThreadingHTTPServer

import fix_verification as fv
import project_analyzer
import taint_autofix

_REAL_COMPUTE_FIX = taint_autofix.compute_fix

APP = textwrap.dedent('''
    import os, sqlite3
    from flask import Flask, request
    app = Flask(__name__)
    BASE = "/srv/files"

    @app.route("/user")
    def user():
        db = sqlite3.connect("x.db")
        name = request.args["name"]
        return str(db.execute("SELECT * FROM users WHERE name = '%s'" % name).fetchall())

    @app.route("/ping")
    def ping():
        host = request.args["host"]
        os.system("ping -c 1 " + host)
        return "ok"

    @app.route("/hello")
    def hello():
        return "<p>Merhaba " + request.args["q"] + "</p>"

    @app.route("/file")
    def file():
        with open(os.path.join(BASE, request.args["f"])) as handle:
            return handle.read()

    @app.route("/user2")
    def user2():
        db = sqlite3.connect("x.db")
        uid = request.args["id"]
        return str(db.execute("SELECT * FROM users WHERE id = " + uid).fetchall())
''').lstrip()

OTHER = textwrap.dedent('''
    import sqlite3
    from flask import Blueprint, request
    bp = Blueprint("b", __name__)

    @bp.route("/search")
    def search():
        db = sqlite3.connect("x.db")
        term = request.args["t"]
        return str(db.execute("SELECT * FROM items WHERE name LIKE '%" + term + "%'").fetchall())
''').lstrip()


def _tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_file():
            digest.update(str(path.relative_to(root)).encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()


class FixVerificationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / "proj"
        self.root.mkdir()
        (self.root / "app.py").write_text(APP)
        (self.root / "other.py").write_text(OTHER)
        self.work = self.base / "work"
        self.work.mkdir()
        self.audit = project_analyzer.analyze_project(str(self.root), allowed_roots=(self.base,))
        self.audit["id"] = "prj_test"
        self.before = _tree_digest(self.root)

    def tearDown(self):
        # Proje dosyalarına yazılmadı, geçici doğrulama dizinleri silindi.
        self.assertEqual(_tree_digest(self.root), self.before)
        self.assertEqual(list(self.work.iterdir()), [])

    def index_of(self, sink_kind, line=None, file="app.py"):
        for index, finding in enumerate(self.audit["findings"]):
            flow = finding.get("taint_flow") or {}
            if finding["file"] == file and flow.get("sink_kind") == sink_kind and (line is None or finding["line"] == line):
                return index
        self.fail(f"{sink_kind} bulgusu yok")

    def verify(self, index):
        return fv.verify_finding_fix(self.audit, index, allowed_roots=(self.base,), work_root=str(self.work))

    def test_sql_command_xss_fixes_are_verified(self):
        for kind in ("sql", "command", "html"):
            with self.subTest(kind=kind):
                result = self.verify(self.index_of(kind, line=10 if kind == "sql" else None))
                self.assertEqual(result["verdict"], "verified", result["reasons"])
                self.assertTrue(result["targets"][0]["closed"])
                self.assertEqual(result["new_findings"], [])
                self.assertTrue(result["parse"]["app.py"]["ok"])
                self.assertTrue(result["diff"].startswith("--- a/app.py\n+++ b/app.py\n"))
                self.assertFalse(result["applied_to_project"])

    def test_path_guard_is_partial_with_manual_review(self):
        result = self.verify(self.index_of("path"))
        self.assertEqual(result["verdict"], "partial")
        self.assertTrue(result["targets"][0].get("guarded"))
        self.assertIn("commonpath", result["diff"])
        self.assertTrue(any("elle gözden geçirme" in reason for reason in result["reasons"]))

    def test_syntax_breaking_patch_fails(self):
        index = self.index_of("sql", line=10)

        def broken(text, relpath, line, kind, *, flow=None):
            suggestion, _ = _REAL_COMPUTE_FIX(text, relpath, line, kind, flow=flow)
            return suggestion, text.replace("def user():", "def user(:")

        with mock.patch.object(fv.ta, "compute_fix", side_effect=broken):
            result = self.verify(index)
        self.assertEqual(result["verdict"], "failed")
        self.assertFalse(result["parse"]["app.py"]["ok"])
        self.assertIn("sözdizimi", " ".join(result["reasons"]))

    def test_patch_that_introduces_new_vulnerability_is_partial(self):
        index = self.index_of("sql", line=10)

        def evil(text, relpath, line, kind, *, flow=None):
            suggestion, fixed = _REAL_COMPUTE_FIX(text, relpath, line, kind, flow=flow)
            return suggestion, fixed.replace('    name = request.args["name"]\n',
                                             '    name = request.args["name"]\n    eval(request.args["code"])\n')

        with mock.patch.object(fv.ta, "compute_fix", side_effect=evil):
            result = self.verify(index)
        self.assertEqual(result["verdict"], "partial")
        self.assertTrue(result["targets"][0]["closed"])
        self.assertTrue(any("CWE-95" in str(item.get("reference")) or "CWE-94" in str(item.get("reference"))
                            for item in result["new_findings"]), result["new_findings"])

    def test_no_automatic_patch_is_reported(self):
        with mock.patch.object(fv.ta, "compute_fix", return_value=({"snippet": "örnek", "strategy": {}}, None)):
            result = self.verify(self.index_of("sql", line=10))
        self.assertEqual(result["verdict"], "failed")
        self.assertEqual(result["snippet"], "örnek")
        self.assertEqual(result["diff"], "")

    def test_bulk_fix_groups_and_closes_all(self):
        groups = fv.fix_groups(self.audit)
        group = next(g for g in groups if g["key"].startswith("sql|CWE-89|execute"))
        self.assertEqual(group["count"], 3)
        self.assertEqual(group["files"], ["app.py", "other.py"])
        result = fv.verify_bulk_fix(self.audit, group=group["key"], allowed_roots=(self.base,), work_root=str(self.work))
        self.assertEqual(result["verdict"], "verified", result["reasons"])
        self.assertEqual(sorted(result["closed_indices"]), sorted(group["indices"]))
        self.assertEqual(result["files"], ["app.py", "other.py"])
        self.assertEqual(result["diff"].count("--- a/"), 2)
        self.assertEqual(result["diff"].count("+++ b/app.py"), 1)

    def test_bulk_validation(self):
        with self.assertRaises(fv.AutofixError):
            fv.verify_bulk_fix(self.audit, group="yok", allowed_roots=(self.base,), work_root=str(self.work))
        with self.assertRaises(fv.AutofixError):
            fv.verify_bulk_fix(self.audit, indices=[True], allowed_roots=(self.base,), work_root=str(self.work))
        with self.assertRaises(fv.AutofixError):
            fv.verify_bulk_fix(self.audit, indices=list(range(fv.MAX_BULK_FINDINGS + 1)), allowed_roots=(self.base,),
                               work_root=str(self.work))

    def test_patch_download_and_line_map(self):
        patch = fv.patch_for_finding(self.audit, self.index_of("sql", line=10), allowed_roots=(self.base,))
        self.assertIn("(name,)", patch)
        mapper = fv.line_map("a\nb\nc\n", "x\na\nB\nc\n")
        self.assertEqual(mapper(1), (2, 2))
        self.assertEqual(mapper(2), (3, 3))
        self.assertEqual(mapper(3), (4, 4))

    def test_busy_slots(self):
        acquired = [fv._SLOTS.acquire(blocking=False) for _ in range(2)]
        try:
            self.assertTrue(all(acquired))
            with self.assertRaises(fv.VerificationBusy):
                self.verify(self.index_of("sql", line=10))
        finally:
            for ok in acquired:
                if ok:
                    fv._SLOTS.release()


@unittest.skipUnless(__import__("taint_js_ast").available(), "Node/Babel köprüsü yok")
class JsFixVerificationTests(unittest.TestCase):
    def test_js_sql_fix_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "proj"
            root.mkdir()
            (root / "server.js").write_text(textwrap.dedent('''
                const express = require("express");
                const mysql = require("mysql");
                const app = express();
                const db = mysql.createConnection({});
                app.get("/u", (req, res) => {
                  db.query("SELECT * FROM users WHERE id = " + req.query.id, (err, rows) => res.json(rows));
                });
            ''').lstrip())
            audit = project_analyzer.analyze_project(str(root), allowed_roots=(base,))
            audit["id"] = "prj_js"
            index = next(i for i, f in enumerate(audit["findings"]) if (f.get("taint_flow") or {}).get("sink_kind") == "sql")
            result = fv.verify_finding_fix(audit, index, allowed_roots=(base,))
            self.assertEqual(result["verdict"], "verified", result["reasons"])
            self.assertEqual(result["parse"]["server.js"]["checker"], "babel")


class FixVerificationApiTests(unittest.TestCase):
    def setUp(self):
        import server
        from storage import Store

        self.server = server
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        data = base / "data"
        data.mkdir()
        root = base / "proj"
        root.mkdir()
        (root / "app.py").write_text(APP)
        (root / "other.py").write_text(OTHER)
        patches = [mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(data)}),
                   mock.patch.object(project_analyzer, "_allowed_roots", return_value=(base,))]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.previous_store = server.STORE
        server.STORE = Store(data / "sniper-test.db")
        self.audit = server.STORE.create_project_audit(project_analyzer.analyze_project(str(root)))
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base_url = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.server.STORE = self.previous_store

    def call(self, path, body=None, raw=False):
        request = urllib.request.Request(self.base_url + path, method="POST" if body is not None else "GET",
                                         data=json.dumps(body).encode() if body is not None else None,
                                         headers={"Content-Type": "application/json"} if body is not None else {})
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                payload = response.read()
                return response.status, (payload.decode() if raw else json.loads(payload)), response.headers
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}"), exc.headers

    def test_endpoints(self):
        audit_id = self.audit["id"]
        detail = self.call(f"/api/project-audits/{audit_id}")[1]
        sql = next(i for i, f in enumerate(detail["findings"])
                   if (f.get("taint_flow") or {}).get("sink_kind") == "sql" and f["file"] == "app.py")

        status, result, _ = self.call(f"/api/project-audits/{audit_id}/findings/{sql}/autofix/verify", {})
        self.assertEqual(status, 200, result)
        self.assertEqual(result["verdict"], "verified")
        self.assertEqual(self.call(f"/api/project-audits/{audit_id}/findings/{sql}/autofix/verify", {"x": 1})[0], 400)
        self.assertEqual(self.call(f"/api/project-audits/{audit_id}/findings/-1/autofix/verify", {})[0], 400)
        self.assertEqual(self.call(f"/api/project-audits/{audit_id}/findings/999/autofix/verify", {})[0], 400)
        self.assertEqual(self.call(f"/api/project-audits/prj_yok/findings/0/autofix/verify", {})[0], 404)

        status, patch, headers = self.call(f"/api/project-audits/{audit_id}/findings/{sql}/autofix.patch", raw=True)
        self.assertEqual(status, 200)
        self.assertTrue(patch.startswith("--- a/app.py"))
        self.assertIn("attachment", headers["Content-Disposition"])

        status, groups, _ = self.call(f"/api/project-audits/{audit_id}/autofix-groups")
        self.assertEqual(status, 200)
        key = next(g["key"] for g in groups["groups"] if g["key"].startswith("sql|CWE-89|execute"))
        status, bulk, _ = self.call(f"/api/project-audits/{audit_id}/autofix/bulk", {"group": key})
        self.assertEqual(status, 200, bulk)
        self.assertEqual(bulk["verdict"], "verified")
        self.assertEqual(len(bulk["closed_indices"]), 3)
        self.assertEqual(self.call(f"/api/project-audits/{audit_id}/autofix/bulk", {"group": key, "indices": [0]})[0], 400)
        self.assertEqual(self.call(f"/api/project-audits/{audit_id}/autofix/bulk", {})[0], 400)

        acquired = [fv._SLOTS.acquire(blocking=False) for _ in range(2)]
        try:
            self.assertEqual(self.call(f"/api/project-audits/{audit_id}/findings/{sql}/autofix/verify", {})[0], 429)
        finally:
            for ok in acquired:
                if ok:
                    fv._SLOTS.release()

        log = [row["action"] for row in self.server.STORE.list_audit_log(limit=50)] if hasattr(self.server.STORE, "list_audit_log") else []
        if log:
            self.assertIn("autofix.verified", log)
            self.assertIn("autofix.bulk_verified", log)


if __name__ == "__main__":
    unittest.main()
