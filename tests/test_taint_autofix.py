"""Doğrulanmış taint akışları için otomatik düzeltme önizlemesi (sniper-autofix-v1)."""
import ast
import json
import os
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import server
import taint_autofix as af
from storage import Store


def added(result):
    return [line[1:] for line in result["diff"].splitlines() if line.startswith("+") and not line.startswith("+++")]


def removed(result):
    return [line[1:] for line in result["diff"].splitlines() if line.startswith("-") and not line.startswith("---")]


def patched(original, result):
    """Tek parçalı farkı uygula ve sonucun geçerli Python olduğunu doğrulamak için metni döndür."""
    out, src = [], original.splitlines()
    lines = result["diff"].splitlines()[2:]
    header = lines[0]
    start = int(header.split()[1].split(",")[0].lstrip("-")) - 1
    out.extend(src[:start])
    pos = start
    for line in lines[1:]:
        if line.startswith("@@"):
            raise AssertionError("tek parça bekleniyordu")
        if line.startswith("+"):
            out.append(line[1:])
        elif line.startswith("-"):
            pos += 1
        else:
            out.append(src[pos]); pos += 1
    out.extend(src[pos:])
    return "\n".join(out) + "\n"


class PythonFixTests(unittest.TestCase):
    def check(self, code, line, kind):
        result = af.suggest_for_source(code, "app.py", line, kind)
        self.assertEqual(result["format"], "sniper-autofix-v1")
        self.assertFalse(result["applied"])
        self.assertEqual(result["mode"], "diff", result)
        ast.parse(patched(code, result))
        return result

    def test_sql_fstring_assigned_query(self):
        code = "import sqlite3\ndef f(cur, q):\n    sql = f\"SELECT * FROM u WHERE name = '{q}' AND x = {q}\"\n    cur.execute(sql)\n"
        r = self.check(code, 4, "sql")
        self.assertIn("    sql = 'SELECT * FROM u WHERE name = ? AND x = ?'", added(r))
        self.assertIn("    sql_params = (q, q)", added(r))
        self.assertIn("    cur.execute(sql, sql_params)", added(r))

    def test_sql_concat_inline(self):
        code = "def f(cur, q):\n    cur.execute(\"SELECT * FROM t WHERE a = \" + q)\n"
        r = self.check(code, 2, "sql")
        # sqlite3 içe aktarılmadığında DB-API "format" yer tutucusu (%s) kullanılır
        self.assertIn("    cur.execute('SELECT * FROM t WHERE a = %s', (q,))", added(r))

    def test_command_to_argv(self):
        code = "import os\ndef f(q):\n    os.system(f\"convert {q} out.png\")\n"
        r = self.check(code, 3, "command")
        self.assertIn("import subprocess", added(r))
        self.assertIn("    subprocess.run(['convert', q, 'out.png'], check=False)", added(r))
        self.assertEqual(r["strategy"]["cwe"], "CWE-78")

    def test_path_guard_keeps_with_statement(self):
        code = "import os\ndef f(name):\n    with open(os.path.join('/srv/up', name)) as fh:  # oku\n        return fh.read()\n"
        r = self.check(code, 3, "path")
        joined = "\n".join(added(r))
        self.assertIn("commonpath", joined)
        self.assertIn("realpath", joined)
        self.assertTrue(any("# oku" in line for line in added(r)))

    def test_weak_random(self):
        code = "import random\ndef token():\n    return random.getrandbits(32)\n"
        r = self.check(code, 3, "weakrand")
        self.assertIn("    return secrets.randbits(32)", added(r))

    def test_html_escape(self):
        code = "def f(n):\n    return '<b>' + n + '</b>'\n"
        r = self.check(code, 2, "html")
        self.assertTrue(any("html.escape(n)" in line for line in added(r)), r["diff"])

    def test_text_mode_when_no_safe_transform(self):
        r = af.suggest_for_source("def f(x):\n    exec(x)\n", "app.py", 2, "eval")
        self.assertIn(r["mode"], {"diff", "text"})
        if r["mode"] == "text":
            self.assertTrue(r["snippet"])

    def test_line_mismatch_falls_back_to_text(self):
        r = af.suggest_for_source("x = 1\n", "app.py", 1, "sql")
        self.assertEqual(r["mode"], "text")
        self.assertTrue(r["snippet"])

    def test_unknown_kind_rejected(self):
        with self.assertRaises(af.AutofixError):
            af.suggest_for_source("x = 1\n", "app.py", 1, "yok-boyle-tur")


class JavascriptFixTests(unittest.TestCase):
    def fix(self, code, line, kind):
        r = af.suggest_for_source(code, "app.js", line, kind)
        self.assertEqual(r["mode"], "diff", r)
        self.assertEqual(r["language"], "javascript")
        return r

    def test_sql_template(self):
        code = "app.get('/u', (req, res) => {\n  db.query(`SELECT * FROM u WHERE n = '${req.query.n}' AND id = ${req.query.id}`);\n});\n"
        r = self.fix(code, 2, "sql")
        self.assertIn("  db.query('SELECT * FROM u WHERE n = ? AND id = ?', [req.query.n, req.query.id]);", added(r))

    def test_exec_to_execfile(self):
        code = "const { exec } = require('child_process');\napp.get('/c', (req) => {\n  exec(`convert ${req.query.f} out.png`);\n});\n"
        r = self.fix(code, 3, "command")
        self.assertTrue(any("execFile('convert', [req.query.f, 'out.png'])" in line for line in added(r)), r["diff"])

    def test_inner_html_to_text_content(self):
        code = "function f(v) {\n  el.innerHTML = v;\n}\n"
        r = self.fix(code, 2, "html")
        self.assertIn("  el.textContent = v;", added(r))
        self.assertIn("  el.innerHTML = v;", removed(r))

    def test_redirect_guard_lines_are_separate(self):
        code = "app.get('/r', (req, res) => {\n  res.redirect(req.query.next);\n});\n"
        r = self.fix(code, 2, "redirect")
        self.assertGreater(len(added(r)), 1)
        self.assertTrue(all("\n" not in line for line in added(r)))


class FindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.root = Path(self.temp.name) / "proje"
        (self.root / "pkg").mkdir(parents=True)
        (self.root / "pkg" / "app.py").write_text("import os\ndef f(q):\n    os.system('ls ' + q)\n", encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def audit(self, **finding):
        base = {"title": "Komut enjeksiyonu", "file": "pkg/app.py", "line": 3, "reference": "CWE-78",
                "taint_flow": {"sink_kind": "command", "sink_line": 3, "source": "q", "source_line": 2}}
        base.update(finding)
        return {"project_path": str(self.root), "findings": [base]}

    def test_suggest_for_finding(self):
        r = af.suggest_for_finding(self.audit(), 0)
        self.assertEqual(r["finding_index"], 0)
        self.assertEqual(r["sink_kind"], "command")
        self.assertIn("subprocess.run", r["diff"])
        self.assertEqual((self.root / "pkg" / "app.py").read_text(encoding="utf-8").count("os.system"), 1)

    def test_kind_from_cwe_without_flow(self):
        r = af.suggest_for_finding(self.audit(taint_flow=None, reference="CWE-78"), 0)
        self.assertEqual(r["sink_kind"], "command")

    def test_path_safety(self):
        for bad in ("../disari.py", "/etc/passwd", "pkg/../../x.py", ""):
            with self.subTest(file=bad):
                with self.assertRaises(af.AutofixError):
                    af.suggest_for_finding(self.audit(file=bad), 0)
        outside = Path(self.temp.name) / "gizli.py"
        outside.write_text("x = 1\n", encoding="utf-8")
        os.symlink(outside, self.root / "pkg" / "bag.py")
        with self.assertRaises(af.AutofixError):
            af.suggest_for_finding(self.audit(file="pkg/bag.py"), 0)
        os.symlink(Path(self.temp.name), self.root / "dizinbag")
        with self.assertRaises(af.AutofixError):
            af.suggest_for_finding(self.audit(file="dizinbag/gizli.py"), 0)

    def test_index_and_kind_errors(self):
        with self.assertRaises(af.AutofixError):
            af.suggest_for_finding(self.audit(), 1)
        with self.assertRaises(af.AutofixError):
            af.suggest_for_finding(self.audit(taint_flow=None, reference="CWE-1"), 0)
        with self.assertRaises(af.AutofixError):
            af.suggest_for_finding({"project_path": "/etc", "findings": self.audit()["findings"]}, 0)


class AutofixApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        root = Path(self.temp.name) / "proje"
        root.mkdir()
        (root / "app.py").write_text("import os\ndef f(q):\n    os.system('ls ' + q)\n", encoding="utf-8")
        self.previous_store = server.STORE
        self.store = Store(Path(self.temp.name) / "data" / "sniper.db")
        server.STORE = self.store
        audit = self.store.create_project_audit({
            "created_at": "2026-10-19T00:00:00Z", "project_path": str(root), "project_name": "proje",
            "score": 50, "grade": "C", "file_count": 1, "bytes_scanned": 60,
            "findings": [
                {"title": "Komut", "severity": "high", "file": "app.py", "line": 3, "reference": "CWE-78",
                 "taint_flow": {"sink_kind": "command", "sink_line": 3, "source": "q", "source_line": 2}},
                {"title": "Bilgi", "severity": "info", "file": "app.py", "line": 1, "reference": "CWE-1"},
            ],
        })
        self.audit_id = audit["id"]
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
        self.temp.cleanup()

    def post(self, path, payload=None):
        request = Request(self.base + path, data=json.dumps(payload or {}).encode("utf-8"), method="POST",
                          headers={"Content-Type": "application/json"})
        try:
            with urlopen(request, timeout=10) as response:
                return response.status, json.loads(response.read())
        except HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    def test_route(self):
        status, body = self.post(f"/api/project-audits/{self.audit_id}/findings/0/autofix")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["mode"], "diff")
        self.assertIn("subprocess.run", body["diff"])
        self.assertFalse(body["applied"])
        self.assertEqual(self.post(f"/api/project-audits/{self.audit_id}/findings/1/autofix")[0], 400)
        self.assertEqual(self.post(f"/api/project-audits/{self.audit_id}/findings/9/autofix")[0], 400)
        self.assertEqual(self.post(f"/api/project-audits/{self.audit_id}/findings/01/autofix")[0], 400)
        self.assertEqual(self.post(f"/api/project-audits/{self.audit_id}/findings/0/autofix", {"x": 1})[0], 400)
        self.assertEqual(self.post("/api/project-audits/prj_yok/findings/0/autofix")[0], 404)


if __name__ == "__main__":
    unittest.main()
