"""Yalnız değişenler (git): değişen dosya kümesi, yeni/düzelen bulgu karşılaştırması, satır kaymasına dayanıklılık,
güvenilmez depo yapılandırmasının çalıştırılmaması, SARIF, CLI eşiği ve API."""
from __future__ import annotations

import io
import json
import os
from contextlib import redirect_stdout
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock
import urllib.error
import urllib.request

from http.server import ThreadingHTTPServer

import changed_scan
import project_analyzer
from project_audit_diff import render_project_audit_sarif
import scan_scope

GIT = shutil.which("git")

SAFE = 'from flask import Flask, request\nimport os\napp = Flask(__name__)\n\n@app.route("/a")\ndef a():\n    return "ok"\n'
VULN_LINE = '    os.system("ping " + request.args["h"])\n'
VULN = SAFE.replace('    return "ok"\n', VULN_LINE + '    return "ok"\n')


def _git(cwd: Path, *args: str) -> str:
    env = {"PATH": "/usr/bin:/bin", "HOME": str(cwd), "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
           "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
    return subprocess.run([GIT, "-C", str(cwd), *args], check=True, capture_output=True, text=True, env=env).stdout


@unittest.skipUnless(GIT, "git yok")
class ChangedScanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.repo = self.base / "repo"
        self.repo.mkdir()
        _git(self.repo, "init", "-q")
        (self.repo / "app.py").write_text(SAFE)
        (self.repo / "util.py").write_text("def helper(x):\n    return x\n")
        (self.repo / ".gitignore").write_text("ignored_*.py\n")
        _git(self.repo, "add", ".")
        _git(self.repo, "commit", "-qm", "base")

    def scan(self, base_ref="HEAD", root=None):
        root = root or self.repo
        return project_analyzer.analyze_project(
            str(root), allowed_roots=(self.base,), scope=scan_scope.parse_scope({"changed_only": True, "base_ref": base_ref}))

    def test_scope_validation(self):
        for bad in ({"changed_only": True}, {"changed_only": True, "base_ref": "--output=x"},
                    {"changed_only": True, "base_ref": "a..b"}, {"changed_only": True, "base_ref": "a;b"}):
            with self.subTest(bad=bad), self.assertRaises(scan_scope.ScopeError):
                scan_scope.parse_scope(bad)
        self.assertEqual(scan_scope.parse_scope({"changed_only": True, "base_ref": "origin/main"}).base_ref, "origin/main")

    def test_new_vulnerability_in_working_tree(self):
        (self.repo / "app.py").write_text(VULN)
        result = self.scan()
        cs = result["changed_scan"]
        self.assertEqual(cs["changed_files"], ["app.py"])
        self.assertTrue(cs["compared"])
        self.assertGreaterEqual(cs["new_findings"], 1)
        new = [f for f in result["findings"] if f["is_new"]]
        self.assertTrue(new and all(f["file"] == "app.py" and f["in_changed_lines"] for f in new))
        self.assertTrue(all(f["context_fingerprint"] for f in result["findings"]))

    def test_line_shift_is_not_new_and_fix_is_reported(self):
        (self.repo / "app.py").write_text(VULN)
        _git(self.repo, "commit", "-qam", "vuln")
        (self.repo / "app.py").write_text("# yorum\n# yorum\n" + VULN)  # yalnız satır kayması
        shifted = self.scan()
        self.assertEqual(shifted["changed_scan"]["new_findings"], 0)
        self.assertTrue(shifted["findings"])
        self.assertTrue(all(not f["in_changed_lines"] for f in shifted["findings"]))
        (self.repo / "app.py").write_text(SAFE)  # düzeltme
        fixed = self.scan()
        self.assertEqual(fixed["changed_scan"]["new_findings"], 0)
        self.assertGreaterEqual(fixed["changed_scan"]["fixed_count"], 1)

    def test_no_changes_rename_ignored_and_deleted(self):
        result = self.scan()
        self.assertEqual(result["changed_scan"]["changed_files"], [])
        self.assertEqual(result["findings"], [])
        _git(self.repo, "mv", "util.py", "helpers.py")
        (self.repo / "ignored_local.py").write_text(VULN)
        (self.repo / "app.py").unlink()
        result = self.scan()
        cs = result["changed_scan"]
        self.assertEqual(cs["changed_files"], [])
        self.assertEqual(cs["renamed_count"], 1)
        self.assertEqual(cs["deleted_count"], 1)

    def test_commit_ref_and_subdirectory_project(self):
        sub = self.repo / "svc"
        sub.mkdir()
        (sub / "main.py").write_text(SAFE)
        _git(self.repo, "add", ".")
        _git(self.repo, "commit", "-qm", "svc")
        (sub / "main.py").write_text(VULN)
        _git(self.repo, "commit", "-qam", "vuln svc")
        (self.repo / "app.py").write_text(VULN)  # proje (svc) dışında: sayılmaz
        result = self.scan("HEAD~1", root=sub)
        self.assertEqual(result["changed_scan"]["changed_files"], ["main.py"])
        self.assertGreaterEqual(result["changed_scan"]["new_findings"], 1)

    def test_cross_file_flow_into_changed_helper(self):
        # Kaynak değişmeyen rota dosyasında, havuz değişen yardımcıda: bağlam (geri kapanış) akışı korumalı.
        (self.repo / "routes.py").write_text(
            "from flask import Flask, request\nfrom svc import run\napp = Flask(__name__)\n\n"
            "@app.route('/r')\ndef r():\n    return run(request.args['h'])\n")
        (self.repo / "svc.py").write_text("def run(h):\n    return h\n")
        (self.repo / "unrelated.py").write_text("X = 1\n")
        _git(self.repo, "add", ".")
        _git(self.repo, "commit", "-qm", "routes")
        (self.repo / "svc.py").write_text("import os\n\ndef run(h):\n    return os.system('ping ' + h)\n")
        result = self.scan()
        self.assertEqual(result["changed_scan"]["changed_files"], ["svc.py"])
        self.assertNotEqual(result["changed_scan"]["context_files"], "tüm proje")
        flows = [f for f in result["findings"] if f["file"] == "svc.py" and f.get("taint_flow") and f["is_new"]]
        self.assertTrue(flows, result["findings"])
        context = changed_scan.import_context(self.repo, {"svc.py"}, scan_scope.DEFAULT_SCOPE)
        self.assertEqual(sorted(context), ["routes.py", "svc.py"])

    def test_errors(self):
        with self.assertRaises(changed_scan.ChangedScanError):
            self.scan("yok-boyle-dal")
        plain = self.base / "plain"
        plain.mkdir()
        (plain / "a.py").write_text(SAFE)
        with self.assertRaises(changed_scan.ChangedScanError):
            self.scan("HEAD", root=plain)

    def test_untrusted_repo_config_is_not_executed(self):
        marker = self.base / "PWNED"
        (self.repo / ".gitattributes").write_text("* filter=evil diff=evil\n")
        _git(self.repo, "add", ".gitattributes")
        _git(self.repo, "commit", "-qm", "attrs")
        for key, value in (("filter.evil.clean", f"touch {marker}.clean; cat"), ("filter.evil.smudge", f"touch {marker}.smudge; cat"),
                           ("diff.evil.textconv", f"touch {marker}.textconv; cat"), ("core.fsmonitor", f"touch {marker}.fsmonitor"),
                           ("core.hooksPath", str(self.base))):
            _git(self.repo, "config", key, value)
        (self.repo / "app.py").write_text(VULN)
        self.scan()
        self.assertEqual(sorted(p.name for p in self.base.iterdir() if p.name.startswith("PWNED")), [])

    def test_sarif_baseline_state(self):
        (self.repo / "app.py").write_text(VULN)
        sarif = render_project_audit_sarif(self.scan())
        results = sarif["runs"][0]["results"]
        self.assertTrue(results)
        self.assertTrue(all(r["baselineState"] == "new" and r["partialFingerprints"]["sniperContext/v1"] for r in results))

    def test_cli_gate_exit_code(self):
        import cli_reports

        db = self.base / "cli.db"
        out = self.base / "out.sarif"
        argv = ["cli_reports.py", "auto-scan", str(self.repo), "--changed-since", "HEAD", "--fail-on", "high",
                "--sarif", str(out), "--db", str(db)]
        (self.repo / "app.py").write_text(VULN)
        with mock.patch.object(project_analyzer, "_allowed_roots", return_value=(self.base,)), \
                mock.patch.object(sys, "argv", argv), redirect_stdout(io.StringIO()) as printed:
            with self.assertRaises(SystemExit) as caught:
                cli_reports.main()
        self.assertEqual(caught.exception.code, 1)
        self.assertIn("BAŞARISIZ", printed.getvalue())
        self.assertEqual(json.loads(out.read_text())["version"], "2.1.0")
        (self.repo / "app.py").write_text(SAFE)
        with mock.patch.object(project_analyzer, "_allowed_roots", return_value=(self.base,)), \
                mock.patch.object(sys, "argv", argv + ["--no-store"]), redirect_stdout(io.StringIO()) as printed:
            cli_reports.main()  # yeni bulgu yok → çıkış yok
        self.assertIn("GEÇTİ", printed.getvalue())


@unittest.skipUnless(GIT, "git yok")
class ChangedScanApiTests(unittest.TestCase):
    def setUp(self):
        import server
        from storage import Store

        self.server = server
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.data_dir = base / "data"
        self.data_dir.mkdir()
        self.repo = base / "repo"
        self.repo.mkdir()
        _git(self.repo, "init", "-q")
        (self.repo / "app.py").write_text(SAFE)
        _git(self.repo, "add", ".")
        _git(self.repo, "commit", "-qm", "base")
        self.previous_store = server.STORE
        server.STORE = Store(self.data_dir / "sniper-test.db")
        for patch in (mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(self.data_dir)}),
                      mock.patch.object(project_analyzer, "_allowed_roots", return_value=(base,))):
            patch.start()
            self.addCleanup(patch.stop)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base_url = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.server.STORE = self.previous_store

    def call(self, path, body):
        request = urllib.request.Request(self.base_url + path, method="POST", data=json.dumps(body).encode(),
                                         headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    def test_git_and_audit_bases(self):
        status, first = self.call("/api/project-audits", {"project_path": str(self.repo)})
        self.assertEqual(status, 201, first)
        (self.repo / "app.py").write_text(VULN)
        status, changed = self.call("/api/project-audits", {"project_path": str(self.repo),
                                                            "scope": {"changed_only": True, "base_ref": "HEAD"}})
        self.assertEqual(status, 201, changed)
        self.assertGreaterEqual(changed["changed_scan"]["new_findings"], 1)
        self.assertTrue(any(f.get("is_new") for f in changed["findings"]))
        status, vs_audit = self.call("/api/project-audits", {"project_path": str(self.repo),
                                                             "scope": {"changed_only": True, "base_ref": first["id"]}})
        self.assertEqual(status, 201, vs_audit)
        self.assertEqual(vs_audit["changed_scan"]["mode"], "audit")
        self.assertGreaterEqual(vs_audit["changed_scan"]["new_findings"], 1)
        self.assertEqual(self.call("/api/project-audits", {"project_path": str(self.repo),
                                                           "scope": {"changed_only": True, "base_ref": "prj_yok"}})[0], 404)
        self.assertEqual(self.call("/api/project-audits", {"project_path": str(self.repo),
                                                           "scope": {"changed_only": True, "base_ref": "olmayan"}})[0], 400)
        self.assertEqual(self.call("/api/scan-scope", {"confirm": True, "scope": {"changed_only": True, "base_ref": "HEAD"}})[0], 400)


if __name__ == "__main__":
    unittest.main()
