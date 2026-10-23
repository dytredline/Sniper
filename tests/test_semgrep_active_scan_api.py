import hashlib
import json
import os
import stat
import tempfile
import unittest
from tests.pin_helpers import pin_env
from http.server import ThreadingHTTPServer
from pathlib import Path
import threading
from unittest.mock import patch
from urllib.request import Request, urlopen
from urllib.error import HTTPError

import server
from storage import Store


class SemgrepActiveScanApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.base = Path(self.temp.name)
        self.previous_store = server.STORE
        server.STORE = Store(self.base / "data" / "sniper.db")
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.httpd.server_address[1]}"

        # Save and patch SNIPER_DATA_DIR
        self._orig_data_dir = os.environ.get("SNIPER_DATA_DIR")
        self.data_dir = self.base / "data_dir"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        os.environ["SNIPER_DATA_DIR"] = str(self.data_dir)

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        server.STORE = self.previous_store
        self.temp.cleanup()
        # Restore SNIPER_DATA_DIR
        if self._orig_data_dir is not None:
            os.environ["SNIPER_DATA_DIR"] = self._orig_data_dir
        else:
            os.environ.pop("SNIPER_DATA_DIR", None)

    def request_json(self, path, payload=None):
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        request = Request(
            self.base_url + path,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"} if body else {},
        )
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read())
        except HTTPError as e:
            return e.code, json.loads(e.read())

    def test_missing_confirm_local(self):
        status, body = self.request_json(
            "/api/tool-runs/semgrep",
            {"project_path": "/tmp"},
        )
        self.assertEqual(status, 400)
        self.assertIn("confirm_local tam olarak true olmalı", body.get("error", ""))

    def test_missing_project_path(self):
        status, body = self.request_json(
            "/api/tool-runs/semgrep",
            {"confirm_local": True},
        )
        self.assertEqual(status, 400)
        self.assertIn("project_path boş olmayan bir metin olmalı", body.get("error", ""))

    def test_invalid_project_path(self):
        status, body = self.request_json(
            "/api/tool-runs/semgrep",
            {"confirm_local": True, "project_path": "/nonexistent"},
        )
        self.assertEqual(status, 400)
        self.assertIn("Proje klasörü bulunamadı veya okunamıyor.", body.get("error", ""))

    def test_missing_binary(self):
        # Create a dummy project
        project_dir = self.base / "project"
        project_dir.mkdir()
        (project_dir / "test.py").write_text("x = 1")

        # Sniper araç dizinindeki varsayılan Opengrep'i devre dışı bırakmak için
        # var olmayan bir yol verilir; doğrulanamayan ikili çalıştırılmaz.
        with patch.dict(os.environ, {"SNIPER_OPENGREP_BINARY": "/nonexistent/opengrep"}):
            status, body = self.request_json(
                "/api/tool-runs/semgrep",
                {"confirm_local": True, "project_path": str(project_dir)},
            )
        self.assertEqual(status, 503)
        self.assertIn("ikilisi açılamadı", body.get("error", ""))
        self.assertNotIn("/nonexistent", body.get("error", ""))

    def test_missing_rules(self):
        # Create a dummy project
        project_dir = self.base / "project"
        project_dir.mkdir()
        (project_dir / "test.py").write_text("x = 1")

        # Create a fake Semgrep binary
        fake_bin = self.base / "fake_semgrep"
        fake_bin.write_text('exit 0')
        fake_bin.chmod(0o755)

        with patch.dict(os.environ, {
            "SNIPER_SEMGREP_BINARY": str(fake_bin), **pin_env("semgrep", fake_bin),
        }, clear=False):
            status, body = self.request_json(
                "/api/tool-runs/semgrep",
                {"confirm_local": True, "project_path": str(project_dir)},
            )
            self.assertEqual(status, 503)
            self.assertIn("Semgrep ikilisi veya kuralları eksik", body.get("error", ""))

    def test_positive_local_scan_with_unsafe(self):
        # Create a dummy project
        project_dir = self.base / "project"
        project_dir.mkdir()
        (project_dir / "unsafe.py").write_text("eval('1+1')")
        (project_dir / "safe.py").write_text("x = 1")

        # Create a fake Semgrep binary that outputs deterministic JSON with one ERROR finding
        fake_bin = self.base / "fake_semgrep"
        fake_bin.write_text("""#!/usr/bin/env python3
import sys
import json
from pathlib import Path

# Parse --output argument
output_path = None
for i, arg in enumerate(sys.argv):
    if arg == "--output" and i + 1 < len(sys.argv):
        output_path = sys.argv[i + 1]
        break

if output_path is None:
    sys.exit(1)

# Read input files to detect eval
input_dir = Path(sys.argv[1])
has_eval = False
for p in input_dir.rglob("*.py"):
    if "eval(" in p.read_text():
        has_eval = True
        break

# Write report
if has_eval:
    report = {
        "results": [
            {
                "check_id": "python.lang.security.audit.eval-detected.eval",
                "path": "unsafe.py",
                "start": {"line": 1, "col": 1},
                "end": {"line": 1, "col": 12},
                "extra": {
                    "message": "Use of eval detected",
                    "metadata": {"cwe": "CWE-94", "owasp": "A1"},
                    "fingerprint": "a" * 32,
                    "lines": "eval('1+1')",
                    "severity": "ERROR"
                }
            }
        ],
        "errors": [],
        "paths": {"scanned": ["unsafe.py", "safe.py"]}
    }
else:
    report = {
        "results": [],
        "errors": [],
        "paths": {"scanned": ["safe.py"]}
    }

Path(output_path).write_text(json.dumps(report, sort_keys=True))
""")
        fake_bin.chmod(0o755)

        # Create a fake trusted rule file
        fake_rules = self.base / "rules.yaml"
        fake_rules.write_text("rules: []")

        with patch.dict(os.environ, {
            "SNIPER_SEMGREP_BINARY": str(fake_bin), **pin_env("semgrep", fake_bin),
            "SNIPER_SEMGREP_RULES": str(fake_rules),
        }, clear=False):
            # First scan with unsafe.py present
            status, body = self.request_json(
                "/api/tool-runs/semgrep",
                {"confirm_local": True, "project_path": str(project_dir)},
            )
            self.assertEqual(status, 200)
            self.assertEqual(body.get("format"), "semgrep-native-json")
            self.assertEqual(body.get("profile"), "local-trusted-rules-v1")
            self.assertEqual(body.get("result_count"), 1)
            self.assertEqual(body.get("severity_counts", {}).get("ERROR"), 1)
            self.assertEqual(len(body.get("report_sha256", "")), 64)
            self.assertNotIn("private", body)
            self.assertNotIn("private_marker", body)

            # Now remove unsafe.py and re-run within same patched env
            (project_dir / "unsafe.py").unlink()
            status2, body2 = self.request_json(
                "/api/tool-runs/semgrep",
                {"confirm_local": True, "project_path": str(project_dir)},
            )
            self.assertEqual(status2, 200)
            self.assertEqual(body2.get("result_count"), 0)
            self.assertEqual(body2.get("severity_counts", {}).get("ERROR"), 0)

    def test_fake_exec_no_report_produced(self):
        # Create a dummy project
        project_dir = self.base / "project"
        project_dir.mkdir()
        (project_dir / "test.py").write_text("x = 1")

        # Create a fake Semgrep binary that exits 0 but does NOT write report
        fake_bin = self.base / "fake_semgrep_no_report"
        fake_bin.write_text("#!/bin/sh\nexit 0\n")
        fake_bin.chmod(0o755)

        # Create a fake trusted rule file
        fake_rules = self.base / "rules.yaml"
        fake_rules.write_text("rules: []")

        # Create a syntactically valid semgrep_report.json in the synthetic project
        # to ensure the fake binary returns zero but report is not produced
        (project_dir / "semgrep_report.json").write_text("{}")

        with patch.dict(os.environ, {
            "SNIPER_SEMGREP_BINARY": str(fake_bin), **pin_env("semgrep", fake_bin),
            "SNIPER_SEMGREP_RULES": str(fake_rules),
        }, clear=False):
            status, body = self.request_json(
                "/api/tool-runs/semgrep",
                {"confirm_local": True, "project_path": str(project_dir)},
            )
            self.assertEqual(status, 502)
            self.assertIn("Semgrep çalıştırması başarısız oldu", body.get("error", ""))
            # Assert the actual private marker string is absent from json.dumps(body)
            body_json_str = json.dumps(body)
            self.assertNotIn("private_marker", body_json_str)
            self.assertNotIn("private:", body_json_str)

    def test_report_with_errors(self):
        # Create a dummy project
        project_dir = self.base / "project"
        project_dir.mkdir()
        (project_dir / "test.py").write_text("x = 1")

        # Create a fake Semgrep binary that outputs report with errors
        fake_bin = self.base / "fake_semgrep_errors"
        fake_bin.write_text("""#!/usr/bin/env python3
import sys
import json
from pathlib import Path

output_path = None
for i, arg in enumerate(sys.argv):
    if arg == "--output" and i + 1 < len(sys.argv):
        output_path = sys.argv[i + 1]
        break

if output_path is None:
    sys.exit(1)

report = {
    "results": [],
    "errors": [{"message": "rule parse error"}],
    "paths": {"scanned": ["test.py"]}
}
Path(output_path).write_text(json.dumps(report))
""")
        fake_bin.chmod(0o755)

        # Create a fake trusted rule file
        fake_rules = self.base / "rules.yaml"
        fake_rules.write_text("rules: []")

        with patch.dict(os.environ, {
            "SNIPER_SEMGREP_BINARY": str(fake_bin), **pin_env("semgrep", fake_bin),
            "SNIPER_SEMGREP_RULES": str(fake_rules),
        }, clear=False):
            status, body = self.request_json(
                "/api/tool-runs/semgrep",
                {"confirm_local": True, "project_path": str(project_dir)},
            )
            self.assertEqual(status, 502)
            self.assertIn("Semgrep çalıştırması başarısız oldu", body.get("error", ""))

    def test_report_with_errors_nonempty(self):
        # Create a dummy project
        project_dir = self.base / "project"
        project_dir.mkdir()
        (project_dir / "test.py").write_text("x = 1")

        # Create a fake Semgrep binary that outputs report with errors
        fake_bin = self.base / "fake_semgrep_errors"
        fake_bin.write_text("""#!/usr/bin/env python3
import sys
import json
from pathlib import Path

output_path = None
for i, arg in enumerate(sys.argv):
    if arg == "--output" and i + 1 < len(sys.argv):
        output_path = sys.argv[i + 1]
        break

if output_path is None:
    sys.exit(1)

report = {
    "results": [],
    "errors": [{"message": "rule parse error"}],
    "paths": {"scanned": ["test.py"]}
}
Path(output_path).write_text(json.dumps(report))
""")
        fake_bin.chmod(0o755)

        # Create a fake trusted rule file
        fake_rules = self.base / "rules.yaml"
        fake_rules.write_text("rules: []")

        with patch.dict(os.environ, {
            "SNIPER_SEMGREP_BINARY": str(fake_bin), **pin_env("semgrep", fake_bin),
            "SNIPER_SEMGREP_RULES": str(fake_rules),
        }, clear=False):
            status, body = self.request_json(
                "/api/tool-runs/semgrep",
                {"confirm_local": True, "project_path": str(project_dir)},
            )
            self.assertEqual(status, 502)
            self.assertIn("Semgrep çalıştırması başarısız oldu", body.get("error", ""))

    def test_extra_key_scanner_args_rejected_without_runner_call(self):
        calls = []

        def stub_semgrep(project_path):
            calls.append(project_path)
            return {"tool": "semgrep", "total_findings": 0}

        with patch.object(server, "run_local_semgrep", side_effect=stub_semgrep):
            status, body = self.request_json(
                "/api/tool-runs/semgrep",
                {
                    "confirm_local": True,
                    "project_path": "/tmp/sniper-stub",
                    "scanner_args": ["--config=auto"],
                },
            )
            self.assertEqual(status, 400)
            self.assertEqual(calls, [])
            self.assertIn("fazla veya eksik alan", body.get("error", ""))

            status_ok, body_ok = self.request_json(
                "/api/tool-runs/semgrep",
                {"confirm_local": True, "project_path": "/tmp/sniper-stub"},
            )
            self.assertEqual(status_ok, 200)
            self.assertEqual(calls, ["/tmp/sniper-stub"])
            self.assertEqual(body_ok.get("tool"), "semgrep")

    def test_non_object_payload_rejected_without_runner_call(self):
        calls = []
        with patch.object(server, "run_local_semgrep", side_effect=lambda p: calls.append(p)):
            status, _ = self.request_json("/api/tool-runs/semgrep", ["not", "an", "object"])
            self.assertEqual(status, 400)
            self.assertEqual(calls, [])
