from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError

import server
from storage import Store


class TrivyVulnerabilityApiTests(unittest.TestCase):
    def setUp(self):
        # Create isolated temp dirs under home
        self.temp_base = tempfile.TemporaryDirectory(dir=Path.home(), prefix="sniper_trivy_vuln_test_")
        self.base = Path(self.temp_base.name)
        self.data_dir = self.base / "data"
        self.data_dir.mkdir(parents=True)
        self.bin_dir = self.base / "bin"
        self.bin_dir.mkdir(parents=True)
        self.cache_dir = self.base / "cache"
        self.cache_dir.mkdir(parents=True)
        self.db_dir = self.cache_dir / "db"
        self.db_dir.mkdir(parents=True)

        # Create fake trivy binary
        self.fake_bin = self.bin_dir / "trivy"
        self._write_fake_trivy_binary()

        # Create fake DB with correct SHA256
        self.fake_db = self.db_dir / "trivy.db"
        self.fake_db.write_bytes(b"fake db content")
        self.fake_meta = self.db_dir / "metadata.json"
        self.fake_meta.write_text(json.dumps({"SchemaVersion": 2, "UpdatedAt": "2024-01-01T00:00:00Z"}, sort_keys=True, separators=(",", ":")))
        self.expected_sha = hashlib.sha256(b"fake db content").hexdigest()

        # Set environment (parent process only)
        self.old_trivy_bin = os.environ.get("SNIPER_TRIVY_BINARY")
        self.old_trivy_sha = os.environ.get("SNIPER_TRIVY_BINARY_SHA256")
        self.old_data_dir = os.environ.get("SNIPER_DATA_DIR")
        self.old_cache_dir = os.environ.get("SNIPER_TRIVY_VULN_CACHE_DIR")
        self.old_db_sha = os.environ.get("SNIPER_TRIVY_VULN_DB_SHA256")
        os.environ["SNIPER_TRIVY_BINARY"] = str(self.fake_bin)
        os.environ["SNIPER_TRIVY_BINARY_SHA256"] = hashlib.sha256(self.fake_bin.read_bytes()).hexdigest()
        os.environ["SNIPER_DATA_DIR"] = str(self.data_dir)
        os.environ["SNIPER_TRIVY_VULN_CACHE_DIR"] = str(self.cache_dir)
        os.environ["SNIPER_TRIVY_VULN_DB_SHA256"] = self.expected_sha

        # Setup server
        self.previous_store = server.STORE
        server.STORE = Store(self.base / "sniper.db")
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.httpd.server_address[1]}"

        # Create test project with requirements.txt
        self.project_dir = self.base / "project"
        self.project_dir.mkdir(parents=True)
        self.req_file = self.project_dir / "requirements.txt"
        self.req_file.write_text("requests==2.28.0\n")

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        server.STORE = self.previous_store
        for key in ["SNIPER_TRIVY_BINARY", "SNIPER_TRIVY_BINARY_SHA256", "SNIPER_DATA_DIR", "SNIPER_TRIVY_VULN_CACHE_DIR", "SNIPER_TRIVY_VULN_DB_SHA256"]:
            if key in os.environ:
                del os.environ[key]
        if self.old_trivy_bin is not None:
            os.environ["SNIPER_TRIVY_BINARY"] = self.old_trivy_bin
        if self.old_trivy_sha is not None:
            os.environ["SNIPER_TRIVY_BINARY_SHA256"] = self.old_trivy_sha
        if self.old_data_dir is not None:
            os.environ["SNIPER_DATA_DIR"] = self.old_data_dir
        if self.old_cache_dir is not None:
            os.environ["SNIPER_TRIVY_VULN_CACHE_DIR"] = self.old_cache_dir
        if self.old_db_sha is not None:
            os.environ["SNIPER_TRIVY_VULN_DB_SHA256"] = self.old_db_sha
        self.temp_base.cleanup()

    def _write_fake_trivy_binary(self):
        content = '''#!/usr/bin/env python3
import sys
import json
import os
from pathlib import Path

def main():
    args = sys.argv[1:]
    report_path = None
    input_dir = None
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--output" and i + 1 < len(args):
            report_path = Path(args[i + 1])
            i += 1
        elif arg == "--format" and i + 1 < len(args) and args[i + 1] == "json":
            i += 1
        elif not arg.startswith("--"):
            input_dir = Path(arg)
        i += 1

    if report_path is None or input_dir is None:
        sys.exit(1)

    # Check for fake failure marker
    if "_SNIPER_FAKE_FAIL" in os.environ:
        sys.exit(1)

    report = {
        "SchemaVersion": 2,
        "Results": []
    }

    # One vulnerability only if requirements.txt contains "vuln-marker"
    req_file = input_dir / "requirements.txt"
    if req_file.is_file():
        content = req_file.read_text()
        if "vuln-marker" in content:
            report["Results"] = [
                {
                    "Target": "requests (2.28.0)",
                    "Class": "lang-pkgs",
                    "Type": "python",
                    "Vulnerabilities": [
                        {
                            "ID": "CVE-2023-32681",
                            "Pkg": "requests",
                            "Version": "2.28.0",
                            "Severity": "MEDIUM",
                            "InstalledVersion": "2.28.0",
                            "FixedVersion": "2.31.0",
                            "Title": "requests: CRLF injection via HTTP header",
                            "Description": "A CRLF injection vulnerability in requests allows an attacker to inject CRLF sequences into HTTP headers.",
                            "References": ["https://nvd.nist.gov/vuln/detail/CVE-2023-32681"]
                        }
                    ]
                }
            ]

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, sort_keys=True, separators=(",", ":")))
    sys.exit(0)

if __name__ == "__main__":
    main()
'''.strip()
        self.fake_bin.write_text(content)
        self.fake_bin.chmod(0o755)

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

    def test_positive_scan_returns_200_with_aggregates(self):
        # Stage requirements.txt with vuln-marker to trigger one finding
        self.req_file.write_text("vuln-marker\nrequests==2.28.0\n")
        status, body = self.request_json(
            "/api/tool-runs/trivy-vulnerability",
            {
                "confirm_local": True,
                "project_path": str(self.project_dir),
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["format"], "trivy-native-json")
        self.assertEqual(body["schema_version"], 2)
        self.assertEqual(body["profile"], "local-python-requirements-v1")
        self.assertEqual(body["result_count"], 1)
        self.assertEqual(body["class_counts"], {
            "os-pkgs": 0,
            "lang-pkgs": 1,
            "config": 0,
            "secret": 0,
            "license": 0,
            "license-file": 0,
            "crypto": 0,
            "custom": 0,
            "unknown": 0,
        })
        self.assertEqual(body["vuln_counts"], {
            "critical": 0,
            "high": 0,
            "medium": 1,
            "low": 0,
            "unknown": 0,
        })
        self.assertEqual(body["finding_counts"], {
            "vulnerabilities": 1,
            "misconfigurations": 0,
            "secrets": 0,
            "licenses": 0,
        })
        self.assertIn("report_sha256", body)
        self.assertTrue(len(body["report_sha256"]) == 64 and all(c in "0123456789abcdef" for c in body["report_sha256"]))

    def test_clean_scan_returns_zero(self):
        # Ensure clean requirements.txt (no marker) → zero findings
        self.req_file.write_text("")
        status, body = self.request_json(
            "/api/tool-runs/trivy-vulnerability",
            {
                "confirm_local": True,
                "project_path": str(self.project_dir),
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["format"], "trivy-native-json")
        self.assertEqual(body["schema_version"], 2)
        self.assertEqual(body["profile"], "local-python-requirements-v1")
        self.assertEqual(body["result_count"], 0)
        self.assertEqual(body["finding_counts"], {
            "vulnerabilities": 0,
            "misconfigurations": 0,
            "secrets": 0,
            "licenses": 0,
        })

    def test_missing_confirm_local_returns_400(self):
        status, body = self.request_json(
            "/api/tool-runs/trivy-vulnerability",
            {
                "confirm_local": False,
                "project_path": str(self.project_dir),
            },
        )
        self.assertEqual(status, 400)
        self.assertIn("confirm_local tam olarak true olmalı", body["error"])

    def test_missing_db_returns_503(self):
        # Remove DB file to trigger unavailable
        self.fake_db.unlink()
        status, body = self.request_json(
            "/api/tool-runs/trivy-vulnerability",
            {
                "confirm_local": True,
                "project_path": str(self.project_dir),
            },
        )
        self.assertEqual(status, 503)
        self.assertIn("Trivy zafiyet tarayıcısı kullanılamıyor", body["error"])

    def test_extra_field_returns_400(self):
        status, body = self.request_json(
            "/api/tool-runs/trivy-vulnerability",
            {
                "confirm_local": True,
                "project_path": str(self.project_dir),
                "extra": "field",
            },
        )
        self.assertEqual(status, 400)
        self.assertIn("fazla veya eksik alan", body["error"])

    def test_private_markers_not_leaked(self):
        # Ensure no raw paths or findings appear in response
        status, body = self.request_json(
            "/api/tool-runs/trivy-vulnerability",
            {
                "confirm_local": True,
                "project_path": str(self.project_dir),
            },
        )
        self.assertEqual(status, 200)
        self.assertNotIn(str(self.project_dir), str(body))
        self.assertNotIn("requests==2.28.0", str(body))
        self.assertNotIn("CVE-2023-32681", str(body))

    def test_trivy_failure_returns_502(self):
        # Force fake Trivy to fail
        os.environ["_SNIPER_FAKE_FAIL"] = "1"
        try:
            status, body = self.request_json(
                "/api/tool-runs/trivy-vulnerability",
                {
                    "confirm_local": True,
                    "project_path": str(self.project_dir),
                },
            )
            self.assertEqual(status, 502)
            self.assertIn("Trivy zafiyet taraması başarısız oldu", body["error"])
        finally:
            if "_SNIPER_FAKE_FAIL" in os.environ:
                del os.environ["_SNIPER_FAKE_FAIL"]

    def test_missing_project_path_returns_400(self):
        status, body = self.request_json(
            "/api/tool-runs/trivy-vulnerability",
            {
                "confirm_local": True,
            },
        )
        self.assertEqual(status, 400)
        self.assertIn("project_path boş olmayan bir metin olmalı", body["error"])

    def test_missing_root_requirements_txt_returns_400(self):
        # Remove root requirements.txt
        self.req_file.unlink()
        status, body = self.request_json(
            "/api/tool-runs/trivy-vulnerability",
            {
                "confirm_local": True,
                "project_path": str(self.project_dir),
            },
        )
        self.assertEqual(status, 400)
        self.assertIn("requirements.txt", body["error"])

    def test_symlink_root_requirements_txt_returns_400(self):
        # Replace requirements.txt with symlink
        self.req_file.unlink()
        link_target = self.project_dir / "target.txt"
        link_target.write_text("requests==2.28.0\n")
        self.req_file.symlink_to(link_target)
        status, body = self.request_json(
            "/api/tool-runs/trivy-vulnerability",
            {
                "confirm_local": True,
                "project_path": str(self.project_dir),
            },
        )
        self.assertEqual(status, 400)
        self.assertIn("requirements.txt", body["error"])
