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


class TrivyImageArchiveApiTests(unittest.TestCase):
    def setUp(self):
        self.temp_base = tempfile.TemporaryDirectory(dir=Path.home(), prefix="sniper_trivy_img_test_")
        self.base = Path(self.temp_base.name)
        self.data_dir = self.base / "data"
        self.data_dir.mkdir(parents=True)
        self.bin_dir = self.base / "bin"
        self.bin_dir.mkdir(parents=True)
        self.cache_dir = self.base / "cache"
        self.cache_dir.mkdir(parents=True)
        self.db_dir = self.cache_dir / "db"
        self.db_dir.mkdir(parents=True)

        self.fake_bin = self.bin_dir / "trivy"
        self._write_fake_trivy_binary()

        self.fake_db = self.db_dir / "trivy.db"
        self.fake_db.write_bytes(b"fake db content")
        self.fake_meta = self.db_dir / "metadata.json"
        self.fake_meta.write_text(json.dumps({"SchemaVersion": 2, "UpdatedAt": "2024-01-01T00:00:00Z"}, sort_keys=True, separators=(",", ":")))
        self.expected_sha = hashlib.sha256(b"fake db content").hexdigest()

        self.old_trivy_bin = os.environ.get("SNIPER_TRIVY_BINARY")
        self.old_data_dir = os.environ.get("SNIPER_DATA_DIR")
        self.old_cache_dir = os.environ.get("SNIPER_TRIVY_VULN_CACHE_DIR")
        self.old_db_sha = os.environ.get("SNIPER_TRIVY_VULN_DB_SHA256")
        os.environ["SNIPER_TRIVY_BINARY"] = str(self.fake_bin)
        os.environ["SNIPER_DATA_DIR"] = str(self.data_dir)
        os.environ["SNIPER_TRIVY_VULN_CACHE_DIR"] = str(self.cache_dir)
        os.environ["SNIPER_TRIVY_VULN_DB_SHA256"] = self.expected_sha

        self.previous_store = server.STORE
        server.STORE = Store(self.base / "sniper.db")
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.httpd.server_address[1]}"

        self.project_dir = self.base / "project"
        self.project_dir.mkdir(parents=True)
        self.tar_path = self.project_dir / "image.tar"
        self.tar_path.write_bytes(b"fixture-tar")

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        server.STORE = self.previous_store
        for k in ["SNIPER_TRIVY_BINARY", "SNIPER_DATA_DIR", "SNIPER_TRIVY_VULN_CACHE_DIR", "SNIPER_TRIVY_VULN_DB_SHA256"]:
            os.environ.pop(k, None)
        if self.old_trivy_bin is not None: os.environ["SNIPER_TRIVY_BINARY"] = self.old_trivy_bin
        if self.old_data_dir is not None: os.environ["SNIPER_DATA_DIR"] = self.old_data_dir
        if self.old_cache_dir is not None: os.environ["SNIPER_TRIVY_VULN_CACHE_DIR"] = self.old_cache_dir
        if self.old_db_sha is not None: os.environ["SNIPER_TRIVY_VULN_DB_SHA256"] = self.old_db_sha
        self.temp_base.cleanup()

    def _write_fake_trivy_binary(self):
        script = '''#!/usr/bin/env python3
import sys, json, os

args = sys.argv[1:]
if len(args) < 1 or args[0] != "image":
    sys.exit(1)

input_idx = args.index("--input") if "--input" in args else -1
output_idx = args.index("--output") if "--output" in args else -1

if input_idx < 0 or output_idx < 0:
    sys.exit(1)

input_path = args[input_idx + 1]
output_path = args[output_idx + 1]

if not os.path.isfile(input_path):
    sys.exit(1)

with open(input_path, "rb") as f:
    content = f.read()
if content != b"fixture-tar":
    sys.exit(1)

if "--scanners" not in args or "vuln" not in args:
    sys.exit(1)
if "--offline-scan" not in args:
    sys.exit(1)
if "--skip-db-update" not in args:
    sys.exit(1)

report = {
    "Results": [{"Class": "os-pkgs", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2024-0001", "Severity": "HIGH", "PkgName": "pkg1"},
        {"VulnerabilityID": "CVE-2024-0002", "Severity": "MEDIUM", "PkgName": "pkg2"}
    ]}],
    "SchemaVersion": 2
}

with open(output_path, "w") as f:
    json.dump(report, f)
'''
        self.fake_bin.write_text(script)
        os.chmod(self.fake_bin, 0o755)

    def test_positive(self):
        payload = {"confirm_local": True, "project_path": str(self.project_dir), "archive_name": "image.tar"}
        req = Request(f"{self.base_url}/api/tool-runs/trivy-image-archive-vulnerability",
                      data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"})
        try:
            resp = urlopen(req)
        except HTTPError as e:
            self.fail(f"Expected 200, got {e.code}: {e.read().decode()}")
        data = json.loads(resp.read())
        self.assertEqual(data["profile"], "local-image-archive-offline-v1")
        self.assertIn("report_sha256", data)
        self.assertEqual(len(data["report_sha256"]), 64)
        self.assertEqual(data["class_counts"], {"os-pkgs": 1, "lang-pkgs": 0, "config": 0, "secret": 0, "license": 0, "license-file": 0, "crypto": 0, "custom": 0, "unknown": 0})
        self.assertEqual(data["vuln_counts"], {"critical": 0, "high": 1, "medium": 1, "low": 0, "unknown": 0})
        self.assertEqual(data["finding_counts"], {"vulnerabilities": 2, "misconfigurations": 0, "secrets": 0, "licenses": 0})
        serialized = json.dumps(data)
        self.assertNotIn("CVE-2024-0001", serialized)
        self.assertNotIn("pkg1", serialized)
        self.assertNotIn(str(self.project_dir), serialized)

    def test_missing_consent(self):
        payload = {"confirm_local": False, "project_path": str(self.project_dir), "archive_name": "image.tar"}
        req = Request(f"{self.base_url}/api/tool-runs/trivy-image-archive-vulnerability",
                      data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"})
        with self.assertRaises(HTTPError) as cm:
            urlopen(req)
        self.assertEqual(cm.exception.code, 400)
