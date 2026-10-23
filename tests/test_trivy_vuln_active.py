from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from trivy_vuln_active import run_local_trivy_vulnerability


class TestTrivyVulnActive(unittest.TestCase):
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

        # Create fake DB
        self.fake_db = self.db_dir / "trivy.db"
        self.fake_db.write_text("fake-db-content")
        self.db_sha = hashlib.sha256(self.fake_db.read_bytes()).hexdigest()

        # Create metadata.json
        (self.db_dir / "metadata.json").write_text("{}")

        # Set environment
        self.old_trivy_bin = os.environ.get("SNIPER_TRIVY_BINARY")
        self.old_data_dir = os.environ.get("SNIPER_DATA_DIR")
        self.old_cache_dir = os.environ.get("SNIPER_TRIVY_VULN_CACHE_DIR")
        self.old_db_sha = os.environ.get("SNIPER_TRIVY_VULN_DB_SHA256")

        os.environ["SNIPER_TRIVY_BINARY"] = str(self.fake_bin)
        os.environ["SNIPER_DATA_DIR"] = str(self.data_dir)
        os.environ["SNIPER_TRIVY_VULN_CACHE_DIR"] = str(self.cache_dir)
        os.environ["SNIPER_TRIVY_VULN_DB_SHA256"] = self.db_sha

        # Create test project with requirements.txt
        self.project_dir = self.base / "project"
        self.project_dir.mkdir(parents=True)
        self.req_file = self.project_dir / "requirements.txt"
        self.req_file.write_text("requests==2.28.0\n")

    def tearDown(self):
        if self.old_trivy_bin is not None:
            os.environ["SNIPER_TRIVY_BINARY"] = self.old_trivy_bin
        elif "SNIPER_TRIVY_BINARY" in os.environ:
            del os.environ["SNIPER_TRIVY_BINARY"]
        if self.old_data_dir is not None:
            os.environ["SNIPER_DATA_DIR"] = self.old_data_dir
        elif "SNIPER_DATA_DIR" in os.environ:
            del os.environ["SNIPER_DATA_DIR"]
        if self.old_cache_dir is not None:
            os.environ["SNIPER_TRIVY_VULN_CACHE_DIR"] = self.old_cache_dir
        elif "SNIPER_TRIVY_VULN_CACHE_DIR" in os.environ:
            del os.environ["SNIPER_TRIVY_VULN_CACHE_DIR"]
        if self.old_db_sha is not None:
            os.environ["SNIPER_TRIVY_VULN_DB_SHA256"] = self.old_db_sha
        elif "SNIPER_TRIVY_VULN_DB_SHA256" in os.environ:
            del os.environ["SNIPER_TRIVY_VULN_DB_SHA256"]
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
    cache_dir = None
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--output" and i + 1 < len(args):
            report_path = Path(args[i + 1])
            i += 1
        elif arg == "--cache-dir" and i + 1 < len(args):
            cache_dir = args[i + 1]
            i += 1
        i += 1

    if report_path is None:
        sys.exit(1)

    exitcode = 0
    if "_SNIPER_FAKE_EXITCODE" in os.environ:
        exitcode = int(os.environ["_SNIPER_FAKE_EXITCODE"])

    # Validate cache dir matches expected validated path
    expected_cache = os.environ.get("_SNIPER_EXPECTED_CACHE_DIR")
    if expected_cache and cache_dir != expected_cache:
        sys.exit(1)

    # Generate report with one vulnerability
    report = {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "requirements.txt",
                "Class": "lang-pkgs",
                "Type": "pip",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-1234",
                        "PkgName": "requests",
                        "PkgPath": "",
                        "InstalledVersion": "2.28.0",
                        "FixedVersion": "2.31.0",
                        "Severity": "HIGH",
                        "Title": "Example vulnerability",
                        "Description": "Example description",
                        "References": ["https://example.com"]
                    }
                ],
                "Misconfigurations": [],
                "Secrets": [],
                "Licenses": []
            }
        ]
    }

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, sort_keys=True, separators=(",", ":")))
    sys.exit(exitcode)

if __name__ == "__main__":
    main()
'''.strip()
        self.fake_bin.write_text(content)
        self.fake_bin.chmod(0o755)

    def test_positive_scan_returns_aggregates(self):
        os.environ["_SNIPER_EXPECTED_CACHE_DIR"] = str(self.cache_dir)
        result = run_local_trivy_vulnerability(str(self.project_dir))
        self.assertEqual(result["profile"], "local-python-requirements-v1")
        self.assertEqual(result["format"], "trivy-native-json")
        self.assertEqual(result["schema_version"], 2)
        self.assertEqual(result["result_count"], 1)
        self.assertEqual(result["class_counts"], {
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
        self.assertEqual(result["vuln_counts"], {
            "critical": 0,
            "high": 1,
            "medium": 0,
            "low": 0,
            "unknown": 0,
        })
        self.assertEqual(result["finding_counts"], {
            "vulnerabilities": 1,
            "misconfigurations": 0,
            "secrets": 0,
            "licenses": 0,
        })
        self.assertIn("report_sha256", result)
        self.assertTrue(len(result["report_sha256"]) == 64 and all(c in "0123456789abcdef" for c in result["report_sha256"]))

    def test_missing_db_fails(self):
        # Remove DB file
        self.fake_db.unlink()
        with self.assertRaises(RuntimeError) as cm:
            run_local_trivy_vulnerability(str(self.project_dir))
        self.assertIn("Trivy veritabanı dosyası mevcut olmalı", str(cm.exception))

    def test_symlink_db_rejected(self):
        # Replace DB with symlink
        real_db = self.db_dir / "real_trivy.db"
        real_db.write_text("real-db-content")
        self.fake_db.unlink()
        os.symlink(real_db, self.fake_db)
        with self.assertRaises(RuntimeError) as cm:
            run_local_trivy_vulnerability(str(self.project_dir))
        self.assertIn("Trivy veritabanı dosyası normal bir dosya olmalı", str(cm.exception))

    def test_symlink_cache_dir_rejected(self):
        # Create a new directory to move cache into
        moved_cache = self.base / "moved_cache"
        # Move original cache_dir to moved_cache
        os.rename(str(self.cache_dir), str(moved_cache))
        # Create symlink at original cache_dir pointing to moved_cache
        os.symlink(moved_cache, str(self.cache_dir))
        with self.assertRaises(RuntimeError) as cm:
            run_local_trivy_vulnerability(str(self.project_dir))
        self.assertIn("Trivy önbellek dizini normal bir dizin olmalı", str(cm.exception))
