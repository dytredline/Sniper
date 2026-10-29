"""Complete dependency JSON downloads must never masquerade as a 500-row page."""

import atexit
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import urlopen

_BOOT_DATA_DIR = tempfile.mkdtemp(prefix="sniper_dependency_export_boot_")
atexit.register(shutil.rmtree, _BOOT_DATA_DIR, True)
os.environ["SNIPER_DATA_DIR"] = _BOOT_DATA_DIR
APP_ROOT = Path(os.environ.get("SNIPER_APP_ROOT", Path(__file__).resolve().parents[1])).resolve()
sys.path.insert(0, str(APP_ROOT))

import server  # noqa: E402
from storage import Store  # noqa: E402


class CompleteDependencyExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name) / "synthetic.db")
        self.previous_store = server.STORE
        server.STORE = self.store
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.httpd.daemon_threads = True
        self.base_url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        server.STORE = self.previous_store
        self.temp.cleanup()

    def _import(self, count):
        findings = [{
            "project_path": "/tmp/synthetic-export", "source": "trivy",
            "vulnerability_id": f"CVE-2099-{i:05d}", "package_name": f"pkg-{i:05d}",
            "installed_version": "1.0", "fixed_version": "1.1",
            "severity": "high" if i < 10 else "low",
            "title": "Synthetic export finding", "summary": "Fixture only",
            "target": "requirements.txt", "references": [],
        } for i in range(count)]
        self.store.import_dependency_findings({
            "project_path": "/tmp/synthetic-export", "source": "trivy",
            "source_path": "/tmp/synthetic-export/trivy.json",
            "source_timestamp": "2099-01-01T00:00:00+00:00",
            "document_hash": "d" * 64, "findings": findings,
        })

    def _get(self, path):
        with urlopen(self.base_url + path, timeout=20) as response:
            return response.status, dict(response.headers), json.load(response)

    def test_501st_finding_is_in_complete_download(self):
        self._import(501)
        _, _, listing = self._get("/api/dependency-security")
        self.assertEqual(len(listing["findings"]), 500)
        self.assertTrue(listing["page"]["has_more"])
        status, headers, exported = self._get("/api/dependency-security/report.json")
        self.assertEqual(status, 200)
        self.assertIn("attachment", headers.get("Content-Disposition", ""))
        self.assertEqual(len(exported["findings"]), 501)
        self.assertEqual(len({finding["id"] for finding in exported["findings"]}), 501)
        self.assertEqual(exported["summary"]["total"], 501)
        self.assertTrue(exported["export_complete"])
        self.assertEqual(exported["exported_count"], 501)
        self.assertEqual(exported["page"]["filtered_total"], 501)
        self.assertFalse(exported["page"]["has_more"])

    def test_filtered_export_and_listing_pagination_are_distinct(self):
        self._import(501)
        _, _, exported = self._get("/api/dependency-security/report.json?severity=low")
        self.assertEqual(len(exported["findings"]), 491)
        self.assertTrue(all(row["severity"] == "low" for row in exported["findings"]))
        self.assertEqual(exported["page"]["filtered_total"], 491)
        with self.assertRaises(HTTPError) as rejected:
            self._get("/api/dependency-security/report.json?limit=1")
        self.assertEqual(rejected.exception.code, 400)

    def test_empty_complete_download_is_not_partial(self):
        _, _, exported = self._get("/api/dependency-security/report.json")
        self.assertEqual(exported["findings"], [])
        self.assertEqual(exported["exported_count"], 0)
        self.assertTrue(exported["export_complete"])
        self.assertFalse(exported["page"]["has_more"])

    def test_oversized_row_does_not_stream_a_partial_attachment(self):
        self._import(1)
        with self.store._connect() as db:
            db.execute(
                "UPDATE dependency_findings SET summary = ?",
                ("x" * 30_000_001,),
            )
        with self.assertRaises(HTTPError) as rejected:
            self._get("/api/dependency-security/report.json")
        self.assertEqual(rejected.exception.code, 413)
        self.assertNotIn("attachment", rejected.exception.headers.get("Content-Disposition", ""))

    def test_oversized_export_fails_without_a_partial_attachment(self):
        self._import(10_001)
        with self.assertRaises(HTTPError) as rejected:
            self._get("/api/dependency-security/report.json")
        self.assertEqual(rejected.exception.code, 413)
        self.assertNotIn("attachment", rejected.exception.headers.get("Content-Disposition", ""))


if __name__ == "__main__":
    unittest.main()
