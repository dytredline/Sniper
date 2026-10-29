"""Behavior regressions for bounded dependency browsing and truthful updates."""

import atexit
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


_BOOT_DATA_DIR = tempfile.mkdtemp(prefix="sniper_dependency_repair_boot_")
atexit.register(shutil.rmtree, _BOOT_DATA_DIR, True)
os.environ["SNIPER_DATA_DIR"] = _BOOT_DATA_DIR
APP_ROOT = Path(os.environ.get("SNIPER_APP_ROOT", Path(__file__).resolve().parents[1])).resolve()
sys.path.insert(0, str(APP_ROOT))
sys.path.insert(1, "/home/community-user/.local/share/sniper/app")

import server  # noqa: E402
from storage import Store  # noqa: E402


def _json_request(url: str, payload: dict | None = None):
    encoded = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = Request(url, data=encoded, headers={"Content-Type": "application/json"} if encoded else {})
    with urlopen(request, timeout=10) as response:
        return response.status, json.load(response)


class DependencyFindingRepairTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name) / "synthetic.db")
        self.previous_store = server.STORE
        server.STORE = self.store
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.base_url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        server.STORE = self.previous_store
        self.temp.cleanup()

    def _import(self, count):
        findings = [
            {
                "project_path": "/tmp/synthetic-dependency-project", "source": "trivy",
                "vulnerability_id": f"CVE-2099-{index:04d}",
                "package_name": f"package-{index:04d}", "installed_version": "1.0",
                "fixed_version": "1.1", "severity": "low", "title": "Synthetic issue",
                "summary": "Fixture only", "target": "requirements.txt", "references": [],
            }
            for index in range(count)
        ]
        self.store.import_dependency_findings({
            "project_path": "/tmp/synthetic-dependency-project", "source": "trivy",
            "source_path": "/tmp/synthetic-dependency-project/report.json",
            "source_timestamp": "2099-01-01T00:00:00+00:00",
            "document_hash": "a" * 64, "findings": findings,
        })

    def test_control_small_list_and_status_only_preserves_note(self):
        self._import(1)
        status, page = _json_request(self.base_url + "/api/dependency-security?limit=100")
        self.assertEqual(status, 200)
        self.assertEqual(page["summary"]["total"], 1)
        self.assertEqual(page["page"]["filtered_total"], 1)
        finding = page["findings"][0]
        _, saved = _json_request(
            self.base_url + f"/api/dependency-findings/{finding['id']}/update",
            {"status": "in_progress", "resolution_notes": "Approved synthetic plan"},
        )
        self.assertEqual(saved["resolution_notes"], "Approved synthetic plan")
        _, updated = _json_request(
            self.base_url + f"/api/dependency-findings/{finding['id']}/update",
            {"status": "resolved"},
        )
        self.assertEqual(updated["status"], "resolved")
        self.assertEqual(updated["resolution_notes"], "Approved synthetic plan")

    def test_omitted_501st_record_can_be_found_and_opened_through_bounded_api(self):
        self._import(501)
        _, first = _json_request(self.base_url + "/api/dependency-security")
        self.assertEqual(first["summary"]["total"], 501)
        self.assertEqual(len(first["findings"]), 500)
        omitted = {f"CVE-2099-{index:04d}" for index in range(501)} - {
            item["vulnerability_id"] for item in first["findings"]
        }
        self.assertEqual(len(omitted), 1)
        omitted_id = omitted.pop()
        _, last_page = _json_request(self.base_url + "/api/dependency-security?limit=100&offset=500")
        self.assertEqual(last_page["page"]["filtered_total"], 501)
        self.assertEqual(len(last_page["findings"]), 1)
        _, filtered = _json_request(self.base_url + "/api/dependency-security?" + urlencode({
            "limit": 100, "offset": 0, "query": omitted_id, "source": "trivy", "severity": "low", "status": "open",
        }))
        self.assertEqual(filtered["page"]["filtered_total"], 1)
        self.assertEqual(filtered["findings"][0]["vulnerability_id"], omitted_id)
        finding_id = filtered["findings"][0]["id"]
        _, updated = _json_request(
            self.base_url + f"/api/dependency-findings/{finding_id}/update",
            {"status": "in_progress", "resolution_notes": "Reached via complete search"},
        )
        self.assertEqual(updated["resolution_notes"], "Reached via complete search")
        _, filtered_again = _json_request(self.base_url + "/api/dependency-security?query=" + omitted_id)
        self.assertEqual(filtered_again["findings"][0]["resolution_notes"], "Reached via complete search")
        with self.assertRaises(HTTPError) as bad_limit:
            _json_request(self.base_url + "/api/dependency-security?limit=501")
        self.assertEqual(bad_limit.exception.code, 400)

    def test_runtime_row_and_refresh_failure_use_persisted_result(self):
        harness = Path(__file__).with_name("fixtures") / "dependency_repair_ui_harness.mjs"
        for mode in ("quick_status", "refresh_failure", "page_navigation"):
            with self.subTest(mode=mode):
                proc = subprocess.run(
                    ["node", str(harness), str(APP_ROOT), mode], capture_output=True,
                    text=True, check=True, timeout=10,
                )
                result = json.loads(proc.stdout)
                if mode == "page_navigation":
                    self.assertTrue(result["requested_offset_100"])
                    self.assertTrue(result["rendered_later_finding"])
                    continue
                self.assertEqual(result["backend_status"], "resolved")
                if mode == "quick_status":
                    self.assertEqual(result["posted"], [{"status": "resolved"}])
                    self.assertEqual(result["backend_note"], "Prior mitigation evidence")
                    self.assertTrue(result["displayed_old_note"])
                else:
                    self.assertEqual(result["backend_note"], "New verified remediation")
                    self.assertTrue(result["displayed_new_note"])
                    self.assertFalse(result["displayed_old_note"])
                    self.assertTrue(result["displayed_refresh_warning"])
                    self.assertFalse(result["displayed_success"])


if __name__ == "__main__":
    unittest.main()
