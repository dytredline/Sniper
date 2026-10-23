import json
from http.server import ThreadingHTTPServer
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.request import Request, urlopen

import server
from storage import Store


class DependencyApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.base = Path(self.temp.name)
        self.project = self.base / "project"
        self.project.mkdir()
        (self.project / "requirements.txt").write_text("demo==1.0\n", encoding="utf-8")
        self.report = self.base / "trivy.json"
        self.report.write_text(json.dumps({"Results": [{"Target": "requirements.txt", "Vulnerabilities": [{
            "VulnerabilityID": "CVE-2026-0100", "PkgName": "demo", "InstalledVersion": "1.0",
            "FixedVersion": "1.1", "Severity": "HIGH", "References": ["https://example.test/100"],
        }]}]}), encoding="utf-8")
        self.previous_store = server.STORE
        server.STORE = Store(self.base / "data" / "sniper.db")
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        server.STORE = self.previous_store
        self.temp.cleanup()

    def request_json(self, path, payload=None):
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        request = Request(
            self.base_url + path,
            data=body,
            method="GET" if payload is None else "POST",
            headers={"Content-Type": "application/json"} if body else {},
        )
        with urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read())

    def test_sbom_import_list_update_and_download(self):
        status, sbom = self.request_json("/api/dependency-security/sbom", {"project_path": str(self.project)})
        self.assertEqual(status, 201)
        self.assertEqual(sbom["component_count"], 1)
        _, document = self.request_json(f"/api/dependency-sboms/{sbom['id']}")
        self.assertEqual(document["bomFormat"], "CycloneDX")

        status, imported = self.request_json("/api/dependency-security/import", {
            "project_path": str(self.project), "report_path": str(self.report), "source": "auto",
        })
        self.assertEqual(status, 201)
        self.assertEqual(imported["finding_count"], 1)
        _, dependency_security = self.request_json("/api/dependency-security")
        finding = dependency_security["findings"][0]
        self.assertEqual(finding["package_name"], "demo")

        _, updated = self.request_json(f"/api/dependency-findings/{finding['id']}/update", {
            "status": "resolved", "resolution_notes": "1.1 sürümünde düzeltildi",
        })
        self.assertEqual(updated["status"], "resolved")
        _, exported = self.request_json("/api/dependency-security/report.json")
        self.assertEqual(exported["summary"]["active"], 0)


if __name__ == "__main__":
    unittest.main()
