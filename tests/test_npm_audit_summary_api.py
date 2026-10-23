import json
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
import tempfile
import threading
from urllib.request import Request, urlopen
from urllib.error import HTTPError

import server
from storage import Store


class NpmAuditSummaryApiTests(unittest.TestCase):
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
        try:
            with urlopen(request, timeout=5) as response:
                return json.loads(response.read())
        except HTTPError as e:
            raise e

    def test_npm_audit_v2_summary_two_packages_high_and_moderate(self):
        audit = {
            "auditReportVersion": 2,
            "vulnerabilities": {
                "lodash": {
                    "severity": "high",
                    "via": ["security-advisory-1"],
                    "title": "secret marker must not appear"
                },
                "minimist": {
                    "severity": "moderate",
                    "via": ["security-advisory-2"],
                    "title": "another secret marker must not appear"
                }
            }
        }
        result = self.request_json("/api/tool-reports/npm-audit/summary", {"audit": audit})
        self.assertEqual(result["format"], "npm-audit-v2")
        self.assertEqual(result["affected_package_count"], 2)
        self.assertEqual(result["package_severity_counts"], {
            "info": 0,
            "low": 0,
            "moderate": 1,
            "high": 1,
            "critical": 0
        })
        self.assertIn("report_sha256", result)
        self.assertNotIn("secret marker", result)
        self.assertNotIn("title", result)

    def test_npm_audit_v2_summary_empty_vulnerabilities(self):
        audit = {
            "auditReportVersion": 2,
            "vulnerabilities": {}
        }
        result = self.request_json("/api/tool-reports/npm-audit/summary", {"audit": audit})
        self.assertEqual(result["format"], "npm-audit-v2")
        self.assertEqual(result["affected_package_count"], 0)
        self.assertEqual(result["package_severity_counts"], {
            "info": 0,
            "low": 0,
            "moderate": 0,
            "high": 0,
            "critical": 0
        })
        self.assertIn("report_sha256", result)

    def test_npm_audit_v2_summary_rejects_version_1(self):
        audit = {
            "auditReportVersion": 1,
            "vulnerabilities": {}
        }
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/npm-audit/summary", {"audit": audit})
        self.assertEqual(cm.exception.code, 400)

    def test_npm_audit_v2_summary_rejects_missing_audit(self):
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/npm-audit/summary", {})
        self.assertEqual(cm.exception.code, 400)

    def test_npm_audit_v2_summary_rejects_non_object_vulnerabilities(self):
        audit = {
            "auditReportVersion": 2,
            "vulnerabilities": []
        }
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/npm-audit/summary", {"audit": audit})
        self.assertEqual(cm.exception.code, 400)

    def test_npm_audit_v2_summary_rejects_unknown_severity(self):
        audit = {
            "auditReportVersion": 2,
            "vulnerabilities": {
                "pkg": {
                    "severity": "unknown"
                }
            }
        }
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/npm-audit/summary", {"audit": audit})
        self.assertEqual(cm.exception.code, 400)

    def test_health_preserved(self):
        result = self.request_json("/api/health")
        self.assertEqual(result["status"], "ok")