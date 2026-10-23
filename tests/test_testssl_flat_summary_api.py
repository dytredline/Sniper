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


class TestsslFlatSummaryApiTests(unittest.TestCase):
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

    def test_testssl_summary_high_and_info_scanTime(self):
        report = [
            {"id": "1", "ip": "127.0.0.1", "port": "443", "severity": "HIGH", "finding": "Heartbleed"},
            {"id": "scanTime", "ip": "127.0.0.1", "port": "443", "severity": "INFO", "finding": "scanTime"}
        ]
        result = self.request_json("/api/tool-reports/testssl/summary", {"report": report})
        self.assertEqual(result["format"], "testssl-flat-json")
        self.assertEqual(result["record_count"], 2)
        self.assertEqual(result["severity_counts"], {
            "INFO": 1,
            "OK": 0,
            "LOW": 0,
            "MEDIUM": 0,
            "HIGH": 1,
            "CRITICAL": 0,
            "WARN": 0,
            "DEBUG": 0,
            "FATAL": 0
        })
        self.assertIn("report_sha256", result)

    def test_testssl_summary_empty_array(self):
        report = []
        result = self.request_json("/api/tool-reports/testssl/summary", {"report": report})
        self.assertEqual(result["format"], "testssl-flat-json")
        self.assertEqual(result["record_count"], 0)
        self.assertEqual(result["severity_counts"], {
            "INFO": 0,
            "OK": 0,
            "LOW": 0,
            "MEDIUM": 0,
            "HIGH": 0,
            "CRITICAL": 0,
            "WARN": 0,
            "DEBUG": 0,
            "FATAL": 0
        })
        self.assertIn("report_sha256", result)

    def test_testssl_summary_wrong_type_top_level(self):
        report = {"not": "array"}
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/testssl/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_testssl_summary_missing_required_field(self):
        report = [{"id": "1", "ip": "127.0.0.1", "port": "443", "severity": "HIGH"}]  # missing "finding"
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/testssl/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_testssl_summary_wrong_type_required_field(self):
        report = [{"id": "1", "ip": "127.0.0.1", "port": 443, "severity": "HIGH", "finding": "test"}]  # port not string
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/testssl/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_testssl_summary_unknown_severity(self):
        report = [{"id": "1", "ip": "127.0.0.1", "port": "443", "severity": "UNKNOWN", "finding": "test"}]
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/testssl/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)
        # Ensure no user input appears in error response
        error_body = cm.exception.read().decode("utf-8")
        self.assertNotIn("UNKNOWN", error_body)

    def test_testssl_summary_secret_marker_absent(self):
        secret_marker = "SECRET_MARKER_2026-10-09"
        report = [
            {"id": secret_marker, "ip": secret_marker, "port": "443", "severity": "HIGH", "finding": secret_marker}
        ]
        result = self.request_json("/api/tool-reports/testssl/summary", {"report": report})
        result_json_str = json.dumps(result)
        self.assertNotIn(secret_marker, result_json_str)
        self.assertEqual(result["severity_counts"]["HIGH"], 1)
        self.assertEqual(result["record_count"], 1)

    def test_testssl_summary_health_200(self):
        report = []
        result = self.request_json("/api/health", None)
        self.assertEqual(result["status"], "ok")

    def test_testssl_summary_exceeds_max_records(self):
        report = [{"id": str(i), "ip": "127.0.0.1", "port": "443", "severity": "INFO", "finding": "test"} for i in range(501)]
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/testssl/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)