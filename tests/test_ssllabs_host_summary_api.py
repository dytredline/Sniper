import hashlib
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


class SsllabsHostSummaryApiTests(unittest.TestCase):
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

    def test_ssllabs_summary_ready_mixed_grades(self):
        report = {
            "status": "READY",
            "endpoints": [
                {"grade": "A+"},
                {"grade": "E"},
                {"grade": None}
            ]
        }
        result = self.request_json("/api/tool-reports/ssllabs-host/summary", {"report": report})
        self.assertEqual(result["format"], "ssllabs-v4-host")
        self.assertEqual(result["assessment_status"], "READY")
        self.assertEqual(result["endpoint_count"], 3)
        self.assertEqual(result["grade_counts"], {
            "A+": 1, "A": 0, "A-": 0, "B": 0, "C": 0,
            "D": 0, "E": 1, "F": 0, "T": 0, "M": 0
        })
        self.assertIn("report_sha256", result)
        expected_sha = hashlib.sha256(
            json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        self.assertEqual(result["report_sha256"], expected_sha)

    def test_ssllabs_summary_error_empty_endpoints(self):
        report = {
            "status": "ERROR",
            "endpoints": []
        }
        result = self.request_json("/api/tool-reports/ssllabs-host/summary", {"report": report})
        self.assertEqual(result["assessment_status"], "ERROR")
        self.assertEqual(result["endpoint_count"], 0)
        self.assertEqual(result["grade_counts"], {g: 0 for g in ["A+", "A", "A-", "B", "C", "D", "E", "F", "T", "M"]})

    def test_ssllabs_summary_in_progress_ungraded(self):
        report = {
            "status": "IN_PROGRESS",
            "endpoints": [
                {"grade": None},
                {"grade": "A"}
            ]
        }
        result = self.request_json("/api/tool-reports/ssllabs-host/summary", {"report": report})
        self.assertEqual(result["assessment_status"], "IN_PROGRESS")
        self.assertEqual(result["endpoint_count"], 2)
        self.assertEqual(result["grade_counts"]["A"], 1)

    def test_ssllabs_summary_non_object_report_http_400(self):
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/ssllabs-host/summary", {"report": [1, 2, 3]})
        self.assertEqual(cm.exception.code, 400)

    def test_ssllabs_summary_missing_status_http_400(self):
        report = {"endpoints": []}
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/ssllabs-host/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_ssllabs_summary_invalid_status_http_400(self):
        report = {"status": "UNKNOWN", "endpoints": []}
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/ssllabs-host/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)
        error_body = cm.exception.read().decode("utf-8")
        self.assertNotIn("UNKNOWN", error_body)

    def test_ssllabs_summary_missing_endpoints_http_400(self):
        report = {"status": "READY"}
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/ssllabs-host/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_ssllabs_summary_endpoint_not_object_http_400(self):
        report = {"status": "READY", "endpoints": ["not-object"]}
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/ssllabs-host/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_ssllabs_summary_too_many_endpoints_http_400(self):
        report = {
            "status": "READY",
            "endpoints": [{"grade": "A"} for _ in range(501)]
        }
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/ssllabs-host/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_ssllabs_summary_invalid_grade_http_400(self):
        report = {
            "status": "READY",
            "endpoints": [{"grade": "G"}]
        }
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/ssllabs-host/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)
        error_body = cm.exception.read().decode("utf-8")
        # Geçersiz not değeri hata metnine yansımamalı ("Geçersiz" sözcüğündeki G sayılmaz).
        self.assertNotRegex(json.loads(error_body)["error"], r"\bG\b")

    def test_ssllabs_summary_non_string_grade_http_400(self):
        report = {
            "status": "READY",
            "endpoints": [{"grade": 123}]
        }
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/ssllabs-host/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_ssllabs_summary_exact_output_keys(self):
        report = {"status": "READY", "endpoints": [{"grade": "A"}]}
        result = self.request_json("/api/tool-reports/ssllabs-host/summary", {"report": report})
        self.assertEqual(set(result.keys()), {"format", "assessment_status", "endpoint_count", "grade_counts", "report_sha256"})

    def test_ssllabs_summary_no_hostname_ip_cert_in_output(self):
        report = {
            "status": "READY",
            "endpoints": [
                {
                    "grade": "A",
                    "ipAddress": "1.2.3.4",
                    "serverName": "example.com",
                    "details": {"cert": {"subject": "CN=example.com"}}
                }
            ]
        }
        result = self.request_json("/api/tool-reports/ssllabs-host/summary", {"report": report})
        self.assertNotIn("ipAddress", result)
        self.assertNotIn("serverName", result)
        self.assertNotIn("cert", result)
        self.assertNotIn("statusMessage", result)
        self.assertNotIn("host", result)
