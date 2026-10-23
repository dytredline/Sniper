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


class NucleiJsonlSummaryApiTests(unittest.TestCase):
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

    def test_nuclei_summary_mixed_severity(self):
        report = [
            {"template-id": "cve-2021-1234", "type": "http", "info": {"severity": "high"}},
            {"template-id": "cve-2021-5678", "type": "http", "info": {"severity": "medium"}},
            {"template-id": "cve-2021-1234", "type": "http", "info": {"severity": "low"}},
            {"template-id": "cve-2021-9012", "type": "network", "info": {"severity": "critical"}},
            {"template-id": "cve-2021-3456", "type": "http", "info": {}}
        ]
        result = self.request_json("/api/tool-reports/nuclei-jsonl/summary", {"report": report})
        self.assertEqual(result["format"], "nuclei-jsonl")
        self.assertEqual(result["record_count"], 5)
        self.assertEqual(result["severity_counts"], {"info": 0, "low": 1, "medium": 1, "high": 1, "critical": 1, "unknown": 1})
        self.assertEqual(result["unique_template_count"], 4)
        self.assertIn("report_sha256", result)
        self.assertEqual(set(result.keys()), {"format", "record_count", "severity_counts", "unique_template_count", "report_sha256"})
        # Validate SHA-256 format
        sha = result["report_sha256"]
        self.assertEqual(len(sha), 64)
        self.assertTrue(all(c in '0123456789abcdef' for c in sha))
        # Validate exact SHA-256 equals raw report digest
        expected_sha = hashlib.sha256(json.dumps(report, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(sha, expected_sha)

    def test_nuclei_summary_empty_array(self):
        report = []
        result = self.request_json("/api/tool-reports/nuclei-jsonl/summary", {"report": report})
        self.assertEqual(result["format"], "nuclei-jsonl")
        self.assertEqual(result["record_count"], 0)
        self.assertEqual(result["severity_counts"], {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0, "unknown": 0})
        self.assertEqual(result["unique_template_count"], 0)
        self.assertIn("report_sha256", result)
        self.assertEqual(set(result.keys()), {"format", "record_count", "severity_counts", "unique_template_count", "report_sha256"})
        # Validate exact SHA-256 equals raw report digest
        expected_sha = hashlib.sha256(json.dumps(report, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(result["report_sha256"], expected_sha)

    def test_nuclei_summary_malformed_http_400(self):
        report = [
            {"template-id": "", "type": "http", "info": {"severity": "high"}}
        ]
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/nuclei-jsonl/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_nuclei_summary_missing_template_id(self):
        report = [
            {"type": "http", "info": {"severity": "high"}}
        ]
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/nuclei-jsonl/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_nuclei_summary_missing_type(self):
        report = [
            {"template-id": "cve-2021-1234", "info": {"severity": "high"}}
        ]
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/nuclei-jsonl/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_nuclei_summary_missing_info(self):
        report = [
            {"template-id": "cve-2021-1234", "type": "http"}
        ]
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/nuclei-jsonl/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_nuclei_summary_uppercase_severity_rejected(self):
        report = [
            {"template-id": "cve-2021-1234", "type": "http", "info": {"severity": "CRITICAL"}}
        ]
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/nuclei-jsonl/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_nuclei_summary_non_object_record(self):
        report = ["not an object"]
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/nuclei-jsonl/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_nuclei_summary_exceeds_limit(self):
        report = [{"template-id": f"t{i}", "type": "http", "info": {}} for i in range(501)]
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/nuclei-jsonl/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_nuclei_summary_privacy_no_echo(self):
        secret_marker = "SECRET_MARKER_2026-10-09"
        report = [
            {"template-id": secret_marker, "type": "http", "info": {"severity": "high"}}
        ]
        result = self.request_json("/api/tool-reports/nuclei-jsonl/summary", {"report": report})
        result_json_str = json.dumps(result)
        self.assertNotIn(secret_marker, result_json_str)
        self.assertEqual(result["record_count"], 1)
        self.assertEqual(result["unique_template_count"], 1)

    def test_nuclei_summary_health_200(self):
        result = self.request_json("/api/health", None)
        self.assertEqual(result["status"], "ok")

    def test_nuclei_summary_null_severity_rejected(self):
        report = [
            {"template-id": "t1", "type": "http", "info": {"severity": None}}
        ]
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/nuclei-jsonl/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_nuclei_summary_missing_severity_counts_unknown(self):
        report = [
            {"template-id": "t1", "type": "http", "info": {}},
            {"template-id": "t2", "type": "http", "info": {"severity": "low"}}
        ]
        result = self.request_json("/api/tool-reports/nuclei-jsonl/summary", {"report": report})
        self.assertEqual(result["severity_counts"], {"info": 0, "low": 1, "medium": 0, "high": 0, "critical": 0, "unknown": 1})
        self.assertEqual(result["record_count"], 2)
        self.assertEqual(result["unique_template_count"], 2)
        # Validate exact SHA-256 equals raw report digest
        expected_sha = hashlib.sha256(json.dumps(report, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(result["report_sha256"], expected_sha)
