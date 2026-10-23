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


class TrufflehogNativeSummaryApiTests(unittest.TestCase):
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

    def test_trufflehog_summary_mixed_verified(self):
        report = [
            {"DetectorName": "AWS", "Verified": True},
            {"DetectorName": "GitHub Token", "Verified": False},
            {"DetectorName": "AWS", "Verified": False}
        ]
        result = self.request_json("/api/tool-reports/trufflehog/summary", {"report": report})
        self.assertEqual(result["format"], "trufflehog-native-json-records")
        self.assertEqual(result["total_findings"], 3)
        self.assertEqual(result["verified_findings"], 1)
        self.assertEqual(result["unverified_findings"], 2)
        self.assertEqual(result["detectors_triggered"], 2)
        self.assertEqual(set(result.keys()), {"format", "total_findings", "verified_findings", "unverified_findings", "detectors_triggered"})

    def test_trufflehog_summary_empty_array(self):
        report = []
        result = self.request_json("/api/tool-reports/trufflehog/summary", {"report": report})
        self.assertEqual(result["format"], "trufflehog-native-json-records")
        self.assertEqual(result["total_findings"], 0)
        self.assertEqual(result["verified_findings"], 0)
        self.assertEqual(result["unverified_findings"], 0)
        self.assertEqual(result["detectors_triggered"], 0)
        self.assertEqual(set(result.keys()), {"format", "total_findings", "verified_findings", "unverified_findings", "detectors_triggered"})

    def test_trufflehog_summary_repeated_detector(self):
        report = [
            {"DetectorName": "SameDetector", "Verified": True},
            {"DetectorName": "SameDetector", "Verified": False}
        ]
        result = self.request_json("/api/tool-reports/trufflehog/summary", {"report": report})
        self.assertEqual(result["total_findings"], 2)
        self.assertEqual(result["verified_findings"], 1)
        self.assertEqual(result["unverified_findings"], 1)
        self.assertEqual(result["detectors_triggered"], 1)
        self.assertEqual(set(result.keys()), {"format", "total_findings", "verified_findings", "unverified_findings", "detectors_triggered"})

    def test_trufflehog_summary_wrong_type_top_level(self):
        report = {"not": "array"}
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/trufflehog/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_trufflehog_summary_missing_detector_name(self):
        report = [{"Verified": True}]
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/trufflehog/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_trufflehog_summary_missing_verified(self):
        report = [{"DetectorName": "AWS"}]
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/trufflehog/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_trufflehog_summary_wrong_type_detector_name(self):
        report = [{"DetectorName": 123, "Verified": True}]
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/trufflehog/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_trufflehog_summary_wrong_type_verified(self):
        report = [{"DetectorName": "AWS", "Verified": "true"}]
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/trufflehog/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_trufflehog_summary_exceeds_max_findings(self):
        report = [{"DetectorName": "r", "Verified": True} for _ in range(501)]
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/trufflehog/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_trufflehog_summary_secret_marker_absent(self):
        secret_marker = "SECRET_MARKER_2026-10-09"
        report = [{"DetectorName": secret_marker, "Verified": True}]
        result = self.request_json("/api/tool-reports/trufflehog/summary", {"report": report})
        result_json_str = json.dumps(result)
        self.assertNotIn(secret_marker, result_json_str)
        self.assertEqual(result["total_findings"], 1)
        self.assertEqual(result["verified_findings"], 1)
        self.assertEqual(result["unverified_findings"], 0)
        self.assertEqual(result["detectors_triggered"], 1)
        self.assertEqual(set(result.keys()), {"format", "total_findings", "verified_findings", "unverified_findings", "detectors_triggered"})

    def test_trufflehog_summary_health_200(self):
        result = self.request_json("/api/health", None)
        self.assertEqual(result["status"], "ok")