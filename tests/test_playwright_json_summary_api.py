from __future__ import annotations

import hashlib
import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import server
from storage import Store

ROUTE = "/api/tool-reports/playwright-json/summary"


def sample_report():
    return {
        "config": {"rootDir": "/private/source"},
        "suites": [{
            "title": "SECRET suite", "file": "/private/source/test.spec.ts",
            "specs": [{"title": "GET /secret?token=PRIVATE", "tests": [
                {"status": "expected", "results": [{"status": "passed", "stdout": ["TOKEN"]}]},
                {"status": "flaky", "results": [{"status": "failed", "stderr": ["PRIVATE"]}, {"status": "passed"}]},
            ]}],
            "suites": [{"title": "nested", "specs": [
                {"title": "child", "tests": [{"status": "unexpected", "results": [{"status": "failed", "errors": ["SECRET"]}]}]},
                {"title": "skipped", "tests": [{"status": "skipped", "results": []}]},
            ]}],
        }],
        "errors": [{"message": "SECRET root error"}],
        "stats": {"expected": 1, "flaky": 1, "unexpected": 1, "skipped": 1, "duration": 100},
    }


class PlaywrightJsonSummaryApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.previous_store = server.STORE
        server.STORE = Store(Path(self.temp.name) / "data" / "sniper.db")
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}{ROUTE}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        server.STORE = self.previous_store
        self.temp.cleanup()

    def request(self, body):
        request = Request(self.url, data=json.dumps(body).encode("utf-8"), method="POST",
                          headers={"Content-Type": "application/json"})
        with urlopen(request, timeout=5) as response:
            return json.load(response)

    def test_nested_cases_are_counted_by_outcome_and_private_fields_never_echoed(self):
        report = sample_report()
        data = self.request({"report": report})
        canonical = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        self.assertEqual(data, {
            "format": "playwright-json", "file_count": 1, "test_count": 4,
            "outcome_counts": {"expected": 1, "skipped": 1, "unexpected": 1, "flaky": 1},
            "report_sha256": hashlib.sha256(canonical.encode()).hexdigest(),
        })
        for private in ("SECRET", "PRIVATE", "TOKEN", "test.spec.ts"):
            self.assertNotIn(private, json.dumps(data))

    def test_crosschecks_top_stats_instead_of_trusting_them(self):
        report = sample_report()
        report["stats"]["expected"] = 3
        with self.assertRaises(HTTPError) as caught:
            self.request({"report": report})
        self.assertEqual(caught.exception.code, 400)

    def test_invalid_report_and_extra_request_fields_rejected(self):
        report = sample_report()
        bad = [{}, {"report": []}, {"report": report, "target": "external.invalid"}]
        for body in bad:
            with self.subTest(body=str(body)[:20]), self.assertRaises(HTTPError) as caught:
                self.request(body)
            self.assertEqual(caught.exception.code, 400)
        report["suites"][0]["specs"][0]["tests"][0]["status"] = "unbounded"
        with self.assertRaises(HTTPError) as caught:
            self.request({"report": report})
        self.assertEqual(caught.exception.code, 400)

    def test_empty_and_oversize_reports_are_rejected(self):
        report = sample_report()
        report["suites"] = []
        report["stats"] = dict.fromkeys(("expected", "skipped", "unexpected", "flaky"), 0)
        with self.assertRaises(HTTPError) as caught:
            self.request({"report": report})
        self.assertEqual(caught.exception.code, 400)
        report = sample_report()
        report["errors"] = [{"message": "A" * 130000}]
        with self.assertRaises(HTTPError) as caught:
            self.request({"report": report})
        self.assertEqual(caught.exception.code, 400)


if __name__ == "__main__":
    unittest.main()
