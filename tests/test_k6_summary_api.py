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


def classic_report():
    return {
        "root_group": {"name": "private check", "checks": [{"name": "private check"}]},
        "state": {"testRunDurationMs": 1000},
        "metrics": {
            "http_reqs": {"type": "counter", "contains": "default", "values": {"count": 42, "rate": 1.5}},
            "http_req_duration": {"type": "trend", "contains": "time", "values": {"p(95)": 123.5},
                                  "thresholds": {"p(95)<250 private URL": {"ok": True}}},
            "private_metric{url:https://private.example.test/secret}": {
                "type": "rate", "values": {"rate": 0.5},
                "thresholds": {"private condition": {"ok": False}},
            },
        },
    }


class K6SummaryApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.previous_store = server.STORE
        server.STORE = Store(Path(self.temp.name) / "data" / "sniper.db")
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/api/tool-reports/k6-summary-json/summary"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        server.STORE = self.previous_store
        self.temp.cleanup()

    def post(self, payload):
        request = Request(self.url, data=json.dumps(payload).encode(), method="POST",
                          headers={"Content-Type": "application/json"})
        with urlopen(request, timeout=5) as response:
            return json.loads(response.read())

    def assert_bad(self, report):
        with self.assertRaises(HTTPError) as caught:
            self.post({"report": report})
        self.assertEqual(caught.exception.code, 400)

    def test_classic_report_aggregates_only_fixed_fields(self):
        response = self.post({"report": classic_report()})
        self.assertEqual(set(response), {"format", "http_requests", "duration_p95_ms", "threshold_counts", "report_sha256"})
        self.assertEqual(response["format"], "k6-handle-summary-json")
        self.assertEqual(response["http_requests"], 42)
        self.assertEqual(response["duration_p95_ms"], 123.5)
        self.assertEqual(response["threshold_counts"], {"passed": 1, "failed": 1})
        self.assertRegex(response["report_sha256"], r"^[0-9a-f]{64}$")
        encoded = json.dumps(response)
        for private in ("private", "example.test", "secret", "condition", "p(95)<250"):
            self.assertNotIn(private, encoded)

    def test_duration_p95_is_optional_and_empty_thresholds_are_zero(self):
        report = classic_report()
        del report["metrics"]["http_req_duration"]
        del report["metrics"]["private_metric{url:https://private.example.test/secret}"]
        response = self.post({"report": report})
        self.assertIsNone(response["duration_p95_ms"])
        self.assertEqual(response["threshold_counts"], {"passed": 0, "failed": 0})

    def test_rejects_new_or_ambiguous_machine_summary(self):
        report = classic_report()
        self.assert_bad({"metrics": report["metrics"]})
        report["$schema"] = "https://schemas.k6.io/summary/1.0.0/schema.json"
        self.assert_bad(report)

    def test_rejects_invalid_metrics_and_thresholds(self):
        report = classic_report()
        report["metrics"]["http_reqs"]["values"]["count"] = True
        self.assert_bad(report)
        report = classic_report()
        report["metrics"]["http_req_duration"]["values"]["p(95)"] = -2
        self.assert_bad(report)
        report = classic_report()
        report["metrics"]["http_req_duration"]["thresholds"]["p(95)<250 private URL"]["ok"] = 1
        self.assert_bad(report)
        report = classic_report()
        report["metrics"]["http_reqs"] = {"type": "rate", "values": {"count": 42}}
        self.assert_bad(report)

    def test_limits_metric_and_threshold_counts(self):
        report = classic_report()
        report["metrics"].update({f"private_{index}": {"type": "counter", "values": {"count": 0}}
                                  for index in range(500)})
        self.assert_bad(report)
        report = classic_report()
        report["metrics"]["http_reqs"]["thresholds"] = {f"private_{index}": {"ok": True}
                                                        for index in range(501)}
        self.assert_bad(report)


if __name__ == "__main__":
    unittest.main()
