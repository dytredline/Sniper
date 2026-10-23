import hashlib
import json
import tempfile
import threading
import unittest
from copy import deepcopy
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import server
from storage import Store


def v1_report():
    return {
        "version": "1.0.0",
        "metadata": {"generatedAt": "2025-01-15T10:30:45.123Z", "k6Version": "1.5.0"},
        "config": {"execution": "local", "duration": 60.0, "script": "private-script.js"},
        "results": {
            "metrics": [
                {"name": "http_reqs", "type": "counter", "contains": "default", "values": {"count": 42}},
                {"name": "http_req_duration", "type": "trend", "contains": "time",
                 "values": {"avg": 30.0, "p(95)": 75.25}},
                {"name": "private URL https://example.test/secret", "type": "counter",
                 "contains": "default", "values": {"count": 2}},
            ],
            "checks": {"results": [{"name": "private check", "passes": 9, "fails": 1}]},
        },
    }


class K6MachineSummaryApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.previous_store = server.STORE
        server.STORE = Store(Path(self.temp.name) / "data" / "sniper.db")
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

    def post(self, path, payload):
        request = Request(self.base_url + path, data=json.dumps(payload).encode(), method="POST",
                          headers={"Content-Type": "application/json"})
        with urlopen(request, timeout=5) as response:
            return json.loads(response.read())

    def machine(self, payload):
        return self.post("/api/tool-reports/k6-machine-summary-v1/summary", payload)

    def assert_machine_bad(self, payload):
        with self.assertRaises(HTTPError) as caught:
            self.machine(payload)
        self.assertEqual(caught.exception.code, 400)

    def test_v1_aggregates_only_fixed_fields_and_hashes_canonically(self):
        report = v1_report()
        response = self.machine({"report": report})
        self.assertEqual(response, {
            "format": "k6-machine-summary-v1",
            "http_requests": 42,
            "duration_p95_ms": 75.25,
            "threshold_counts": {"passed": 0, "failed": 0},
            "report_sha256": hashlib.sha256(json.dumps(
                report, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                allow_nan=False).encode()).hexdigest(),
        })
        encoded = json.dumps(response)
        for private in ("private", "example.test", "secret", "script.js", "check"):
            self.assertNotIn(private, encoded)

    def test_optional_duration_and_checks_do_not_invent_thresholds(self):
        report = v1_report()
        report["results"]["metrics"] = report["results"]["metrics"][:1]
        report["results"]["checks"]["results"][0]["fails"] = 33
        response = self.machine({"report": report})
        self.assertIsNone(response["duration_p95_ms"])
        self.assertEqual(response["threshold_counts"], {"passed": 0, "failed": 0})

    def test_official_example_has_expected_aggregate_values(self):
        example = Path(__file__).resolve().parent / "fixtures/k6_machine_summary_v1_basic.json"
        response = self.machine({"report": json.loads(example.read_text())})
        self.assertEqual(response["http_requests"], 1500)
        self.assertEqual(response["duration_p95_ms"], 421.32)
        self.assertEqual(response["threshold_counts"], {"passed": 0, "failed": 0})

    def test_rejects_wrong_envelope_version_and_classic_report(self):
        report = v1_report()
        self.assert_machine_bad({"report": report, "extra": 1})
        self.assert_machine_bad({"report": {"root_group": {}, "state": {}, "metrics": {}}})
        report["version"] = "2.0.0"
        self.assert_machine_bad({"report": report})
        self.assert_machine_bad({"report": []})

    def test_rejects_ambiguous_and_invalid_metrics(self):
        report = v1_report()
        report["results"]["metrics"].append(deepcopy(report["results"]["metrics"][0]))
        self.assert_machine_bad({"report": report})
        report = v1_report()
        report["results"]["metrics"][0]["values"]["count"] = True
        self.assert_machine_bad({"report": report})
        report = v1_report()
        report["results"]["metrics"][1]["values"]["p(95)"] = -1
        self.assert_machine_bad({"report": report})
        report = v1_report()
        report["results"]["metrics"] = report["results"]["metrics"][1:]
        self.assert_machine_bad({"report": report})
        report = v1_report()
        report["results"]["metrics"] = report["results"]["metrics"][:1] * 501
        self.assert_machine_bad({"report": report})

    def test_large_private_counter_does_not_break_fixed_aggregate(self):
        report = v1_report()
        report["results"]["metrics"][2]["values"]["count"] = 10 ** 1000
        response = self.machine({"report": report})
        self.assertEqual(response["http_requests"], 42)
        self.assertEqual(response["duration_p95_ms"], 75.25)

    def test_k6_1_7_1_complete_snake_case_metadata_from_upstream_issue(self):
        # grafana/k6#6004: 1.7.1 emitted these two names despite the v1 schema.
        report = v1_report()
        report["metadata"] = {
            "generated_at": "2026-05-19T13:30:31.29647397Z",
            "k6_version": "1.7.1",
        }
        result = self.machine({"report": report})
        self.assertEqual(result["format"], "k6-machine-summary-v1")
        self.assertEqual(result["http_requests"], 42)
        self.assertEqual(result["duration_p95_ms"], 75.25)
        self.assertEqual(result["threshold_counts"], {"passed": 0, "failed": 0})
        self.assertEqual(result["report_sha256"], hashlib.sha256(json.dumps(
            report, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False).encode()).hexdigest())
        encoded = json.dumps(result)
        for secret in ("private", "example.test", "script.js", "generated_at", "k6_version"):
            self.assertNotIn(secret, encoded)

    def test_rejects_mixed_partial_and_dual_metadata_aliases(self):
        bad_metadata = [
            {"generatedAt": "2026-05-19T13:30:31Z", "k6_version": "1.7.1"},
            {"generated_at": "2026-05-19T13:30:31Z", "k6Version": "1.7.1"},
            {"generated_at": "2026-05-19T13:30:31Z"},
            {"k6_version": "1.7.1"},
            {"generatedAt": "2026-05-19T13:30:31Z",
             "k6Version": "1.7.1", "generated_at": "2026-05-19T13:30:31Z",
             "k6_version": "1.7.1"},
        ]
        for metadata in bad_metadata:
            with self.subTest(metadata=metadata):
                report = v1_report()
                report["metadata"] = metadata
                self.assert_machine_bad({"report": report})

    def test_classic_endpoint_remains_unchanged(self):
        classic = {
            "root_group": {}, "state": {},
            "metrics": {"http_reqs": {"type": "counter", "values": {"count": 4}}},
        }
        response = self.post("/api/tool-reports/k6-summary-json/summary", {"report": classic})
        self.assertEqual(response["format"], "k6-handle-summary-json")
        self.assertEqual(response["http_requests"], 4)


if __name__ == "__main__":
    unittest.main()
