import json
import re
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
import tempfile
import threading
from urllib.request import Request, urlopen
from urllib.error import HTTPError

import server
from storage import Store


class ZapTraditionalJsonSummaryApiTests(unittest.TestCase):
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

    def test_zap_summary_riskcode3_count2_and_riskcode0_count1(self):
        report = {
            "site": [
                {
                    "alerts": [
                        {"riskcode": "3", "count": "2"},
                        {"riskcode": "0", "count": "1"}
                    ]
                }
            ]
        }
        result = self.request_json("/api/tool-reports/zap/summary", {"report": report})
        self.assertEqual(result["format"], "zap-traditional-json")
        self.assertEqual(result["site_count"], 1)
        self.assertEqual(result["alert_type_count"], 2)
        self.assertEqual(result["instance_count"], 3)
        # Risk_counts counts ALERT TYPES, not instances
        self.assertEqual(result["risk_counts"], {
            "informational": 1,
            "low": 0,
            "medium": 0,
            "high": 1
        })
        self.assertIn("report_sha256", result)

    def test_zap_summary_empty_site_list(self):
        report = {"site": []}
        result = self.request_json("/api/tool-reports/zap/summary", {"report": report})
        self.assertEqual(result["format"], "zap-traditional-json")
        self.assertEqual(result["site_count"], 0)
        self.assertEqual(result["alert_type_count"], 0)
        self.assertEqual(result["instance_count"], 0)
        self.assertEqual(result["risk_counts"], {
            "informational": 0,
            "low": 0,
            "medium": 0,
            "high": 0
        })
        self.assertIn("report_sha256", result)

    def test_zap_summary_wrong_shape_top_level_alerts(self):
        report = {"alerts": []}
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/zap/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_zap_summary_invalid_riskcode(self):
        report = {
            "site": [
                {
                    "alerts": [
                        {"riskcode": "5", "count": "1"}
                    ]
                }
            ]
        }
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/zap/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_zap_summary_secret_marker_absent(self):
        secret_marker = "SECRET_MARKER_2026-10-09"
        report = {
            "site": [
                {
                    "alerts": [
                        {
                            "riskcode": "3",
                            "count": "1",
                            "name": secret_marker,
                            "description": secret_marker,
                            "uri": secret_marker,
                            "evidence": secret_marker,
                            "attack": secret_marker
                        }
                    ]
                }
            ]
        }
        result = self.request_json("/api/tool-reports/zap/summary", {"report": report})
        # Serialize result to verify marker is absent in the raw JSON string
        result_json_str = json.dumps(result)
        self.assertNotIn(secret_marker, result_json_str)
        # Verify expected counts
        self.assertEqual(result["risk_counts"], {
            "informational": 0,
            "low": 0,
            "medium": 0,
            "high": 1
        })
        self.assertEqual(result["instance_count"], 1)

    def test_zap_summary_health_200(self):
        report = {"site": []}
        result = self.request_json("/api/tool-reports/zap/summary", {"report": report})
        self.assertEqual(result["format"], "zap-traditional-json")

    def test_zap_summary_count_negative(self):
        report = {
            "site": [
                {
                    "alerts": [
                        {"riskcode": "3", "count": "-1"}
                    ]
                }
            ]
        }
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/zap/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_zap_summary_count_leading_plus(self):
        report = {
            "site": [
                {
                    "alerts": [
                        {"riskcode": "3", "count": "+2"}
                    ]
                }
            ]
        }
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/zap/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_zap_summary_count_with_spaces(self):
        report = {
            "site": [
                {
                    "alerts": [
                        {"riskcode": "3", "count": " 2"}
                    ]
                }
            ]
        }
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/zap/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)
