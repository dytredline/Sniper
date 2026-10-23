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


class DependabotAlertsSummaryApiTests(unittest.TestCase):
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

    def test_dependabot_open_high_and_fixed_medium(self):
        alerts = [
            {
                "state": "open",
                "security_advisory": {"severity": "high"}
            },
            {
                "state": "fixed",
                "security_advisory": {"severity": "medium"}
            }
        ]
        result = self.request_json("/api/tool-reports/dependabot/summary", {"alerts": alerts})
        self.assertEqual(result["format"], "dependabot-alerts")
        self.assertEqual(result["alert_count"], 2)
        self.assertEqual(result["state_counts"], {
            "open": 1,
            "dismissed": 0,
            "fixed": 1,
            "auto_dismissed": 0
        })
        self.assertEqual(result["severity_counts"], {
            "low": 0,
            "medium": 1,
            "high": 1,
            "critical": 0
        })
        self.assertIn("report_sha256", result)
        self.assertEqual(len(result["report_sha256"]), 64)

    def test_dependabot_empty_alerts(self):
        result = self.request_json("/api/tool-reports/dependabot/summary", {"alerts": []})
        self.assertEqual(result["format"], "dependabot-alerts")
        self.assertEqual(result["alert_count"], 0)
        self.assertEqual(result["state_counts"], {
            "open": 0,
            "dismissed": 0,
            "fixed": 0,
            "auto_dismissed": 0
        })
        self.assertEqual(result["severity_counts"], {
            "low": 0,
            "medium": 0,
            "high": 0,
            "critical": 0
        })
        self.assertIn("report_sha256", result)

    def test_dependabot_missing_alerts_key(self):
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/dependabot/summary", {})
        self.assertEqual(cm.exception.code, 400)

    def test_dependabot_alerts_not_array(self):
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/dependabot/summary", {"alerts": "not-array"})
        self.assertEqual(cm.exception.code, 400)

    def test_dependabot_alert_not_object(self):
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/dependabot/summary", {"alerts": ["not-object"]})
        self.assertEqual(cm.exception.code, 400)

    def test_dependabot_missing_state(self):
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/dependabot/summary", {"alerts": [{"security_advisory": {"severity": "high"}}]})
        self.assertEqual(cm.exception.code, 400)

    def test_dependabot_missing_security_advisory(self):
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/dependabot/summary", {"alerts": [{"state": "open"}]})
        self.assertEqual(cm.exception.code, 400)

    def test_dependabot_missing_severity(self):
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/dependabot/summary", {"alerts": [{"state": "open", "security_advisory": {}}]})
        self.assertEqual(cm.exception.code, 400)

    def test_dependabot_invalid_state_OPEN(self):
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/dependabot/summary", {"alerts": [{"state": "OPEN", "security_advisory": {"severity": "high"}}]})
        self.assertEqual(cm.exception.code, 400)

    def test_dependabot_invalid_state_with_spaces(self):
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/dependabot/summary", {"alerts": [{"state": " open ", "security_advisory": {"severity": "high"}}]})
        self.assertEqual(cm.exception.code, 400)

    def test_dependabot_invalid_severity_HIGH(self):
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/dependabot/summary", {"alerts": [{"state": "open", "security_advisory": {"severity": "HIGH"}}]})
        self.assertEqual(cm.exception.code, 400)

    def test_dependabot_invalid_severity_moderate(self):
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/dependabot/summary", {"alerts": [{"state": "open", "security_advisory": {"severity": "moderate"}}]})
        self.assertEqual(cm.exception.code, 400)

    def test_dependabot_secret_marker_absent(self):
        secret_marker = "SECRET_MARKER_2026-10-09"
        alerts = [
            {
                "state": "open",
                "security_advisory": {"severity": "high"},
                "package": {"name": secret_marker},
                "manifest_path": secret_marker,
                "repository": {"url": secret_marker},
                "advisory": {"id": secret_marker, "summary": secret_marker, "description": secret_marker}
            }
        ]
        result = self.request_json("/api/tool-reports/dependabot/summary", {"alerts": alerts})
        result_json_str = json.dumps(result)
        self.assertNotIn(secret_marker, result_json_str)
        self.assertEqual(result["alert_count"], 1)
        self.assertEqual(result["severity_counts"]["high"], 1)

    def test_dependabot_health_200(self):
        result = self.request_json("/api/tool-reports/dependabot/summary", {"alerts": []})
        self.assertEqual(result["format"], "dependabot-alerts")

    def test_dependabot_too_many_alerts(self):
        alerts = [{"state": "open", "security_advisory": {"severity": "low"}} for _ in range(501)]
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/dependabot/summary", {"alerts": alerts})
        self.assertEqual(cm.exception.code, 400)