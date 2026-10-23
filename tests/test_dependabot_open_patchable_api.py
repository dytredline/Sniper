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


class DependabotOpenPatchableApiTests(unittest.TestCase):
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

    def test_dependabot_open_with_patch_and_fixed(self):
        alerts = [
            {
                "state": "open",
                "security_advisory": {"severity": "high"},
                "security_vulnerability": {"first_patched_version": {"identifier": "2.0.1"}}
            },
            {
                "state": "open",
                "security_advisory": {"severity": "medium"},
                "security_vulnerability": {"first_patched_version": {}}
            },
            {
                "state": "fixed",
                "security_advisory": {"severity": "low"},
                "security_vulnerability": {"first_patched_version": {"identifier": "1.0.0"}}
            }
        ]
        result = self.request_json("/api/tool-reports/dependabot/summary", {"alerts": alerts})
        self.assertEqual(result["format"], "dependabot-alerts")
        self.assertEqual(result["alert_count"], 3)
        self.assertEqual(result["state_counts"], {
            "open": 2,
            "dismissed": 0,
            "fixed": 1,
            "auto_dismissed": 0
        })
        self.assertEqual(result["open_alerts_with_available_patched_version"], 1)

    def test_dependabot_open_blank_and_whitespace_identifier(self):
        alerts = [
            {
                "state": "open",
                "security_advisory": {"severity": "high"},
                "security_vulnerability": {"first_patched_version": {"identifier": ""}}
            },
            {
                "state": "open",
                "security_advisory": {"severity": "medium"},
                "security_vulnerability": {"first_patched_version": {"identifier": "   "}}
            },
            {
                "state": "dismissed",
                "security_advisory": {"severity": "low"},
                "security_vulnerability": {"first_patched_version": {"identifier": "1.0.0"}}
            }
        ]
        result = self.request_json("/api/tool-reports/dependabot/summary", {"alerts": alerts})
        self.assertEqual(result["open_alerts_with_available_patched_version"], 0)

    def test_dependabot_open_missing_vulnerability_fields(self):
        alerts = [
            {
                "state": "open",
                "security_advisory": {"severity": "high"}
            },
            {
                "state": "open",
                "security_advisory": {"severity": "medium"},
                "security_vulnerability": {}
            },
            {
                "state": "open",
                "security_advisory": {"severity": "low"},
                "security_vulnerability": {"first_patched_version": {}}
            }
        ]
        result = self.request_json("/api/tool-reports/dependabot/summary", {"alerts": alerts})
        self.assertEqual(result["open_alerts_with_available_patched_version"], 0)

    def test_dependabot_open_malformed_identifier(self):
        alerts = [
            {
                "state": "open",
                "security_advisory": {"severity": "high"},
                "security_vulnerability": {"first_patched_version": {"identifier": None}}
            },
            {
                "state": "open",
                "security_advisory": {"severity": "medium"},
                "security_vulnerability": {"first_patched_version": {"identifier": 123}}
            },
            {
                "state": "open",
                "security_advisory": {"severity": "low"},
                "security_vulnerability": {"first_patched_version": {"identifier": "2.0.0"}}
            }
        ]
        result = self.request_json("/api/tool-reports/dependabot/summary", {"alerts": alerts})
        self.assertEqual(result["open_alerts_with_available_patched_version"], 1)

    def test_dependabot_open_no_security_vulnerability_key(self):
        alerts = [
            {
                "state": "open",
                "security_advisory": {"severity": "high"}
            },
            {
                "state": "open",
                "security_advisory": {"severity": "medium"},
                "security_vulnerability": None
            }
        ]
        result = self.request_json("/api/tool-reports/dependabot/summary", {"alerts": alerts})
        self.assertEqual(result["open_alerts_with_available_patched_version"], 0)

    def test_dependabot_open_all_valid_patches(self):
        alerts = [
            {
                "state": "open",
                "security_advisory": {"severity": "high"},
                "security_vulnerability": {"first_patched_version": {"identifier": "1.0.1"}}
            },
            {
                "state": "open",
                "security_advisory": {"severity": "critical"},
                "security_vulnerability": {"first_patched_version": {"identifier": "2.0.0"}}
            }
        ]
        result = self.request_json("/api/tool-reports/dependabot/summary", {"alerts": alerts})
        self.assertEqual(result["open_alerts_with_available_patched_version"], 2)
