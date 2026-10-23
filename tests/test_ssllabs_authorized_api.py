import json
import os
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import server
from storage import Store


class SsllabsAuthorizedApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.base = Path(self.temp.name)
        self.previous_store = server.STORE
        self.previous_limiter = server.LIMITER
        server.STORE = Store(self.base / "data" / "sniper.db")
        server.LIMITER = server.RateLimiter()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.httpd.server_port}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=3)
        server.STORE = self.previous_store
        server.LIMITER = self.previous_limiter
        self.temp.cleanup()

    def post(self, path, payload):
        request = Request(
            self.base_url + path,
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read())
        except HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_control_saved_report_summary_remains_available(self):
        status, body = self.post(
            "/api/tool-reports/ssllabs-host/summary",
            {"report": {"status": "READY", "endpoints": [{"grade": "A"}]}},
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["format"], "ssllabs-v4-host")
        self.assertEqual(body["grade_counts"]["A"], 1)

    def test_direct_authorized_route_uses_one_consent_and_no_registered_records(self):
        summary = {
            "format": "ssllabs-v4-host",
            "assessment_status": "READY",
            "endpoint_count": 1,
            "grade_counts": {
                "A+": 0, "A": 1, "A-": 0, "B": 0, "C": 0,
                "D": 0, "E": 0, "F": 0, "T": 0, "M": 0,
            },
            "report_sha256": "a" * 64,
        }
        with patch.dict(os.environ, {
            "SNIPER_SSLLABS_LIVE_ENABLED": "true",
            "SNIPER_SSLLABS_EMAIL": "registered@example.com",
        }, clear=False), patch("server.run_ssllabs_live", return_value=summary) as run:
            status, body = self.post("/api/tool-runs/ssllabs-authorized", {
                "target": "Example.COM.",
                "confirm_authorized": True,
            })

        self.assertEqual(status, 200)
        self.assertEqual(body["assessment_status"], "READY")
        run.assert_called_once_with("example.com", "registered@example.com")
        receipt = body["authorization_receipt"]
        self.assertEqual(receipt["consent_version"], "ssllabs-third-party-authorization-v1")
        self.assertIs(receipt["confirm_authorized"], True)
        self.assertEqual(receipt["normalized_target"], "example.com")
        self.assertEqual(receipt["third_party"], "Qualys SSL Labs")
        self.assertRegex(receipt["confirmed_at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+00:00$")
        self.assertEqual(receipt["actor"]["id"], "local-operator")
        audit = server.STORE.recent_audit_log(limit=1)[0]
        self.assertEqual(audit["action"], "ssllabs.direct_authorized.completed")
        self.assertEqual(audit["details"]["authorization_receipt"], receipt)

    def test_direct_authorized_route_fails_closed_without_exact_consent_or_with_extra_fields(self):
        cases = (
            {"target": "example.com"},
            {"target": "example.com", "confirm_authorized": False},
            {"target": "example.com", "confirm_authorized": 1},
            {"target": "example.com", "confirm_authorized": True, "engagement_id": "not-needed"},
        )
        for payload in cases:
            with self.subTest(payload=payload):
                status, _ = self.post("/api/tool-runs/ssllabs-authorized", payload)
                self.assertIn(status, (400, 403))

    def test_direct_authorized_route_keeps_public_hostname_and_configuration_gates(self):
        with patch.dict(os.environ, {
            "SNIPER_SSLLABS_LIVE_ENABLED": "true",
            "SNIPER_SSLLABS_EMAIL": "registered@example.com",
        }, clear=False), patch("server.run_ssllabs_live") as run:
            for target in ("127.0.0.1", "service.local", "singlelabel"):
                with self.subTest(target=target):
                    status, _ = self.post("/api/tool-runs/ssllabs-authorized", {
                        "target": target,
                        "confirm_authorized": True,
                    })
                    self.assertEqual(status, 400)
            run.assert_not_called()

        with patch.dict(os.environ, {
            "SNIPER_SSLLABS_LIVE_ENABLED": "false",
            "SNIPER_SSLLABS_EMAIL": "registered@example.com",
        }, clear=False), patch("server.run_ssllabs_live") as run:
            status, _ = self.post("/api/tool-runs/ssllabs-authorized", {
                "target": "example.com",
                "confirm_authorized": True,
            })
            self.assertEqual(status, 503)
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
