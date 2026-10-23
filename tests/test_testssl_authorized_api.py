import hashlib
import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

import server
from storage import Store


class TestsslAuthorizedApiTests(unittest.TestCase):
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
        self.opener = build_opener(ProxyHandler({}))

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
            with self.opener.open(request, timeout=5) as response:
                return response.status, json.loads(response.read())
        except HTTPError as exc:
            with exc:
                return exc.code, json.loads(exc.read())

    def test_direct_target_accepts_exact_human_consent_without_registered_records(self):
        normalized = "example.test:443"
        result = {
            "format": "testssl-authorized-v1",
            "profile": "authorized-protocols-v1",
            "record_count": 2,
            "severity_counts": {
                "INFO": 0, "OK": 2, "LOW": 0, "MEDIUM": 0, "HIGH": 0,
                "CRITICAL": 0, "WARN": 0, "DEBUG": 0, "FATAL": 0,
            },
            "report_sha256": "a" * 64,
            "target_sha256": hashlib.sha256(normalized.encode()).hexdigest(),
            "resolved_ip_sha256": "b" * 64,
            "elapsed_seconds": 0.5,
        }
        with patch("server.run_testssl_authorized", return_value=result, create=True) as run:
            status, body = self.post("/api/tool-runs/testssl-authorized", {
                "target": " Example.TEST.:443 ",
                "profile": "protocols",
                "confirm_authorized": True,
            })
        self.assertEqual(status, 200)
        self.assertEqual(body["profile"], "authorized-protocols-v1")
        self.assertEqual(body["report_sha256"], "a" * 64)
        self.assertNotIn("example.test", json.dumps(body).lower())
        receipt = body["authorization_receipt"]
        self.assertEqual(receipt["consent_version"], "direct-target-authorization-v1")
        self.assertIs(receipt["confirm_authorized"], True)
        self.assertRegex(receipt["confirmed_at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+00:00$")
        self.assertEqual(receipt["actor"]["id"], "local-operator")
        run.assert_called_once_with(" Example.TEST.:443 ", profile="protocols")
        audit = server.STORE.recent_audit_log(limit=1)[0]
        self.assertEqual(audit["action"], "testssl.direct_authorized.completed")
        self.assertEqual(audit["details"]["authorization_receipt"], receipt)
        self.assertEqual(audit["details"]["target_sha256"], result["target_sha256"])
        self.assertNotIn("example.test", json.dumps(audit).lower())

    def test_direct_target_rejects_missing_consent_extra_fields_and_custom_profile(self):
        cases = (
            ({"target": "example.test:443", "profile": "protocols"}, 403),
            ({"target": "example.test:443", "profile": "protocols", "confirm_authorized": 1}, 403),
            ({"target": "example.test:443", "profile": "custom", "confirm_authorized": True}, 400),
            ({"target": "example.test:443", "profile": "full", "confirm_authorized": True,
              "flags": ["--phone-out"]}, 400),
        )
        for payload, expected in cases:
            with self.subTest(payload=payload):
                status, _ = self.post("/api/tool-runs/testssl-authorized", payload)
                self.assertEqual(status, expected)

    def test_existing_loopback_route_remains_available_as_control(self):
        legacy = {
            "format": "testssl-loopback-v1",
            "record_count": 0,
            "severity_counts": {
                "INFO": 0, "OK": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0,
                "CRITICAL": 0, "WARN": 0, "DEBUG": 0, "FATAL": 0,
            },
            "report_sha256": "c" * 64,
            "elapsed_seconds": 0.1,
        }
        with patch("server.run_testssl_loopback", return_value=legacy) as run:
            status, body = self.post("/api/tool-runs/testssl-protocols", {
                "confirm_local": True,
                "target": "127.0.0.1:443",
            })
        self.assertEqual(status, 200)
        self.assertEqual(body["format"], "testssl-loopback-v1")
        run.assert_called_once_with("127.0.0.1", 443)


if __name__ == "__main__":
    unittest.main()
