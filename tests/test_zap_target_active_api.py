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
from scanner import normalize_target
from storage import Store


class ZapTargetActiveApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.root = Path(self.temp.name)
        self.previous_store, self.previous_host, self.previous_port = server.STORE, server.HOST, server.PORT
        server.STORE = Store(self.root / "data" / "sniper.db")
        server.HOST = "127.0.0.1"
        self.target = server.STORE.create_target(normalize_target("https://target.example/"))
        from datetime import datetime, timezone, timedelta
        now = datetime.now(timezone.utc)
        start_str = (now - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        end_str = (now + timedelta(hours=1, minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        valid_window = f"{start_str}/{end_str}"
        self.engagement = server.STORE.create_engagement(
            target_id=self.target["id"], name="Fixture only",
            authorization_ref="FIXTURE-AUTHORIZATION", scope_notes="One exact URL",
            out_of_scope="", test_window=valid_window, special_approvals={},
        )
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.httpd.daemon_threads = True
        server.PORT = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.env = patch.dict(os.environ, {"SNIPER_DATA_DIR": str(self.root / "data")})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.httpd.shutdown(); self.httpd.server_close(); self.thread.join(timeout=2)
        server.STORE, server.HOST, server.PORT = self.previous_store, self.previous_host, self.previous_port
        self.temp.cleanup()

    def post(self, payload):
        req = Request(
            f"http://127.0.0.1:{self.httpd.server_address[1]}/api/tool-runs/zap-target-active",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"}, method="POST",
        )
        try:
            with urlopen(req, timeout=5) as response:
                return response.status, json.loads(response.read())
        except HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def body(self):
        return {"target_id": self.target["id"], "engagement_id": self.engagement["id"],
                "confirm_authorized": True, "confirm_active": True}

    def test_active_route_requires_stored_authorized_target_and_returns_sanitized_runtime_result(self):
        expected = {"format":"zap-target-active-v1", "profile":"single-url-active-v1",
                    "site_count":1,"alert_type_count":1,"instance_count":2,
                    "risk_counts":{"informational":0,"low":1,"medium":0,"high":0},
                    "report_sha256":"a"*64,"elapsed_seconds":1.25}
        with patch.object(server, "run_zap_target_active", create=True, return_value=expected) as runner:
            status, data = self.post(self.body())
        self.assertEqual(status, 200)
        self.assertEqual(data, expected)
        runner.assert_called_once_with(self.target)
        self.assertNotIn("target.example", json.dumps(data))

    def test_explicit_confirmations_and_no_target_override(self):
        for body in ({**self.body(),"confirm_authorized":False},
                     {**self.body(),"confirm_active":False},
                     {**self.body(),"url":"https://other.invalid/"},
                     {**self.body(),"unexpected":True}):
            with self.subTest(body=body):
                status,_ = self.post(body)
                self.assertIn(status,(400,403))

    def test_engagement_mismatch_and_exclusions_fail_closed(self):
        other = server.STORE.create_target(normalize_target("https://other.example/"))
        status,_ = self.post({**self.body(),"target_id":other["id"]})
        self.assertEqual(status,403)
        excluded = server.STORE.create_engagement(
            target_id=self.target["id"],name="Excluded fixture",authorization_ref="FIXTURE",
            scope_notes="One URL",out_of_scope="/admin",test_window="fixture",special_approvals={},
        )
        status,_ = self.post({**self.body(),"engagement_id":excluded["id"]})
        self.assertEqual(status,403)

    def test_plan_bounds_and_public_dns_override_not_accepted(self):
        import zap_target_active
        plan = zap_target_active._plan("https://target.example/path", self.root)
        self.assertIn("maxScanDurationInMins: 2",plan)
        self.assertIn("maxRuleDurationInMins: 1",plan)
        self.assertIn("delayInMs: 1000",plan)
        self.assertIn("threadPerHost: 1",plan)
        self.assertNotIn("type: spider",plan)
        self.assertIn("includePaths:",plan)
        private = normalize_target("http://127.0.0.1/")
        record = {"url":private.url,"scheme":private.scheme,"hostname":private.hostname,
                  "port":private.port,"path":private.path}
        with patch.dict(os.environ,{"SNIPER_ALLOW_PRIVATE_TARGETS":"1"}), \
             patch.object(zap_target_active,"resolve_public_ips",return_value=["127.0.0.1"]):
            with self.assertRaises(ValueError):
                zap_target_active._validated_target(target=record)

    def test_test_window_validation(self):
        from datetime import datetime, timezone, timedelta
        import time
        now = datetime.now(timezone.utc)
        body = self.body()
        # Fake runner to detect whether scan was started
        fake_result = {"format": "zap-target-active-v1", "profile": "single-url-active-v1",
                       "site_count": 0, "alert_type_count": 0, "instance_count": 0,
                       "risk_counts": {"informational": 0, "low": 0, "medium": 0, "high": 0},
                       "report_sha256": "b" * 64, "elapsed_seconds": 0.0}

        # Helper to update engagement with window
        def set_window(window: str):
            self.engagement = server.STORE.update_engagement(
                self.engagement["id"], {"test_window": window}
            )
            self.assertIsNotNone(self.engagement)
            self.assertEqual(self.engagement["test_window"], window)

        # 1. Blank window (empty string)
        set_window("")
        with patch.object(server, "run_zap_target_active", return_value=fake_result) as runner:
            status, _ = self.post(body)
            self.assertEqual(status, 403)
            runner.assert_not_called()

        # 2. Whitespace-only window
        set_window("   ")
        with patch.object(server, "run_zap_target_active", return_value=fake_result) as runner:
            status, _ = self.post(body)
            self.assertEqual(status, 403)
            runner.assert_not_called()

        # 3. Malformed window (no separator)
        set_window("2025-01-01T00:00:00Z")
        with patch.object(server, "run_zap_target_active", return_value=fake_result) as runner:
            status, _ = self.post(body)
            self.assertEqual(status, 403)
            runner.assert_not_called()

        # 4. Expired window
        start_str = (now - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        end_str = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        set_window(f"{start_str}/{end_str}")
        with patch.object(server, "run_zap_target_active", return_value=fake_result) as runner:
            status, _ = self.post(body)
            self.assertEqual(status, 403)
            runner.assert_not_called()

        # 5. Future window
        start_str = (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        end_str = (now + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        set_window(f"{start_str}/{end_str}")
        with patch.object(server, "run_zap_target_active", return_value=fake_result) as runner:
            status, _ = self.post(body)
            self.assertEqual(status, 403)
            runner.assert_not_called()

        # 6. Duration > 24 hours
        start_str = (now - timedelta(hours=12)).strftime("%Y-%m-%dT%H:%M:%SZ")
        end_str = (now + timedelta(hours=12, seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        set_window(f"{start_str}/{end_str}")
        with patch.object(server, "run_zap_target_active", return_value=fake_result) as runner:
            status, _ = self.post(body)
            self.assertEqual(status, 403)
            runner.assert_not_called()

        # 7. Remaining time < 300 seconds (start = now-60s, end = now+120s ⇒ 180 seconds remaining)
        start_str = (now - timedelta(seconds=60)).strftime("%Y-%m-%dT%H:%M:%SZ")
        end_str = (now + timedelta(seconds=120)).strftime("%Y-%m-%dT%H:%M:%SZ")
        set_window(f"{start_str}/{end_str}")
        with patch.object(server, "run_zap_target_active", return_value=fake_result) as runner:
            status, _ = self.post(body)
            self.assertEqual(status, 403)
            runner.assert_not_called()

        # 8. Valid window (now - 5 min, now + 25 min ⇒ 20 min duration, remaining > 300s)
        start_str = (now - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        end_str = (now + timedelta(minutes=25)).strftime("%Y-%m-%dT%H:%M:%SZ")
        set_window(f"{start_str}/{end_str}")
        with patch.object(server, "run_zap_target_active", return_value=fake_result) as runner:
            status, data = self.post(body)
            self.assertEqual(status, 200)
            self.assertEqual(data, fake_result)
            runner.assert_called_once_with(self.target)


if __name__ == "__main__":
    unittest.main()
