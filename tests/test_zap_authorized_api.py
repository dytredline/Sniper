from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import request_context
import server
from storage import Store


class ZapAuthorizedApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="sniper_zap_authorized_")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data_dir = self.root / "data"
        self.data_dir.mkdir(mode=0o700)
        self.old_store = server.STORE
        server.STORE = Store(self.data_dir / "sniper.db")
        self.addCleanup(setattr, server, "STORE", self.old_store)
        self.env = mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(self.data_dir)})
        self.env.start()
        self.addCleanup(self.env.stop)

        self.handler = server.SniperHandler.__new__(server.SniperHandler)
        self.handler.path = "/api/tool-runs/zap-authorized"
        self.responses: list[tuple[int, dict]] = []
        self.handler._json = lambda body, status=200, **_kw: self.responses.append((int(status), body))
        self.handler._error = lambda status, message: self.responses.append((int(status), {"error": message}))

    @staticmethod
    def _summary() -> dict:
        return {
            "format": "zap-authorized-v1",
            "profile": "same-origin-authorized-spider-active-v1",
            "site_count": 1,
            "alert_type_count": 1,
            "instance_count": 2,
            "risk_counts": {"informational": 0, "low": 1, "medium": 0, "high": 0},
            "report_sha256": "a" * 64,
            "elapsed_seconds": 1.25,
        }

    def test_free_http_target_needs_only_exact_authorization_and_returns_receipt(self) -> None:
        actor = {"id": "usr_operator", "username": "operator", "role": "admin"}
        with request_context.acting_as(actor), \
             mock.patch.object(server, "run_zap_authorized", create=True, return_value=self._summary()) as runner:
            self.handler._dispatch_post({
                "target": "HTTP://127.0.0.1:43117/app",
                "confirm_authorized": True,
            })

        status, body = self.responses.pop()
        self.assertEqual(status, 200)
        self.assertEqual(body["format"], "zap-authorized-v1")
        self.assertEqual(body["receipt"]["actor"]["id"], "usr_operator")
        self.assertEqual(body["receipt"]["target"], "http://127.0.0.1:43117/app")
        self.assertEqual(body["receipt"]["consent_version"], "zap-authorized-consent-v1")
        self.assertRegex(body["receipt"]["confirmed_at"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00$")
        runner.assert_called_once_with("http://127.0.0.1:43117/app")

        events = server.STORE.recent_audit_log(limit=10)
        self.assertEqual([row["action"] for row in events[:2]], [
            "zap_authorized_run.completed",
            "zap_authorized_run.started",
        ])
        self.assertEqual(events[0]["entity_id"], body["receipt"]["run_id"])
        self.assertEqual(events[1]["details"]["consent_version"], "zap-authorized-consent-v1")

    def test_missing_or_non_boolean_consent_and_extra_fields_fail_before_runner(self) -> None:
        cases = (
            {"target": "https://example.test/"},
            {"target": "https://example.test/", "confirm_authorized": 1},
            {"target": "https://example.test/", "confirm_authorized": "true"},
            {"target": "https://example.test/", "confirm_authorized": True, "engagement_id": "eng_x"},
        )
        for payload in cases:
            with self.subTest(payload=payload), \
                 mock.patch.object(server, "run_zap_authorized", create=True) as runner:
                self.handler._dispatch_post(payload)
                self.assertIn(self.responses.pop()[0], (400, 403))
                runner.assert_not_called()

    def test_non_http_credentials_query_and_fragment_are_rejected_before_runtime(self) -> None:
        targets = (
            "ftp://example.test/",
            "https://user:pass@example.test/",
            "https://example.test/?q=1",
            "https://example.test/#frag",
            "https://example.test:99999/",
        )
        for target in targets:
            with self.subTest(target=target), \
                 mock.patch.object(server, "run_zap_authorized", create=True) as runner:
                self.handler._dispatch_post({"target": target, "confirm_authorized": True})
                self.assertEqual(self.responses.pop()[0], 400)
                runner.assert_not_called()

    def test_missing_runtime_fails_closed_with_exact_readiness_and_audited_failure(self) -> None:
        readiness = {
            "format": "zap-authorized-readiness-v1",
            "ready": False,
            "runtime": "owasp-zap-2.17.0-java17",
            "checks": [],
            "missing": ["systemd-run:missing:/usr/bin/systemd-run"],
        }
        with mock.patch.object(server, "run_zap_authorized", side_effect=server.ZapUnavailable("missing")), \
             mock.patch.object(server, "zap_authorized_runtime_readiness", return_value=readiness):
            self.handler._dispatch_post({
                "target": "http://127.0.0.1:43117/app",
                "confirm_authorized": True,
            })
        status, body = self.responses.pop()
        self.assertEqual(status, 503)
        self.assertEqual(body["readiness"]["missing"], readiness["missing"])
        events = server.STORE.recent_audit_log(limit=10)
        self.assertEqual([row["action"] for row in events[:2]], [
            "zap_authorized_run.failed",
            "zap_authorized_run.started",
        ])
        self.assertEqual(events[0]["details"]["reason"], "runtime_unavailable")


if __name__ == "__main__":
    unittest.main()
