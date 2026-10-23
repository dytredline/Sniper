from __future__ import annotations

import hashlib
import json
import os
from http.server import ThreadingHTTPServer
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import mcp_scan_requests
import server
from scanner import normalize_target
from storage import Store


class MCPAuthorizedTargetReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(self.temp.cleanup)
        self.data_dir = Path(self.temp.name) / "data"
        self.env = mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(self.data_dir)})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.store = Store(self.data_dir / "sniper.db")
        self.analyst = {"id": "usr_analyst", "username": "analist", "role": "analyst"}
        self.admin = {"id": "usr_admin", "username": "yonetici", "role": "admin"}

    def test_free_target_request_is_normalized_and_human_receipt_is_content_addressed(self) -> None:
        catalog = mcp_scan_requests.catalog(self.store, environ={})
        profile = next(row for row in catalog["profiles"] if row["id"] == "operator_authorized_http")
        self.assertTrue(profile["free_target_entry"])
        self.assertNotIn("allowed_targets", profile)
        self.assertIn("burp-suite", {row["tool_id"] for row in profile["allowed_tools"]})

        item = mcp_scan_requests.create_request(
            self.store,
            "operator_authorized_http",
            {"tool_id": "burp-suite", "target": "HTTPS://Example.COM:443/team/"},
            requester=self.analyst,
            confirm_request=True,
            environ={},
        )
        self.assertEqual(item["parameters"], {
            "tool_id": "burp-suite", "target": "https://example.com/team/",
        })
        self.assertEqual(item["normalized_target"], "https://example.com/team/")
        self.assertEqual(item["status"], "pending")
        self.assertNotIn("authorization_receipt", item)

        approved = mcp_scan_requests.claim_request(
            self.store, item["id"], approved_by=self.admin, confirm_authorized=True,
        )
        self.assertEqual(approved["status"], "approved")
        self.assertEqual(approved["dispatch"], {
            "mode": "manual_handoff",
            "tool_id": "burp-suite",
            "target": "https://example.com/team/",
        })
        receipt = approved["authorization_receipt"]
        self.assertEqual(receipt["consent_version"], mcp_scan_requests.AUTHORIZATION_CONSENT_VERSION_V2)
        self.assertEqual(receipt["plan_sha256"], approved["plan_sha256"])
        self.assertIs(receipt["confirm_authorized"], True)
        self.assertEqual(receipt["normalized_target"], "https://example.com/team/")
        self.assertEqual(receipt["actor"], {"id": "usr_admin", "username": "yonetici"})
        self.assertRegex(receipt["confirmed_at"], r"Z\Z")
        canonical = json.dumps(
            {key: value for key, value in receipt.items() if key != "receipt_sha256"},
            ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        self.assertEqual(receipt["receipt_sha256"], hashlib.sha256(canonical).hexdigest())
        self.assertTrue(mcp_scan_requests.verify_authorization_receipt(receipt))

    def test_exact_boolean_is_required_and_tampered_receipt_fails_closed(self) -> None:
        item = mcp_scan_requests.create_request(
            self.store,
            "operator_authorized_http",
            {"tool_id": "owasp-zap", "target": "example.org"},
            requester=self.analyst,
            confirm_request=True,
            environ={},
        )
        for invalid in (False, 1, "true", None):
            with self.subTest(confirm_authorized=invalid), self.assertRaises(mcp_scan_requests.ScanRequestError):
                mcp_scan_requests.claim_request(
                    self.store, item["id"], approved_by=self.admin, confirm_authorized=invalid,
                )
        approved = mcp_scan_requests.claim_request(
            self.store, item["id"], approved_by=self.admin, confirm_authorized=True,
        )
        queue_path = self.data_dir / mcp_scan_requests.FILE_NAME
        queue = json.loads(queue_path.read_text())
        queue["requests"][0]["authorization_receipt"]["normalized_target"] = "https://changed.invalid/"
        queue_path.write_text(json.dumps(queue))
        os.chmod(queue_path, 0o600)
        with self.assertRaisesRegex(mcp_scan_requests.ScanRequestError, "bütünlük"):
            mcp_scan_requests.list_requests(self.store)
        self.assertEqual(approved["parameters"]["target"], "https://example.org/")

    def test_non_http_target_and_unknown_tool_are_rejected_without_queue_record(self) -> None:
        for parameters in (
            {"tool_id": "burp-suite", "target": "file:///etc/passwd"},
            {"tool_id": "unknown-scanner", "target": "https://example.com"},
        ):
            with self.subTest(parameters=parameters), self.assertRaises(mcp_scan_requests.ScanRequestError):
                mcp_scan_requests.create_request(
                    self.store, "operator_authorized_http", parameters,
                    requester=self.analyst, confirm_request=True, environ={},
                )
        self.assertFalse((self.data_dir / mcp_scan_requests.FILE_NAME).exists())

    def test_existing_nuclei_dispatch_payload_is_preserved_and_gets_same_receipt(self) -> None:
        target = self.store.create_target(normalize_target("https://example.net"))
        engagement = self.store.create_engagement(
            target_id=target["id"], name="Kayıtlı kontrol", authorization_ref="AUTH-35",
            scope_notes="Tek hedef", out_of_scope="", test_window="", special_approvals={},
        )
        item = mcp_scan_requests.create_request(
            self.store, "nuclei_http_authorized",
            {"target_id": target["id"], "engagement_id": engagement["id"]},
            requester=self.analyst, confirm_request=True, environ={},
        )
        claimed = mcp_scan_requests.claim_request(
            self.store, item["id"], approved_by=self.admin, confirm_authorized=True,
        )
        self.assertEqual(claimed["status"], "launching")
        self.assertEqual(claimed["launch"], {
            "route": "/api/nuclei/http-scans",
            "payload": {
                "target_id": target["id"], "engagement_id": engagement["id"],
                "confirm_authorized": True,
            },
        })
        self.assertEqual(claimed["authorization_receipt"]["normalized_target"], "https://example.net/")


class MCPAuthorizedTargetReceiptApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(self.temp.cleanup)
        self.data_dir = Path(self.temp.name) / "data"
        self.env = mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(self.data_dir)})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.previous_store = server.STORE
        server.STORE = Store(self.data_dir / "sniper.db")
        self.addCleanup(setattr, server, "STORE", self.previous_store)
        self.item = mcp_scan_requests.create_request(
            server.STORE, "operator_authorized_http",
            {"tool_id": "burp-suite", "target": "https://EXAMPLE.com:443/load"},
            requester={"id": "usr_analyst", "username": "analist", "role": "analyst"},
            confirm_request=True,
        )
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop)
        self.base_url = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def _stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)

    def request(self, payload: dict) -> tuple[int, dict]:
        request = Request(
            self.base_url + f"/api/mcp-scan-requests/{self.item['id']}/approve",
            data=json.dumps(payload).encode(), method="POST", headers={"Content-Type": "application/json"},
        )
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read())
        except HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_server_requires_checkbox_boolean_then_records_manual_handoff_without_starting_scanner(self) -> None:
        with mock.patch.object(server.JOBS, "submit") as submit:
            self.assertEqual(self.request({"confirm": True})[0], 400)
            self.assertEqual(self.request({"confirm": True, "confirm_authorized": "true"})[0], 400)
            status, body = self.request({"confirm": True, "confirm_authorized": True})
            submit.assert_not_called()
        self.assertEqual(status, 200, body)
        self.assertEqual(body["request"]["status"], "approved")
        self.assertEqual(body["dispatch"], {
            "mode": "manual_handoff", "tool_id": "burp-suite", "target": "https://example.com/load",
        })
        self.assertTrue(mcp_scan_requests.verify_authorization_receipt(
            body["request"]["authorization_receipt"],
        ))
        audit = next(row for row in server.STORE.recent_audit_log(20)
                     if row["action"] == "mcp_scan_request.authorized")
        self.assertEqual(
            audit["details"]["receipt_sha256"],
            body["request"]["authorization_receipt"]["receipt_sha256"],
        )
        self.assertTrue(server.STORE.verify_audit_chain()["verified"])


if __name__ == "__main__":
    unittest.main()
