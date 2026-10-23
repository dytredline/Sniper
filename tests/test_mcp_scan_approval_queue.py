from __future__ import annotations

import json
import os
from http.server import ThreadingHTTPServer
from pathlib import Path
import stat
import tempfile
import threading
import unittest
from unittest import mock
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import mcp_scan_requests
import mcp_triage_server
from nuclei_aggregate_history import AggregateHistoryJournal
import sandbox_targets
import server
from scanner import normalize_target
from storage import Store


class MCPScanApprovalQueueTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data_dir = self.root / "data"
        self.env = mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(self.data_dir)})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.store = Store(self.data_dir / "sniper.db")
        self.target = self.store.create_target(normalize_target("https://example.com"))
        self.engagement = self.store.create_engagement(
            target_id=self.target["id"],
            name="Yetkili test",
            authorization_ref="AUTH-42",
            scope_notes="Yalnız kayıtlı hedef",
            out_of_scope="",
            test_window="",
            special_approvals={},
        )
        self.analyst = {"id": "usr_analyst", "username": "analist", "role": "analyst"}

    def test_catalog_only_exposes_prevalidated_profile_targets(self) -> None:
        catalog = mcp_scan_requests.catalog(self.store, environ=dict(os.environ))
        by_id = {profile["id"]: profile for profile in catalog["profiles"]}
        self.assertIn("nuclei_http_authorized", by_id)
        self.assertIn("sandbox_k6", by_id)
        self.assertEqual(
            by_id["nuclei_http_authorized"]["allowed_targets"],
            [{
                "target_id": self.target["id"],
                "engagement_id": self.engagement["id"],
                "label": "example.com",
            }],
        )
        self.assertFalse(catalog["starts_scans"])
        encoded = json.dumps(catalog)
        self.assertNotIn("AUTH-42", encoded)
        self.assertNotIn("scope_notes", encoded)

    def test_catalog_and_k6_request_derive_data_dir_from_store(self) -> None:
        sandbox_targets.add_local_target(
            3010, ["k6"], "yerel", environ={"SNIPER_DATA_DIR": str(self.data_dir)}
        )
        catalog = mcp_scan_requests.catalog(self.store, environ={})
        profile = next(item for item in catalog["profiles"] if item["id"] == "sandbox_k6")
        self.assertEqual(profile["allowed_targets"], [{
            "target": "http://127.0.0.1:3010", "label": "yerel", "kind": "local",
        }])
        item = mcp_scan_requests.create_request(
            self.store, "sandbox_k6", {"target": "http://127.0.0.1:3010"},
            requester=self.analyst, confirm_request=True, environ={},
        )
        self.assertEqual(item["parameters"]["preset"], "orta")

    def test_request_is_pending_until_separate_human_claim(self) -> None:
        item = mcp_scan_requests.create_request(
            self.store,
            "nuclei_http_authorized",
            {"target_id": self.target["id"], "engagement_id": self.engagement["id"]},
            requester=self.analyst,
            confirm_request=True,
            environ=dict(os.environ),
        )
        self.assertEqual(item["status"], "pending")
        self.assertNotIn("confirm_authorized", item["parameters"])
        queue_path = self.data_dir / mcp_scan_requests.FILE_NAME
        self.assertTrue(queue_path.is_file())
        self.assertEqual(stat.S_IMODE(queue_path.stat().st_mode), 0o600)

        claim = mcp_scan_requests.claim_request(
            self.data_dir,
            item["id"],
            approved_by={"id": "usr_admin", "username": "yonetici", "role": "admin"},
            confirm_authorized=True,
        )
        self.assertEqual(claim["status"], "launching")
        self.assertEqual(claim["launch"]["route"], "/api/nuclei/http-scans")
        self.assertIs(claim["launch"]["payload"]["confirm_authorized"], True)
        started = mcp_scan_requests.mark_started(self.data_dir, item["id"], "job_123")
        self.assertEqual((started["status"], started["job_id"]), ("started", "job_123"))
        with self.assertRaises(mcp_scan_requests.ScanRequestError):
            mcp_scan_requests.claim_request(
                self.data_dir,
                item["id"],
                approved_by={"id": "usr_admin", "username": "yonetici", "role": "admin"},
                confirm_authorized=True,
            )

    def test_persisted_nuclei_aggregate_is_reconciled_into_triage_summary(self) -> None:
        item = mcp_scan_requests.create_request(
            self.store, "nuclei_http_authorized",
            {"target_id": self.target["id"], "engagement_id": self.engagement["id"]},
            requester=self.analyst, confirm_request=True,
        )
        mcp_scan_requests.claim_request(
            self.store, item["id"], approved_by={"id": "admin", "username": "admin", "role": "admin"},
            confirm_authorized=True,
        )
        outer_id, scanner_id = "job_" + "a" * 24, "b" * 16
        mcp_scan_requests.mark_started(self.store, item["id"], outer_id)
        jobs = self.data_dir / "jobs"
        jobs.mkdir(mode=0o700)
        outer = jobs / f"{outer_id}.json"
        outer.write_text(json.dumps({"id": outer_id, "state": "succeeded", "result": {
            "job_id": scanner_id, "state": "starting",
        }}))
        os.chmod(outer, 0o600)
        AggregateHistoryJournal(self.data_dir).save([(
            scanner_id,
            {"state": "completed", "elapsed_seconds": 1.5, "report_sha256": "c" * 64,
             "record_count": 3, "unique_template_count": 2,
             "severity_counts": {"high": 1, "medium": 2}},
        )])

        row = mcp_scan_requests.list_requests(self.store)[0]
        self.assertEqual(row["status"], "completed")
        self.assertEqual(row["scanner_job_id"], scanner_id)
        self.assertEqual(row["triage_summary"]["record_count"], 3)
        self.assertEqual(row["triage_summary"]["severity_counts"], {"high": 1, "medium": 2})
        self.assertNotIn("result", row)

    def test_invalid_or_mismatched_request_fails_closed_without_queue_file(self) -> None:
        other = self.store.create_target(normalize_target("https://example.org"))
        for profile, params, confirm in (
            ("nuclei_http_authorized", {"target_id": other["id"], "engagement_id": self.engagement["id"]}, True),
            ("nuclei_http_authorized", {"target_id": self.target["id"], "engagement_id": self.engagement["id"], "url": "https://evil.invalid"}, True),
            ("nuclei_http_authorized", {"target_id": self.target["id"], "engagement_id": self.engagement["id"]}, False),
        ):
            with self.subTest(params=params, confirm=confirm), self.assertRaises(mcp_scan_requests.ScanRequestError):
                mcp_scan_requests.create_request(
                    self.store, profile, params, requester=self.analyst,
                    confirm_request=confirm, environ=dict(os.environ),
                )
        self.assertFalse((self.data_dir / mcp_scan_requests.FILE_NAME).exists())

    def test_mcp_requires_bound_reader_for_catalog_and_analyst_for_request(self) -> None:
        names = {tool["name"] for tool in mcp_triage_server.TOOLS}
        self.assertTrue({"list_scan_profiles", "list_scan_requests", "request_scan"} <= names)

        anonymous = mcp_triage_server.TriageMCPServer(self.store)
        denied = anonymous.call_tool("list_scan_profiles", {})
        self.assertTrue(denied["isError"])
        self.assertFalse((self.data_dir / mcp_scan_requests.FILE_NAME).exists())

        reader = mcp_triage_server.TriageMCPServer(
            self.store, user={"id": "usr_reader", "username": "okuyucu", "role": "reader"}
        )
        self.assertFalse(reader.call_tool("list_scan_profiles", {})["isError"])
        self.assertTrue(reader.call_tool("request_scan", {
            "profile_id": "nuclei_http_authorized",
            "parameters": {"target_id": self.target["id"], "engagement_id": self.engagement["id"]},
            "confirm_request": True,
        })["isError"])

        analyst = mcp_triage_server.TriageMCPServer(self.store, user=self.analyst)
        accepted = analyst.call_tool("request_scan", {
            "profile_id": "nuclei_http_authorized",
            "parameters": {"target_id": self.target["id"], "engagement_id": self.engagement["id"]},
            "confirm_request": True,
        })
        self.assertFalse(accepted["isError"], accepted)
        body = json.loads(accepted["content"][0]["text"])
        self.assertEqual(body["status"], "pending")
        self.assertIn("ayrı yönetici onayı", body["message"])


class MCPScanApprovalApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data_dir = self.root / "data"
        self.env = mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(self.data_dir)})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.previous_store = server.STORE
        server.STORE = Store(self.data_dir / "sniper.db")
        self.addCleanup(setattr, server, "STORE", self.previous_store)
        target = server.STORE.create_target(normalize_target("https://example.com"))
        engagement = server.STORE.create_engagement(
            target_id=target["id"], name="Yetkili", authorization_ref="AUTH-9",
            scope_notes="Tek hedef", out_of_scope="", test_window="", special_approvals={},
        )
        self.item = mcp_scan_requests.create_request(
            server.STORE, "nuclei_http_authorized",
            {"target_id": target["id"], "engagement_id": engagement["id"]},
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

    def request(self, method: str, path: str, payload: dict | None = None) -> tuple[int, dict]:
        body = None if payload is None else json.dumps(payload).encode()
        req = Request(self.base_url + path, data=body, method=method,
                      headers={"Content-Type": "application/json"} if body is not None else {})
        try:
            with urlopen(req, timeout=5) as response:
                return response.status, json.loads(response.read())
        except HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_admin_approval_submits_exact_whitelisted_job(self) -> None:
        class FakeJob:
            id = "job_exact"

            @staticmethod
            def public() -> dict:
                return {"id": "job_exact", "state": "queued"}

        with mock.patch.object(server.JOBS, "submit", return_value=FakeJob()) as submit:
            status, body = self.request(
                "POST", f"/api/mcp-scan-requests/{self.item['id']}/approve", {"confirm": True}
                | {"confirm_authorized": True}
            )
        self.assertEqual(status, 202, body)
        self.assertEqual(body["request"]["status"], "started")
        self.assertEqual(body["job"], {"id": "job_exact", "state": "queued"})
        args, kwargs = submit.call_args
        self.assertEqual(args[0], "/api/nuclei/http-scans")
        self.assertIn("dedupe_key", kwargs)
        rows = mcp_scan_requests.list_requests(server.STORE)
        self.assertEqual((rows[0]["status"], rows[0]["job_id"]), ("started", "job_exact"))

    def test_approval_requires_exact_confirmation_and_cancel_is_terminal(self) -> None:
        with mock.patch.object(server.JOBS, "submit") as submit:
            self.assertEqual(self.request(
                "POST", f"/api/mcp-scan-requests/{self.item['id']}/approve", {}
            )[0], 400)
            self.assertEqual(self.request(
                "POST", f"/api/mcp-scan-requests/{self.item['id']}/approve", {"confirm": True}
            )[0], 400)
            self.assertEqual(self.request(
                "POST", f"/api/mcp-scan-requests/{self.item['id']}/approve",
                {"confirm": True, "confirm_authorized": "true"},
            )[0], 400)
            submit.assert_not_called()
        status, body = self.request(
            "POST", f"/api/mcp-scan-requests/{self.item['id']}/cancel", {"confirm": True}
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body["request"]["status"], "cancelled")
        with mock.patch.object(server.JOBS, "submit") as submit:
            self.assertEqual(self.request(
                "POST", f"/api/mcp-scan-requests/{self.item['id']}/approve", {"confirm": True}
                | {"confirm_authorized": True}
            )[0], 409)
            submit.assert_not_called()

    def test_unexpected_submit_failure_is_recorded_and_returns_service_unavailable(self) -> None:
        with mock.patch.object(server.JOBS, "submit", side_effect=RuntimeError("private detail")):
            status, body = self.request(
                "POST", f"/api/mcp-scan-requests/{self.item['id']}/approve", {"confirm": True}
                | {"confirm_authorized": True}
            )
        self.assertEqual(status, 503, body)
        self.assertNotIn("private detail", json.dumps(body))
        row = mcp_scan_requests.list_requests(server.STORE)[0]
        self.assertEqual(row["status"], "failed")

    def test_get_lists_requests_without_private_launch_fields(self) -> None:
        status, body = self.request("GET", "/api/mcp-scan-requests")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["requests"][0]["id"], self.item["id"])
        self.assertNotIn("_route", json.dumps(body))
        self.assertNotIn("confirm_authorized", json.dumps(body))


if __name__ == "__main__":
    unittest.main()
