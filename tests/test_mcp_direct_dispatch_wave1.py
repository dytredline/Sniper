from __future__ import annotations

import json
import os
from http.server import ThreadingHTTPServer
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest import mock
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

import mcp_scan_requests
import ops_files
import server
from job_queue import JobPersistenceError, JobQueue
from storage import Store


ANALYST = {"id": "usr_analyst", "username": "analist", "role": "analyst"}
ADMIN = {"id": "usr_admin", "username": "yonetici", "role": "admin"}


class MCPDirectDispatchPlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(self.temp.cleanup)
        self.data_dir = Path(self.temp.name) / "data"
        self.store = Store(self.data_dir / "sniper.db")

    def request(self, tool_id: str, target: str) -> dict:
        return mcp_scan_requests.create_request(
            self.store,
            "operator_authorized_http",
            {"tool_id": tool_id, "target": target},
            requester=ANALYST,
            confirm_request=True,
            environ={},
        )

    def test_catalog_dispatch_modes_match_the_exact_job_plan_map(self) -> None:
        catalog = mcp_scan_requests.catalog(self.store, environ={})
        profile = next(row for row in catalog["profiles"] if row["id"] == "operator_authorized_http")
        modes = {row["tool_id"]: row["dispatch_mode"] for row in profile["allowed_tools"]}
        self.assertEqual(
            {tool_id for tool_id, mode in modes.items() if mode == "job"},
            {"owasp-zap", "k6", "openssl", "schemathesis", "testssl", "nmap", "nuclei",
             "ssllabs", "browser-tests"},
        )
        self.assertEqual(
            {tool_id for tool_id, mode in modes.items() if mode == "manual_handoff"},
            {"burp-suite"},
        )
        self.assertEqual(set(mcp_scan_requests.OPERATOR_JOB_DISPATCH), {
            "owasp-zap", "k6", "openssl", "schemathesis", "testssl", "nmap", "nuclei",
            "ssllabs", "browser-tests",
        })

    def test_job_tools_build_only_the_fixed_routes_and_payloads(self) -> None:
        cases = (
            (
                "owasp-zap", "HTTPS://Example.COM:443/team/",
                "/api/tool-runs/zap-authorized",
                {"target": "https://example.com/team/", "confirm_authorized": True},
            ),
            (
                "k6", "HTTPS://Example.COM:443/load/health",
                "/api/tool-runs/k6-authorized",
                {
                    "target": "https://example.com:443", "path": "/load/health",
                    "method": "GET", "preset": "hafif", "confirm_authorized": True,
                },
            ),
            (
                "openssl", "HTTPS://Example.COM:443/",
                "/api/tool-runs/openssl-x509-authorized",
                {"target": "https://example.com:443", "confirm_authorized": True},
            ),
        )
        for tool_id, target, route, payload in cases:
            with self.subTest(tool_id=tool_id):
                item = self.request(tool_id, target)
                claim = mcp_scan_requests.claim_request(
                    self.store, item["id"], approved_by=ADMIN, confirm_authorized=True,
                )
                self.assertEqual(claim["status"], "launching")
                self.assertEqual(claim["launch"], {"route": route, "payload": payload})

    def test_openssl_rejects_non_https_or_non_root_before_queue_record(self) -> None:
        for target in ("http://example.com/", "https://example.com/team", "https://example.com/?x=1"):
            with self.subTest(target=target), self.assertRaises(mcp_scan_requests.ScanRequestError):
                self.request("openssl", target)
        self.assertFalse((self.data_dir / mcp_scan_requests.FILE_NAME).exists())

    def test_manual_handoff_tool_preserves_a_non_executing_dispatch_contract(self) -> None:
        item = self.request("burp-suite", "https://example.com/team/")
        claim = mcp_scan_requests.claim_request(
            self.store, item["id"], approved_by=ADMIN, confirm_authorized=True,
        )
        self.assertEqual(claim["status"], "approved")
        self.assertEqual(claim["dispatch"], {
            "mode": "manual_handoff", "tool_id": "burp-suite", "target": "https://example.com/team/",
        })


class MCPDirectDispatchRefreshTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(self.temp.cleanup)
        self.data_dir = Path(self.temp.name) / "data"
        self.store = Store(self.data_dir / "sniper.db")

    def start(self, suffix: str) -> tuple[dict, str]:
        item = mcp_scan_requests.create_request(
            self.store, "operator_authorized_http",
            {"tool_id": "k6", "target": f"https://example.com/{suffix}"},
            requester=ANALYST, confirm_request=True, environ={},
        )
        mcp_scan_requests.claim_request(
            self.store, item["id"], approved_by=ADMIN, confirm_authorized=True,
        )
        job_id = "job_" + ("1" if suffix == "ok" else "2") * 24
        mcp_scan_requests.mark_started(self.store, item["id"], job_id)
        return item, job_id

    def persist_job(self, job_id: str, state: str) -> None:
        directory = self.data_dir / "jobs"
        directory.mkdir(mode=0o700)
        path = directory / f"{job_id}.json"
        path.write_text(json.dumps({"id": job_id, "state": state}), encoding="utf-8")
        os.chmod(path, 0o600)

    def test_successful_outer_job_refreshes_to_completed(self) -> None:
        item, job_id = self.start("ok")
        self.persist_job(job_id, "succeeded")
        refreshed = next(row for row in mcp_scan_requests.list_requests(self.store) if row["id"] == item["id"])
        self.assertEqual(refreshed["status"], "completed")
        self.assertEqual(refreshed["triage_summary"], {
            "state": "completed", "tool_id": "k6", "summary_state": "summary_unavailable",
        })

    def test_failed_outer_job_refreshes_to_failed(self) -> None:
        item, job_id = self.start("failed")
        self.persist_job(job_id, "failed")
        refreshed = next(row for row in mcp_scan_requests.list_requests(self.store) if row["id"] == item["id"])
        self.assertEqual(refreshed["status"], "failed")
        self.assertEqual(refreshed["failure_reason"], "tarama işi tamamlanamadı")

    def test_started_request_without_durable_outer_job_recovers_failed(self) -> None:
        item, _job_id = self.start("missing")
        path = self.data_dir / mcp_scan_requests.FILE_NAME
        data = json.loads(path.read_text())
        row = next(row for row in data["requests"] if row["id"] == item["id"])
        row["started_at"] = "2000-01-01T00:00:00Z"
        path.write_text(json.dumps(data), encoding="utf-8")
        os.chmod(path, 0o600)
        refreshed = next(row for row in mcp_scan_requests.list_requests(self.store) if row["id"] == item["id"])
        self.assertEqual(refreshed["status"], "failed")
        self.assertIn("kalıcı iş kaydı", refreshed["failure_reason"])


class MCPDirectDispatchApiTests(unittest.TestCase):
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
            {"tool_id": "owasp-zap", "target": "https://example.com/team/"},
            requester=ANALYST, confirm_request=True, environ={},
        )
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop)
        self.base_url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.opener = build_opener(ProxyHandler({}))

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
            with self.opener.open(request, timeout=5) as response:
                return response.status, json.loads(response.read())
        except HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_exact_human_approval_returns_202_started_job_and_receipt_audit(self) -> None:
        class FakeJob:
            id = "job_" + "a" * 24

            @staticmethod
            def public() -> dict:
                return {"id": FakeJob.id, "route": "/api/tool-runs/zap-authorized", "state": "queued"}

        class Progress:
            @staticmethod
            def set_progress(_value) -> None:
                return None

        with mock.patch.object(server.JOBS, "submit", return_value=FakeJob()) as submit, \
                mock.patch.object(server, "_run_post_capture", return_value=(200, {"format": "synthetic"})) as capture:
            for invalid in (
                {"confirm": True},
                {"confirm": True, "confirm_authorized": "true"},
                {"confirm": True, "confirm_authorized": True, "extra": True},
            ):
                self.assertEqual(self.request(invalid)[0], 400)
            submit.assert_not_called()
            status, body = self.request({"confirm": True, "confirm_authorized": True})
            runner = submit.call_args.args[1]
            self.assertEqual(runner(Progress()), (200, {"format": "synthetic"}))

        self.assertEqual(status, 202, body)
        self.assertEqual(body["request"]["status"], "started")
        self.assertEqual(body["request"]["job_id"], FakeJob.id)
        self.assertEqual(body["job"]["state"], "queued")
        self.assertEqual(submit.call_args.args[0], "/api/tool-runs/zap-authorized")
        self.assertEqual(capture.call_args.args[-2:], (
            "/api/tool-runs/zap-authorized",
            {"target": "https://example.com/team/", "confirm_authorized": True},
        ))
        receipt_sha = body["request"]["authorization_receipt"]["receipt_sha256"]
        audit = next(row for row in server.STORE.recent_audit_log(20)
                     if row["action"] == "mcp_scan_request.started")
        self.assertEqual(audit["details"]["receipt_sha256"], receipt_sha)
        self.assertTrue(server.STORE.verify_audit_chain()["verified"])

    def test_loopback_http_approval_runs_the_real_queue_and_capture_path_with_synthetic_tool(self) -> None:
        item = mcp_scan_requests.create_request(
            server.STORE, "operator_authorized_http",
            {"tool_id": "k6", "target": "http://127.0.0.1:49123/health"},
            requester=ANALYST, confirm_request=True, environ={},
        )
        previous_jobs = server.JOBS
        server.JOBS = JobQueue(
            workers=1, max_queued=2, timeout_seconds=5,
            store_dir=self.data_dir / "jobs", on_finish=server._job_finished,
        )
        self.addCleanup(setattr, server, "JOBS", previous_jobs)
        synthetic = {
            "format": "k6-authorized-target-v1", "status": "completed",
            "normalized_target": "http://127.0.0.1:49123",
            "relay": {"connections": 1, "refused": 0, "bytes": 32},
            "summary": {"http_requests": 1},
        }
        with mock.patch.object(server, "run_k6_authorized", return_value=synthetic) as run:
            original = self.item
            self.item = item
            try:
                status, body = self.request({"confirm": True, "confirm_authorized": True})
            finally:
                self.item = original
            self.assertEqual(status, 202, body)
            job_id = body["job"]["id"]
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                job = server.JOBS.get(job_id)
                if job and job["state"] in {"succeeded", "failed"}:
                    break
                time.sleep(0.02)
            else:
                self.fail("sentetik MCP işi süre sınırında tamamlanmadı")
        self.assertEqual(job["state"], "succeeded", job)
        self.assertEqual(job["result"]["format"], "k6-authorized-target-v1")
        run.assert_called_once_with({
            "target": "http://127.0.0.1:49123", "path": "/health", "method": "GET",
            "preset": "hafif", "confirm_authorized": True,
        })
        row = next(row for row in mcp_scan_requests.list_requests(server.STORE) if row["id"] == item["id"])
        self.assertEqual(row["status"], "completed")

    def test_job_id_persistence_failure_publishes_no_job_and_runs_no_tool(self) -> None:
        previous_jobs = server.JOBS
        server.JOBS = JobQueue(
            workers=1, max_queued=2, timeout_seconds=5,
            store_dir=self.data_dir / "jobs", on_finish=server._job_finished,
        )
        self.addCleanup(setattr, server, "JOBS", previous_jobs)
        with mock.patch.object(
            mcp_scan_requests, "mark_started", side_effect=ops_files.OpsStoreError("sentetik persist"),
        ), mock.patch.object(server, "_run_post_capture") as capture:
            status, body = self.request({"confirm": True, "confirm_authorized": True})
        self.assertEqual(status, 503, body)
        self.assertEqual(server.JOBS.list(), [])
        capture.assert_not_called()
        row = next(row for row in mcp_scan_requests.list_requests(server.STORE)
                   if row["id"] == self.item["id"])
        self.assertEqual(row["status"], "failed")
        self.assertIn("kalıcı kuyruğa", row["failure_reason"])

    def test_initial_job_file_persistence_failure_never_binds_or_runs(self) -> None:
        previous_jobs = server.JOBS
        server.JOBS = JobQueue(
            workers=1, max_queued=2, timeout_seconds=5,
            store_dir=self.data_dir / "jobs", on_finish=server._job_finished,
        )
        self.addCleanup(setattr, server, "JOBS", previous_jobs)
        with mock.patch.object(
            server.JOBS, "_persist", side_effect=JobPersistenceError("sentetik job persist"),
        ), mock.patch.object(server, "_run_post_capture") as capture:
            status, body = self.request({"confirm": True, "confirm_authorized": True})
        self.assertEqual(status, 503, body)
        self.assertEqual(server.JOBS.list(), [])
        capture.assert_not_called()
        row = next(row for row in mcp_scan_requests.list_requests(server.STORE)
                   if row["id"] == self.item["id"])
        self.assertEqual(row["status"], "failed")

    def test_publish_failure_after_binding_rolls_back_job_and_fails_request(self) -> None:
        previous_jobs = server.JOBS
        server.JOBS = JobQueue(
            workers=1, max_queued=2, timeout_seconds=5,
            store_dir=self.data_dir / "jobs", on_finish=server._job_finished,
        )
        self.addCleanup(setattr, server, "JOBS", previous_jobs)
        # Create the idle worker before injecting the final publish wakeup failure.
        server.JOBS._ensure_workers()
        with mock.patch.object(
            server.JOBS._wakeup, "notify", side_effect=RuntimeError("sentetik publish"),
        ), mock.patch.object(server, "_run_post_capture") as capture:
            status, body = self.request({"confirm": True, "confirm_authorized": True})
        self.assertEqual(status, 503, body)
        self.assertEqual(server.JOBS.list(), [])
        self.assertEqual(list((self.data_dir / "jobs").glob("job_*.json")), [])
        capture.assert_not_called()
        row = next(row for row in mcp_scan_requests.list_requests(server.STORE)
                   if row["id"] == self.item["id"])
        self.assertEqual(row["status"], "failed")

    def test_started_audit_failure_after_publish_returns_accepted_not_false_failure(self) -> None:
        previous_jobs = server.JOBS
        server.JOBS = JobQueue(
            workers=1, max_queued=2, timeout_seconds=5,
            store_dir=self.data_dir / "jobs", on_finish=server._job_finished,
        )
        self.addCleanup(setattr, server, "JOBS", previous_jobs)
        original_log = server.STORE.log
        ran = threading.Event()

        def selective_log(action, entity_id, details=None):
            if action == "mcp_scan_request.started":
                raise ops_files.OpsStoreError("sentetik audit persist")
            return original_log(action, entity_id, details)

        def synthetic_capture(*_args, **_kwargs):
            ran.set()
            return 200, {"format": "synthetic"}

        with mock.patch.object(server.STORE, "log", side_effect=selective_log), \
                mock.patch.object(server, "_run_post_capture", side_effect=synthetic_capture):
            status, body = self.request({"confirm": True, "confirm_authorized": True})
            self.assertEqual(status, 202, body)
            self.assertEqual(body["request"]["status"], "started")
            self.assertTrue(ran.wait(2))
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            job = server.JOBS.get(body["job"]["id"])
            if job and job["state"] == "succeeded":
                break
            time.sleep(0.02)
        self.assertEqual(job["state"], "succeeded")
        row = next(row for row in mcp_scan_requests.list_requests(server.STORE)
                   if row["id"] == self.item["id"])
        self.assertEqual(row["status"], "completed")


if __name__ == "__main__":
    unittest.main()
