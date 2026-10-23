from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest import mock

import mcp_scan_requests as mcp
from job_queue import JobQueue
from nuclei_aggregate_history import AggregateHistoryJournal
from nuclei_broad_jobs import BroadNucleiJobs
import request_context
import server
from storage import Store


ANALYST = {"id": "usr_analyst", "username": "analist", "role": "analyst"}
ADMIN = {"id": "usr_admin", "username": "yonetici", "role": "admin"}


def schema() -> dict:
    return {
        "openapi": "3.0.3",
        "info": {"title": "R57", "version": "1"},
        "paths": {"/items": {"get": {"responses": {"200": {"description": "ok"}}}}},
    }


class MCPRetentionAndSummaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(self.temp.cleanup)
        self.data_dir = Path(self.temp.name) / "data"
        self.store = Store(self.data_dir / "sniper.db")
        self.queue_path = self.data_dir / mcp.FILE_NAME

    def _write_rows(self, rows: list[dict]) -> None:
        self.queue_path.write_text(json.dumps({"format": mcp.FORMAT, "requests": rows}), encoding="utf-8")
        os.chmod(self.queue_path, 0o600)

    @staticmethod
    def _row(index: int, status: str) -> dict:
        return {
            "id": f"msr_{index:016x}",
            "profile_id": "retention_fixture",
            "status": status,
            "parameters": {"fixture": index},
            "requested_by": {"id": "fixture", "username": "fixture"},
            "created_at": f"2026-10-22T00:{index // 60:02d}:{index % 60:02d}Z",
        }

    def _create_nmap(self, target: str = "new.example") -> dict:
        return mcp.create_request(
            self.store,
            "operator_authorized_http",
            {"tool_id": "nmap", "target": target},
            requester=ANALYST,
            confirm_request=True,
            environ={},
        )

    def _complete_outer(self, item: dict, result: object) -> dict:
        mcp.claim_request(self.store, item["id"], approved_by=ADMIN, confirm_authorized=True)
        job_id = "job_" + "a" * 24
        mcp.mark_started(self.store, item["id"], job_id)
        jobs = self.data_dir / "jobs"
        jobs.mkdir(mode=0o700, exist_ok=True)
        path = jobs / f"{job_id}.json"
        path.write_text(json.dumps({"id": job_id, "state": "succeeded", "result": result}), encoding="utf-8")
        os.chmod(path, 0o600)
        return next(row for row in mcp.list_requests(self.store) if row["id"] == item["id"])

    def test_capacity_prunes_only_oldest_terminal_rows_and_retains_every_nonterminal_state(self) -> None:
        protected_states = ("pending", "approved", "launching", "started", "running")
        rows = [self._row(index, protected_states[index % len(protected_states)]) for index in range(195)]
        rows += [self._row(195 + index, ("completed", "cancelled", "failed")[index % 3]) for index in range(5)]
        protected_ids = {row["id"] for row in rows[:195]}
        terminal_ids = [row["id"] for row in rows[195:]]
        self._write_rows(rows)

        created = self._create_nmap()
        persisted = json.loads(self.queue_path.read_text(encoding="utf-8"))["requests"]
        persisted_ids = {row["id"] for row in persisted}
        self.assertEqual(len(persisted), mcp.MAX_REQUESTS)
        self.assertTrue(protected_ids <= persisted_ids)
        self.assertNotIn(terminal_ids[0], persisted_ids)
        self.assertTrue(set(terminal_ids[1:]) <= persisted_ids)
        self.assertIn(created["id"], persisted_ids)

    def test_full_nonterminal_capacity_rejects_schema_request_and_leaves_no_spool(self) -> None:
        protected_states = ("pending", "approved", "launching", "started", "running")
        self._write_rows([
            self._row(index, protected_states[index % len(protected_states)])
            for index in range(mcp.MAX_REQUESTS)
        ])

        with self.assertRaisesRegex(mcp.ScanRequestError, "dolu"):
            mcp.create_request(
                self.store,
                "operator_authorized_http",
                {"tool_id": "schemathesis", "target": "https://full.example/",
                 "options": {"schema": schema()}},
                requester=ANALYST,
                confirm_request=True,
                environ={},
            )
        spool = self.data_dir / mcp.SCHEMA_SPOOL_DIR
        self.assertFalse(spool.exists() and any(spool.iterdir()))
        after = json.loads(self.queue_path.read_text(encoding="utf-8"))["requests"]
        self.assertEqual({row["id"] for row in after}, {self._row(i, "pending")["id"] for i in range(200)})

    def test_schema_spool_write_failure_unlinks_partial_file(self) -> None:
        with mock.patch.object(mcp.os, "fsync", side_effect=OSError("synthetic fsync failure")):
            with self.assertRaisesRegex(mcp.ScanRequestError, "yazılamadı"):
                mcp.create_request(
                    self.store,
                    "operator_authorized_http",
                    {"tool_id": "schemathesis", "target": "https://write-failure.example/",
                     "options": {"schema": schema()}},
                    requester=ANALYST,
                    confirm_request=True,
                    environ={},
                )
        spool = self.data_dir / mcp.SCHEMA_SPOOL_DIR
        self.assertTrue(spool.is_dir())
        self.assertEqual(list(spool.iterdir()), [])

    def test_non_nuclei_success_has_tool_specific_masked_summary(self) -> None:
        item = self._create_nmap()
        completed = self._complete_outer(item, {
            "profile": "authorized-service-light-v1",
            "host_count": 1,
            "up_host_count": 1,
            "open_port_count": 2,
            "open_ports": [80, 443],
            "report_sha256": "a" * 64,
            "target_sha256": "b" * 64,
            "target": "https://must-not-leak.invalid/private",
            "raw": "secret",
            "attacker_named_metric": 999,
        })
        self.assertEqual(completed["status"], "completed")
        self.assertEqual(completed["triage_summary"], {
            "state": "completed",
            "tool_id": "nmap",
            "summary_state": "available",
            "profile": "authorized-service-light-v1",
            "host_count": 1,
            "up_host_count": 1,
            "open_port_count": 2,
            "open_ports": [80, 443],
            "report_sha256": "a" * 64,
        })
        encoded = json.dumps(completed["triage_summary"])
        for forbidden in ("must-not-leak", "target_sha256", "raw", "attacker_named_metric"):
            self.assertNotIn(forbidden, encoded)

    def test_malformed_non_nuclei_result_is_explicitly_summary_unavailable(self) -> None:
        item = mcp.create_request(
            self.store,
            "operator_authorized_http",
            {"tool_id": "owasp-zap", "target": "https://malformed.example/"},
            requester=ANALYST,
            confirm_request=True,
            environ={},
        )
        completed = self._complete_outer(item, {
            "target": "https://must-not-leak.invalid/", "raw": {"secret": True}, "dynamic": 9,
        })
        self.assertEqual(completed["status"], "completed")
        self.assertEqual(completed["triage_summary"], {
            "state": "completed",
            "tool_id": "owasp-zap",
            "summary_state": "summary_unavailable",
        })

    def test_persisted_outer_cancel_recovers_mcp_as_cancelled_not_failed(self) -> None:
        item = self._create_nmap()
        mcp.claim_request(self.store, item["id"], approved_by=ADMIN, confirm_authorized=True)
        job_id = "job_" + "e" * 24
        mcp.mark_started(self.store, item["id"], job_id)
        jobs = self.data_dir / "jobs"
        jobs.mkdir(mode=0o700)
        outer = jobs / f"{job_id}.json"
        outer.write_text(json.dumps({
            "id": job_id, "state": "cancelled", "finished_at": "2026-10-22T12:00:00Z",
        }), encoding="utf-8")
        os.chmod(outer, 0o600)

        recovered = next(row for row in mcp.list_requests(self.store) if row["id"] == item["id"])
        self.assertEqual(recovered["status"], "cancelled")
        self.assertEqual(recovered["cancelled_at"], "2026-10-22T12:00:00Z")
        self.assertEqual(recovered["cancellation_reason"], "bağlı dış iş iptal edildi")
        self.assertNotIn("failure_reason", recovered)

    def test_persisted_nuclei_inner_cancel_recovers_mcp_as_cancelled_not_failed(self) -> None:
        item = mcp.create_request(
            self.store,
            "operator_authorized_http",
            {"tool_id": "nuclei", "target": "http://127.0.0.1:49123/"},
            requester=ANALYST,
            confirm_request=True,
            environ={},
        )
        mcp.claim_request(self.store, item["id"], approved_by=ADMIN, confirm_authorized=True)
        outer_id, scanner_id = "job_" + "f" * 24, "d" * 16
        mcp.mark_started(self.store, item["id"], outer_id)
        jobs = self.data_dir / "jobs"
        jobs.mkdir(mode=0o700)
        outer = jobs / f"{outer_id}.json"
        outer.write_text(json.dumps({
            "id": outer_id, "state": "succeeded", "result": {"job_id": scanner_id, "state": "starting"},
        }), encoding="utf-8")
        os.chmod(outer, 0o600)
        self.assertEqual(mcp.list_requests(self.store)[0]["scanner_job_id"], scanner_id)
        AggregateHistoryJournal(self.data_dir).save([(
            scanner_id, {"state": "cancelled", "elapsed_seconds": 1.0},
        )])

        recovered = next(row for row in mcp.list_requests(self.store) if row["id"] == item["id"])
        self.assertEqual(recovered["status"], "cancelled")
        self.assertEqual(recovered["cancellation_reason"], "Nuclei iç işi iptal edildi")
        self.assertNotIn("failure_reason", recovered)

    def test_fixed_summary_schemas_cover_every_non_nuclei_runtime_tool(self) -> None:
        relay = {"connections": 1, "refused": 0, "bytes": 10, "dynamic_relay": "do-not-copy"}
        digest = "a" * 64
        cases = {
            "owasp-zap": {
                "format": "zap-authorized-v1", "profile": "same-origin-authorized-spider-active-v1",
                "site_count": 1, "alert_type_count": 2, "instance_count": 3,
                "risk_counts": {"informational": 0, "low": 1, "medium": 1, "high": 0,
                                "dynamic_risk": "do-not-copy"},
                "report_sha256": digest, "elapsed_seconds": 1.0,
            },
            "k6": {
                "format": "k6-authorized-target-v1", "status": "completed", "thresholds_ok": True,
                "script_sha256": digest, "relay": relay,
                "summary": {"format": "k6-handle-summary-json", "http_requests": 3,
                            "duration_p95_ms": 12.5, "threshold_counts": {"passed": 2, "failed": 0,
                                                                            "dynamic": 99},
                            "report_sha256": digest, "dynamic_summary": "do-not-copy"},
            },
            "openssl": {
                "format": "openssl-x509-authorized-v1", "verification": "passed", "validity": "valid",
                "not_before_utc": "2026-01-01T00:00:00Z", "not_after_utc": "2027-01-01T00:00:00Z",
                "days_until_expiry": 70, "report_sha256": digest,
            },
            "nmap": {
                "profile": "authorized-default-v1", "host_count": 1, "up_host_count": 1,
                "open_port_count": 1, "open_ports": [443], "report_sha256": digest,
            },
            "testssl": {
                "format": "testssl-authorized-v1", "profile": "authorized-protocols-v1",
                "record_count": 1,
                "severity_counts": {"INFO": 0, "OK": 1, "LOW": 0, "MEDIUM": 0, "HIGH": 0,
                                    "CRITICAL": 0, "WARN": 0, "DEBUG": 0, "FATAL": 0,
                                    "dynamic_severity": 99},
                "report_sha256": digest, "elapsed_seconds": 0.5,
            },
            "browser-tests": {
                "format": "playwright-authorized-v1", "status": "completed", "driver_sha256": digest,
                "relay": relay, "findings": [{"target": "https://must-not-leak.invalid"}],
                "facts": {"raw": "do-not-copy"},
            },
            "ssllabs": {
                "format": "ssllabs-v4-host", "assessment_status": "READY", "endpoint_count": 1,
                "successful_endpoint_count": 1,
                "grade_counts": {"A+": 0, "A": 1, "A-": 0, "B": 0, "C": 0, "D": 0,
                                 "E": 0, "F": 0, "T": 0, "M": 0, "dynamic_grade": 99},
                "summary_sha256": digest,
            },
            "schemathesis": {
                "format": "schemathesis-authorized-target-v1", "status": "completed",
                "issues_found": False, "schema_sha256": digest, "relay": relay,
                "summary": {"format": "schemathesis-junit-xml", "suite_count": 1, "testcase_count": 1,
                            "outcome_counts": {"passed": 1, "failed": 0, "errors": 0, "skipped": 0,
                                               "dynamic_outcome": 99},
                            "report_sha256": digest, "dynamic_summary": "do-not-copy"},
            },
        }
        for tool_id, result in cases.items():
            with self.subTest(tool_id=tool_id):
                result.update(target="https://must-not-leak.invalid/private", raw="do-not-copy", dynamic_key=99)
                summary = mcp._masked_outer_summary({
                    "_tool_id": tool_id,
                    "profile_id": "operator_authorized_http",
                    "parameters": {"tool_id": tool_id},
                }, result)
                self.assertEqual(summary["summary_state"], "available", summary)
                encoded = json.dumps(summary)
                for forbidden in ("must-not-leak", "do-not-copy", "dynamic_"):
                    self.assertNotIn(forbidden, encoded)

    def test_allowlisted_summary_fields_still_reject_adversarial_values(self) -> None:
        base = {
            "profile": "authorized-default-v1", "host_count": 1, "up_host_count": 1,
            "open_port_count": 1, "open_ports": [443], "report_sha256": "a" * 64,
        }
        adversarial = (
            {**base, "profile": "https://secret.invalid/profile"},
            {**base, "profile": ["authorized-default-v1", "https://secret.invalid"]},
            {**base, "open_ports": ["443"]},
            {**base, "open_ports": [{"target": "secret"}]},
            {**base, "open_port_count": 2, "open_ports": [443, 443]},
            {**base, "host_count": 2**53},
            {**base, "report_sha256": "A" * 64},
            {**base, "report_sha256": "not-a-sha"},
        )
        item = {"_tool_id": "nmap", "profile_id": "operator_authorized_http",
                "parameters": {"tool_id": "nmap"}}
        for result in adversarial:
            with self.subTest(result=result):
                self.assertEqual(mcp._masked_outer_summary(item, result), {
                    "state": "completed", "tool_id": "nmap", "summary_state": "summary_unavailable",
                })

        zap = {
            "format": "zap-authorized-v1", "profile": "https://secret.invalid/profile",
            "site_count": 1, "alert_type_count": 1, "instance_count": 1,
            "risk_counts": {"informational": 0, "low": 1, "medium": 0, "high": 0},
            "report_sha256": "a" * 64,
        }
        self.assertEqual(mcp._masked_outer_summary({"_tool_id": "owasp-zap"}, zap)["summary_state"],
                         "summary_unavailable")
        unknown = mcp._masked_outer_summary(
            {"_tool_id": "https://secret.invalid/tool"},
            {"format": "anything", "target": "https://secret.invalid"},
        )
        self.assertEqual(unknown, {
            "state": "completed", "tool_id": "unknown", "summary_state": "summary_unavailable",
        })

    def test_route_aggregate_invariants_fail_closed(self) -> None:
        digest = "a" * 64
        zap = {
            "format": "zap-authorized-v1", "profile": "same-origin-authorized-spider-active-v1",
            "site_count": 1, "alert_type_count": 1, "instance_count": 1,
            "risk_counts": {"informational": 0, "low": 1, "medium": 0, "high": 0},
            "report_sha256": digest,
        }
        ssllabs = {
            "format": "ssllabs-v4-host", "assessment_status": "READY", "endpoint_count": 1,
            "grade_counts": {"A+": 0, "A": 1, "A-": 0, "B": 0, "C": 0, "D": 0,
                             "E": 0, "F": 0, "T": 0, "M": 0},
            "summary_sha256": digest,
        }
        nmap = {
            "profile": "authorized-default-v1", "host_count": 1, "up_host_count": 1,
            "open_port_count": 1, "open_ports": [443], "report_sha256": digest,
        }
        cases = (
            ("owasp-zap", {**zap, "site_count": 21}),
            ("owasp-zap", {**zap, "alert_type_count": 501}),
            ("owasp-zap", {**zap, "instance_count": 5001}),
            ("owasp-zap", {**zap, "alert_type_count": 2}),
            ("ssllabs", {**ssllabs, "grade_counts": {**ssllabs["grade_counts"], "A+": 1}}),
            ("nmap", {**nmap, "host_count": 501}),
            ("nmap", {**nmap, "host_count": 0, "up_host_count": 1}),
            ("nmap", {**nmap, "open_port_count": 25, "open_ports": list(range(1, 26))}),
        )
        for tool_id, result in cases:
            with self.subTest(tool_id=tool_id, result=result):
                summary = mcp._masked_outer_summary({"_tool_id": tool_id}, result)
                self.assertEqual(summary, {
                    "state": "completed", "tool_id": tool_id, "summary_state": "summary_unavailable",
                })


class MCPCancelApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(self.temp.cleanup)
        self.data_dir = Path(self.temp.name) / "data"
        self.previous_store = server.STORE
        server.STORE = Store(self.data_dir / "sniper.db")
        self.addCleanup(setattr, server, "STORE", self.previous_store)
        self.handler = server.SniperHandler.__new__(server.SniperHandler)
        self.responses: list[tuple[int, dict]] = []
        self.handler._json = lambda body, status=200, **_kw: self.responses.append((int(status), body))
        self.handler._error = lambda status, message: self.responses.append((int(status), {"error": message}))

    def _start(self, tool_id: str = "nmap", *, target: str | None = None) -> tuple[dict, str]:
        target = target or ("http://127.0.0.1:49123/" if tool_id == "nuclei" else "cancel.example")
        item = mcp.create_request(
            server.STORE,
            "operator_authorized_http",
            {"tool_id": tool_id, "target": target},
            requester=ANALYST,
            confirm_request=True,
            environ={},
        )
        mcp.claim_request(server.STORE, item["id"], approved_by=ADMIN, confirm_authorized=True)
        job_id = "job_" + "c" * 24
        mcp.mark_started(server.STORE, item["id"], job_id)
        return item, job_id

    def _cancel(self, request_id: str) -> tuple[int, dict]:
        self.responses.clear()
        with request_context.acting_as(ADMIN):
            self.handler._mcp_scan_requests_post(
                f"/api/mcp-scan-requests/{request_id}/cancel", {"confirm": True},
            )
        return self.responses[-1]

    def test_started_queued_outer_job_is_really_cancelled_before_mcp_terminal_transition(self) -> None:
        item, job_id = self._start()
        with mock.patch.object(server.JOBS, "get", return_value={"id": job_id, "state": "queued"}) as get, \
                mock.patch.object(server.JOBS, "cancel", return_value={
                    "id": job_id, "state": "cancelled", "cancel_requested": True,
                }) as cancel:
            status, body = self._cancel(item["id"])
        self.assertEqual(status, 200, body)
        get.assert_called_once_with(job_id)
        cancel.assert_called_once_with(job_id)
        self.assertEqual(body["request"]["status"], "cancelled")
        self.assertEqual(mcp.list_requests(server.STORE)[0]["status"], "cancelled")

    def test_real_job_queue_queued_job_is_cancelled_and_never_runs(self) -> None:
        gate = threading.Event()
        blocker_started = threading.Event()
        scan_ran = threading.Event()
        queue = JobQueue(
            workers=1, max_queued=4, timeout_seconds=10, store_dir=self.data_dir / "jobs",
        )

        def block(_job) -> tuple[int, dict]:
            blocker_started.set()
            gate.wait(5)
            return 200, {"ok": True}

        blocker = queue.submit("/synthetic/block", block, dedupe_key="block")
        self.assertTrue(blocker_started.wait(2))
        item, _unused_job_id = self._start()

        def should_not_run(_job) -> tuple[int, dict]:
            scan_ran.set()
            return 200, {"ok": True}

        queued = queue.submit("/api/nmap/authorized-target-scan", should_not_run, dedupe_key="r57-scan")
        path = self.data_dir / mcp.FILE_NAME
        data = json.loads(path.read_text(encoding="utf-8"))
        row = next(row for row in data["requests"] if row["id"] == item["id"])
        row["job_id"] = queued.id
        path.write_text(json.dumps(data), encoding="utf-8")
        os.chmod(path, 0o600)
        try:
            with mock.patch.object(server, "JOBS", queue):
                status, body = self._cancel(item["id"])
            self.assertEqual(status, 200, body)
            self.assertEqual(body["request"]["status"], "cancelled")
            self.assertEqual(queue.get(queued.id)["state"], "cancelled")
            self.assertFalse(scan_ran.is_set())
        finally:
            gate.set()
        deadline = time.monotonic() + 2.0
        while queue.get(blocker.id)["state"] == "running" and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(queue.get(blocker.id)["state"], "succeeded")
        self.assertIn(blocker.id, {job["id"] for job in queue.list()})

    def test_running_outer_job_accepts_cancel_requested_and_mcp_stays_cancelled(self) -> None:
        item, job_id = self._start()
        with mock.patch.object(server.JOBS, "get", return_value={"id": job_id, "state": "running"}), \
                mock.patch.object(server.JOBS, "cancel", return_value={
                    "id": job_id, "state": "running", "cancel_requested": True,
                }) as cancel:
            status, body = self._cancel(item["id"])
        self.assertEqual(status, 200, body)
        cancel.assert_called_once_with(job_id)
        self.assertEqual(body["request"]["status"], "cancelled")
        self.assertEqual(mcp.list_requests(server.STORE)[0]["status"], "cancelled")

    def test_missing_or_terminal_outer_job_fails_closed_without_false_mcp_cancel(self) -> None:
        for mode in ("missing", "terminal"):
            with self.subTest(mode=mode):
                item, job_id = self._start()
                current = None if mode == "missing" else {"id": job_id, "state": "succeeded"}
                with mock.patch.object(server.JOBS, "get", return_value=current), \
                        mock.patch.object(server.JOBS, "cancel") as cancel:
                    status, _body = self._cancel(item["id"])
                self.assertEqual(status, 409)
                cancel.assert_not_called()
                row = next(row for row in mcp.list_requests(server.STORE) if row["id"] == item["id"])
                self.assertIn(row["status"], {"started", "running"})
                mcp.mark_failed(server.STORE, item["id"], "test cleanup")

    def test_nuclei_inner_job_uses_existing_broad_jobs_cancel_contract(self) -> None:
        item, outer_id = self._start("nuclei")
        scanner_id = "d" * 16
        jobs = self.data_dir / "jobs"
        jobs.mkdir(mode=0o700)
        outer = jobs / f"{outer_id}.json"
        outer.write_text(json.dumps({
            "id": outer_id,
            "state": "succeeded",
            "result": {"job_id": scanner_id, "state": "starting"},
        }), encoding="utf-8")
        os.chmod(outer, 0o600)
        self.assertEqual(mcp.list_requests(server.STORE)[0]["scanner_job_id"], scanner_id)
        inner = mock.Mock()
        inner.cancel.return_value = {"job_id": scanner_id, "state": "cancelled"}
        with mock.patch.object(server, "get_broad_nuclei_jobs", return_value=inner), \
                mock.patch.object(server.JOBS, "get", return_value={
                    "id": outer_id, "state": "succeeded",
                }), mock.patch.object(server.JOBS, "cancel") as outer_cancel:
            status, body = self._cancel(item["id"])
        self.assertEqual(status, 200, body)
        inner.cancel.assert_called_once_with(scanner_id)
        outer_cancel.assert_not_called()
        self.assertEqual(body["request"]["status"], "cancelled")

    def test_broad_nuclei_cancel_propagates_terminal_race_from_bounded_process(self) -> None:
        scanner_id = "e" * 16
        for terminal in ("completed", "failed"):
            with self.subTest(terminal=terminal):
                bounded = mock.Mock()
                bounded.status.return_value = {"state": "running", "elapsed_seconds": 1.0}
                bounded.cancel.return_value = {"state": terminal, "elapsed_seconds": 1.1}
                manager = BroadNucleiJobs.__new__(BroadNucleiJobs)
                manager._jobs_lock = threading.Lock()
                manager._jobs = {scanner_id: {"job_id": scanner_id, "bounded": bounded}}
                manager._recent_completed = []
                result = manager.cancel(scanner_id)
                self.assertEqual(result["job_id"], scanner_id)
                self.assertEqual(result["state"], terminal)

    def test_nuclei_terminal_cancel_race_fails_closed_without_false_mcp_cancel(self) -> None:
        for terminal in ("completed", "failed"):
            with self.subTest(terminal=terminal):
                port = 49124 if terminal == "completed" else 49125
                item, outer_id = self._start("nuclei", target=f"http://127.0.0.1:{port}/")
                scanner_id = ("a" if terminal == "completed" else "b") * 16
                jobs = self.data_dir / "jobs"
                jobs.mkdir(mode=0o700, exist_ok=True)
                outer = jobs / f"{outer_id}.json"
                outer.write_text(json.dumps({
                    "id": outer_id,
                    "state": "succeeded",
                    "result": {"job_id": scanner_id, "state": "starting"},
                }), encoding="utf-8")
                os.chmod(outer, 0o600)
                inner = mock.Mock()
                inner.cancel.return_value = {"job_id": scanner_id, "state": terminal}
                with mock.patch.object(server, "get_broad_nuclei_jobs", return_value=inner), \
                        mock.patch.object(server.JOBS, "get", return_value={
                            "id": outer_id, "state": "succeeded",
                        }), mock.patch.object(server.JOBS, "cancel") as outer_cancel:
                    status, _body = self._cancel(item["id"])
                self.assertEqual(status, 409)
                outer_cancel.assert_not_called()
                row = next(row for row in mcp.list_requests(server.STORE) if row["id"] == item["id"])
                self.assertNotEqual(row["status"], "cancelled")


if __name__ == "__main__":
    unittest.main()
