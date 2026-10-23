from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock

import mcp_scan_requests as mcp
from nuclei_aggregate_history import AggregateHistoryJournal
from nuclei_finding_journal import NucleiFindingJournal
import server
from scanner import normalize_target
from storage import Store


ANALYST = {"id": "usr_analyst", "username": "analist", "role": "analyst"}
OTHER = {"id": "usr_other", "username": "diger", "role": "analyst"}
ADMIN = {"id": "usr_admin", "username": "yonetici", "role": "admin"}


def schema() -> dict:
    return {
        "openapi": "3.0.3",
        "info": {"title": "MCP", "version": "1"},
        "paths": {
            "/items": {
                "post": {"responses": {"204": {"description": "ok"}}},
                "delete": {"responses": {"204": {"description": "ok"}}},
            }
        },
    }


class Wave2PlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(self.temp.cleanup)
        self.data_dir = Path(self.temp.name) / "data"
        self.store = Store(self.data_dir / "sniper.db")

    def create(self, parameters: dict) -> dict:
        return mcp.create_request(
            self.store, "operator_authorized_http", parameters,
            requester=ANALYST, confirm_request=True, environ={},
        )

    def claim(self, item: dict) -> dict:
        return mcp.claim_request(self.store, item["id"], approved_by=ADMIN, confirm_authorized=True)

    def test_all_runtime_tools_have_exact_fixed_routes_and_burp_stays_manual(self) -> None:
        cases = (
            ({"tool_id": "nmap", "target": "Example.COM", "profile": "service-light"},
             "/api/nmap/authorized-target-scan",
             {"target": "example.com", "profile": "service-light", "confirm_authorized": True}),
            ({"tool_id": "testssl", "target": "Example.COM:8443", "profile": "full"},
             "/api/tool-runs/testssl-authorized",
             {"target": "example.com:8443", "profile": "full", "confirm_authorized": True}),
            ({"tool_id": "browser-tests", "target": "HTTPS://Example.COM/"},
             "/api/tool-runs/playwright-authorized",
             {"target": "https://example.com", "confirm_authorized": True}),
            ({"tool_id": "nuclei", "target": "HTTPS://Example.COM/"},
             "/api/nuclei/authorized-origin-scans",
             {"target_origin": "https://example.com", "confirm_authorized": True}),
            ({"tool_id": "ssllabs", "target": "EXAMPLE.COM"},
             "/api/tool-runs/ssllabs-authorized",
             {"target": "example.com", "confirm_authorized": True}),
        )
        for parameters, route, payload in cases:
            with self.subTest(tool=parameters["tool_id"]):
                claim = self.claim(self.create(parameters))
                self.assertEqual(claim["launch"], {"route": route, "payload": payload})
                self.assertIn(route, server.JOB_ROUTES)
                self.assertEqual(claim["authorization_receipt"]["plan_sha256"], claim["plan_sha256"])
                self.assertEqual(len(claim["authorization_receipt"]["scope_summary"]), 1)

        manual = self.claim(self.create({"tool_id": "burp-suite", "target": "https://example.com/"}))
        self.assertEqual(manual["status"], "approved")
        self.assertEqual(manual["dispatch"]["mode"], "manual_handoff")

    def test_exact_parameter_shapes_profiles_and_scope_expansion_are_rejected(self) -> None:
        invalid = (
            {"tool_id": "nmap", "target": "https://example.com/path"},
            {"tool_id": "nmap", "target": "example.com:443"},
            {"tool_id": "nmap", "target": "example.com", "profile": "aggressive"},
            {"tool_id": "testssl", "target": "example.com"},
            {"tool_id": "testssl", "target": "example.com:443", "profile": "weak"},
            {"tool_id": "browser-tests", "target": "https://example.com/path"},
            {"tool_id": "nuclei", "target": "https://example.com/?wide=1"},
            {"tool_id": "ssllabs", "target": "https://example.com"},
            {"tool_id": "ssllabs", "target": "127.0.0.1"},
            {"tool_id": "openssl", "target": "https://example.com/", "profile": "x"},
            {"tool_id": "browser-tests", "target": "https://example.com/", "options": {}},
            {"tool_id": "schemathesis", "target": "https://example.com/", "options": {"schema": schema()}, "extra": 1},
        )
        for parameters in invalid:
            with self.subTest(parameters=parameters), self.assertRaises(mcp.ScanRequestError):
                self.create(parameters)

    def test_schemathesis_schema_is_private_spooled_and_reverified(self) -> None:
        item = self.create({
            "tool_id": "schemathesis", "target": "https://example.com/",
            "options": {"schema": schema()},
        })
        queue_text = (self.data_dir / mcp.FILE_NAME).read_text(encoding="utf-8")
        self.assertNotIn('"paths"', queue_text)
        ref = item["parameters"]["options"]["schema_ref"]
        spool_dir = self.data_dir / mcp.SCHEMA_SPOOL_DIR
        spool = spool_dir / ref
        self.assertEqual(spool_dir.stat().st_mode & 0o777, 0o700)
        self.assertEqual(spool.stat().st_mode & 0o777, 0o600)
        claim = self.claim(item)
        self.assertEqual(claim["launch"]["route"], "/api/tool-runs/schemathesis-authorized")
        self.assertEqual(claim["launch"]["payload"]["schema"], schema())
        self.assertIn("POST/DELETE", claim["authorization_receipt"]["consent_scope"])
        approved_queue_text = (self.data_dir / mcp.FILE_NAME).read_text(encoding="utf-8")
        self.assertNotIn('"paths"', approved_queue_text)
        self.assertNotIn('"title": "MCP"', approved_queue_text)
        mcp.mark_started(self.store, item["id"], "job_" + "a" * 24)
        self.assertFalse(spool.exists())
        started_queue_text = (self.data_dir / mcp.FILE_NAME).read_text(encoding="utf-8")
        self.assertNotIn('"paths"', started_queue_text)
        self.assertNotIn('"title": "MCP"', started_queue_text)

        tampered = self.create({
            "tool_id": "schemathesis", "target": "https://example.org/",
            "options": {"schema": schema()},
        })
        tampered_spool = spool_dir / tampered["parameters"]["options"]["schema_ref"]
        tampered_spool.write_text("{}", encoding="utf-8")
        os.chmod(tampered_spool, 0o600)
        with self.assertRaises(mcp.ScanRequestError):
            self.claim(tampered)

    def test_cancel_and_failed_submit_cleanup_schema_spool(self) -> None:
        one = self.create({"tool_id": "schemathesis", "target": "https://one.example/",
                           "options": {"schema": schema()}})
        ref = one["parameters"]["options"]["schema_ref"]
        mcp.cancel_request(self.store, one["id"], cancelled_by=ADMIN)
        self.assertFalse((self.data_dir / mcp.SCHEMA_SPOOL_DIR / ref).exists())

    def test_schema_spool_parent_symlink_swap_never_unlinks_victim(self) -> None:
        item = self.create({"tool_id": "schemathesis", "target": "https://swap.example/",
                            "options": {"schema": schema()}})
        ref = item["parameters"]["options"]["schema_ref"]
        spool = self.data_dir / mcp.SCHEMA_SPOOL_DIR
        original = self.data_dir / "original-spool"
        victim = self.data_dir / "victim"
        spool.rename(original)
        victim.mkdir(mode=0o700)
        victim_file = victim / ref
        victim_file.write_text("do-not-delete", encoding="utf-8")
        os.chmod(victim_file, 0o600)
        spool.symlink_to(victim, target_is_directory=True)

        cancelled = mcp.cancel_request(self.store, item["id"], cancelled_by=ADMIN)
        self.assertEqual(cancelled["status"], "cancelled")
        self.assertEqual(victim_file.read_text(encoding="utf-8"), "do-not-delete")
        self.assertTrue((original / ref).is_file())

    def test_stale_launch_reservation_recovers_failed_and_cleans_schema(self) -> None:
        item = self.create({"tool_id": "schemathesis", "target": "https://restart.example/",
                            "options": {"schema": schema()}})
        ref = item["parameters"]["options"]["schema_ref"]
        self.claim(item)
        path = self.data_dir / mcp.FILE_NAME
        data = json.loads(path.read_text())
        row = next(row for row in data["requests"] if row["id"] == item["id"])
        row["launching_at"] = "2000-01-01T00:00:00Z"
        path.write_text(json.dumps(data), encoding="utf-8")
        os.chmod(path, 0o600)

        recovered = next(row for row in mcp.list_requests(self.store) if row["id"] == item["id"])
        self.assertEqual(recovered["status"], "failed")
        self.assertIn("rezervasyonu", recovered["failure_reason"])
        self.assertFalse((self.data_dir / mcp.SCHEMA_SPOOL_DIR / ref).exists())
        replacement = self.create({
            "tool_id": "schemathesis", "target": "https://restart.example/",
            "options": {"schema": schema()},
        })
        self.claim(replacement)
        cancelled = mcp.cancel_request(self.store, replacement["id"], cancelled_by=ADMIN)
        self.assertEqual(cancelled["status"], "cancelled")

    def test_semantically_duplicate_schema_has_one_pending_row_and_one_spool(self) -> None:
        parameters = {"tool_id": "schemathesis", "target": "https://duplicate.example/",
                      "options": {"schema": schema()}}
        self.create(parameters)
        with self.assertRaisesRegex(mcp.ScanRequestError, "zaten var"):
            self.create(parameters)
        rows = mcp.list_requests(self.store, requester=ANALYST)
        self.assertEqual(len([row for row in rows if row["status"] == "pending"]), 1)
        spool = self.data_dir / mcp.SCHEMA_SPOOL_DIR
        self.assertEqual(len(list(spool.glob("schema-msr_*.json"))), 1)

    def test_legacy_registered_pending_rows_are_backfilled_and_rederived_at_claim(self) -> None:
        target = self.store.create_target(normalize_target("https://registered.example"))
        engagement = self.store.create_engagement(
            target_id=target["id"], name="Legacy", authorization_ref="AUTH-R43",
            scope_notes="Tek hedef", out_of_scope="", test_window="", special_approvals={},
        )
        nuclei = mcp.create_request(
            self.store, "nuclei_http_authorized",
            {"target_id": target["id"], "engagement_id": engagement["id"]},
            requester=ANALYST, confirm_request=True, environ={},
        )
        path = self.data_dir / mcp.FILE_NAME
        data = json.loads(path.read_text())
        row = next(row for row in data["requests"] if row["id"] == nuclei["id"])
        for key in ("effective_profile", "scope_summary", "consent_scope", "plan_sha256"):
            row.pop(key, None)
        row["_route"] = "/api/tool-runs/zap-authorized"
        row["_launch_payload"] = {"target": "https://tampered.invalid"}
        path.write_text(json.dumps(data), encoding="utf-8")
        os.chmod(path, 0o600)
        claimed = self.claim(nuclei)
        self.assertEqual(claimed["launch"]["route"], "/api/nuclei/http-scans")
        self.assertEqual(claimed["authorization_receipt"]["effective_profile"], "nuclei_http_authorized")

        resolved = {"kind": "loopback"}
        with mock.patch.object(mcp.sandbox_targets, "resolve_run_target", return_value=resolved), \
                mock.patch.object(mcp.sandbox_targets, "resolve_preset", return_value={"name": "hafif"}):
            k6 = mcp.create_request(
                self.store, "sandbox_k6", {"target": "http://127.0.0.1:49123"},
                requester=ANALYST, confirm_request=True, environ={},
            )
            data = json.loads(path.read_text())
            row = next(row for row in data["requests"] if row["id"] == k6["id"])
            for key in ("effective_profile", "scope_summary", "consent_scope", "plan_sha256"):
                row.pop(key, None)
            row["_route"] = "/api/tool-runs/zap-authorized"
            row["_launch_payload"] = {"target": "https://tampered.invalid"}
            path.write_text(json.dumps(data), encoding="utf-8")
            os.chmod(path, 0o600)
            claimed_k6 = self.claim(k6)
        self.assertEqual(claimed_k6["launch"]["route"], "/api/tool-runs/k6-sandbox")
        self.assertEqual(claimed_k6["authorization_receipt"]["effective_profile"], "sandbox_k6")

        two = self.create({"tool_id": "schemathesis", "target": "https://two.example/",
                           "options": {"schema": schema()}})
        ref = two["parameters"]["options"]["schema_ref"]
        self.claim(two)
        mcp.mark_failed(self.store, two["id"], "sentetik")
        self.assertFalse((self.data_dir / mcp.SCHEMA_SPOOL_DIR / ref).exists())

    def test_plan_and_persisted_launch_tamper_fail_closed_but_v1_receipt_verifies(self) -> None:
        item = self.create({"tool_id": "nmap", "target": "example.com"})
        path = self.data_dir / mcp.FILE_NAME
        data = json.loads(path.read_text())
        row = next(row for row in data["requests"] if row["id"] == item["id"])
        row["_route"] = "/api/tool-runs/zap-authorized"
        row["_launch_payload"] = {"target": "https://evil.invalid", "confirm_authorized": True}
        path.write_text(json.dumps(data), encoding="utf-8")
        os.chmod(path, 0o600)
        claim = self.claim(item)
        self.assertEqual(claim["launch"]["route"], "/api/nmap/authorized-target-scan")

        item2 = self.create({"tool_id": "nmap", "target": "other.example"})
        data = json.loads(path.read_text())
        row = next(row for row in data["requests"] if row["id"] == item2["id"])
        row["plan_sha256"] = "0" * 64
        path.write_text(json.dumps(data), encoding="utf-8")
        os.chmod(path, 0o600)
        with self.assertRaises(mcp.ScanRequestError):
            self.claim(item2)

        legacy = {
            "consent_version": mcp.AUTHORIZATION_CONSENT_VERSION,
            "confirm_authorized": True,
            "actor": {"id": "a", "username": "u"},
            "confirmed_at": "2026-10-22T00:00:00Z",
            "normalized_target": "https://example.com/",
            "profile_id": "operator_authorized_http", "request_id": "msr_" + "1" * 16,
            "tool_id": "burp-suite",
        }
        legacy["receipt_sha256"] = hashlib.sha256(mcp._canonical_receipt(legacy)).hexdigest()
        self.assertTrue(mcp.verify_authorization_receipt(legacy))

    def test_v2_receipt_is_bound_back_to_the_persisted_visible_plan(self) -> None:
        item = self.create({"tool_id": "nmap", "target": "example.com"})
        self.claim(item)
        path = self.data_dir / mcp.FILE_NAME
        data = json.loads(path.read_text())
        row = next(row for row in data["requests"] if row["id"] == item["id"])
        row["scope_summary"] = ["genişletilmiş sahte kapsam"]
        path.write_text(json.dumps(data), encoding="utf-8")
        os.chmod(path, 0o600)
        with self.assertRaisesRegex(mcp.ScanRequestError, "eşleşmiyor"):
            mcp.list_requests(self.store)

    def test_v2_receipt_rejects_profile_and_approver_row_tamper(self) -> None:
        item = self.create({"tool_id": "nmap", "target": "example.com"})
        self.claim(item)
        path = self.data_dir / mcp.FILE_NAME
        data = json.loads(path.read_text())
        row = next(row for row in data["requests"] if row["id"] == item["id"])
        row["parameters"]["profile"] = "service-light"
        path.write_text(json.dumps(data), encoding="utf-8")
        os.chmod(path, 0o600)
        with self.assertRaisesRegex(mcp.ScanRequestError, "planıyla eşleşmiyor"):
            mcp.list_requests(self.store)

        row["parameters"]["profile"] = "default"
        row["approved_by"] = {"id": "forged", "username": "forged"}
        path.write_text(json.dumps(data), encoding="utf-8")
        os.chmod(path, 0o600)
        with self.assertRaisesRegex(mcp.ScanRequestError, "onaylayan yöneticiyle eşleşmiyor"):
            mcp.list_requests(self.store)


class DirectNucleiFindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(self.temp.cleanup)
        self.data_dir = Path(self.temp.name) / "data"
        self.store = Store(self.data_dir / "sniper.db")
        self.item = mcp.create_request(
            self.store, "operator_authorized_http",
            {"tool_id": "nuclei", "target": "http://127.0.0.1:49123/"},
            requester=ANALYST, confirm_request=True, environ={},
        )

    def test_direct_findings_are_masked_idempotent_owner_scoped_and_triage_pending(self) -> None:
        finding = {
            "template_id": "headers", "title": "Missing header", "severity": "low",
            "fingerprint_sha256": "1" * 64, "evidence_sha256": "2" * 64,
        }
        digest = hashlib.sha256(b"http://127.0.0.1:49123").hexdigest()
        self.assertEqual(self.store.import_network_direct_scan_findings(
            request_id=self.item["id"], scanner_job_id="a" * 16,
            target_sha256=digest, findings=[finding],
        ), 1)
        self.assertEqual(self.store.import_network_direct_scan_findings(
            request_id=self.item["id"], scanner_job_id="a" * 16,
            target_sha256=digest, findings=[finding],
        ), 0)
        with sqlite3.connect(self.store.path) as db:
            target_count = db.execute("SELECT COUNT(*) FROM targets").fetchone()[0]
            engagement_count = db.execute("SELECT COUNT(*) FROM engagements").fetchone()[0]
            columns = {row[1] for row in db.execute("PRAGMA table_info(network_direct_scan_findings)")}
        self.assertEqual((target_count, engagement_count), (0, 0))
        self.assertNotIn("target", columns)
        self.assertIn("target_sha256", columns)

        # Complete status is required by the public MCP finding facade.
        path = self.data_dir / mcp.FILE_NAME
        data = json.loads(path.read_text())
        next(row for row in data["requests"] if row["id"] == self.item["id"])["status"] = "completed"
        path.write_text(json.dumps(data), encoding="utf-8")
        os.chmod(path, 0o600)
        rows = mcp.list_findings(self.store, self.item["id"], requester=ANALYST)
        self.assertEqual(len(rows), 1)
        with self.assertRaises(mcp.ScanRequestError):
            mcp.list_findings(self.store, self.item["id"], requester=OTHER)
        suggestion = mcp.submit_finding_triage(
            self.store, self.item["id"], rows[0]["id"], requester=ANALYST,
            verdict="likely_true", confidence=0.8, rationale="sentetik kanıt",
        )
        self.assertEqual(suggestion["decision"], "pending")

    def test_outer_success_keeps_running_until_nested_journal_completes(self) -> None:
        claim = mcp.claim_request(self.store, self.item["id"], approved_by=ADMIN, confirm_authorized=True)
        self.assertEqual(claim["launch"]["route"], "/api/nuclei/authorized-origin-scans")
        outer_id, scanner_id = "job_" + "a" * 24, "b" * 16
        mcp.mark_started(self.store, self.item["id"], outer_id)
        jobs = self.data_dir / "jobs"
        jobs.mkdir(mode=0o700)
        outer = jobs / f"{outer_id}.json"
        outer.write_text(json.dumps({"id": outer_id, "state": "running"}), encoding="utf-8")
        os.chmod(outer, 0o600)
        outer_running = mcp.list_requests(self.store, requester=ANALYST)[0]
        self.assertEqual(outer_running["status"], "running")
        outer.write_text(json.dumps({"id": outer_id, "state": "succeeded", "result": {
            "job_id": scanner_id, "state": "starting",
        }}), encoding="utf-8")
        os.chmod(outer, 0o600)
        running = mcp.list_requests(self.store, requester=ANALYST)[0]
        self.assertEqual((running["status"], running["scanner_job_id"]), ("running", scanner_id))

        AggregateHistoryJournal(self.data_dir).save([(
            scanner_id,
            {"state": "completed", "elapsed_seconds": 1.0, "report_sha256": "c" * 64,
             "record_count": 1, "unique_template_count": 1, "severity_counts": {"low": 1}},
        )])
        NucleiFindingJournal(self.data_dir).save_job(scanner_id, [{
            "template-id": "headers", "info": {"name": "Missing header", "severity": "low"},
            "matched-at": "http://127.0.0.1:49123/private", "request": "secret",
        }])
        completed = mcp.list_requests(self.store, requester=ANALYST)[0]
        self.assertEqual(completed["status"], "completed")
        self.assertTrue(completed["triage_summary"]["findings_imported"])
        findings = mcp.list_findings(self.store, self.item["id"], requester=ANALYST)
        self.assertEqual(len(findings), 1)
        self.assertNotIn("127.0.0.1", json.dumps(findings))

    def test_outer_success_without_valid_nested_id_fails_closed(self) -> None:
        mcp.claim_request(self.store, self.item["id"], approved_by=ADMIN, confirm_authorized=True)
        outer_id = "job_" + "d" * 24
        mcp.mark_started(self.store, self.item["id"], outer_id)
        jobs = self.data_dir / "jobs"
        jobs.mkdir(mode=0o700)
        outer = jobs / f"{outer_id}.json"
        outer.write_text(json.dumps({"id": outer_id, "state": "succeeded", "result": {
            "job_id": "not-an-inner-id", "state": "starting",
        }}), encoding="utf-8")
        os.chmod(outer, 0o600)
        failed = mcp.list_requests(self.store, requester=ANALYST)[0]
        self.assertEqual(failed["status"], "failed")
        self.assertIn("iç iş kimliği", failed["failure_reason"])


class DynamicConsentContractTests(unittest.TestCase):
    def test_ui_has_one_dynamic_checkbox_and_no_startup_post(self) -> None:
        root = Path(__file__).resolve().parents[1]
        source = (root / "static" / "mcp_scan_approval.js").read_text(encoding="utf-8")
        self.assertIn("consentText(item)", source)
        self.assertIn("Qualys SSL Labs", source)
        self.assertIn("POST/DELETE", source)
        self.assertEqual(source.count('consent.type = "checkbox"'), 1)
        self.assertIn('method: "POST"', source)
        self.assertIn('render(await call("/api/mcp-scan-requests"))', source)


if __name__ == "__main__":
    unittest.main()
