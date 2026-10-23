from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from nuclei_aggregate_history import AggregateHistoryJournal
from nuclei_finding_journal import NucleiFindingJournal
import mcp_scan_requests
import mcp_triage_server
from scanner import normalize_target
from storage import Store


class NucleiFindingJournalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(self.temp.cleanup)
        self.data_dir = Path(self.temp.name) / "data"
        self.data_dir.mkdir(mode=0o700)

    def test_records_are_bounded_and_sensitive_nuclei_fields_are_not_persisted(self) -> None:
        records = [{
            "template-id": "http/misconfiguration/test",
            "info": {"name": "Test header exposed", "severity": "high"},
            "matched-at": f"https://secret.example/private/{index}?token=top-secret",
            "request": "Authorization: Bearer top-secret",
            "response": "secret response body",
        } for index in range(NucleiFindingJournal.MAX_FINDINGS_PER_JOB + 3)]
        saved = NucleiFindingJournal(self.data_dir).save_job("a" * 16, records)
        self.assertEqual(len(saved["findings"]), NucleiFindingJournal.MAX_FINDINGS_PER_JOB)
        self.assertTrue(saved["truncated"])
        raw = (self.data_dir / NucleiFindingJournal.NAME).read_text()
        self.assertNotIn("secret.example", raw)
        self.assertNotIn("top-secret", raw)
        self.assertNotIn("response body", raw)
        self.assertEqual(set(saved["findings"][0]), {
            "template_id", "title", "severity", "fingerprint_sha256", "evidence_sha256",
        })
        self.assertEqual(oct((self.data_dir / NucleiFindingJournal.NAME).stat().st_mode & 0o777), "0o600")


class NucleiFindingTriageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(self.temp.cleanup)
        self.data_dir = Path(self.temp.name) / "data"
        self.env = mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(self.data_dir)})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.store = Store(self.data_dir / "sniper.db")
        target = self.store.create_target(normalize_target("https://example.com"))
        engagement = self.store.create_engagement(
            target_id=target["id"], name="Yetkili", authorization_ref="AUTH-1",
            scope_notes="Tek hedef", out_of_scope="", test_window="", special_approvals={},
        )
        self.analyst = {"id": "usr_analyst", "username": "analist", "role": "analyst"}
        self.other = {"id": "usr_other", "username": "diger", "role": "analyst"}
        self.request = mcp_scan_requests.create_request(
            self.store, "nuclei_http_authorized",
            {"target_id": target["id"], "engagement_id": engagement["id"]},
            requester=self.analyst, confirm_request=True,
        )
        mcp_scan_requests.claim_request(
            self.store, self.request["id"],
            approved_by={"id": "admin", "username": "admin", "role": "admin"},
            confirm_authorized=True,
        )
        self.outer_id, self.scanner_id = "job_" + "a" * 24, "b" * 16
        mcp_scan_requests.mark_started(self.store, self.request["id"], self.outer_id)
        jobs = self.data_dir / "jobs"
        jobs.mkdir(mode=0o700)
        outer = jobs / f"{self.outer_id}.json"
        outer.write_text(json.dumps({"id": self.outer_id, "state": "succeeded", "result": {
            "job_id": self.scanner_id, "state": "starting",
        }}))
        os.chmod(outer, 0o600)
        AggregateHistoryJournal(self.data_dir).save([(
            self.scanner_id,
            {"state": "completed", "elapsed_seconds": 1.0, "report_sha256": "c" * 64,
             "record_count": 1, "unique_template_count": 1, "severity_counts": {"high": 1}},
        )])
        NucleiFindingJournal(self.data_dir).save_job(self.scanner_id, [{
            "template-id": "http/misconfiguration/test",
            "info": {"name": "Exposed panel", "severity": "high"},
            "matched-at": "https://example.com/admin?token=private",
            "request": "secret request",
        }])

    def test_completed_job_imports_real_findings_and_accepts_pending_triage_suggestion(self) -> None:
        request = mcp_scan_requests.list_requests(self.store, requester=self.analyst)[0]
        self.assertEqual(request["triage_summary"]["finding_count"], 1)
        findings = mcp_scan_requests.list_findings(
            self.store, request["id"], requester=self.analyst,
        )
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual((finding["template_id"], finding["severity"]),
                         ("http/misconfiguration/test", "high"))
        self.assertNotIn("example.com", json.dumps(finding))
        saved = mcp_scan_requests.submit_finding_triage(
            self.store, request["id"], finding["id"], requester=self.analyst,
            verdict="likely_true", confidence=0.9, rationale="Şablon ve önem eşleşiyor.",
            agent="test-agent", model="test-model",
        )
        self.assertEqual(saved["decision"], "pending")
        refreshed = mcp_scan_requests.list_findings(
            self.store, request["id"], requester=self.analyst,
        )[0]
        self.assertEqual(refreshed["latest_triage"]["verdict"], "likely_true")

    def test_request_owner_boundary_is_enforced_for_scan_findings(self) -> None:
        mcp_scan_requests.list_requests(self.store, requester=self.analyst)
        with self.assertRaises(mcp_scan_requests.ScanRequestError):
            mcp_scan_requests.list_findings(self.store, self.request["id"], requester=self.other)

    def test_mcp_exposes_scan_finding_tools_without_raw_evidence(self) -> None:
        server = mcp_triage_server.TriageMCPServer(self.store, user=self.analyst)
        mcp_scan_requests.list_requests(self.store, requester=self.analyst)
        listed = server.call_tool("list_scan_result_findings", {"request_id": self.request["id"]})
        self.assertFalse(listed["isError"], listed)
        payload = json.loads(listed["content"][0]["text"])
        finding = payload["findings"][0]
        submitted = server.call_tool("submit_scan_result_triage", {
            "request_id": self.request["id"], "finding_id": finding["id"],
            "verdict": "uncertain", "confidence": 0.4, "rationale": "Çalışma zamanı kanıtı gerekli.",
        })
        self.assertFalse(submitted["isError"], submitted)
        self.assertNotIn("matched-at", listed["content"][0]["text"])


if __name__ == "__main__":
    unittest.main()
