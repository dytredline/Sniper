from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scanner import NormalizedTarget, utc_now
from storage import DependencyExportTooLarge, Store


class Wave6And8StorageMethodsTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmp.name) / "sniper_wave6_8_test.db"
        self.store = Store(self.db_path)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _create_target(self, url: str = "https://example.local") -> dict:
        hostname = url.split("://", 1)[1].split("/", 1)[0]
        return self.store.create_target(
            NormalizedTarget(
                url=url,
                scheme="https",
                hostname=hostname,
                port=443,
                path="/",
            )
        )

    def test_m45_list_scans_page_pagination_and_anchor_stability(self) -> None:
        target = self._create_target("https://pagination.example.local")
        created_ids = []
        for idx in range(5):
            scan = self.store.create_scan(target["id"])
            self.store.complete_scan(
                scan["id"],
                {
                    "score": 90 - idx,
                    "grade": "A",
                    "findings": [
                        {
                            "id": f"F-{idx}",
                            "title": f"Finding {idx}",
                            "severity": "low",
                        }
                    ],
                },
            )
            created_ids.append(scan["id"])

        first_page = self.store.list_scans_page(limit=2, offset=0)
        self.assertEqual(len(first_page["scans"]), 2)
        self.assertTrue(first_page["has_more"])
        self.assertEqual(first_page["next_offset"], 2)
        anchor = first_page["anchor"]
        self.assertIsInstance(anchor, int)
        self.assertGreater(anchor, 0)
        self.assertEqual(
            [s["id"] for s in first_page["scans"]],
            [created_ids[4], created_ids[3]],
        )

        # Insert a newer scan after the anchor was captured; subsequent pages must stay pinned to anchor
        extra_scan = self.store.create_scan(target["id"])
        self.assertNotEqual(extra_scan["id"], created_ids[-1])

        second_page = self.store.list_scans_page(limit=2, offset=2, anchor=anchor)
        self.assertEqual(
            [s["id"] for s in second_page["scans"]],
            [created_ids[2], created_ids[1]],
        )
        self.assertTrue(second_page["has_more"])
        self.assertEqual(second_page["next_offset"], 4)

        third_page = self.store.list_scans_page(limit=2, offset=4, anchor=anchor)
        self.assertEqual([s["id"] for s in third_page["scans"]], [created_ids[0]])
        self.assertFalse(third_page["has_more"])
        self.assertIsNone(third_page["next_offset"])

        # Validation checks
        for bad_offset in (-1, 1_000_001, True, "0"):
            with self.subTest(bad_offset=bad_offset):
                with self.assertRaises(ValueError):
                    self.store.list_scans_page(limit=10, offset=bad_offset)  # type: ignore[arg-type]

        for bad_anchor in (-1, 9_223_372_036_854_775_808, False, "1"):
            with self.subTest(bad_anchor=bad_anchor):
                with self.assertRaises(ValueError):
                    self.store.list_scans_page(limit=10, offset=0, anchor=bad_anchor)  # type: ignore[arg-type]

        for bad_limit in (True, "10", None):
            with self.subTest(bad_limit=bad_limit):
                with self.assertRaises(ValueError):
                    self.store.list_scans_page(limit=bad_limit, offset=0)  # type: ignore[arg-type]

    def test_m30_project_audit_triage_and_audit_log_atomic_persistence(self) -> None:
        audit = self.store.create_project_audit(
            {
                "created_at": utc_now(),
                "project_path": "/tmp/synthetic-project",
                "project_name": "synthetic-project",
                "score": 82,
                "grade": "B",
                "file_count": 4,
                "bytes_scanned": 1024,
                "findings": [
                    {
                        "severity": "high",
                        "title": "Hardcoded token pattern",
                        "file": "config.py",
                        "line": 12,
                    },
                    {
                        "severity": "medium",
                        "title": "Debug flag enabled",
                        "file": "app.py",
                        "line": 8,
                    },
                ],
            }
        )
        self.assertEqual(len(audit["findings"]), 2)
        self.assertEqual(audit["findings"][0]["triage"]["disposition"], "unreviewed")
        self.assertEqual(audit["findings"][1]["triage"]["disposition"], "unreviewed")

        updated = self.store.update_project_audit_finding_triage(
            audit["id"],
            0,
            disposition="confirmed",
            note="Verified in synthetic fixture config.py",
        )
        self.assertEqual(updated["findings"][0]["triage"]["disposition"], "confirmed")
        self.assertEqual(updated["findings"][0]["triage"]["note"], "Verified in synthetic fixture config.py")
        self.assertIsNotNone(updated["findings"][0]["triage"]["reviewed_at"])
        self.assertEqual(updated["findings"][1]["triage"]["disposition"], "unreviewed")

        # Alias set_project_audit_finding_triage must also work identically
        updated_alias = self.store.set_project_audit_finding_triage(
            audit["id"],
            1,
            disposition="accepted_risk",
            note="Dev-only configuration in synthetic test",
        )
        self.assertEqual(updated_alias["findings"][1]["triage"]["disposition"], "accepted_risk")

        # Verify audit_log entries were written inside the triage transactions
        logs = self.store.recent_audit_log(limit=10)
        triage_logs = [entry for entry in logs if entry["action"] == "project_audit.finding_triaged"]
        self.assertEqual(len(triage_logs), 2)
        self.assertEqual(triage_logs[0]["entity_id"], audit["id"])
        self.assertEqual(triage_logs[0]["details"]["finding_index"], 1)
        self.assertEqual(triage_logs[0]["details"]["disposition"], "accepted_risk")

        # Validation errors
        with self.assertRaises(ValueError):
            self.store.update_project_audit_finding_triage("prj_missing", 0, disposition="confirmed", note="")
        with self.assertRaises(ValueError):
            self.store.update_project_audit_finding_triage(audit["id"], True, disposition="confirmed", note="")  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            self.store.update_project_audit_finding_triage(audit["id"], -1, disposition="confirmed", note="")
        with self.assertRaises(ValueError):
            self.store.update_project_audit_finding_triage(audit["id"], 2, disposition="confirmed", note="")
        with self.assertRaises(ValueError):
            self.store.update_project_audit_finding_triage(audit["id"], 0, disposition="invalid_disp", note="")
        with self.assertRaises(TypeError):
            self.store.update_project_audit_finding_triage(audit["id"], 0, disposition="confirmed", note=123)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            self.store.update_project_audit_finding_triage(audit["id"], 0, disposition="confirmed", note="x" * 2001)

    def test_m31_manual_findings_risk_accepted_filtering_and_evidence_review(self) -> None:
        target = self._create_target("https://manual.example.local")
        engagement = self.store.create_engagement(
            target_id=target["id"],
            name="Wave 6 Manual Review Engagement",
            authorization_ref="AUTH-2026-W6",
            scope_notes="In-scope web portal",
            out_of_scope="Third-party payment gateway",
            test_window="2026-10-17/2026-10-24",
            special_approvals={
                "controlled_lockout": False,
                "staging_capacity": False,
                "redacted_data_proof": True,
            },
        )
        eng_id = engagement["id"]

        f_open = self.store.create_manual_finding(
            eng_id,
            {
                "severity": "high",
                "title": "IDOR on account export",
                "affected_asset": "/api/account/export",
                "description": "Missing ownership check",
                "impact": "Cross-tenant read",
                "evidence": "Redacted HTTP trace",
                "reproduction": "GET /api/account/export?id=2",
                "recommendation": "Enforce tenant ownership check",
                "status": "open",
            },
        )
        f_risk = self.store.create_manual_finding(
            eng_id,
            {
                "severity": "low",
                "title": "Verbose banner header",
                "affected_asset": "/",
                "description": "Server header discloses minor build tag",
                "impact": "Informational",
                "evidence": "Server: synth/1.0",
                "reproduction": "HEAD /",
                "recommendation": "Suppress build tag",
                "status": "open",
            },
        )
        updated_risk = self.store.update_manual_finding(
            f_risk["id"],
            {
                "status": "risk_accepted",
                "resolution_notes": "Accepted by security architecture board for internal lab",
            },
        )
        self.assertIsNotNone(updated_risk)
        self.assertEqual(updated_risk["status"], "risk_accepted")

        all_findings = self.store.list_manual_findings(eng_id, status="all")
        self.assertEqual(len(all_findings), 2)

        active_findings = self.store.list_manual_findings(eng_id, status="active")
        self.assertEqual([f["id"] for f in active_findings], [f_open["id"]])

        risk_accepted_findings = self.store.list_manual_findings(eng_id, status="risk_accepted")
        self.assertEqual([f["id"] for f in risk_accepted_findings], [f_risk["id"]])
        self.assertEqual(risk_accepted_findings[0]["status_history"][-1]["to_status"], "risk_accepted")

        high_findings = self.store.list_manual_findings(eng_id, status="all", severity="high")
        self.assertEqual([f["id"] for f in high_findings], [f_open["id"]])

        eng_detail = self.store.get_engagement(eng_id)
        self.assertIsNotNone(eng_detail)
        self.assertEqual(eng_detail["remediation"]["total"], 2)
        self.assertEqual(eng_detail["remediation"]["active"], 1)
        self.assertEqual(eng_detail["remediation"]["risk_accepted"], 1)

        with self.assertRaises(ValueError):
            self.store.list_manual_findings(eng_id, status="unknown_status")
        with self.assertRaises(ValueError):
            self.store.list_manual_findings(eng_id, severity="unknown_severity")

    def test_m32_dependency_security_workflow_filtering_pagination_and_export_caps(self) -> None:
        report_trivy = {
            "project_path": "/workspace/alpha-service",
            "source": "trivy",
            "source_path": "trivy-alpha.json",
            "source_timestamp": "2026-10-16T10:00:00Z",
            "document_hash": hashlib.sha256(b"trivy-alpha-1").hexdigest(),
            "findings": [
                {
                    "project_path": "/workspace/alpha-service",
                    "source": "trivy",
                    "vulnerability_id": "CVE-2026-1001",
                    "package_name": "urllib3",
                    "installed_version": "1.26.4",
                    "fixed_version": "1.26.19",
                    "severity": "critical",
                    "title": "Proxy-Authorization header leak on redirect",
                    "summary": "Critical redirect issue",
                    "target": "requirements.txt",
                    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-1001"],
                },
                {
                    "project_path": "/workspace/alpha-service",
                    "source": "trivy",
                    "vulnerability_id": "CVE-2026-1002",
                    "package_name": "jinja2",
                    "installed_version": "3.0.1",
                    "fixed_version": "3.1.4",
                    "severity": "high",
                    "title": "Sandbox attribute escape",
                    "summary": "High template issue",
                    "target": "requirements.txt",
                    "references": [],
                },
            ],
        }
        report_osv = {
            "project_path": "/workspace/beta-worker",
            "source": "osv",
            "source_path": "osv-beta.json",
            "source_timestamp": "2026-10-16T12:00:00Z",
            "document_hash": hashlib.sha256(b"osv-beta-1").hexdigest(),
            "findings": [
                {
                    "project_path": "/workspace/beta-worker",
                    "source": "osv",
                    "vulnerability_id": "GHSA-xxxx-yyyy-zzzz",
                    "package_name": "cryptography",
                    "installed_version": "41.0.0",
                    "fixed_version": "42.0.5",
                    "severity": "medium",
                    "title": "NULL pointer dereference in PKCS12 parsing",
                    "summary": "Medium crypto issue",
                    "target": "poetry.lock",
                    "references": [],
                }
            ],
        }
        self.store.import_dependency_findings(report_trivy)
        self.store.import_dependency_findings(report_osv)

        initial = self.store.dependency_security()
        self.assertEqual(initial["summary"]["total"], 3)
        self.assertEqual(initial["summary"]["filtered"], 3)
        self.assertEqual(initial["summary"]["active"], 3)
        self.assertEqual(initial["summary"]["critical"], 1)
        self.assertEqual(initial["summary"]["high"], 1)

        # Transition one finding to risk_accepted and one to in_progress
        by_vuln = {f["vulnerability_id"]: f for f in initial["findings"]}
        u1 = self.store.update_dependency_finding(
            by_vuln["CVE-2026-1002"]["id"],
            status="in_progress",
            resolution_notes="Upgrading jinja2 in sprint 42",
        )
        self.assertEqual(u1["status"], "in_progress")
        self.assertEqual(u1["resolution_notes"], "Upgrading jinja2 in sprint 42")

        u2 = self.store.update_dependency_finding(
            by_vuln["GHSA-xxxx-yyyy-zzzz"]["id"],
            status="risk_accepted",
            resolution_notes="PKCS12 parser unused in worker",
        )
        self.assertEqual(u2["status"], "risk_accepted")

        # Filter by source, severity, status, and query
        trivy_only = self.store.dependency_security(source="trivy")
        self.assertEqual(trivy_only["page"]["filtered_total"], 2)
        self.assertEqual({f["source"] for f in trivy_only["findings"]}, {"trivy"})

        risk_only = self.store.dependency_security(status="risk_accepted")
        self.assertEqual(risk_only["page"]["filtered_total"], 1)
        self.assertEqual(risk_only["findings"][0]["vulnerability_id"], "GHSA-xxxx-yyyy-zzzz")
        self.assertEqual(risk_only["summary"]["risk_accepted"], 1)
        self.assertEqual(risk_only["summary"]["in_progress"], 1)
        self.assertEqual(risk_only["summary"]["active"], 2)

        queried = self.store.dependency_security(query="urllib3")
        self.assertEqual(queried["page"]["filtered_total"], 1)
        self.assertEqual(queried["findings"][0]["package_name"], "urllib3")

        # Pagination
        paged = self.store.dependency_security(limit=1, offset=1)
        self.assertEqual(paged["page"]["returned"], 1)
        self.assertEqual(paged["page"]["filtered_total"], 3)
        self.assertTrue(paged["page"]["has_more"])
        self.assertEqual(len(paged["report_findings"]), 3)

        # Complete export mode
        exported = self.store.dependency_security(complete_export=True, source="trivy")
        self.assertTrue(exported["export_complete"])
        self.assertEqual(exported["exported_count"], 2)
        self.assertFalse(exported["page"]["has_more"])

        # Complete export row limit guard (>10,000 rows)
        orig_connect = self.store._connect

        class _RowCapConnectionWrapper:
            def __init__(self, real_conn):
                self._real = real_conn

            def execute(self, sql, params=()):
                if "SELECT COUNT(*) AS count FROM dependency_findings" in sql:
                    class _FakeCursor:
                        def fetchone(self_inner):
                            return {"count": 10_001}
                    return _FakeCursor()
                return self._real.execute(sql, params)

            def __getattr__(self, name):
                return getattr(self._real, name)

        from contextlib import contextmanager

        @contextmanager
        def _fake_connect():
            with orig_connect() as conn:
                yield _RowCapConnectionWrapper(conn)

        with mock.patch.object(self.store, "_connect", side_effect=_fake_connect):
            with self.assertRaises(DependencyExportTooLarge):
                self.store.dependency_security(complete_export=True)

        # Validation errors
        with self.assertRaises(ValueError):
            self.store.dependency_security(complete_export="yes")  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            self.store.dependency_security(limit=0)
        with self.assertRaises(ValueError):
            self.store.dependency_security(offset=-1)
        with self.assertRaises(ValueError):
            self.store.dependency_security(source="invalid")
        with self.assertRaises(ValueError):
            self.store.dependency_security(severity="invalid")
        with self.assertRaises(ValueError):
            self.store.dependency_security(status="invalid")

    def test_m33_secret_finding_evidence_and_provenance_summary(self) -> None:
        target = self._create_target("https://provenance.example.local")
        engagement = self.store.create_engagement(
            target_id=target["id"],
            name="Wave 8 Provenance Engagement",
            authorization_ref="AUTH-2026-W8",
            scope_notes="Repository and TLS review",
            out_of_scope="None",
            test_window="2026-10-17/2026-10-24",
            special_approvals={
                "controlled_lockout": False,
                "staging_capacity": False,
                "redacted_data_proof": True,
            },
        )
        eng_id = engagement["id"]
        first_control_id = engagement["tests"][0]["control_id"]

        gitleaks_summary = {
            "report_sha256": hashlib.sha256(b"gitleaks-sample-1").hexdigest(),
            "total_findings": 2,
            "rules_triggered": 2,
            "files_affected": 1,
        }
        linked_gitleaks, created = self.store.add_gitleaks_tool_evidence(
            eng_id,
            first_control_id,
            gitleaks_summary,
        )
        self.assertTrue(created)
        self.assertEqual(linked_gitleaks["tool_identity"], "gitleaks-native-json")
        self.assertEqual(linked_gitleaks["total_findings"], 2)

        # Duplicate submission is idempotent
        _, created_again = self.store.add_gitleaks_tool_evidence(
            eng_id,
            first_control_id,
            gitleaks_summary,
        )
        self.assertFalse(created_again)

        second_control_id = engagement["tests"][1]["control_id"]
        generic_summary = {
            "report_sha256": hashlib.sha256(b"generic-provenance-1").hexdigest(),
            "finding_count": 3,
            "profile": "offline-provenance-v1",
        }
        linked_generic, gen_created = self.store.add_generic_tool_evidence(
            eng_id,
            second_control_id,
            "provenance-bundle-json",
            generic_summary,
            "Provenance JSON",
        )
        self.assertTrue(gen_created)
        self.assertEqual(linked_generic["tool_identity"], "provenance-bundle-json")
        self.assertEqual(linked_generic["finding_count"], 3)

        provenance = self.store.get_engagement_evidence_provenance(eng_id)
        self.assertIsNotNone(provenance)
        self.assertEqual(provenance["total_count"], 2)
        self.assertEqual(
            provenance["by_tool_identity"],
            {"gitleaks-native-json": 1, "provenance-bundle-json": 1},
        )
        self.assertEqual(
            provenance["by_control_id"],
            {first_control_id: 1, second_control_id: 1},
        )
        self.assertEqual(
            {r["report_sha256"] for r in provenance["records"]},
            {gitleaks_summary["report_sha256"], generic_summary["report_sha256"]},
        )


if __name__ == "__main__":
    unittest.main()
