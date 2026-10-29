import sys
import tempfile
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scanner import normalize_target  # noqa: E402
from storage import Store  # noqa: E402


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name) / "test.db")

    def tearDown(self):
        self.temp.cleanup()

    def test_target_scan_and_dashboard_lifecycle(self):
        target = self.store.create_target(normalize_target("https://example.com"))
        self.assertEqual(target["status"], "ready")
        self.assertNotIn("verification_token", target)
        scan = self.store.create_scan(target["id"])
        self.store.mark_scan_running(scan["id"])
        self.store.complete_scan(scan["id"], {
            "score": 92, "grade": "A", "counts": {"low": 1},
            "findings": [{"id": "finding-a", "severity": "low", "title": "Test"}],
            "metadata": {}, "scope": {},
        })
        completed = self.store.get_scan(scan["id"])
        self.assertEqual(completed["status"], "completed")
        self.assertEqual(completed["score"], 92)
        self.assertTrue(completed["comparison"]["baseline"])
        self.assertEqual(completed["comparison"]["new_count"], 1)
        second = self.store.create_scan(target["id"])
        self.store.mark_scan_running(second["id"])
        self.store.complete_scan(second["id"], {
            "score": 80, "grade": "B", "counts": {"medium": 1},
            "findings": [{"id": "finding-b", "severity": "medium", "title": "Yeni test"}],
            "metadata": {}, "scope": {},
        })
        compared = self.store.get_scan(second["id"])
        self.assertEqual(compared["comparison"]["score_delta"], -12)
        self.assertEqual(compared["comparison"]["new_count"], 1)
        self.assertEqual(compared["comparison"]["resolved_count"], 1)
        self.assertEqual(len(compared["comparison"]["resolved_findings"]), 1)
        trend = self.store.target_trend(target["id"])
        self.assertEqual(len(trend["points"]), 2)
        self.assertEqual(self.store.list_targets()[0]["latest_score"], 80)
        self.assertEqual(self.store.dashboard()["ready_count"], 1)

    def test_manual_engagement_lifecycle(self):
        target = self.store.create_target(normalize_target("https://manual.example.com"))
        engagement = self.store.create_engagement(
            target_id=target["id"], name="Yetkili manuel test", authorization_ref="SO-2026-42",
            scope_notes="/ uygulaması", out_of_scope="Üçüncü taraf ödeme sağlayıcısı",
            test_window="2026-09-01 22:00–23:00", special_approvals={"redacted_data_proof": True},
        )
        self.assertGreaterEqual(engagement["coverage"]["total"], 159)
        self.assertTrue(any(category["slug"] == "logging" for category in engagement["categories"]))
        self.assertTrue(any(test["control_id"] == "SNIPER-SAFE-DATA-01" for test in engagement["tests"]))
        first = engagement["tests"][0]
        self.store.update_manual_test(
            engagement["id"], first["control_id"], status="passed", notes="Kontrol edildi", evidence="İşlem kaydı #1",
        )
        finding = self.store.create_manual_finding(engagement["id"], {
            "severity": "high", "title": "Yetki kontrolü eksik", "affected_asset": "/api/orders/42",
            "description": "Test açıklaması", "impact": "Başka hesaba erişim", "evidence": "Maskeli kanıt",
            "reproduction": "Yetkili test hesabıyla doğrulandı", "recommendation": "Nesne düzeyi kontrol ekleyin",
            "owasp_category": "A01:2021", "cwe_id": "CWE-639",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", "cvss_score": 8.1,
            "remediation_owner": "API ekibi", "due_date": "2000-01-01",
            "resolution_notes": "Düzeltme bekleniyor",
        })
        self.assertEqual(finding["status"], "open")
        self.assertEqual(finding["cwe_id"], "CWE-639")
        self.assertEqual(finding["cvss_score"], 8.1)
        self.assertEqual(self.store.dashboard()["overdue_finding_count"], 1)
        in_progress = self.store.update_manual_finding(finding["id"], {
            "status": "in_progress", "resolution_notes": "API ekibine atandı",
        })
        self.assertEqual(in_progress["status"], "in_progress")
        self.assertIsNone(in_progress["resolved_at"])
        resolved = self.store.update_manual_finding(finding["id"], {
            "status": "resolved", "resolution_notes": "Sürüm 2.4 ile düzeltildi",
        })
        self.assertIsNotNone(resolved["resolved_at"])
        self.assertIsNotNone(resolved["last_retested_at"])
        reopened = self.store.update_manual_finding(finding["id"], {
            "status": "reopened", "resolution_notes": "Yeniden testte devam ediyor",
        })
        self.assertIsNone(reopened["resolved_at"])
        self.assertIsNotNone(reopened["last_retested_at"])
        refreshed = self.store.get_engagement(engagement["id"])
        self.assertEqual(refreshed["coverage"]["completed"], 1)
        self.assertEqual(len(refreshed["findings"]), 1)
        self.assertEqual(self.store.dashboard()["manual_finding_count"], 1)

    def test_manual_finding_status_history_lifecycle(self):
        target = self.store.create_target(normalize_target("https://history.example.com"))
        engagement = self.store.create_engagement(
            target_id=target["id"], name="Test", authorization_ref="Test",
            scope_notes="", out_of_scope="", test_window="2025-01-01", special_approvals={}
        )
        finding = self.store.create_manual_finding(
            engagement["id"], {
                "severity": "low", "title": "Title", "affected_asset": "",
                "description": "desc", "impact": "impact", "evidence": "evidence",
                "reproduction": "rec", "recommendation": "", "owasp_category": "",
                "cwe_id": "", "cvss_vector": "", "cvss_score": 0.0,
                "remediation_owner": "", "due_date": "", "resolution_notes": "",
            }
        )
        engagement_after_create = self.store.get_engagement(engagement["id"])
        self.assertEqual(len(engagement_after_create["findings"]), 1)
        self.assertEqual(engagement_after_create["findings"][0]["status"], "open")
        self.assertEqual(engagement_after_create["findings"][0]["status_history"], [])

        updated = self.store.update_manual_finding(finding["id"], {"status": "in_progress"})
        self.assertIsNotNone(updated)
        engagement_after_first = self.store.get_engagement(engagement["id"])
        history1 = engagement_after_first["findings"][0]["status_history"]
        self.assertEqual(len(history1), 1)
        self.assertEqual(history1[0]["from_status"], "open")
        self.assertEqual(history1[0]["to_status"], "in_progress")

        updated2 = self.store.update_manual_finding(finding["id"], {"status": "resolved"})
        self.assertIsNotNone(updated2)
        engagement_after_second = self.store.get_engagement(engagement["id"])
        history2 = engagement_after_second["findings"][0]["status_history"]
        self.assertEqual(len(history2), 2)
        self.assertEqual(history2[1]["from_status"], "in_progress")
        self.assertEqual(history2[1]["to_status"], "resolved")

        updated3 = self.store.update_manual_finding(finding["id"], {"status": "resolved"})
        self.assertIsNotNone(updated3)
        engagement_after_third = self.store.get_engagement(engagement["id"])
        history3 = engagement_after_third["findings"][0]["status_history"]
        self.assertEqual(len(history3), 2, "same-status update must not append history")

        updated4 = self.store.update_manual_finding(finding["id"], {"title": "new title"})
        self.assertIsNotNone(updated4)
        engagement_after_fourth = self.store.get_engagement(engagement["id"])
        history4 = engagement_after_fourth["findings"][0]["status_history"]
        self.assertEqual(len(history4), 2, "non-status update must not append history")

    def test_engagement_governance_fields_are_optional(self):
        target = self.store.create_target(normalize_target("https://optional.example.com"))
        engagement = self.store.create_engagement(
            target_id=target["id"], name="Yerel tam kapsam",
            authorization_ref="", scope_notes="", out_of_scope="", test_window="",
            special_approvals={},
        )
        self.assertEqual(engagement["authorization_ref"], "")
        self.assertEqual(engagement["scope_notes"], "")
        self.assertEqual(engagement["coverage"]["total"], 158)

    def test_safe_lab_run_lifecycle(self):
        lab_run = self.store.create_lab_run(
            scenario_type="capacity_plan",
            name="Staging kapasite planı",
            environment="staging",
            authorization_ref="SO-2026-88",
            assumptions={"target_rps": 120, "duration_seconds": 60},
            results={
                "projection_only": True,
                "projected_requests": 7200,
                "traffic_generated": False,
                "requests_generated": 0,
            },
            evidence_summary="Henüz çalıştırılmadı.",
        )
        self.assertEqual(lab_run["status"], "planned")
        self.assertFalse(lab_run["results"]["traffic_generated"])
        self.assertEqual(lab_run["results"]["requests_generated"], 0)
        updated = self.store.update_lab_run(
            lab_run["id"], status="completed", evidence_summary="Maskeli sonuç hash: abc12345",
        )
        self.assertEqual(updated["status"], "completed")
        self.assertEqual(len(self.store.list_lab_runs()), 1)
        self.assertEqual(self.store.dashboard()["lab_run_count"], 1)

    def test_lab_run_invariant_fields_persistence(self):
        # Valid capacity_plan control in staging environment
        valid_capacity = self.store.create_lab_run(
            scenario_type="capacity_plan",
            name="Valid capacity control",
            environment="staging",
            authorization_ref="SO-2026-88",
            assumptions={"target_rps": 100, "duration_seconds": 30},
            results={
                "projection_only": True,
                "projected_requests": 3000,
                "traffic_generated": False,
                "requests_generated": 0,
            },
            evidence_summary="Valid capacity control test.",
        )
        self.assertEqual(valid_capacity["scenario_type"], "capacity_plan")
        self.assertEqual(valid_capacity["environment"], "staging")
        self.assertFalse(valid_capacity["results"]["traffic_generated"])
        self.assertEqual(valid_capacity["results"]["requests_generated"], 0)

        # Reload to verify persistence
        reloaded_capacity = self.store.get_lab_run(valid_capacity["id"])
        self.assertFalse(reloaded_capacity["results"]["traffic_generated"])
        self.assertEqual(reloaded_capacity["results"]["requests_generated"], 0)

        # Valid external_result control
        valid_external = self.store.create_lab_run(
            scenario_type="external_result",
            name="Valid external result control",
            environment="staging",
            authorization_ref="SO-2026-88",
            assumptions={"tool_name": "external_tool", "evidence_hash": "hash123"},
            results={
                "traffic_generated_by_sniper": False,
                "requests_generated_by_sniper": 0,
            },
            evidence_summary="Valid external result test.",
        )
        self.assertEqual(valid_external["scenario_type"], "external_result")
        self.assertFalse(valid_external["results"]["traffic_generated_by_sniper"])
        self.assertEqual(valid_external["results"]["requests_generated_by_sniper"], 0)

        # Reload to verify persistence
        reloaded_external = self.store.get_lab_run(valid_external["id"])
        self.assertFalse(reloaded_external["results"]["traffic_generated_by_sniper"])
        self.assertEqual(reloaded_external["results"]["requests_generated_by_sniper"], 0)

        # Invalid direct input for capacity_plan (should persist false/0 per contract)
        invalid_capacity = self.store.create_lab_run(
            scenario_type="capacity_plan",
            name="Invalid capacity input",
            environment="staging",
            authorization_ref="SO-2026-88",
            assumptions={"target_rps": 100, "duration_seconds": 30},
            results={
                "projection_only": True,
                "projected_requests": 3000,
                "traffic_generated": True,
                "requests_generated": 7,
            },
            evidence_summary="Invalid capacity input test.",
        )
        # Per contract: invariant fields must be false/0 regardless of input
        self.assertFalse(invalid_capacity["results"]["traffic_generated"])
        self.assertEqual(invalid_capacity["results"]["requests_generated"], 0)

        # Reload to verify persistence
        reloaded_invalid_capacity = self.store.get_lab_run(invalid_capacity["id"])
        self.assertFalse(reloaded_invalid_capacity["results"]["traffic_generated"])
        self.assertEqual(reloaded_invalid_capacity["results"]["requests_generated"], 0)

        # Invalid direct input for external_result (should persist false/0 per contract)
        invalid_external = self.store.create_lab_run(
            scenario_type="external_result",
            name="Invalid external result input",
            environment="staging",
            authorization_ref="SO-2026-88",
            assumptions={"tool_name": "external_tool", "evidence_hash": "hash456"},
            results={
                "traffic_generated_by_sniper": True,
                "requests_generated_by_sniper": 2,
            },
            evidence_summary="Invalid external result input test.",
        )
        # Per contract: invariant fields must be false/0 regardless of input
        self.assertFalse(invalid_external["results"]["traffic_generated_by_sniper"])
        self.assertEqual(invalid_external["results"]["requests_generated_by_sniper"], 0)

        # Reload to verify persistence
        reloaded_invalid_external = self.store.get_lab_run(invalid_external["id"])
        self.assertFalse(reloaded_invalid_external["results"]["traffic_generated_by_sniper"])
        self.assertEqual(reloaded_invalid_external["results"]["requests_generated_by_sniper"], 0)


if __name__ == "__main__":
    unittest.main()
