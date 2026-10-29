import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import server  # noqa: E402
from storage import Store  # noqa: E402


class LabPlanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name) / "test.db")
        self.store_patch = patch.object(server, "STORE", self.store)
        self.store_patch.start()

    def tearDown(self):
        self.store_patch.stop()
        self.temp.cleanup()

    def test_capacity_plan_is_projection_only(self):
        plan = server.build_lab_plan({
            "scenario_type": "capacity_plan",
            "name": "Staging planı",
            "environment": "staging",
            "authorization_ref": "SO-42",
            "target_rps": 50,
            "duration_seconds": 120,
            "baseline_latency_ms": 200,
            "max_error_percent": 2.5,
            "abort_latency_ms": 1000,
            "recovery_seconds": 60,
            "emergency_contact": "Nöbetçi ekip",
        })
        self.assertEqual(plan["results"]["projected_requests"], 6000)
        self.assertEqual(plan["results"]["estimated_concurrency"], 10)
        self.assertFalse(plan["results"]["traffic_generated"])
        self.assertEqual(plan["results"]["requests_generated"], 0)

    def test_lockout_plan_rejects_production_and_password_material(self):
        base = {
            "scenario_type": "lockout_plan",
            "name": "Kilitlenme planı",
            "environment": "production",
            "authorization_ref": "SO-43",
            "synthetic_account_alias": "sentetik-01",
            "max_attempts": 5,
            "interval_seconds": 10,
            "expected_lockout_seconds": 300,
            "monitoring_signal": "auth_lockout_total",
        }
        with self.assertRaisesRegex(ValueError, "laboratuvar veya staging"):
            server.build_lab_plan(base)
        with self.assertRaisesRegex(ValueError, "parola listesi"):
            server.build_lab_plan({**base, "environment": "staging", "password_list": ["secret"]})

    def test_external_result_keeps_only_masked_summary(self):
        plan = server.build_lab_plan({
            "scenario_type": "external_result",
            "name": "Harici kapasite sonucu",
            "environment": "production",
            "authorization_ref": "SO-44",
            "tool_name": "Kuruluş içi test aracı",
            "test_window": "2026-09-01 22:00–22:10",
            "evidence_hash": "sha256:abcdef1234567890",
            "outcome_summary": "Eşik aşılmadı; ham günlük saklanmadı.",
            "evidence_summary": "Kimliksizleştirilmiş özet.",
        })
        self.assertTrue(plan["results"]["masked_evidence_only"])
        self.assertEqual(plan["results"]["requests_generated_by_sniper"], 0)

    def test_linked_plan_requires_matching_special_approval(self):
        from scanner import normalize_target

        target = self.store.create_target(normalize_target("https://approval.example.com"))
        engagement = self.store.create_engagement(
            target_id=target["id"], name="Onaysız kapasite", authorization_ref="SO-45",
            scope_notes="Staging", out_of_scope="Üretim", test_window="2026-09-01",
            special_approvals={},
        )
        with self.assertRaisesRegex(ValueError, "özel onay"):
            server.build_lab_plan({
                "scenario_type": "capacity_plan", "name": "Plan", "environment": "staging",
                "authorization_ref": "SO-45", "engagement_id": engagement["id"], "target_rps": 10,
                "duration_seconds": 10, "baseline_latency_ms": 100, "max_error_percent": 1,
                "abort_latency_ms": 500, "recovery_seconds": 30, "emergency_contact": "Ekip",
            })

    def test_external_result_can_link_to_existing_control(self):
        from scanner import normalize_target

        target = self.store.create_target(normalize_target("https://evidence.example.com"))
        engagement = self.store.create_engagement(
            target_id=target["id"], name="Kanıt eşleme", authorization_ref="SO-46",
            scope_notes="", out_of_scope="", test_window="",
            special_approvals={"redacted_data_proof": True},
        )
        control_id = self.store.get_engagement(engagement["id"])["tests"][0]["control_id"]
        plan = server.build_lab_plan({
            "scenario_type": "external_result", "name": "ZAP sonucu", "environment": "staging",
            "authorization_ref": "SO-46", "engagement_id": engagement["id"],
            "control_id": control_id, "tool_name": "OWASP ZAP", "test_window": "22:00–22:10",
            "evidence_hash": "sha256:abcdef1234567890", "outcome_summary": "Maskeli özet",
        })
        self.assertEqual(plan["assumptions"]["control_id"], control_id)

    def test_external_result_rejects_unknown_control(self):
        from scanner import normalize_target

        target = self.store.create_target(normalize_target("https://invalid-control.example.com"))
        engagement = self.store.create_engagement(
            target_id=target["id"], name="Geçersiz kontrol", authorization_ref="SO-47",
            scope_notes="", out_of_scope="", test_window="",
            special_approvals={"redacted_data_proof": True},
        )
        with self.assertRaisesRegex(ValueError, "bulunamadı"):
            server.build_lab_plan({
                "scenario_type": "external_result", "name": "Sonuç", "environment": "staging",
                "authorization_ref": "SO-47", "engagement_id": engagement["id"],
                "control_id": "UNKNOWN-999", "tool_name": "Harici araç", "test_window": "22:00",
                "evidence_hash": "sha256:abcdef1234567890", "outcome_summary": "Maskeli özet",
            })


if __name__ == "__main__":
    unittest.main()
