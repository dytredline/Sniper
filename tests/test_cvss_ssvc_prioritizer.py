import unittest

from cvss40 import compute_cvss40
from cvss_ssvc_prioritizer import (
    CVSS40_NOTE,
    build_cvss40_vector,
    compute_cvss31,
    infer_cvss31_vector,
    prioritize_findings,
    ssvc_decision,
)


class Cvss31ScoreTests(unittest.TestCase):
    def test_official_check_values(self):
        cases = {
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
            "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 7.8,
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N": 5.9,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0.0,
        }
        for vector, expected in cases.items():
            with self.subTest(vector=vector):
                self.assertEqual(compute_cvss31(vector)["base_score"], expected)

    def test_severity_bands(self):
        self.assertEqual(compute_cvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")["severity"], "Critical")
        self.assertEqual(compute_cvss31("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")["severity"], "High")
        self.assertEqual(compute_cvss31("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N")["severity"], "Medium")
        self.assertEqual(compute_cvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")["severity"], "None")

    def test_invalid_vectors_raise(self):
        for bad in (
            "",
            "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",
            "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P",
        ):
            with self.subTest(vector=bad):
                with self.assertRaises(ValueError):
                    compute_cvss31(bad)
        with self.assertRaises(ValueError):
            compute_cvss31(None)  # type: ignore[arg-type]


class Cvss40VectorTests(unittest.TestCase):
    def test_vector_built_from_scope_change(self):
        vector = build_cvss40_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")
        self.assertEqual(vector, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N")

    def test_vector_unchanged_scope_has_no_subsequent_impact(self):
        vector = build_cvss40_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(vector, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")


class InferenceTests(unittest.TestCase):
    def test_cwe_table_and_reference_extraction(self):
        self.assertEqual(
            infer_cvss31_vector({"cwe": "CWE-89"}),
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        )
        self.assertEqual(
            infer_cvss31_vector({"cwe": "", "reference": "OWASP A03 · CWE-79"}),
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        )

    def test_exposure_adjusts_attack_vector(self):
        finding = {"cwe": "CWE-918"}
        self.assertTrue(infer_cvss31_vector(finding, exposure="internal").startswith("CVSS:3.1/AV:A/"))
        self.assertTrue(infer_cvss31_vector(finding, exposure="local").startswith("CVSS:3.1/AV:L/"))
        with self.assertRaises(ValueError):
            infer_cvss31_vector(finding, exposure="mars")

    def test_severity_fallback(self):
        vector = infer_cvss31_vector({"severity": "high", "category": "unknown"})
        self.assertEqual(compute_cvss31(vector)["base_score"], 8.1)
        info_vector = infer_cvss31_vector({"severity": "info"})
        self.assertEqual(compute_cvss31(info_vector)["base_score"], 0.0)


class SsvcTests(unittest.TestCase):
    def test_active_total_essential_is_act(self):
        self.assertEqual(
            ssvc_decision(exploitation="active", automatable=False, technical_impact="total", mission_prevalence="essential"),
            "Act",
        )

    def test_none_partial_is_track(self):
        self.assertEqual(
            ssvc_decision(exploitation="none", automatable=False, technical_impact="partial", mission_prevalence="support"),
            "Track",
        )

    def test_poc_is_track_star(self):
        self.assertEqual(
            ssvc_decision(exploitation="poc", automatable=False, technical_impact="partial", mission_prevalence="support"),
            "Track*",
        )

    def test_active_partial_is_attend_unless_wellbeing(self):
        self.assertEqual(
            ssvc_decision(exploitation="active", automatable=False, technical_impact="partial", mission_prevalence="minimal"),
            "Attend",
        )
        self.assertEqual(
            ssvc_decision(
                exploitation="active",
                automatable=False,
                technical_impact="partial",
                mission_prevalence="minimal",
                public_wellbeing="irreversible",
            ),
            "Act",
        )

    def test_poc_automatable_total_is_attend(self):
        self.assertEqual(
            ssvc_decision(exploitation="poc", automatable=True, technical_impact="total", mission_prevalence="minimal"),
            "Attend",
        )

    def test_invalid_inputs_raise(self):
        with self.assertRaises(ValueError):
            ssvc_decision(exploitation="maybe", automatable=False, technical_impact="total", mission_prevalence="support")
        with self.assertRaises(ValueError):
            ssvc_decision(exploitation="none", automatable=False, technical_impact="huge", mission_prevalence="support")


class PrioritizeTests(unittest.TestCase):
    def setUp(self):
        self.findings = [
            {"title": "Eksik güvenlik başlığı", "severity": "low", "category": "headers", "cwe": "CWE-693"},
            {"title": "SQL enjeksiyonu", "severity": "critical", "category": "injection", "cwe": "CWE-89"},
            {"title": "XSS", "severity": "medium", "category": "xss", "cwe": "CWE-79", "kev": True},
            "geçersiz",
        ]

    def test_ordering_sla_and_cvss40(self):
        report = prioritize_findings(self.findings, now="2026-10-18", discovered_at="2026-10-01")
        self.assertEqual(report["format"], "sniper-cvss-ssvc-prioritization-v1")
        self.assertEqual(report["finding_count"], 3)
        self.assertEqual(report["skipped"], 1)
        items = report["prioritized_findings"]
        # KEV (active) XSS, kısmi etki → Attend önce; ardından Track içinde CVSS'e göre SQLi, sonra başlık.
        self.assertEqual(items[0]["title"], "XSS")
        self.assertEqual(items[0]["ssvc_decision"], "Attend")
        self.assertEqual(items[0]["sla_days"], 7)
        self.assertEqual(items[1]["ssvc_decision"], "Track")
        self.assertEqual(items[1]["title"], "SQL enjeksiyonu")
        self.assertEqual(items[1]["cvss31_score"], 9.8)
        self.assertEqual(items[1]["cvss31_severity"], "Critical")
        self.assertEqual(items[1]["sla_days"], 7)
        self.assertEqual(items[1]["due_date"], "2026-10-08")
        self.assertEqual(items[1]["sla_status"], "overdue")
        self.assertEqual(items[1]["days_remaining"], -10)
        self.assertEqual(items[2]["title"], "Eksik güvenlik başlığı")
        for item in items:
            self.assertEqual(item["cvss40_score"], compute_cvss40(item["cvss40_vector"])["score"])
            self.assertEqual(item["cvss40_severity"], compute_cvss40(item["cvss40_vector"])["severity"])
            self.assertEqual(item["cvss40_note"], CVSS40_NOTE)
            self.assertTrue(item["cvss40_vector"].startswith("CVSS:4.0/"))
        self.assertEqual(items[1]["cvss40_vector"], "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
        self.assertEqual(items[1]["cvss40_score"], 9.3)
        self.assertEqual([i["priority_rank"] for i in items], [1, 2, 3])
        self.assertEqual(report["ssvc_summary"]["Attend"], 1)
        self.assertEqual(report["ssvc_summary"]["Track"], 2)
        self.assertEqual(report["max_cvss31"], 9.8)
        self.assertGreaterEqual(report["overdue_count"], 1)

    def test_active_exploitation_caps_sla_to_two_days(self):
        report = prioritize_findings(
            [{"title": "RCE", "cwe": "CWE-502", "severity": "critical", "exploitation": "active"}],
            now="2026-10-18",
            discovered_at="2026-10-17",
        )
        item = report["prioritized_findings"][0]
        self.assertEqual(item["ssvc_decision"], "Act")
        self.assertEqual(item["sla_days"], 2)
        self.assertEqual(item["due_date"], "2026-10-19")
        self.assertEqual(item["sla_status"], "within_sla")
        self.assertEqual(item["days_remaining"], 1)

    def test_deterministic(self):
        first = prioritize_findings(self.findings, now="2026-10-18", discovered_at="2026-10-01")
        second = prioritize_findings(list(self.findings), now="2026-10-18", discovered_at="2026-10-01")
        self.assertEqual(first, second)

    def test_custom_sla_and_within_sla(self):
        report = prioritize_findings(
            [{"title": "Başlık", "cwe": "CWE-693", "severity": "low"}],
            now="2026-10-18",
            discovered_at="2026-10-17T10:00:00Z",
            sla_policy={"Medium": 45},
        )
        item = report["prioritized_findings"][0]
        self.assertEqual(item["cvss31_severity"], "Medium")
        self.assertEqual(item["sla_days"], 45)
        self.assertEqual(item["sla_status"], "within_sla")

    def test_invalid_inputs(self):
        with self.assertRaises(ValueError):
            prioritize_findings("not-a-list")  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            prioritize_findings([{}] * 10_001)
        with self.assertRaises(ValueError):
            prioritize_findings([], exposure="space")
        with self.assertRaises(ValueError):
            prioritize_findings([], now="18/10/2026")


if __name__ == "__main__":
    unittest.main()
