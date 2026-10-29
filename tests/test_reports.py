import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from server import render_engagement_csv, render_engagement_sarif, render_sarif  # noqa: E402


class ReportTests(unittest.TestCase):
    def test_sarif_report_maps_findings_and_fingerprints(self):
        report = render_sarif({
            "id": "scn_test", "status": "completed", "target_url": "https://example.com/",
            "target_hostname": "example.com", "score": 72, "grade": "C",
            "findings": [{
                "id": "abc123", "severity": "high", "category": "headers",
                "title": "Eksik güvenlik başlığı", "description": "Başlık bulunamadı.",
                "evidence": "header: missing", "recommendation": "Başlığı ekleyin.",
                "reference": "OWASP TEST",
            }],
        })
        self.assertEqual(report["version"], "2.1.0")
        run = report["runs"][0]
        self.assertEqual(run["results"][0]["level"], "error")
        self.assertEqual(run["results"][0]["fingerprints"]["sniper/v1"], "abc123")
        self.assertEqual(run["tool"]["driver"]["rules"][0]["id"], "SNIPER-abc123")

    def test_engagement_exports_combine_manual_and_automatic_findings(self):
        engagement = {
            "id": "eng_test", "target_url": "https://example.com/", "coverage": {"percent": 64},
            "findings": [{
                "id": "fnd_1", "severity": "high", "status": "retest_required",
                "title": "Yetki kontrolü eksik", "description": "Nesne erişimi sınırlandırılmamış.",
                "affected_asset": "/api/orders/42", "recommendation": "Sunucu kontrolü ekleyin.",
                "owasp_category": "A01:2021", "cwe_id": "CWE-639", "cvss_score": 8.1,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                "remediation_owner": "API ekibi", "due_date": "2026-09-30",
                "resolution_notes": "Yeniden test bekliyor",
            }],
            "latest_scan": {"findings": [{
                "id": "auto_1", "severity": "low", "status": "open", "title": "Başlık eksik",
                "description": "Güvenlik başlığı yok.", "recommendation": "Başlığı ekleyin.",
                "owasp": "OWASP A05:2021", "cwe": "CWE-693",
            }]},
        }
        csv_report = render_engagement_csv(engagement)
        self.assertIn("manual,fnd_1,high,retest_required", csv_report)
        self.assertIn("automatic,auto_1,low,open", csv_report)
        sarif = render_engagement_sarif(engagement)
        run = sarif["runs"][0]
        self.assertEqual(len(run["results"]), 2)
        self.assertEqual(run["results"][0]["properties"]["cvssScore"], 8.1)
        self.assertEqual(run["results"][0]["properties"]["status"], "retest_required")

    def test_csv_neutralizes_spreadsheet_formulas(self):
        report = render_engagement_csv({
            "target_url": "https://example.com/", "findings": [{
                "id": "fnd_formula", "source": "manual", "severity": "low", "status": "open",
                "title": "=HYPERLINK(\"https://invalid.example\")", "affected_asset": "+SUM(1,1)",
            }],
        })
        self.assertIn("'=HYPERLINK", report)
        self.assertIn("'+SUM(1,1)", report)


if __name__ == "__main__":
    unittest.main()
