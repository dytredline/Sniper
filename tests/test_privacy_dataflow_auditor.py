from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from privacy_dataflow_auditor import (  # noqa: E402
    audit_privacy_inline,
    audit_privacy_project,
)


class PrivacyDataflowInlineTests(unittest.TestCase):
    def test_pii_logging_high_and_special_category_critical(self) -> None:
        content = (
            "import logging\n"
            "logger = logging.getLogger(__name__)\n"
            "def register(user, patient):\n"
            "    logger.info('Kayit: tckn=%s email=%s', user.tckn, user.email)\n"
            "    logger.warning('Hasta tanisi: %s', patient.diagnosis)\n"
        )
        result = audit_privacy_inline(content, filename="service.py")

        self.assertEqual(result["format"], "sniper-privacy-dataflow-inline-v1")
        by_line = {item["line"]: item for item in result["findings"]}
        self.assertEqual(by_line[4]["control_id"], "SNIPER-LOGG-02")
        self.assertEqual(by_line[4]["severity"], "high")
        self.assertEqual(by_line[4]["cwe"], "CWE-532")
        self.assertEqual(by_line[5]["control_id"], "SNIPER-LOGG-02")
        self.assertEqual(by_line[5]["severity"], "critical")
        self.assertTrue(by_line[5]["special_category"])
        self.assertTrue(result["special_category_detected"])
        self.assertIn("Kimlik", result["pii_categories_detected"])
        ropa = {entry["data_category"]: entry for entry in result["ropa"]}
        self.assertIn("log", ropa["Sağlık"]["sinks"])
        self.assertTrue(ropa["Sağlık"]["special_category"])
        self.assertIn("tckn", ropa["Kimlik"]["fields"])
        self.assertEqual(ropa["Kimlik"]["files"], ["service.py"])

    def test_pii_sent_to_llm_api(self) -> None:
        content = (
            "from openai import OpenAI\n"
            "client = OpenAI()\n"
            "def summarize(patient):\n"
            "    prompt = f'Hasta {patient.full_name} TCKN {patient.tc_kimlik_no} {patient.diagnosis}'\n"
            "    return client.chat.completions.create(model='gpt-4o', messages=[{'role': 'user', 'content': prompt}])\n"
        )
        result = audit_privacy_inline(content, filename="ai.py")
        llm = [item for item in result["findings"] if item["control_id"] == "SNIPER-AI-06"]
        self.assertEqual(len(llm), 1)
        self.assertEqual(llm[0]["severity"], "high")
        self.assertEqual(llm[0]["cwe"], "CWE-359")
        self.assertEqual(llm[0]["line"], 5)

    def test_pii_sent_to_analytics(self) -> None:
        content = (
            "function onSignup(user) {\n"
            "  analytics.identify(user.id, { email: user.email, phone: user.phoneNumber });\n"
            "}\n"
        )
        result = audit_privacy_inline(content, filename="signup.js")
        controls = {item["control_id"] for item in result["findings"]}
        self.assertIn("SNIPER-DATA-05", controls)

    def test_tracking_without_consent_is_medium(self) -> None:
        content = (
            "<html><head>\n"
            "<script async src=\"https://www.googletagmanager.com/gtag/js?id=G-DEMO123\"></script>\n"
            "<script>window.dataLayer = window.dataLayer || []; function gtag(){dataLayer.push(arguments);}"
            " gtag('js', new Date()); gtag('config', 'G-DEMO123');</script>\n"
            "</head></html>\n"
        )
        result = audit_privacy_inline(content, filename="index.html")
        self.assertEqual(result["finding_count"], 1, result["findings"])
        finding = result["findings"][0]
        self.assertEqual(finding["control_id"], "SNIPER-DATA-07")
        self.assertEqual(finding["severity"], "medium")
        self.assertEqual(finding["title"], "Kullanıcı rızası alınmadan izleme betiği yükleniyor")

    def test_clean_code_has_no_findings(self) -> None:
        python_content = (
            "import logging\n"
            "logger = logging.getLogger(__name__)\n"
            "def login(user):\n"
            "    logger.info('login ok user_id=%s', user.id)\n"
            "    logger.info('contact=%s', mask_email(user.email))\n"
            "    analytics.identify(user.pseudonymous_id)\n"
        )
        result = audit_privacy_inline(python_content, filename="auth.py")
        self.assertEqual(result["finding_count"], 0, result["findings"])

        html_content = (
            "<html><head>\n"
            "<script>window.dataLayer = window.dataLayer || []; function gtag(){dataLayer.push(arguments);}\n"
            "gtag('consent', 'default', {'ad_storage': 'denied', 'analytics_storage': 'denied'});</script>\n"
            "<script async src=\"https://www.googletagmanager.com/gtag/js?id=G-DEMO123\"></script>\n"
            "</head></html>\n"
        )
        html_result = audit_privacy_inline(html_content, filename="index.html")
        self.assertEqual(html_result["finding_count"], 0, html_result["findings"])

    def test_health_check_is_not_health_data(self) -> None:
        content = "logger.info('health check ok', extra={'health_check': True})\n"
        result = audit_privacy_inline(content, filename="probe.py")
        self.assertEqual(result["finding_count"], 0, result["findings"])
        self.assertEqual(result["pii_categories_detected"], [])

    def test_empty_content_raises_value_error(self) -> None:
        with self.assertRaises(ValueError):
            audit_privacy_inline("")
        with self.assertRaises(ValueError):
            audit_privacy_inline("  \n ")
        with self.assertRaises(ValueError):
            audit_privacy_inline(None)  # type: ignore[arg-type]


class PrivacyDataflowProjectTests(unittest.TestCase):
    def test_project_erasure_gap_and_unencrypted_special_category(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            root = Path(tmp)
            (root / "backend").mkdir()
            (root / "backend" / "models.py").write_text(
                "from sqlalchemy import Column, String\n"
                "from sqlalchemy.orm import declarative_base\n"
                "Base = declarative_base()\n"
                "class Patient(Base):\n"
                "    __tablename__ = 'patients'\n"
                "    id = Column(String, primary_key=True)\n"
                "    tckn = Column(String)\n"
                "    diagnosis = Column(String)\n",
                encoding="utf-8",
            )
            allowed = (Path.home().resolve(),)

            result = audit_privacy_project(str(root), allowed_roots=allowed)

            self.assertEqual(result["format"], "sniper-privacy-dataflow-audit-v1")
            self.assertEqual(result["scanned_files"], 1)
            controls = {item["control_id"] for item in result["findings"]}
            self.assertIn("SNIPER-DATA-02", controls)
            self.assertIn("SNIPER-DATA-08", controls)
            self.assertFalse(result["erasure_flow_detected"])
            self.assertTrue(result["special_category_detected"])
            ropa = {entry["data_category"]: entry for entry in result["ropa"]}
            self.assertIn("storage", ropa["Sağlık"]["sinks"])
            self.assertIn("storage", ropa["Kimlik"]["sinks"])

            (root / "backend" / "gdpr.py").write_text(
                "def delete_user(session, user_id):\n"
                "    session.query(Patient).filter_by(id=user_id).delete()\n",
                encoding="utf-8",
            )
            second = audit_privacy_project(str(root), allowed_roots=allowed)
            second_controls = {item["control_id"] for item in second["findings"]}
            self.assertNotIn("SNIPER-DATA-08", second_controls)
            self.assertIn("SNIPER-DATA-02", second_controls)
            self.assertTrue(second["erasure_flow_detected"])


if __name__ == "__main__":
    unittest.main()
