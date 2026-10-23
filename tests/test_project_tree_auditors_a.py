from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import ai_llm_security_auditor as ai_llm
import audit_logging_integrity_auditor as audit_logging
import browser_extension_pwa_auditor as browser_extension
import business_logic_auditor as business_logic
import cloud_iam_rbac_auditor as cloud_iam
import database_rls_schema_auditor as database_schema
from project_tree import ProjectTreeError


class ProjectTreeAuditorsBatchATests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="sniper-project-tree-auditors-a-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()

    def _project(self, name: str) -> Path:
        project = self.base / name / "project"
        project.mkdir(parents=True)
        return project

    def _assert_project_report(
        self,
        report: dict,
        *,
        expected_format: str,
        project: Path,
        expected_file: str,
    ) -> None:
        self.assertEqual(report["format"], expected_format)
        self.assertEqual(report["project"], project.name)
        self.assertEqual(report["project_path"], str(project))
        self.assertEqual(report["scanned_files"], 1)
        self.assertGreater(report["finding_count"], 0)
        self.assertEqual({finding["file"] for finding in report["findings"]}, {expected_file})

    def test_validation_parent_swap_never_scans_outside_sentinel(self) -> None:
        project = self._project("race")
        (project / "inside.py").write_text("VALUE = 1\n", encoding="utf-8")
        validated = project.resolve(strict=True)

        outside_parent = self.base / "outside-parent"
        outside_project = outside_parent / "project"
        outside_project.mkdir(parents=True)
        (outside_project / "sentinel.py").write_text(
            'prompt = f"OUTSIDE_SENTINEL {user_input}"\n',
            encoding="utf-8",
        )

        def validate_then_swap(_value: str, *, allowed_roots=None) -> Path:
            parent = project.parent
            parent.rename(self.base / "validated-parent")
            parent.symlink_to(outside_parent, target_is_directory=True)
            return validated

        with mock.patch.object(ai_llm, "validate_project_path", side_effect=validate_then_swap):
            try:
                report = ai_llm.audit_ai_llm_project(str(project), allowed_roots=(self.base,))
            except ProjectTreeError:
                return

        evidence = "\n".join(str(item.get("evidence", "")) for item in report["findings"])
        self.assertNotIn(
            "OUTSIDE_SENTINEL",
            evidence,
            "doğrulanmış ebeveyn değiştirildikten sonra dış ağacın bulgusu rapora karıştı",
        )
        self.fail("proje kökü doğrulamadan sonra değiştiğinde tarama fail-closed reddedilmeliydi")

    def test_ai_llm_project_normal_control(self) -> None:
        project = self._project("ai")
        (project / "agent.py").write_bytes(b'prompt = f"hello {user_input}"\n# \xff\n')
        report = ai_llm.audit_ai_llm_project(str(project), allowed_roots=(self.base,))
        self._assert_project_report(
            report,
            expected_format="sniper-ai-llm-security-audit-v1",
            project=project,
            expected_file="agent.py",
        )

    def test_audit_logging_project_normal_control(self) -> None:
        project = self._project("logging")
        (project / "admin.py").write_text(
            '@app.route("/admin", methods=["DELETE"])\n'
            "def delete_user():\n"
            "    db.delete()\n",
            encoding="utf-8",
        )
        report = audit_logging.audit_logging_project(str(project), allowed_roots=(self.base,))
        self._assert_project_report(
            report,
            expected_format="sniper-audit-logging-audit-v1",
            project=project,
            expected_file="admin.py",
        )

    def test_browser_extension_project_normal_control(self) -> None:
        project = self._project("browser")
        manifest = project / "extension" / "manifest.json"
        manifest.parent.mkdir()
        manifest.write_text(
            json.dumps(
                {
                    "manifest_version": 2,
                    "name": "unsafe extension",
                    "version": "1.0",
                    "permissions": ["<all_urls>"],
                }
            ),
            encoding="utf-8",
        )
        report = browser_extension.audit_extension_pwa_project(str(project), allowed_roots=(self.base,))
        self._assert_project_report(
            report,
            expected_format="sniper-browser-extension-pwa-audit-v1",
            project=project,
            expected_file="extension/manifest.json",
        )
        self.assertEqual(report["extension_manifest_count"], 1)

    def test_business_logic_project_normal_control(self) -> None:
        project = self._project("business")
        (project / "logic.py").write_text(
            "def transfer(user, amount):\n    user.balance -= amount\n",
            encoding="utf-8",
        )
        report = business_logic.audit_business_logic_project(str(project), allowed_roots=(self.base,))
        self._assert_project_report(
            report,
            expected_format="sniper-business-logic-audit-v1",
            project=project,
            expected_file="logic.py",
        )

    def test_cloud_iam_project_normal_control(self) -> None:
        project = self._project("cloud")
        (project / "role.yaml").write_text(
            "apiVersion: rbac.authorization.k8s.io/v1\n"
            "kind: ClusterRole\n"
            "rules:\n"
            '- apiGroups: ["*"]\n'
            '  resources: ["*"]\n'
            '  verbs: ["*"]\n',
            encoding="utf-8",
        )
        report = cloud_iam.audit_cloud_iam_project(str(project), allowed_roots=(self.base,))
        self._assert_project_report(
            report,
            expected_format="sniper-cloud-iam-project-audit-v1",
            project=project,
            expected_file="role.yaml",
        )

    def test_database_schema_project_normal_control(self) -> None:
        project = self._project("database")
        (project / "schema.sql").write_text(
            "CREATE TABLE users (id int, tenant_id UUID);\n",
            encoding="utf-8",
        )
        report = database_schema.audit_database_schema_project(str(project), allowed_roots=(self.base,))
        self._assert_project_report(
            report,
            expected_format="sniper-database-schema-audit-v1",
            project=project,
            expected_file="schema.sql",
        )

    def test_skip_empty_oversized_and_file_count_contracts_are_preserved(self) -> None:
        project = self._project("contracts")
        (project / "a.py").write_text('prompt = f"a {user_input}"\n', encoding="utf-8")
        (project / "b.py").write_text('prompt = f"b {user_input}"\n', encoding="utf-8")
        (project / "empty.py").write_text("", encoding="utf-8")
        (project / "oversized.py").write_bytes(b"x" * (ai_llm.MAX_INLINE_BYTES + 1))
        ignored = project / "node_modules"
        ignored.mkdir()
        (ignored / "outside.py").write_text(
            'prompt = f"SKIPPED_SENTINEL {user_input}"\n',
            encoding="utf-8",
        )

        with mock.patch.object(ai_llm, "MAX_PROJECT_FILES", 1):
            report = ai_llm.audit_ai_llm_project(str(project), allowed_roots=(self.base,))

        self.assertEqual(report["scanned_files"], 1)
        serialized = json.dumps(report, ensure_ascii=False)
        self.assertNotIn("SKIPPED_SENTINEL", serialized)


if __name__ == "__main__":
    unittest.main()
