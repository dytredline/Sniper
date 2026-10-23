import csv
import json
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest

from cli_reports import (
    auto_scan_project,
    export_dependency_report,
    export_project,
    generate_dependency_sbom,
    import_dependency_report,
    list_dependency_findings,
)
from project_analyzer import ProjectRejected
from storage import Store


class CliReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.base = Path(self.temp.name)
        self.db_path = self.base / "data" / "sniper.db"
        self.project = self.base / "sample-project"
        self.project.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def test_auto_scan_uses_supplied_database_and_preserves_all_findings(self):
        (self.project / "main.py").write_text(
            'import hashlib\nPASSWORD = "private-test-password"\nhashlib.sha1(b"x")\n',
            encoding="utf-8",
        )
        saved = auto_scan_project(str(self.project), limit=10, db_path=self.db_path)
        stored = Store(self.db_path).get_project_audit(saved["id"])
        self.assertEqual(stored["finding_count"], len(stored["findings"]))
        self.assertGreater(stored["finding_count"], 0)

    def test_auto_scan_enforces_requested_file_limit(self):
        (self.project / "one.py").write_text("print(1)\n", encoding="utf-8")
        (self.project / "two.py").write_text("print(2)\n", encoding="utf-8")
        with self.assertRaises(ProjectRejected):
            auto_scan_project(str(self.project), limit=1, db_path=self.db_path)
        self.assertEqual(Store(self.db_path).list_project_audits(), [])

    def test_json_and_csv_exports_are_safe_and_complete(self):
        store = Store(self.db_path)
        saved = store.create_project_audit({
            "created_at": "2026-09-19T00:00:00+00:00",
            "project_path": str(self.project),
            "project_name": "=FORMULA,project",
            "score": 92,
            "grade": "A",
            "file_count": 1,
            "bytes_scanned": 12,
            "summary": {"ok": True},
            "findings": [{"title": "örnek"}],
        })
        json_path = export_project(saved["id"], "json", self.base, db_path=self.db_path)
        csv_path = export_project(saved["id"], "csv", self.base, db_path=self.db_path)
        self.assertEqual(json.loads(json_path.read_text(encoding="utf-8"))["finding_count"], 1)
        with csv_path.open(encoding="utf-8", newline="") as handle:
            rows = list(csv.reader(handle))
        self.assertEqual(rows[1][1], "'=FORMULA,project")

    def test_dependency_commands_share_persistent_database(self):
        (self.project / "requirements.txt").write_text("demo==1.0\n", encoding="utf-8")
        sbom_path = self.base / "exports" / "bom.json"
        saved = generate_dependency_sbom(str(self.project), sbom_path, db_path=self.db_path)
        self.assertEqual(saved["component_count"], 1)
        self.assertEqual(json.loads(sbom_path.read_text(encoding="utf-8"))["bomFormat"], "CycloneDX")

        trivy_path = self.base / "trivy.json"
        trivy_path.write_text(json.dumps({"Results": [{"Target": "requirements.txt", "Vulnerabilities": [{
            "VulnerabilityID": "CVE-2026-0099", "PkgName": "demo", "InstalledVersion": "1.0",
            "FixedVersion": "1.1", "Severity": "HIGH", "References": ["https://example.test/99"],
        }]}]}), encoding="utf-8")
        import_dependency_report(str(trivy_path), str(self.project), db_path=self.db_path)
        rows = list_dependency_findings(db_path=self.db_path)
        self.assertEqual(rows[0]["vulnerability_id"], "CVE-2026-0099")

        report_path = export_dependency_report(self.base / "exports" / "dependencies.json", db_path=self.db_path)
        exported = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(exported["summary"]["active"], 1)

    def test_list_projects_cli_json_view_with_non_ascii_and_limit(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_db = Path(tmpdir) / "test.db"
            tmp_db.parent.mkdir(parents=True, exist_ok=True)
            store = Store(tmp_db)

            store.create_project_audit({
                "created_at": "2026-09-19T00:00:00+00:00",
                "project_path": str(self.project),
                "project_name": "Özgün Proje",
                "score": 85,
                "grade": "B",
                "file_count": 1,
                "bytes_scanned": 12,
                "summary": {"ok": True},
                "findings": [],
            })
            store.create_project_audit({
                "created_at": "2026-09-20T00:00:00+00:00",
                "project_path": str(self.project),
                "project_name": "Projekt Über",
                "score": 92,
                "grade": "A",
                "file_count": 2,
                "bytes_scanned": 24,
                "summary": {"ok": True},
                "findings": [],
            })
            store.create_project_audit({
                "created_at": "2026-09-21T00:00:00+00:00",
                "project_path": str(self.project),
                "project_name": "日本語プロジェクト",
                "score": 78,
                "grade": "C",
                "file_count": 3,
                "bytes_scanned": 36,
                "summary": {"ok": True},
                "findings": [],
            })

            cli_args = [
                sys.executable, "cli_reports.py", "list",
                "--db", str(tmp_db),
                "--view", "json",
                "--limit", "2",
            ]
            result = subprocess.run(
                cli_args,
                capture_output=True,
                text=True,
                cwd=Path(__file__).resolve().parent.parent,
            )
            self.assertEqual(result.returncode, 0)
            items = json.loads(result.stdout)
            self.assertEqual(len(items), 2)
            # Most recent first (by rowid DESC)
            self.assertEqual(items[0]["project_name"], "日本語プロジェクト")
            self.assertEqual(items[1]["project_name"], "Projekt Über")

    def test_list_projects_cli_json_empty_database(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_db = Path(tmpdir) / "empty.db"
            tmp_db.parent.mkdir(parents=True, exist_ok=True)

            cli_args = [
                sys.executable, "cli_reports.py", "list",
                "--db", str(tmp_db),
                "--view", "json",
                "--limit", "50",
            ]
            result = subprocess.run(
                cli_args,
                capture_output=True,
                text=True,
                cwd=Path(__file__).resolve().parent.parent,
            )
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "[]\n")

    def test_list_projects_cli_table_view(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_db = Path(tmpdir) / "test.db"
            tmp_db.parent.mkdir(parents=True, exist_ok=True)
            store = Store(tmp_db)

            store.create_project_audit({
                "created_at": "2026-09-19T00:00:00+00:00",
                "project_path": str(self.project),
                "project_name": "Özgün Proje",
                "score": 85,
                "grade": "B",
                "file_count": 1,
                "bytes_scanned": 12,
                "summary": {"ok": True},
                "findings": [],
            })

            cli_args = [
                sys.executable, "cli_reports.py", "list",
                "--db", str(tmp_db),
                "--view", "table",
            ]
            result = subprocess.run(
                cli_args,
                capture_output=True,
                text=True,
                cwd=Path(__file__).resolve().parent.parent,
            )
            self.assertEqual(result.returncode, 0)
            self.assertIn("Özgün Proje", result.stdout)
            self.assertIn("85", result.stdout)
            self.assertIn("B", result.stdout)

    def test_list_projects_cli_flat_view(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_db = Path(tmpdir) / "test.db"
            tmp_db.parent.mkdir(parents=True, exist_ok=True)
            store = Store(tmp_db)

            store.create_project_audit({
                "created_at": "2026-09-19T00:00:00+00:00",
                "project_path": str(self.project),
                "project_name": "Projekt Über",
                "score": 92,
                "grade": "A",
                "file_count": 2,
                "bytes_scanned": 24,
                "summary": {"ok": True},
                "findings": [],
            })

            cli_args = [
                sys.executable, "cli_reports.py", "list",
                "--db", str(tmp_db),
                "--view", "flat",
            ]
            result = subprocess.run(
                cli_args,
                capture_output=True,
                text=True,
                cwd=Path(__file__).resolve().parent.parent,
            )
            self.assertEqual(result.returncode, 0)
            self.assertIn("Projekt Über", result.stdout)
            self.assertIn("92", result.stdout)
            self.assertIn("A", result.stdout)


if __name__ == "__main__":
    unittest.main()
