from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from scanner import normalize_target
import server
from storage import Store


class UnifiedFindingsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(Path(self.temp.name) / "sniper.db")
        root = Path(self.temp.name) / "project"
        root.mkdir()
        (root / "app.py").write_text("print('ok')\n")
        self.audit = self.store.create_project_audit({
            "created_at": "2026-10-21T10:00:00Z", "project_path": str(root), "project_name": "project",
            "score": 40, "grade": "D", "file_count": 1, "bytes_scanned": 12,
            "findings": [{"severity": "high", "title": "Komut enjeksiyonu", "category": "data_flow",
                          "reference": "CWE-78", "file": "app.py", "line": 1,
                          "evidence": "PROJECT-SECRET-EVIDENCE"}],
        })
        target = self.store.create_target(normalize_target("https://sensitive-target.example/private"))
        self.engagement = self.store.create_engagement(
            target_id=target["id"], name="Yetkili denetim", authorization_ref="AUTH-1", scope_notes="",
            out_of_scope="", test_window="", special_approvals={},
        )
        self.manual = self.store.create_manual_finding(self.engagement["id"], {
            "severity": "critical", "title": "Yetki kontrolü", "affected_asset": "/api/orders/{id}",
            "description": "MANUAL-SECRET-DESCRIPTION", "impact": "MANUAL-SECRET-IMPACT",
            "evidence": "MANUAL-SECRET-EVIDENCE", "reproduction": "MANUAL-SECRET-REPRODUCTION",
            "recommendation": "kontrol ekle", "cwe_id": "CWE-639", "remediation_owner": "API ekibi",
            "due_date": "2000-01-01",
        })
        self.store.import_network_scan_findings(
            request_id="msr_" + "a" * 16, scanner_job_id="b" * 16, target_id=target["id"],
            engagement_id=self.engagement["id"], findings=[{
                "template_id": "http/exposed-panel", "title": "Açık yönetim paneli", "severity": "medium",
                "fingerprint_sha256": "c" * 64, "evidence_sha256": "d" * 64,
            }],
        )
        with self.store._connect() as db:
            now = "2026-10-21T10:01:00Z"
            db.execute("""INSERT INTO dependency_findings(
                id,fingerprint,project_path,package_name,installed_version,vulnerability_id,severity,fixed_version,
                source,title,summary,target,references_json,status,resolution_notes,first_seen_at,last_seen_at,
                source_timestamp,latest_import_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                ("depfnd_1", "e"*64, str(root), "demo", "1.0", "CVE-2026-1", "high", "1.1", "osv",
                 "Demo dependency", "private summary", "", "[]", "open", "", now, now, now, None))

    def test_all_sources_are_normalized_without_raw_evidence(self) -> None:
        result = self.store.list_unified_findings(limit=20)
        self.assertEqual({item["source"] for item in result["items"]}, {"project", "manual", "network", "dependency"})
        self.assertEqual(result["total"], 4)
        self.assertEqual(result["items"][0]["severity"], "critical")
        manual = next(item for item in result["items"] if item["source"] == "manual")
        self.assertTrue(manual["overdue"])
        self.assertEqual(manual["assignee"], {"id": None, "name": "API ekibi"})
        network = next(item for item in result["items"] if item["source"] == "network")
        self.assertEqual(network["reference"], "http/exposed-panel")
        dependency = next(item for item in result["items"] if item["source"] == "dependency")
        self.assertEqual(dependency["reference"], "CVE-2026-1")
        encoded = json.dumps(result)
        for secret in ("PROJECT-SECRET", "MANUAL-SECRET", "sensitive-target.example", "fingerprint_sha256",
                       "evidence_sha256"):
            self.assertNotIn(secret, encoded)

    def test_filters_limits_and_invalid_values_fail_closed(self) -> None:
        result = self.store.list_unified_findings(sources={"project"}, severities={"high"}, statuses={"open"}, limit=1)
        self.assertEqual(result["total"], 1)
        self.assertEqual(result["items"][0]["source"], "project")
        for kwargs in ({"sources": {"other"}}, {"severities": {"urgent"}}, {"statuses": {"resolved"}},
                       {"limit": 0}, {"limit": True}, {"offset": -1}, {"offset": True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.store.list_unified_findings(**kwargs)
        page = self.store.list_unified_findings(limit=2, offset=2)
        self.assertEqual(page["returned"], 2)
        self.assertEqual(page["offset"], 2)

    def test_network_lifecycle_is_visible_in_unified_view(self) -> None:
        finding = self.store.list_network_scan_findings("msr_" + "a" * 16)[0]
        self.store.update_network_finding(finding["id"], status="in_progress", assignee_name="Ağ ekibi",
                                          due_date="2000-01-01")
        item = self.store.list_unified_findings(sources={"network"})["items"][0]
        self.assertEqual(item["status"], "in_progress")
        self.assertEqual(item["assignee"], {"id": None, "name": "Ağ ekibi"})
        self.assertTrue(item["overdue"])

    def test_schema_migration_is_versioned_and_idempotent(self) -> None:
        finding = self.store.list_network_scan_findings("msr_" + "a" * 16)[0]
        with self.store._connect() as db:
            self.assertIsNone(db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations'").fetchone())
        self.store.update_network_finding(finding["id"], status="open")
        Store(self.store.path)
        with self.store._connect() as db:
            rows = db.execute("SELECT version,name FROM schema_migrations ORDER BY version").fetchall()
        self.assertEqual([(row["version"], row["name"]) for row in rows],
                         [(1, "network-finding-lifecycle")])


class UnifiedFindingsApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = server.SniperHandler.__new__(server.SniperHandler)
        self.responses: list[tuple[int, dict]] = []
        self.client._json = lambda body, status=200, **_kw: self.responses.append((int(status), body))
        self.client._error = lambda status, message: self.responses.append((int(status), {"error": message}))

    def test_query_is_bounded_and_forwarded(self) -> None:
        expected = {"format": "sniper-unified-findings/1", "items": [], "total": 0}
        from unittest import mock
        with mock.patch.object(server.STORE, "list_unified_findings", return_value=expected) as listed:
            self.client._unified_findings_get({
                "source": ["project,manual"], "status": ["open"], "severity": ["high,critical"], "limit": ["25"],
            })
        self.assertEqual(self.responses.pop(), (200, expected))
        listed.assert_called_once_with(sources={"project", "manual"}, statuses={"open"},
                                       severities={"high", "critical"}, limit=25, offset=0)
        self.client._unified_findings_get({"source": ["unknown"]})
        self.assertEqual(self.responses.pop()[0], 400)


if __name__ == "__main__":
    unittest.main()
