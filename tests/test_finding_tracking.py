"""Bulgu takibi: satır kaymasına dayanıklı parmak izi, yaşam döngüsü, kapsam kuralları, triaj taşıma,
geriye dönük doldurma, proje yönetici özeti ve API."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest import mock
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import finding_tracking as ft
import project_analyzer
from project_audit_diff import _active_findings
from project_executive_summary import build_project_executive_summary, render_page_html
from storage import Store


def flow_finding(file="app.py", line=10, sink="c.execute", source="request.args"):
    return {
        "category": "data_query", "severity": "critical", "reference": "CWE-89", "file": file, "line": line,
        "title": "Doğrulanmış veri akışı: istek girdisi SQL sorgusuna ulaşıyor (SQL enjeksiyonu)",
        "evidence": f"Veri akışı: {source} (satır {line - 2}) → {sink} (satır {line})",
        "recommendation": "Parametre bağlayın.",
        "taint_flow": {"sink_kind": "sql", "sink": sink, "sink_line": line, "source": source, "source_label": "request",
                       "source_line": line - 2, "via": ["q"], "source_file": file},
    }


def pattern_finding(file="app.py", line=30, title="Günlüğe hassas veri yazma olasılığı", severity="medium"):
    return {"category": "logging", "severity": severity, "reference": "CWE-532", "file": file, "line": line,
            "title": title, "evidence": "Hassas alan değişkeni günlük çağrısına veriliyor; değer kaydedilmedi.",
            "recommendation": "Maskeleyin."}


class FingerprintTests(unittest.TestCase):
    def test_line_independent(self):
        self.assertEqual(ft.fingerprint(flow_finding(line=10)), ft.fingerprint(flow_finding(line=40)))
        self.assertEqual(ft.fingerprint(pattern_finding(line=3)), ft.fingerprint(pattern_finding(line=300)))

    def test_distinguishes_file_sink_and_source(self):
        base = ft.fingerprint(flow_finding())
        self.assertNotEqual(base, ft.fingerprint(flow_finding(file="other.py")))
        self.assertNotEqual(base, ft.fingerprint(flow_finding(sink="cur.execute")))
        self.assertNotEqual(base, ft.fingerprint(flow_finding(source="request.form")))
        self.assertNotEqual(base, ft.fingerprint(pattern_finding()))


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.root = base / "proj"
        (self.root / "tests").mkdir(parents=True)
        for name in ("app.py", "views.py", "tests/test_app.py"):
            (self.root / name).write_text("x = 1\n")
        self.store = Store(base / "data" / "sniper.db")
        self.counter = 0

    def audit(self, findings, scope=None, base_audit_id=None, skipped=None, root=None):
        self.counter += 1
        result = {
            "created_at": f"2026-10-{self.counter:02d}T10:00:00Z", "project_path": str(root or self.root),
            "project_name": "proj", "score": 70, "grade": "C", "file_count": 3, "bytes_scanned": 10,
            "findings": findings, "scope": scope or {}, "skipped_files": skipped or {},
        }
        if base_audit_id:
            result["base_audit_id"] = base_audit_id
        return self.store.create_project_audit(result)

    def statuses(self):
        return {(item["file"], item["line"]): item["status"] for item in self.store.list_tracked_findings(str(self.root))}

    def test_new_seen_fixed_reopened(self):
        first = self.audit([flow_finding(line=10), pattern_finding(file="views.py", line=5)])
        self.assertEqual(first["tracking"]["new_count"], 2)
        self.assertTrue(all(f["tracking"]["is_new"] for f in first["findings"]))
        # Satırlar kaydı, views.py bulgusu düzeldi.
        second = self.audit([flow_finding(line=25)])
        self.assertEqual(second["tracking"], {**second["tracking"], "new_count": 0, "seen_count": 1, "fixed_count": 1})
        self.assertFalse(second["findings"][0]["tracking"]["is_new"])
        self.assertEqual(self.statuses(), {("app.py", 25): "open", ("views.py", 5): "fixed"})
        third = self.audit([flow_finding(line=25), pattern_finding(file="views.py", line=7)])
        self.assertEqual(third["tracking"]["reopened_count"], 1)
        self.assertEqual(self.statuses()[("views.py", 7)], "reopened")
        summary = self.store.tracked_project_summary(str(self.root))
        self.assertEqual(summary["active"], 2)
        self.assertEqual(len(summary["trend"]), 3)

    def test_duplicates_match_nearest_line(self):
        self.audit([pattern_finding(line=10), pattern_finding(line=50)])
        ids_before = {item["line"]: item["id"] for item in self.store.list_tracked_findings(str(self.root))}
        result = self.audit([pattern_finding(line=53)])  # üste 3 satır eklendi, ilk bulgu düzeldi
        self.assertEqual(result["findings"][0]["tracking"]["id"], ids_before[50])
        self.assertEqual(self.statuses(), {("app.py", 10): "fixed", ("app.py", 53): "open"})

    def test_supplement_scan_never_fixes(self):
        base = self.audit([flow_finding()])
        extra = self.audit([pattern_finding(file="tests/test_app.py")],
                           scope={"skipped_only": True, "include_dirs": ["tests"]}, base_audit_id=base["id"])
        self.assertEqual(extra["tracking"]["mode"], "supplement")
        self.assertEqual(extra["tracking"]["fixed_count"], 0)
        self.assertEqual(set(self.statuses().values()), {"open"})
        # Sonraki varsayılan analiz tests/ dizinini görmez: test bulgusu açık kalır, "doğrulanamadı" sayılır.
        normal = self.audit([flow_finding()])
        self.assertEqual(normal["tracking"]["not_rescanned_count"], 1)
        self.assertEqual(self.statuses()[("tests/test_app.py", 30)], "open")

    def test_out_of_scope_files_stay_open(self):
        self.audit([flow_finding(file="views.py")])
        (self.root / "views.py").write_text("x = 1\n" * 300_000)  # artık 1 MB sınırını aşıyor
        result = self.audit([])
        self.assertEqual(result["tracking"]["fixed_count"], 0)
        self.assertEqual(result["tracking"]["not_rescanned_count"], 1)
        budget = self.audit([], skipped={"budget": 1})
        self.assertEqual(budget["tracking"]["fixed_count"], 0)

    def test_deleted_file_and_missing_root(self):
        self.audit([flow_finding(file="views.py")])
        (self.root / "views.py").unlink()
        self.assertEqual(self.audit([])["tracking"]["fixed_count"], 1)
        other = Path(self.tmp.name) / "gone"
        self.audit([flow_finding()], root=other)
        self.assertEqual(self.audit([], root=other)["tracking"]["fixed_count"], 0)

    def test_project_wide_finding_fixed_only_by_full_audit(self):
        wide = pattern_finding(file="Proje geneli", line=0, title="Dış isteklerde SSRF koruması doğrulanamadı")
        base = self.audit([wide])
        self.audit([], scope={"skipped_only": True}, base_audit_id=base["id"])
        self.assertEqual(self.statuses()[("Proje geneli", 0)], "open")
        self.audit([])
        self.assertEqual(self.statuses()[("Proje geneli", 0)], "fixed")

    def test_triage_carries_over_and_suppresses(self):
        first = self.audit([flow_finding(), pattern_finding()])
        self.store.update_project_audit_finding_triage(first["id"], 1, disposition="false_positive", note="test verisi")
        second = self.audit([flow_finding(line=12), pattern_finding(line=33)])
        inherited = second["findings"][1]["triage"]
        self.assertEqual(inherited["disposition"], "false_positive")
        self.assertTrue(inherited["inherited"])
        self.assertTrue(second["findings"][1]["tracking"]["suppressed"])
        self.assertEqual(len(_active_findings(second)), 1)  # raporlarda gürültü yapmaz
        # Bastırılmış bulgu kaybolunca "düzeldi" olmaz, kararı korunur.
        self.audit([flow_finding()])
        self.assertEqual(self.statuses()[("app.py", 33)], "false_positive")

    def test_manual_status_change_and_validation(self):
        first = self.audit([flow_finding(), pattern_finding(file="views.py")])
        tracked = first["findings"][0]["tracking"]["id"]
        result = self.store.set_tracked_finding_status(tracked, "in_progress", "yamada")
        self.assertEqual(result["status"], "in_progress")
        self.assertEqual(result["events"][-1]["event"], "status_changed")
        with self.assertRaises(ft.TrackingError):
            self.store.set_tracked_finding_status(tracked, "fixed", "")
        with self.assertRaises(LookupError):
            self.store.set_tracked_finding_status("trk_yok", "open", "")
        self.audit([flow_finding()])
        fixed = first["findings"][1]["tracking"]["id"]
        with self.assertRaises(ft.TrackingError):
            self.store.set_tracked_finding_status(fixed, "open", "")
        with sqlite3.connect(self.store.path) as db:
            actions = [row[0] for row in db.execute("SELECT action FROM audit_log")]
        self.assertIn("tracked_finding.status_changed", actions)
        self.assertTrue(self.store.verify_audit_chain()["verified"])

    def test_backfill_existing_audits(self):
        self.audit([flow_finding()])
        with sqlite3.connect(self.store.path) as db:  # takip öncesi döneme ait analizleri taklit et
            for table in ("tracked_finding_occurrences", "tracked_finding_events", "tracked_findings", "project_audit_tracking"):
                db.execute(f"DELETE FROM {table}")
        self.audit([flow_finding(line=20)])  # bu proje artık takipli: eski analiz atlanır
        result = self.store.backfill_finding_tracking()
        self.assertEqual(result, {"processed_audits": 0, "skipped_projects_already_tracked": 1})
        with sqlite3.connect(self.store.path) as db:
            for table in ("tracked_finding_occurrences", "tracked_finding_events", "tracked_findings", "project_audit_tracking"):
                db.execute(f"DELETE FROM {table}")
        self.assertEqual(self.store.backfill_finding_tracking()["processed_audits"], 2)
        self.assertEqual(self.store.backfill_finding_tracking()["processed_audits"], 0)
        self.assertEqual(self.statuses(), {("app.py", 20): "open"})

    def test_tracking_failure_does_not_block_audit(self):
        with mock.patch.object(ft, "record_audit", side_effect=sqlite3.OperationalError("boom")):
            audit = self.audit([flow_finding()])
        self.assertEqual(len(audit["findings"]), 1)
        self.assertNotIn("tracking", audit)

    def test_executive_summary(self):
        self.audit([flow_finding(), pattern_finding(file="views.py")])
        latest = self.audit([flow_finding(line=11)])
        summary = build_project_executive_summary(self.store, latest)
        self.assertEqual(summary["risk_level"], "critical")
        self.assertEqual(summary["active_findings"], 1)
        self.assertEqual(summary["fixed_total"], 1)
        self.assertIsNotNone(summary["mean_time_to_fix_hours"])
        self.assertEqual(summary["this_audit"]["fixed_count"], 1)
        self.assertEqual(summary["top_findings"][0]["reference"], "CWE-89")
        page = render_page_html(summary)
        self.assertIn("Yönetici özeti", page)
        self.assertIn("Ölçüm güveni", page)


VULN = 'import os\nfrom flask import request\n\ndef run():\n    os.system("ping " + request.args["h"])\n'
SAFE = 'import subprocess\nfrom flask import request\n\ndef run():\n    subprocess.run(["ping", request.args["h"]])\n'


class FindingTrackingApiTests(unittest.TestCase):
    def setUp(self):
        import server

        self.server = server
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.data_dir = base / "data"
        self.data_dir.mkdir()
        self.root = base / "proj"
        self.root.mkdir()
        (self.root / "app.py").write_text(VULN)
        self.previous_store = server.STORE
        server.STORE = Store(self.data_dir / "sniper-test.db")
        for patch in (mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(self.data_dir)}),
                      mock.patch.object(project_analyzer, "_allowed_roots", return_value=(base,))):
            patch.start()
            self.addCleanup(patch.stop)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base_url = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.server.STORE = self.previous_store

    def call(self, path, body=None, raw=False):
        request = urllib.request.Request(
            self.base_url + path, method="POST" if body is not None else "GET",
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Content-Type": "application/json"} if body is not None else {},
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                data = response.read()
                return response.status, (data.decode() if raw else json.loads(data))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    def test_end_to_end(self):
        status, first = self.call("/api/project-audits", {"project_path": str(self.root)})
        self.assertEqual(status, 201, first)
        command = [f for f in first["findings"] if f.get("reference") == "CWE-78" and f.get("taint_flow")]
        self.assertTrue(command and command[0]["tracking"]["is_new"])
        project = first["project_path"]

        (self.root / "app.py").write_text("# yeni satır\n" * 4 + VULN)  # satır kayması
        status, second = self.call("/api/project-audits", {"project_path": str(self.root)})
        self.assertEqual(second["tracking"]["new_count"], 0)
        self.assertEqual(second["tracking"]["fixed_count"], 0)

        (self.root / "app.py").write_text(SAFE)
        status, third = self.call("/api/project-audits", {"project_path": str(self.root)})
        self.assertGreaterEqual(third["tracking"]["fixed_count"], 1)

        status, projects = self.call("/api/finding-tracking/projects")
        self.assertEqual(projects["projects"][0]["project_path"], project)
        query = urllib.parse.urlencode({"project_path": project, "status": "fixed"})
        status, fixed = self.call(f"/api/finding-tracking?{query}")
        self.assertTrue(any(item["reference"] == "CWE-78" for item in fixed["findings"]))
        tracked_id = fixed["findings"][0]["id"]
        status, detail = self.call(f"/api/finding-tracking/{tracked_id}")
        self.assertEqual([event["event"] for event in detail["events"]][-1], "fixed")
        self.assertEqual(self.call(f"/api/finding-tracking?{urllib.parse.urlencode({'project_path': project, 'status': 'x'})}")[0], 400)
        self.assertEqual(self.call("/api/finding-tracking")[0], 400)

        status, summary = self.call(f"/api/finding-tracking/summary?{urllib.parse.urlencode({'project_path': project})}")
        self.assertEqual(len(summary["trend"]), 3)

        status, active = self.call(f"/api/finding-tracking?{urllib.parse.urlencode({'project_path': project, 'status': 'open'})}")
        if active["findings"]:
            target = active["findings"][0]["id"]
            self.assertEqual(self.call(f"/api/finding-tracking/{target}/status", {"status": "risk_accepted"})[0], 400)
            status, changed = self.call(f"/api/finding-tracking/{target}/status",
                                        {"confirm": True, "status": "risk_accepted", "note": "iç ağ"})
            self.assertEqual((status, changed["status"]), (200, "risk_accepted"))
        self.assertEqual(self.call(f"/api/finding-tracking/{tracked_id}/status", {"confirm": True, "status": "open"})[0], 400)
        self.assertEqual(self.call("/api/finding-tracking/trk_yok/status", {"confirm": True, "status": "open"})[0], 404)
        self.assertEqual(self.call("/api/finding-tracking/backfill", {"confirm": True})[1]["processed_audits"], 0)

        status, executive = self.call(f"/api/project-audits/{third['id']}/executive-summary")
        self.assertEqual(executive["format"], "sniper-project-executive-summary-v1")
        status, page = self.call(f"/api/project-audits/{third['id']}/executive-summary.html", raw=True)
        self.assertIn("Yönetici özeti", page)
        status, report = self.call(f"/api/project-audits/{third['id']}/report.html", raw=True)
        self.assertIn("Yönetici özeti", report)


import urllib.parse  # noqa: E402

if __name__ == "__main__":
    unittest.main()
