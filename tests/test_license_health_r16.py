"""16. tur: bağımlılık lisans uyumu (çevrimdışı) ve Sniper öz sağlık panosu (salt okunur)."""
from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path
import stat
import tempfile
import threading
import unittest
from unittest import mock
import urllib.error
import urllib.request

from http.server import ThreadingHTTPServer

import auth
import dependency_security
import license_compliance as lc
import notifications
import project_analyzer
import project_executive_summary
import scan_scope
import scheduler as sch
import system_health as sh

UTC = dt.timezone.utc


class _Env:
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.data = self.base / "data"
        self.data.mkdir()
        patch = mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(self.data)})
        patch.start()
        self.addCleanup(patch.stop)


class NormalizeAndClassifyTests(unittest.TestCase):
    def test_spdx_normalization(self):
        cases = {
            "MIT": "MIT", "(MIT OR Apache-2.0)": "MIT OR Apache-2.0", "GPL-2.0+": "GPL-2.0-or-later",
            "Apache License, Version 2.0": "Apache-2.0", "MIT/Apache-2.0": "MIT OR Apache-2.0",
            "GNU General Public License v3 (GPLv3)": "GPL-3.0-only", "AGPL-3.0": "AGPL-3.0-only",
            "lgpl-2.1": "LGPL-2.1-only", "BSD": "BSD-3-Clause", "Apache-2.0 WITH LLVM-exception": "Apache-2.0 WITH LLVM-exception",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(lc.normalize(raw)["expression"], expected)
        self.assertEqual(lc.normalize(["MIT", "GPL-3.0"])["expression"], "MIT OR GPL-3.0-only")  # composer: seçmeli
        self.assertEqual(lc.normalize({"type": "ISC"})["expression"], "ISC")  # eski npm biçimi
        for unknown in ("UNLICENSED", "SEE LICENSE IN LICENSE.md", "garip lisans", "", None):
            with self.subTest(unknown=unknown):
                self.assertIsNone(lc.normalize(unknown)["expression"])

    def test_classification_or_and_with(self):
        policy = lc.DEFAULT_POLICY
        self.assertEqual(lc.classify("MIT", policy), "allowed")
        self.assertEqual(lc.classify("GPL-3.0-only", policy), "caution")
        self.assertEqual(lc.classify("MIT OR GPL-3.0-only", policy), "allowed")      # en uygun seçenek
        self.assertEqual(lc.classify("MIT AND GPL-3.0-only", policy), "caution")     # en kısıtlayıcı
        self.assertEqual(lc.classify("LGPL-2.1-only", policy), "allowed")            # zayıf copyleft varsayılan izinli
        self.assertEqual(lc.classify("SSPL-1.0", policy), "caution")
        self.assertEqual(lc.classify("GPL-2.0-only WITH Classpath-exception-2.0", policy), "allowed")
        self.assertEqual(lc.classify("GPL-3.0-only WITH GCC-exception-3.1", policy), "caution")
        self.assertEqual(lc.classify(None, policy), "review")
        custom = lc.validate_policy({"denied": ["AGPL-*"], "caution": ["GPL-*"], "allowed": ["MIT"]})
        self.assertEqual(lc.classify("AGPL-3.0-or-later", custom), "denied")
        self.assertEqual(lc.classify("Apache-2.0", custom), "review")  # hiçbir listede değil

    def test_license_text_heuristic(self):
        self.assertEqual(lc.detect_license_text("Permission is hereby granted, free of charge, to any person"), "MIT")
        self.assertEqual(lc.detect_license_text("GNU AFFERO GENERAL PUBLIC LICENSE\n Version 3, 19 November 2007"),
                         "AGPL-3.0-only")
        self.assertEqual(lc.detect_license_text("GNU LESSER GENERAL PUBLIC LICENSE Version 2.1 ... GNU General Public "
                                                "License"), "LGPL-2.1-only")
        self.assertIsNone(lc.detect_license_text("Tüm hakları saklıdır."))


class PolicyStorageTests(_Env, unittest.TestCase):
    def test_policy_persisted_private_and_validated(self):
        policy, customized = lc.load_policy()
        self.assertFalse(customized)
        self.assertIn("GPL-*", policy["caution"])
        saved = lc.save_policy({"denied": ["AGPL-*", "SSPL-1.0"], "caution": ["GPL-*"], "allowed": ["MIT", "Apache-2.0"]})
        loaded, customized = lc.load_policy()
        self.assertTrue(customized)
        self.assertEqual(loaded, saved)
        self.assertEqual(stat.S_IMODE((self.data / lc.POLICY_FILE).stat().st_mode), 0o600)
        for bad in ({"denied": "GPL"}, {"denied": ["<script>"]}, {"other": []}, [], {"allowed": ["x"] * 201}):
            with self.subTest(bad=bad), self.assertRaises(lc.LicensePolicyError):
                lc.save_policy(bad)
        self.assertFalse(lc.load_policy()[0] == lc.DEFAULT_POLICY)
        lc.reset_policy()
        self.assertEqual(lc.load_policy()[0]["caution"], lc.DEFAULT_POLICY["caution"])
        (self.data / lc.POLICY_FILE).write_text("{bozuk")
        self.assertEqual(lc.load_policy(), (json.loads(json.dumps(lc.DEFAULT_POLICY)), False))


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


class ProjectLicenseTests(_Env, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.root = self.base / "proj"
        root = self.root
        _write(root / "index.js", "console.log(1)\n")
        _write(root / "package.json", json.dumps({"name": "p", "license": "MIT"}))
        _write(root / "package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {
            "": {"name": "p"},
            "node_modules/gpl-lib": {"version": "1.0.0", "license": "GPL-3.0"},
            "node_modules/dev-agpl": {"version": "2.0.0", "license": "AGPL-3.0-only", "dev": True},
            "node_modules/left-pad": {"version": "1.3.0"},
            "node_modules/mystery": {"version": "0.1.0"},
        }}))
        _write(root / "node_modules/left-pad/package.json", json.dumps({"name": "left-pad", "version": "1.3.0", "license": "WTFPL"}))
        _write(root / "composer.lock", json.dumps({"packages": [{"name": "acme/sspl", "version": "1.0", "license": ["SSPL-1.0"]}],
                                                  "packages-dev": [{"name": "acme/tool", "version": "2.0", "license": ["MIT"]}]}))
        meta = root / ".venv/lib/python3.12/site-packages/requests-2.32.0.dist-info/METADATA"
        _write(meta, "Metadata-Version: 2.1\nName: requests\nVersion: 2.32.0\nClassifier: License :: OSI Approved :: "
                     "Apache Software License\n\nbody")
        _write(root / "vendor/modules.txt", "# github.com/x/y v1.2.3\n## explicit\ngithub.com/x/y\n")
        _write(root / "vendor/github.com/x/y/LICENSE", "GNU GENERAL PUBLIC LICENSE\nVersion 2, June 1991\n")
        _write(root / "vendor/serde/Cargo.toml", '[package]\nname = "serde"\nversion = "1.0.0"\nlicense = "MIT OR Apache-2.0"\n')
        _write(root / "vendor/bundle/ruby/3.2.0/specifications/rack-3.0.0.gemspec", 's.licenses = ["MIT"]\n')
        outside = self.base / "outside"
        _write(outside / "package.json", json.dumps({"name": "evil", "version": "9.9.9", "license": "AGPL-3.0-only"}))
        (root / "node_modules" / "evil").symlink_to(outside, target_is_directory=True)

    def analyze(self, scope=None):
        return project_analyzer.analyze_project(str(self.root), allowed_roots=(self.base,), scope=scope)

    def test_report_findings_and_check(self):
        result = self.analyze()
        report = result["licenses"]
        self.assertEqual(report["format"], lc.FORMAT)
        self.assertEqual(report["project_license"]["expression"], "MIT")
        names = {(i["ecosystem"], i["name"]): i for i in report["items"]}
        self.assertEqual(names[("npm", "gpl-lib")]["category"], "caution")
        self.assertTrue(names[("npm", "dev-agpl")]["dev"])
        self.assertEqual(names[("Packagist", "acme/sspl")]["expression"], "SSPL-1.0")
        self.assertEqual(names[("Golang", "github.com/x/y")]["expression"], "GPL-2.0-only")
        self.assertTrue(names[("Golang", "github.com/x/y")]["heuristic"])
        self.assertNotIn(("npm", "evil"), names, "kök dışına giden sembolik bağ okunmamalı")
        by_license = {e["license"]: e for e in report["by_license"]}
        for allowed in ("WTFPL", "Apache-2.0", "MIT OR Apache-2.0", "MIT"):
            self.assertEqual(by_license[allowed]["category"], "allowed")
        self.assertGreaterEqual(report["by_category"]["review"], 1)  # mystery: lisans yok → inceleme
        titles = sorted(f["title"] for f in result["findings"] if f["category"] == "license")
        self.assertEqual(titles, [
            "Bağımlılık lisansı dikkat gerektiriyor: GPL-2.0-only",
            "Bağımlılık lisansı dikkat gerektiriyor: GPL-3.0-only",
            "Bağımlılık lisansı dikkat gerektiriyor: SSPL-1.0",
        ])  # geliştirme bağımlılığındaki AGPL dikkat düzeyinde bulgu üretmez
        self.assertTrue(all(f["severity"] == "low" for f in result["findings"] if f["category"] == "license"))
        check = next(c for c in result["checks"] if c["id"] == "licenses")
        self.assertEqual(check["status"], "review")

    def test_denied_policy_raises_severity_and_partial_scan_skips(self):
        lc.save_policy({"denied": ["SSPL-*", "AGPL-*"], "caution": [], "allowed": ["MIT", "Apache-2.0", "WTFPL"]})
        result = self.analyze()
        license_findings = {f["title"]: f for f in result["findings"] if f["category"] == "license"}
        self.assertEqual(license_findings["Bağımlılık lisansı politika gereği yasak: SSPL-1.0"]["severity"], "high")
        self.assertEqual(license_findings["Bağımlılık lisansı politika gereği yasak: AGPL-3.0-only"]["severity"], "low")  # dev
        self.assertIn("geliştirme", license_findings["Bağımlılık lisansı politika gereği yasak: AGPL-3.0-only"]["evidence"])
        _write(self.root / "tests" / "test_x.py", "x = 1\n")
        partial = self.analyze(scan_scope.parse_scope({"preset": "skipped"}))
        self.assertIsNone(partial["licenses"])

    def test_cyclonedx_licenses_and_executive_summary(self):
        sbom = dependency_security.generate_cyclonedx_sbom(str(self.root), allowed_roots=(self.base,))
        by_name = {c["name"]: c for c in sbom["components"]}
        self.assertEqual(by_name["gpl-lib"]["licenses"], [{"license": {"id": "GPL-3.0-only"}}])
        self.assertEqual(by_name["left-pad"]["licenses"], [{"license": {"id": "WTFPL"}}])
        self.assertNotIn("licenses", by_name["mystery"])
        self.assertEqual(lc.cyclonedx_licenses({"expression": "MIT OR Apache-2.0"}), [{"expression": "MIT OR Apache-2.0"}])
        self.assertEqual(lc.cyclonedx_licenses({"expression": None, "raw": "Özel lisans"}), [{"license": {"name": "Özel lisans"}}])

        audit = self.analyze()
        summary = lc.executive_summary(audit["licenses"])
        self.assertEqual(summary["project_license"], "MIT")
        self.assertEqual({item["name"] for item in summary["top"]}, {"gpl-lib", "acme/sspl", "github.com/x/y"})
        page = {"risk_label": "Orta", "score": 80, "grade": "B", "active_findings": 0, "active_by_severity": {},
                "this_audit": {}, "suppressed_findings": 0, "fixed_total": 0, "verified_flow_findings": 0,
                "pattern_findings": 0, "measurement_note": "", "licenses": summary}
        html = project_executive_summary.render_section_html(page)
        self.assertIn("Bağımlılık lisansları", html)
        self.assertIn("gpl-lib@1.0.0", html)

    def test_no_dependencies_means_no_report(self):
        empty = self.base / "empty"
        _write(empty / "app.py", "print(1)\n")
        result = project_analyzer.analyze_project(str(empty), allowed_roots=(self.base,))
        self.assertIsNone(result["licenses"])
        self.assertEqual(next(c for c in result["checks"] if c["id"] == "licenses")["status"], "na")


class _FakeStore:
    def __init__(self, verified=True):
        self.verified = verified

    def verify_audit_chain(self):
        return {"verified": self.verified, "event_count": 3, "integrity": "hmac_anchored",
                "first_broken_id": None if self.verified else 2, "integrity_problems": [] if self.verified else ["x"]}


class SystemHealthTests(_Env, unittest.TestCase):
    def setUp(self):
        super().setUp()
        sh._CACHE.clear()
        self.home = self.base / "home"
        (self.home / ".config" / "sniper").mkdir(parents=True)
        import sqlite3
        sqlite3.connect(self.data / "sniper.db").close()
        patch = mock.patch.dict(os.environ, {"SNIPER_OSV_DB_ROOT": str(self.base / "osv")})
        patch.start()
        self.addCleanup(patch.stop)

    def report(self, **kwargs):
        defaults = dict(data_dir=self.data, app_root=None, store=_FakeStore(), jobs=[],
                        job_stats={"queued": 0, "running": 0, "workers": 2}, home=self.home,
                        pin_states=lambda: [{"tool": "k6", "state": "pinned"}])
        defaults.update(kwargs)
        return sh.build_report(**defaults)

    def by_id(self, report):
        return {c["id"]: c for c in report["checks"]}

    def test_report_statuses_and_read_only(self):
        before = sorted(p.name for p in self.data.iterdir() if not p.name.endswith(".lock"))
        report = self.report()
        checks = self.by_id(report)
        self.assertEqual(report["format"], sh.FORMAT)
        self.assertTrue(report["read_only"])
        self.assertEqual(checks["database"]["status"], "ok")
        self.assertEqual(checks["db_backup"]["status"], "warn")       # yedek yok
        self.assertEqual(checks["osv_db"]["status"], "warn")          # OSV veritabanı yok
        self.assertEqual(checks["auth"]["status"], "warn")            # giriş kapalı
        self.assertEqual(checks["tool_pins"]["status"], "ok")
        self.assertEqual(checks["schedules"]["status"], "info")
        self.assertNotIn("initial_password", checks)
        self.assertEqual(report["overall"], "warn")
        after = sorted(p.name for p in self.data.iterdir() if not p.name.endswith(".lock"))  # kilit dosyaları hariç
        self.assertEqual(after, before, "rapor veri dizinine yazmamalı")

    def test_problem_detection(self):
        (self.home / sh.INITIAL_PASSWORD_FILE).write_text("x")
        backup = self.data / "sniper.db.bak-20200101"
        backup.write_text("x")
        old = dt.datetime(2020, 1, 1, tzinfo=UTC).timestamp()
        os.utime(backup, (old, old))
        manager = auth.AuthManager(self.data)
        manager.create_admin_and_enable("yonetici", "Uzun-ve-guclu-parola-42")
        report = self.report(store=_FakeStore(verified=False), pin_states=lambda: [{"tool": "node", "state": "mismatch"}],
                             jobs=[{"state": "queued", "created_at": "2020-01-01T00:00:00Z"}],
                             job_stats={"queued": 1, "running": 2, "workers": 2})
        checks = self.by_id(report)
        self.assertEqual(checks["initial_password"]["status"], "warn")
        self.assertEqual(checks["db_backup"]["status"], "fail")
        self.assertEqual(checks["auth"]["status"], "warn")            # yöneticide TOTP yok
        self.assertIn("yonetici", checks["auth"]["detail"])
        self.assertEqual(checks["audit_chain"]["status"], "fail")
        self.assertEqual(checks["tool_pins"]["status"], "fail")
        self.assertEqual(checks["job_queue"]["status"], "warn")       # 2020'den beri bekleyen iş
        self.assertEqual(report["overall"], "fail")
        self.assertTrue(backup.exists() and (self.home / sh.INITIAL_PASSWORD_FILE).exists(), "hiçbir şey silinmez")

    def test_schedule_failures_reported(self):
        sch_data = {"format": 1, "timezone": "Europe/Istanbul", "schedules": [
            {"id": "sch_000000000001", "name": "gece", "enabled": True, "last_status": "failed"},
            {"id": "sch_000000000002", "name": "öğle", "enabled": True, "last_status": "succeeded"}]}
        (self.data / sch.FILE_NAME).write_text(json.dumps(sch_data))
        check = self.by_id(self.report())["schedules"]
        self.assertEqual(check["status"], "warn")
        self.assertIn("gece: failed", check["detail"])

    def test_notifications_dedupe_and_daily_interval(self):
        report = self.report()
        t0 = dt.datetime(2026, 10, 20, 9, 0, tzinfo=UTC)
        first = sh.notify_if_needed(report, now=t0)
        self.assertIsNotNone(first)
        self.assertEqual(first["event"], "system_health")
        self.assertIsNone(sh.notify_if_needed(report, now=t0 + dt.timedelta(hours=1)))   # aynı sorunlar: tekrar yok
        again = sh.notify_if_needed(report, now=t0 + dt.timedelta(hours=25))             # 24 saattir sürüyor: hatırlat
        self.assertIsNotNone(again)
        (self.home / sh.INITIAL_PASSWORD_FILE).write_text("x")
        newer = sh.notify_if_needed(self.report(), now=t0 + dt.timedelta(hours=26))       # yeni sorun: hemen
        self.assertIsNotNone(newer)
        self.assertEqual(notifications.list_items()["total"], 3)

        calls = []
        build = lambda: calls.append(1) or report  # noqa: E731
        self.assertIsNone(sh.daily_check(build, now=t0 + dt.timedelta(hours=27)))         # son denetimden 24 sa geçmedi
        self.assertIsNotNone(sh.daily_check(build, now=t0 + dt.timedelta(hours=51)))
        self.assertEqual(len(calls), 1)

    def test_notification_event_can_be_disabled(self):
        settings = notifications.validate_settings({"events": {"system_health": {"enabled": False}}})
        notifications.save_settings(settings)
        self.assertIsNone(sh.notify_if_needed(self.report(), now=dt.datetime(2026, 10, 20, tzinfo=UTC)))
        self.assertTrue(notifications.default_settings()["events"]["system_health"]["enabled"])

    def test_scheduler_runs_maintenance_hook(self):
        calls = []
        scheduler = sch.Scheduler(submit=lambda plan: "job", job_state=lambda job: None,
                                  maintenance=lambda: calls.append(1) or scheduler.stop())
        scheduler.loop(interval=0.01)
        self.assertEqual(calls, [1])
        broken = sch.Scheduler(submit=lambda plan: "job", job_state=lambda job: None,
                               maintenance=lambda: (_ for _ in ()).throw(RuntimeError("x")))
        threading.Timer(0.05, broken.stop).start()
        with mock.patch("traceback.print_exc") as printed:
            broken.loop(interval=0.01)  # bakım hatası döngüyü düşürmez
        self.assertTrue(printed.called)


class ApiAndRoleTests(_Env, unittest.TestCase):
    def setUp(self):
        super().setUp()
        import server
        from storage import Store

        self.server = server
        self.previous_store = server.STORE
        server.STORE = Store(self.data / "sniper-test.db")
        patches = [mock.patch.object(server, "DATA_DIR", self.data),
                   mock.patch.dict(os.environ, {"SNIPER_OSV_DB_ROOT": str(self.base / "osv")}),
                   mock.patch.object(sh, "_pin_states", lambda: [{"tool": "k6", "state": "pinned"}])]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.server.STORE = self.previous_store

    def call(self, path, body=None):
        request = urllib.request.Request(self.url + path, method="POST" if body is not None else "GET",
                                         data=json.dumps(body).encode() if body is not None else None,
                                         headers={"Content-Type": "application/json"} if body is not None else {})
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    def test_license_policy_api(self):
        status, data = self.call("/api/license-policy")
        self.assertEqual(status, 200)
        self.assertFalse(data["customized"])
        self.assertEqual(data["categories"]["denied"], "Yasak")
        self.assertEqual(self.call("/api/license-policy", {"policy": {"denied": ["GPL-*"]}})[0], 400)  # onaysız
        self.assertEqual(self.call("/api/license-policy", {"confirm": True})[0], 400)
        self.assertEqual(self.call("/api/license-policy", {"confirm": True, "policy": {"denied": ["<x>"]}})[0], 400)
        status, data = self.call("/api/license-policy", {"confirm": True, "policy": {"denied": ["GPL-*"], "caution": [], "allowed": ["MIT"]}})
        self.assertEqual(status, 200, data)
        self.assertTrue(data["customized"])
        self.assertEqual(data["policy"]["denied"], ["GPL-*"])
        status, data = self.call("/api/license-policy", {"confirm": True, "reset": True})
        self.assertEqual(data["policy"]["caution"], lc.DEFAULT_POLICY["caution"])
        events = [e["action"] for e in self.server.STORE.recent_audit_log()]
        self.assertEqual(events.count("license_policy.changed"), 2)

    def test_health_report_api(self):
        status, data = self.call("/api/system/health-report")
        self.assertEqual(status, 200, data)
        self.assertEqual(data["format"], sh.FORMAT)
        ids = {c["id"] for c in data["checks"]}
        self.assertTrue({"disk_free", "database", "db_backup", "osv_db", "job_queue", "audit_chain", "tool_pins",
                         "version", "auth"} <= ids)
        self.assertEqual(self.call("/api/system/health-report?refresh=1")[0], 200)

    def test_roles(self):
        self.assertEqual(auth.required_level("GET", "/api/system/health-report"), "analyst")
        self.assertEqual(auth.required_level("GET", "/api/license-policy"), "read")
        self.assertEqual(auth.required_level("POST", "/api/license-policy"), "admin")
        self.assertFalse(auth.role_allows("reader", auth.required_level("GET", "/api/system/health-report")))
        self.assertTrue(auth.role_allows("analyst", auth.required_level("GET", "/api/system/health-report")))


if __name__ == "__main__":
    unittest.main()
