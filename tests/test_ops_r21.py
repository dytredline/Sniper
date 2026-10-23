"""21. tur işletim: yeni bildirim olayları (yinelenme korumalı), zamanlanmış SCA/konteyner/SBOM planları,
OSV tazeliği / zamanlayıcı / önbellek sağlık denetimleri ve saklama politikasının önbellek kategorisi."""
from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import data_retention  # noqa: E402
import notifications  # noqa: E402
import scheduler  # noqa: E402
import system_health  # noqa: E402

NOW = dt.datetime(2026, 10, 21, 12, 0, tzinfo=dt.timezone.utc)


class _DataDirCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.env = {"SNIPER_DATA_DIR": self.tmp.name}

    def items(self):
        return notifications.list_items(environ=self.env)["items"]


class AuditCategoryEventTests(_DataDirCase):
    def audit(self, findings, kind="project"):
        return {"id": "prj_1", "project_path": "/p/demo", "project_name": "demo", "audit_kind": kind, "findings": findings}

    def test_malicious_once_and_suppressed_skipped(self):
        mal = {"category": "supply_chain", "severity": "critical", "file": "package-lock.json", "cwe": "CWE-506",
               "title": "Kötü amaçlı paket: evil 1.0.0 (MAL-2025-1)"}
        hidden = {**mal, "title": "Kötü amaçlı paket: other 2.0.0 (MAL-2025-2)",
                  "triage": {"disposition": "false_positive"}}
        out = notifications.on_audit_categories(self.audit([mal, hidden]), environ=self.env, now=NOW)
        self.assertEqual([i["event"] for i in out], ["malicious_package"])
        self.assertEqual(out[0]["severity"], "critical")
        self.assertEqual(out[0]["data"]["count"], 1)
        # Aynı bulgu ikinci analizde yeniden bildirilmez.
        self.assertEqual(notifications.on_audit_categories(self.audit([mal]), environ=self.env, now=NOW), [])

    def test_container_critical_and_license_forbidden(self):
        findings = [
            {"category": "container_os", "severity": "critical", "file": "var/lib/dpkg/status",
             "title": "Açıklı işletim sistemi paketi: glibc (CVE-2023-4911)"},
            {"category": "container_os", "severity": "high", "file": "var/lib/dpkg/status", "title": "yüksek"},
            {"category": "license", "severity": "high", "file": "package.json",
             "title": "Bağımlılık lisansı politika gereği yasak: AGPL-3.0-only"},
            {"category": "license", "severity": "low", "file": "package.json",
             "title": "Bağımlılık lisansı dikkat gerektiriyor: GPL-3.0"},
        ]
        out = notifications.on_audit_categories(self.audit(findings, "container"), environ=self.env, now=NOW)
        self.assertEqual(sorted(i["event"] for i in out), ["container_critical", "license_forbidden"])
        crit = next(i for i in out if i["event"] == "container_critical")
        self.assertEqual(crit["data"]["count"], 1)

    def test_disabled_event_emits_nothing(self):
        settings = notifications.default_settings()
        settings["events"]["container_critical"]["enabled"] = False
        notifications.save_settings(settings, environ=self.env)
        finding = {"category": "container_os", "severity": "critical", "file": "x", "title": "kritik"}
        self.assertEqual(notifications.on_audit_categories(self.audit([finding]), environ=self.env, now=NOW), [])

    def test_hook_from_project_audit_created(self):
        mal = {"category": "supply_chain", "severity": "critical", "file": "requirements.txt",
               "title": "Kötü amaçlı paket: pyg-utils 0.1 (MAL-2024-9)"}
        store = mock.Mock()
        with mock.patch.object(notifications, "project_audit_changes",
                               return_value={"baseline_id": None, "new": [], "fixed": [], "first_audit": True}):
            out = notifications.on_project_audit_created(store, self.audit([mal]), environ=self.env, now=NOW)
        self.assertIn("malicious_package", [i["event"] for i in out])


class DependencyScanEventTests(_DataDirCase):
    def test_malicious_and_fix_first_dedupe(self):
        findings = [{"package_name": "evil", "installed_version": "1.0.0", "vulnerability_id": "MAL-2025-7"},
                    {"package_name": "lodash", "installed_version": "4.17.4", "vulnerability_id": "GHSA-x"}]
        priority = {"order": [
            {"package_name": "lodash", "installed_version": "4.17.4", "vulnerability_id": "GHSA-x", "score": 70,
             "tier": "fix_first", "fixed_version": "4.17.21"},
            {"package_name": "debug", "installed_version": "2.0.0", "vulnerability_id": "GHSA-y", "score": 10,
             "tier": "monitor"},
        ]}
        out = notifications.on_dependency_scan("/p/app", findings, priority, environ=self.env, now=NOW)
        self.assertEqual([i["event"] for i in out], ["malicious_package", "sca_fix_first"])
        self.assertIn("4.17.21", out[1]["details"][0])
        self.assertEqual(notifications.on_dependency_scan("/p/app", findings, priority, environ=self.env, now=NOW), [])

    def test_malicious_bypasses_quiet_hours(self):
        settings = notifications.default_settings()
        settings["quiet_hours"] = {"enabled": True, "start": "00:00", "end": "23:59", "allow_critical": False}
        settings["channels"]["desktop"]["enabled"] = True
        notifications.save_settings(settings, environ=self.env)
        with mock.patch.object(notifications, "_send_desktop", return_value="sent"):
            out = notifications.on_dependency_scan(
                "/p/app", [{"package_name": "evil", "installed_version": "1", "vulnerability_id": "MAL-1"}], None,
                environ=self.env, now=NOW)
            normal = notifications.emit("scan_failed", "critical", "t", "m", environ=self.env, now=NOW)
        self.assertEqual(out[0]["channels"]["desktop"], "sent")
        self.assertEqual(normal["channels"]["desktop"], "quiet_hours")

    def test_dedupe_store_is_bounded(self):
        with mock.patch.object(notifications, "MAX_DEDUPE_PER_EVENT", 3):
            notifications._first_seen("sca_fix_first", ["a", "b", "c", "d"], now=NOW, environ=self.env)
        data = json.loads((Path(self.tmp.name) / notifications.DEDUPE_FILE).read_text())
        self.assertEqual(len(data["events"]["sca_fix_first"]), 3)


class OsvStaleTests(_DataDirCase):
    def test_once_per_day(self):
        status = [{"ecosystem": "npm", "status": "present", "age_hours": 24 * 9},
                  {"ecosystem": "PyPI", "status": "present", "age_hours": 3},
                  {"ecosystem": "Go", "status": "missing"}]
        item = notifications.check_osv_stale(now=NOW, environ=self.env, status_fn=lambda: status)
        self.assertIsNotNone(item)
        self.assertEqual(item["data"]["ecosystems"], ["npm"])
        self.assertIsNone(notifications.check_osv_stale(now=NOW, environ=self.env, status_fn=lambda: status))
        tomorrow = NOW + dt.timedelta(days=1)
        self.assertIsNotNone(notifications.check_osv_stale(now=tomorrow, environ=self.env, status_fn=lambda: status))

    def test_fresh_dbs_no_notice(self):
        status = [{"ecosystem": "npm", "status": "present", "age_hours": 2}]
        self.assertIsNone(notifications.check_osv_stale(now=NOW, environ=self.env, status_fn=lambda: status))


class SchedulerTargetTests(unittest.TestCase):
    def test_new_types_and_payloads(self):
        keys = {t["key"]: t for t in scheduler.available_scan_types()}
        for key in ("dependency_offline", "container_image", "sbom_file"):
            self.assertIn(key, keys)
        self.assertEqual(keys["container_image"]["target_kind"], "image")
        self.assertIn("SBOM", keys["sbom_file"]["target_label"])
        self.assertEqual(scheduler.job_request({"scan_type": "dependency_offline", "project_path": "/p"}),
                         ("/api/dependency-security/offline-scan", {"project_path": "/p", "confirm_local": True}))
        self.assertEqual(scheduler.job_request({"scan_type": "container_image", "project_path": "/i.tar"}),
                         ("/api/container-images", {"image_path": "/i.tar"}))
        self.assertEqual(scheduler.job_request({"scan_type": "sbom_file", "project_path": "/s.json"}),
                         ("/api/dependency-security/sbom-scan", {"sbom_path": "/s.json", "confirm": True}))
        for route in ("/api/dependency-security/offline-scan", "/api/container-images",
                      "/api/dependency-security/sbom-scan"):
            self.assertIn(route, scheduler.SCAN_ROUTES)

    def test_path_validated_by_target_kind(self):
        calls = []

        def validate(path, kind="project"):
            calls.append(kind)
            if kind == "image" and not path.endswith(".tar"):
                raise scheduler.ScheduleError("imaj değil")
            return path

        with tempfile.TemporaryDirectory() as tmp:
            env = {"SNIPER_DATA_DIR": tmp}
            created = scheduler.apply_action("create", {"schedule": {
                "name": "imaj", "scan_type": "container_image", "project_path": "/i/app.tar", "frequency": "günlük 03:00"}},
                validate_path=validate, now=NOW, environ=env)
            self.assertEqual(created["schedule"]["project_path"], "/i/app.tar")
            self.assertEqual(calls, ["image"])
            sid = created["schedule"]["id"]
            with self.assertRaises(scheduler.ScheduleError):  # tür değişince yol yeniden doğrulanır
                scheduler.apply_action("update", {"id": sid, "schedule": {"scan_type": "sbom_file"}},
                                       validate_path=lambda p, kind="project": (_ for _ in ()).throw(
                                           scheduler.ScheduleError("sbom değil")), now=NOW, environ=env)
            # Eski tek argümanlı proje doğrulayıcısı proje türlerinde çalışmaya devam eder.
            scheduler.apply_action("create", {"schedule": {
                "name": "proje", "scan_type": "dependency_offline", "project_path": "/p", "frequency": "günlük 04:00"}},
                validate_path=lambda p: p, now=NOW, environ=env)


class HealthChecksTests(unittest.TestCase):
    def test_sniper_service_autostart_states(self):
        enabled = lambda unit, props: {"LoadState": "loaded", "ActiveState": "active",  # noqa: E731
                                       "SubState": "running", "UnitFileState": "enabled"}
        disabled = lambda unit, props: {"LoadState": "loaded", "ActiveState": "active",  # noqa: E731
                                        "SubState": "running", "UnitFileState": "disabled"}
        stopped = lambda unit, props: {"LoadState": "loaded", "ActiveState": "inactive",  # noqa: E731
                                       "SubState": "dead", "UnitFileState": "enabled"}
        self.assertEqual(system_health.check_service_autostart(show=enabled, refresh=True)[0]["status"], "ok")
        disabled_check = system_health.check_service_autostart(show=disabled, refresh=True)[0]
        self.assertEqual(disabled_check["status"], "warn")
        self.assertIn("enable", disabled_check["recommendation"])
        self.assertEqual(system_health.check_service_autostart(show=stopped, refresh=True)[0]["status"], "fail")
        self.assertEqual(system_health.check_service_autostart(show=lambda unit, props: None, refresh=True)[0]["status"],
                         "unknown")

    def test_osv_timer_states(self):
        def show_ok(unit, props):
            if unit.endswith(".timer"):
                return {"ActiveState": "active", "LastTriggerUSec": "Tue 2026-10-20", "NextElapseUSecRealtime": "Thu"}
            return {"Result": "success", "ExecMainStatus": "0"}

        def show_fail(unit, props):
            if unit.endswith(".timer"):
                return {"ActiveState": "active"}
            return {"Result": "exit-code", "ExecMainStatus": "1"}

        self.assertEqual(system_health.check_osv_timer(NOW, show=show_ok, refresh=True)[0]["status"], "ok")
        self.assertEqual(system_health.check_osv_timer(NOW, show=show_fail, refresh=True)[0]["status"], "fail")
        inactive = lambda unit, props: {"ActiveState": "inactive"} if unit.endswith(".timer") else {"Result": "success"}
        self.assertEqual(system_health.check_osv_timer(NOW, show=inactive, refresh=True)[0]["status"], "warn")
        with tempfile.TemporaryDirectory() as tmp:  # systemd yok, manifest yok
            check = system_health.check_osv_timer(NOW, Path(tmp), show=lambda u, p: None, refresh=True)[0]
            self.assertEqual(check["status"], "unknown")

    def test_freshness_and_malware_cache(self):
        items = [{"ecosystem": "npm", "state": "ok", "age_hours": 2.0, "sha256": "a" * 64},
                 {"ecosystem": "PyPI", "state": "stale", "age_hours": 24 * 9.0, "sha256": "b" * 64}]
        with mock.patch.object(system_health, "osv_freshness_items", return_value=items):
            check = system_health.check_osv_freshness(NOW, Path("/yok"), refresh=True)[0]
            self.assertEqual(check["status"], "warn")
            self.assertEqual([i["ecosystem"] for i in check["items"]], ["npm", "PyPI"])
            with tempfile.TemporaryDirectory() as tmp:
                cache = Path(tmp) / "cache"
                cache.mkdir()
                (cache / f"osv-malware-{'a' * 32}.json").write_text("{}")
                (cache / f"osv-malware-{'c' * 32}.json").write_text("{}")
                info = system_health.check_malware_cache(Path(tmp), NOW, Path("/yok"))[0]
                self.assertIn("1 güncel, 1 eski", info["value"])

    def test_license_caches_disabled_in_tests(self):
        self.assertEqual(system_health.check_license_caches()[0]["value"], "kapalı")


class RetentionCacheTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.data = base / "data"
        self.osv = base / "osv"
        self.xdg = base / "xdg"
        for path in (self.data / "cache", self.data / "sandbox-runs", self.osv / "index-cache",
                     self.xdg / "sniper-lsp"):
            path.mkdir(parents=True)
        self.env = {"SNIPER_DATA_DIR": str(self.data), "SNIPER_OSV_DB_ROOT": str(self.osv),
                    "XDG_CACHE_HOME": str(self.xdg)}
        old = time.time() - 60 * 86400
        self.files = {
            "malware_stale": self.data / "cache" / f"osv-malware-{'d' * 32}.json",
            "malware_current": self.data / "cache" / f"osv-malware-{'e' * 32}.json",
            "index_stale": self.osv / "index-cache" / f"debian-12-{'d' * 16}.json.gz",
            "lsp_old": self.xdg / "sniper-lsp" / "x.json",
        }
        for path in self.files.values():
            path.write_text("{}")
            os.utime(path, (old, old))
        self.pdf = self.data / "sandbox-runs" / "pdf-abc123"
        (self.pdf / "job").mkdir(parents=True)
        (self.pdf / "job" / "report.html").write_text("<p>x</p>")
        os.utime(self.pdf, (old, old))

    def policy(self, enabled=True):
        policy = data_retention.validate_policy({"enabled": True, "caches": {"enabled": enabled, "older_than_days": 30}})
        return policy

    def test_default_disabled_and_validation(self):
        self.assertFalse(data_retention.DEFAULT_POLICY["caches"]["enabled"])
        with self.assertRaises(data_retention.RetentionError):
            data_retention.validate_policy({"caches": {"older_than_days": 0}})
        with mock.patch.object(data_retention, "_current_osv_shas", return_value={"e" * 64}):
            plan = data_retention.build_plan(self.data, policy=self.policy(False), environ=self.env)
        self.assertEqual(plan["categories"]["caches"], [])

    def test_plan_and_execute(self):
        with mock.patch.object(data_retention, "_current_osv_shas", return_value={"e" * 64}):
            plan = data_retention.build_plan(self.data, policy=self.policy(), environ=self.env)
            names = {item["name"] for item in plan["categories"]["caches"]}
            self.assertEqual(names, {f"data:cache/{self.files['malware_stale'].name}",
                                     f"osv:index-cache/{self.files['index_stale'].name}",
                                     "data:sandbox-runs/pdf-abc123", "lsp:x.json"})
            logs = []
            result = data_retention.execute_plan(self.data, plan["plan_id"], policy=self.policy(), environ=self.env,
                                                 log=lambda *a: logs.append(a))
        self.assertEqual(result["deleted"]["caches"], 4)
        self.assertTrue(self.files["malware_current"].exists())
        self.assertFalse(self.files["malware_stale"].exists())
        self.assertFalse(self.pdf.exists())
        self.assertIn("data_retention.caches_deleted", [entry[0] for entry in logs])

    def test_unknown_current_archives_keep_osv_caches(self):
        with mock.patch.object(data_retention, "_current_osv_shas", return_value=None):
            plan = data_retention.build_plan(self.data, policy=self.policy(), environ=self.env)
        kinds = {item["kind"] for item in plan["categories"]["caches"]}
        self.assertNotIn("malware_cache", kinds)
        self.assertNotIn("container_index", kinds)

    def test_remove_refuses_escape(self):
        outside = Path(self.tmp.name) / "outside.txt"
        outside.write_text("x")
        self.assertFalse(data_retention._remove_cache_item(self.data, {"name": "data:../outside.txt"}, self.env))
        self.assertFalse(data_retention._remove_cache_item(self.data, {"name": "etc:passwd"}, self.env))
        link = self.data / "sandbox-runs" / "pdf-link"
        link.symlink_to(Path(self.tmp.name))
        self.assertFalse(data_retention._remove_cache_item(self.data, {"name": "data:sandbox-runs/pdf-link", "dir": True},
                                                           self.env))
        self.assertTrue(outside.exists())


if __name__ == "__main__":
    unittest.main()
