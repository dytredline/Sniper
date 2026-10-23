"""Saklama politikası, DB yedek döndürme, elle yedek alma ve geri yükleme (17. tur, W3-OPS). Yalnız geçici dizinler."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
import urllib.error
import urllib.request

import data_retention as dr
import system_health

APP = Path(__file__).resolve().parents[1]
DAY = 86400


def _db(path: Path, rows: int = 1) -> None:
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE IF NOT EXISTS t (v TEXT)")
    con.executemany("INSERT INTO t VALUES (?)", [(str(i),) for i in range(rows)])
    con.commit()
    con.close()


def _stamp(epoch: float) -> str:
    return time.strftime("%Y%m%dT%H%M", time.localtime(epoch))


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.env = {"SNIPER_DATA_DIR": self.tmp.name}

    def test_default_is_off_and_validation(self):
        policy = dr.load_policy(self.env)
        self.assertFalse(policy["enabled"])
        self.assertFalse(policy["auto_daily"])
        self.assertFalse(policy["backups"]["include_named"])
        self.assertFalse(policy["project_audits"]["enabled"])
        saved = dr.save_policy({"enabled": True, "backups": {"keep_last": 3}}, self.env)
        self.assertEqual(saved["backups"]["keep_last"], 3)
        self.assertEqual(saved["backups"]["keep_daily"], 7, "eksik alan varsayılandan")
        self.assertEqual(os.stat(Path(self.tmp.name) / dr.POLICY_FILE).st_mode & 0o777, 0o600)
        for bad in ({"x": 1}, {"enabled": 1}, {"backups": {"keep_last": 0}}, {"backups": {"nope": 1}},
                    {"project_audits": {"older_than_days": 5}}, {"temp": []}, []):
            with self.subTest(bad=bad), self.assertRaises(dr.RetentionError):
                dr.validate_policy(bad)


class BackupRotationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.now = time.time()

    def make(self, name: str, age_days: float, size: int = 10) -> None:
        path = self.dir / name
        path.write_bytes(b"x" * size)
        os.chmod(path, 0o600)
        when = self.now - age_days * DAY
        os.utime(path, (when, when))

    def test_listing_parses_names_labels_and_sidecars(self):
        self.make(f"sniper.db.bak-{_stamp(self.now - 2 * DAY)}", 2)
        self.make(f"sniper.db.bak-{_stamp(self.now - 2 * DAY)}-shm", 2, size=5)
        self.make(f"sniper.db.bak-{_stamp(self.now - DAY)}-claude-r16", 1)
        self.make(f"auth.db.bak-{_stamp(self.now - DAY)}-ui", 1)
        (self.dir / "sniper.db.bak-link").symlink_to(self.dir / f"auth.db.bak-{_stamp(self.now - DAY)}-ui")
        os.chmod(self.dir / f"sniper.db.bak-{_stamp(self.now - DAY)}-claude-r16", 0o644)
        items = {b["name"]: b for b in dr.list_db_backups(self.dir)}
        self.assertEqual(len(items), 3, "yan dosya ve sembolik bağ ayrı yedek sayılmaz")
        plain = items[f"sniper.db.bak-{_stamp(self.now - 2 * DAY)}"]
        self.assertEqual(plain["bytes"], 15)
        self.assertEqual(len(plain["sidecars"]), 1)
        self.assertFalse(plain["named"])
        self.assertTrue(items[f"sniper.db.bak-{_stamp(self.now - DAY)}-claude-r16"]["named"])
        self.assertTrue(items[f"sniper.db.bak-{_stamp(self.now - DAY)}-claude-r16"]["world_readable"])
        self.assertFalse(items[f"auth.db.bak-{_stamp(self.now - DAY)}-ui"]["named"], "ui etiketi yönetilen yedektir")

    def test_rotation_keeps_last_daily_weekly_and_protects_named(self):
        for age in range(0, 60, 1):  # 60 gün boyunca günde bir yönetilen yedek
            self.make(f"sniper.db.bak-{_stamp(self.now - age * DAY - 7200)}-auto", age + 0.09)
        for age in (40, 50):
            self.make(f"sniper.db.bak-{_stamp(self.now - age * DAY - 3600)}-claude-r{age}", age + 0.05)
        backups = dr.list_db_backups(self.dir)
        rules = {"keep_last": 3, "keep_daily": 7, "keep_weekly": 4, "include_named": False}
        doomed = {d["name"] for d in dr.select_backup_deletions(backups, rules, self.now)}
        kept = {b["name"] for b in backups} - doomed
        self.assertTrue(all("-claude-" not in name for name in doomed), "etiketli yedekler varsayılanda korunur")
        managed_kept = [n for n in kept if n.endswith("-auto")]
        self.assertGreaterEqual(len(managed_kept), 7)
        self.assertLessEqual(len(managed_kept), 7 + 4 + 3)
        self.assertIn(backups[0]["name"], kept, "en yeni yedek kalır")
        with_named = {d["name"] for d in dr.select_backup_deletions(backups, {**rules, "include_named": True}, self.now)}
        self.assertTrue(any("-claude-" in name for name in with_named))

    def test_stamp_parsing_is_not_ambiguous(self):
        # "T2358" saat:dakika'dır; %H%M%S ile 23:05:08 okunmamalı (gece yarısı civarı yanlış silme hatası)
        self.assertEqual(time.localtime(dr._parse_stamp("20261020T2358"))[3:5], (23, 58))
        self.assertEqual(time.localtime(dr._parse_stamp("20261020T235801"))[3:6], (23, 58, 1))
        self.assertIsNone(dr._parse_stamp("2026102T2358"))

    def test_recent_backups_never_deleted(self):
        for minutes in range(1, 6):
            self.make(f"sniper.db.bak-{_stamp(self.now - minutes * 120)}-auto", minutes * 120 / DAY)
        rules = {"keep_last": 1, "keep_daily": 0, "keep_weekly": 0, "include_named": False}
        self.assertEqual(dr.select_backup_deletions(dr.list_db_backups(self.dir), rules, self.now), [])


class PlanExecutionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.env = {"SNIPER_DATA_DIR": self.tmp.name}
        self.now = time.time()
        from storage import Store

        self.store = Store(self.dir / "sniper.db")
        self.logs: list[tuple[str, str, dict]] = []

    def log(self, action, entity, details):
        self.logs.append((action, entity, details))
        self.store.log(action, entity, details)

    def _audit(self, audit_id: str, project: str, days_ago: float) -> None:
        created = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(self.now - days_ago * DAY))
        with sqlite3.connect(self.dir / "sniper.db") as con:
            con.execute("INSERT INTO project_audits(id, created_at, project_path, project_name, score, grade, file_count, "
                        "bytes_scanned, summary_json, findings_json) VALUES (?,?,?,?,0,'A',1,1,'{}','[]')",
                        (audit_id, created, project, Path(project).name))

    def _fixture(self):
        for age in (100, 90, 80):
            path = self.dir / f"sniper.db.bak-{_stamp(self.now - age * DAY)}"
            _db(path)
            os.utime(path, (self.now - age * DAY, self.now - age * DAY))
        named = self.dir / f"sniper.db.bak-{_stamp(self.now - 70 * DAY)}-claude-r9"
        _db(named)
        jobs = self.dir / "jobs"
        jobs.mkdir(mode=0o700)
        old = {"state": "succeeded", "finished_epoch": self.now - 40 * DAY}
        (jobs / "job_0000000000000001.json").write_text(json.dumps(old))
        (jobs / "job_0000000000000002.json").write_text(json.dumps({"state": "running", "finished_epoch": None}))
        for path in jobs.iterdir():
            os.utime(path, (self.now - 40 * DAY, self.now - 40 * DAY))
        tmp = self.dir / ".x.json.123.tmp"
        tmp.write_text("{}")
        os.utime(tmp, (self.now - 30 * DAY, self.now - 30 * DAY))
        center = {"items": [
            {"id": "ntf_old_read", "created_at": "2020-01-01T00:00:00Z", "read": True, "event": "scan_failed"},
            {"id": "ntf_old_unread", "created_at": "2020-01-01T00:00:00Z", "read": False, "event": "scan_failed"},
            {"id": "ntf_new_read", "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "read": True},
        ]}
        (self.dir / "notifications.json").write_text(json.dumps(center))
        for i in range(4):
            self._audit(f"prj_old{i}", "/p/a", 500 + i)
        self._audit("prj_new", "/p/a", 1)
        self._audit("prj_tracked", "/p/b", 900)
        self._audit("prj_b_latest", "/p/b", 2)
        with sqlite3.connect(self.dir / "sniper.db") as con:  # Store şemayı kurdu (finding_tracking.ensure_schema)
            con.execute("INSERT INTO tracked_findings(id, project_path, fingerprint, status, severity, category, reference, "
                        "title, file, line, first_seen_at, first_audit_id, last_seen_at, last_audit_id, finding_json) "
                        "VALUES ('trk_1', '/p/b', 'fp', 'open', 'high', 'x', 'r', 't', 'f', 1, 'a', 'prj_tracked', 'b', "
                        "'prj_b_latest', '{}')")

    def test_preview_deletes_nothing_and_run_requires_enabled_and_same_plan(self):
        self._fixture()
        policy = dr.validate_policy({"backups": {"keep_last": 1, "keep_daily": 0, "keep_weekly": 0},
                                     "project_audits": {"enabled": True, "older_than_days": 30, "keep_per_project": 1}})
        before = sorted(p.name for p in self.dir.rglob("*"))
        plan = dr.build_plan(self.dir, policy=policy, now=self.now, environ=self.env)
        self.assertEqual(sorted(p.name for p in self.dir.rglob("*") if not p.name.endswith(".lock")),
                         [n for n in before if not n.endswith(".lock")], "önizleme hiçbir şey silmez")
        cats = plan["categories"]
        self.assertEqual(len(cats["backups"]), 2, "en yeni yönetilen kalır; etiketli korunur")
        self.assertTrue(all("-claude-" not in b["name"] for b in cats["backups"]))
        self.assertEqual({a["id"] for a in cats["project_audits"]}, {"prj_old0", "prj_old1", "prj_old2", "prj_old3"},
                         "takip başvurusu olan ve proje başına en yeni analiz korunur")
        self.assertEqual([n["id"] for n in cats["notifications"]], ["ntf_old_read"])
        self.assertEqual([j["name"] for j in cats["jobs"]], ["job_0000000000000001.json"])
        self.assertEqual([t["name"] for t in cats["temp"]], [".x.json.123.tmp"])
        with self.assertRaises(dr.RetentionError):  # politika kapalı
            dr.execute_plan(self.dir, plan["plan_id"], log=self.log, policy=policy, now=self.now, environ=self.env)
        policy["enabled"] = True
        with self.assertRaises(dr.RetentionError) as caught:
            dr.execute_plan(self.dir, "0" * 32, log=self.log, policy=policy, now=self.now, environ=self.env)
        self.assertIn("değişti", str(caught.exception))
        self.assertEqual(self.logs, [])
        result = dr.execute_plan(self.dir, plan["plan_id"], log=self.log, policy=policy, now=self.now, environ=self.env)
        self.assertEqual(len(result["deleted"]["backups"]), 2)
        self.assertEqual(result["deleted"]["project_audits"], 4)
        self.assertFalse((self.dir / "jobs" / "job_0000000000000001.json").exists())
        self.assertTrue((self.dir / "jobs" / "job_0000000000000002.json").exists(), "çalışan iş korunur")
        center = json.loads((self.dir / "notifications.json").read_text())
        self.assertEqual([i["id"] for i in center["items"]], ["ntf_old_unread", "ntf_new_read"])
        with sqlite3.connect(self.dir / "sniper.db") as con:
            left = {r[0] for r in con.execute("SELECT id FROM project_audits")}
            self.assertEqual(left, {"prj_new", "prj_tracked", "prj_b_latest"})
            actions = [r[0] for r in con.execute("SELECT action FROM audit_log ORDER BY id")]
        for action in ("data_retention.backups_deleted", "data_retention.project_audits_deleted",
                       "data_retention.notifications_deleted", "data_retention.jobs_deleted", "data_retention.temp_deleted"):
            self.assertIn(action, actions)
        self.assertTrue(any(p.name.endswith("-claude-r9") for p in self.dir.iterdir()))

    def test_daily_auto_only_when_enabled_and_once_a_day(self):
        self._fixture()
        self.assertIsNone(dr.daily_auto(self.dir, log=self.log, environ=self.env, now=self.now))
        dr.save_policy({"enabled": True, "backups": {"keep_last": 1, "keep_daily": 0, "keep_weekly": 0}}, self.env)
        self.assertIsNone(dr.daily_auto(self.dir, log=self.log, environ=self.env, now=self.now), "auto_daily kapalı")
        dr.save_policy({"enabled": True, "auto_daily": True, "backups": {"keep_last": 1, "keep_daily": 0, "keep_weekly": 0}}, self.env)
        first = dr.daily_auto(self.dir, log=self.log, environ=self.env, now=self.now)
        self.assertTrue(first and first["executed"])
        self.assertTrue(all(d.get("automatic") for _, _, d in self.logs))
        self.assertIsNone(dr.daily_auto(self.dir, log=self.log, environ=self.env, now=self.now + 3600), "günde en çok bir kez")


class BackupAndRestoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        _db(self.dir / "sniper.db", rows=3)
        _db(self.dir / "auth.db", rows=1)

    def test_take_backup_is_consistent_private_and_restorable_via_cli(self):
        result = dr.take_backup(self.dir)
        names = [b["name"] for b in result["created"]]
        self.assertEqual(len(names), 2)
        for name in names:
            self.assertRegex(name, r"^(sniper|auth)\.db\.bak-\d{8}T\d{6}-ui$")
            self.assertEqual(os.stat(self.dir / name).st_mode & 0o777, 0o600)
        self.assertTrue(all(b["integrity"] == "ok" for b in result["created"]))
        sniper_backup = next(n for n in names if n.startswith("sniper"))
        _db(self.dir / "sniper.db", rows=5)  # sonradan değişiklik
        restored = dr.restore_db_backup(self.dir, sniper_backup)
        self.assertEqual(restored["restored"], sniper_backup)
        with sqlite3.connect(self.dir / "sniper.db") as con:
            self.assertEqual(con.execute("SELECT count(*) FROM t").fetchone()[0], 3)
        self.assertTrue(any(p.name.endswith("-pre-restore") for p in self.dir.iterdir()), "önce güvenlik yedeği")
        listed = {item["name"] for item in dr.list_db_backups(self.dir)}
        self.assertIn(sniper_backup, listed)
        with self.assertRaises(dr.RetentionError):
            dr.restore_db_backup(self.dir, "../sniper.db")
        with self.assertRaises(dr.RetentionError):
            dr.take_backup(self.dir, label="../x")


class HealthTests(unittest.TestCase):
    def test_backup_storage_check_flags_world_readable_and_heavy(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            for i in range(35):
                path = base / f"sniper.db.bak-2026010{i % 9 + 1}T{1000 + i:04d}-auto"
                path.write_bytes(b"x")
                os.chmod(path, 0o600)
            os.chmod(base / "sniper.db.bak-20260101T1000-auto", 0o644)
            checks = {c["id"]: c for c in system_health.check_backup_storage(base, {"SNIPER_DATA_DIR": tmp})}
            self.assertEqual(checks["db_backup_storage"]["status"], "warn")
            self.assertIn("döndürme kapalı", checks["db_backup_storage"]["value"])
            self.assertEqual(checks["db_backup_permissions"]["status"], "warn")
            dr.save_policy({"enabled": True}, {"SNIPER_DATA_DIR": tmp})
            again = {c["id"]: c for c in system_health.check_backup_storage(base, {"SNIPER_DATA_DIR": tmp})}
            self.assertEqual(again["db_backup_storage"]["status"], "info")


class ApiTests(unittest.TestCase):
    def setUp(self):
        import server
        from storage import Store
        from http.server import ThreadingHTTPServer

        self.server = server
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.prev = (server.STORE, server.DATA_DIR)
        server.STORE = Store(self.dir / "sniper.db")
        server.DATA_DIR = self.dir
        patch = mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": self.tmp.name})
        patch.start()
        self.addCleanup(patch.stop)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.server.STORE, self.server.DATA_DIR = self.prev

    def call(self, path, body=None):
        request = urllib.request.Request(self.base + path, method="POST" if body is not None else "GET",
                                         data=json.dumps(body).encode() if body is not None else None,
                                         headers={"Content-Type": "application/json"} if body is not None else {})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    def test_routes_confirm_preview_and_run(self):
        status, data = self.call("/api/system/backups")
        self.assertEqual(status, 200)
        self.assertFalse(data["ui_restore"])
        self.assertEqual(self.call("/api/system/backups", {})[0], 400, "onaysız yedek yok")
        status, created = self.call("/api/system/backups", {"confirm": True})
        self.assertEqual(status, 201, created)
        self.assertEqual(len(created["db_backups"]), 1)
        status, retention = self.call("/api/system/retention")
        self.assertEqual(status, 200)
        self.assertFalse(retention["policy"]["enabled"])
        plan_id = retention["plan"]["plan_id"]
        self.assertEqual(self.call("/api/system/retention/run", {"confirm": True, "plan_id": plan_id})[0], 400, "politika kapalı")
        self.assertEqual(self.call("/api/system/retention/policy", {"confirm": True, "policy": {"enabled": "evet"}})[0], 400)
        status, saved = self.call("/api/system/retention/policy", {"confirm": True, "policy": {"enabled": True}})
        self.assertEqual(status, 200, saved)
        self.assertEqual(self.call("/api/system/retention/run", {"confirm": True, "plan_id": "f" * 32})[0], 409)
        status, ran = self.call("/api/system/retention/run", {"confirm": True, "plan_id": saved["plan"]["plan_id"]})
        self.assertEqual(status, 200, ran)
        self.assertTrue(ran["executed"])
        with sqlite3.connect(self.dir / "sniper.db") as con:
            actions = [r[0] for r in con.execute("SELECT action FROM audit_log")]
        self.assertIn("system_backup.created", actions)
        self.assertIn("data_retention.policy_changed", actions)

    def test_admin_only_routes(self):
        import auth

        for path in ("/api/system/backups", "/api/system/retention"):
            self.assertEqual(auth.required_level("GET", path), "admin")
        for path in ("/api/system/backups", "/api/system/retention/policy", "/api/system/retention/run"):
            self.assertEqual(auth.required_level("POST", path), "admin")


if __name__ == "__main__":
    unittest.main()
