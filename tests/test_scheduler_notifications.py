"""Zamanlanmış taramalar (sahte saat, çakışma, telafi) ve yerel bildirimler (merkez, masaüstü, SMTP, webhook)."""
from __future__ import annotations

import datetime as dt
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import tempfile
import threading
import time
import unittest
from unittest import mock
import urllib.error
import urllib.request

import notifications
import ops_files
import scheduler as sch

UTC = dt.timezone.utc


def at(text: str) -> dt.datetime:
    return dt.datetime.fromisoformat(text).replace(tzinfo=UTC)


class _Env:
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.env = {"SNIPER_DATA_DIR": self.tmp.name}
        patch = mock.patch.dict(os.environ, self.env)
        patch.start()
        self.addCleanup(patch.stop)


class FrequencyTests(unittest.TestCase):
    def test_forms_and_istanbul_offsets(self):
        tz = sch.zone("Europe/Istanbul")
        now = at("2026-10-20T09:00:00")
        cases = {
            "hourly": "2026-10-20T10:00:00+00:00",
            "hourly 15": "2026-10-20T09:15:00+00:00",
            "daily 03:00": "2026-10-21T00:00:00+00:00",
            "weekly mon 02:30": "2026-10-25T23:30:00+00:00",
            "weekly pzt 02:30": "2026-10-25T23:30:00+00:00",
            "*/5 * * * *": "2026-10-20T09:05:00+00:00",
            "0 9 1 * 1": "2026-10-26T06:00:00+00:00",  # gün ve haftagünü kısıtlı: VEYA
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(sch.next_run(sch.parse_frequency(text), now, tz).isoformat(), expected)

    def test_rejects_invalid(self):
        for bad in ("", "daily 25:00", "weekly xx 10:00", "1 2 3", "61 * * * *", "* * * * 8", "hourly 99", None):
            with self.subTest(bad=bad), self.assertRaises(sch.ScheduleError):
                sch.parse_frequency(bad)


class SchedulerTests(_Env, unittest.TestCase):
    def make(self, frequency="daily 03:00", **extra):
        payload = {"schedule": {"name": "Gece", "project_path": "/p", "frequency": frequency, **extra}}
        return sch.apply_action("create", payload, validate_path=lambda p: p, now=self.now)["schedule"]

    def setUp(self):
        super().setUp()
        self.now = at("2026-10-20T09:00:00")
        self.submitted: list[str] = []
        self.states: dict[str, str] = {}
        self.logs: list[tuple] = []

        def submit(item):
            job_id = f"job_{len(self.submitted):024d}"
            self.submitted.append(item["id"])
            self.states[job_id] = "queued"
            return job_id

        self.scheduler = sch.Scheduler(submit=submit, job_state=self.states.get, clock=lambda: self.now,
                                       log=lambda *a: self.logs.append(a))

    def test_runs_once_when_due_and_file_is_private(self):
        item = self.make()
        self.assertEqual(item["next_run_at"], "2026-10-21T00:00:00Z")
        self.assertEqual(self.scheduler.tick(), [])
        self.now = at("2026-10-21T00:00:10")
        results = self.scheduler.tick()
        self.assertEqual([r["status"] for r in results], ["submitted"])
        self.assertEqual(results[0]["trigger"], "schedule")
        self.assertEqual(self.scheduler.tick(), [])  # aynı dakikada ikinci kez çalışmaz
        data = sch.load()
        self.assertEqual(data["schedules"][0]["next_run_at"], "2026-10-22T00:00:00Z")
        self.assertEqual(os.stat(Path(self.tmp.name) / sch.FILE_NAME).st_mode & 0o777, 0o600)
        self.assertEqual(self.logs[-1][0], "schedule.run")

    def test_overlap_is_skipped(self):
        self.make("hourly")
        self.now = at("2026-10-20T10:00:05")
        self.scheduler.tick()
        job_id = sch.load()["schedules"][0]["last_job_id"]
        self.states[job_id] = "running"
        self.now = at("2026-10-20T11:00:05")
        self.assertEqual([r["status"] for r in self.scheduler.tick()], ["skipped_overlap"])
        self.assertEqual(len(self.submitted), 1)
        self.states[job_id] = "succeeded"
        self.now = at("2026-10-20T12:00:05")
        self.assertEqual([r["status"] for r in self.scheduler.tick()], ["submitted"])

    def test_missed_runs_catch_up_at_most_once(self):
        self.make("hourly")
        self.now = at("2026-10-20T17:30:00")  # 7 saatlik kesinti: tek telafi
        results = self.scheduler.tick()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["trigger"], "catch_up")
        self.assertEqual(self.scheduler.tick(), [])
        self.assertEqual(sch.load()["schedules"][0]["next_run_at"], "2026-10-20T18:00:00Z")

    def test_disabled_run_now_duplicate_and_job_finish(self):
        item = self.make("hourly")
        sch.apply_action("disable", {"id": item["id"]}, validate_path=lambda p: p, now=self.now)
        self.now = at("2026-10-20T10:00:05")
        self.assertEqual(self.scheduler.tick(), [])
        self.assertEqual(self.scheduler.run_now(item["id"])["status"], "submitted")
        job_id = sch.load()["schedules"][0]["last_job_id"]
        self.states[job_id] = "failed"
        found = self.scheduler.on_job_finished(job_id, "failed", "2026-10-20T10:01:00Z")
        self.assertEqual(found["id"], item["id"])
        self.assertEqual(sch.load()["schedules"][0]["last_status"], "failed")

        class DuplicateJob(Exception):
            pass

        def duplicate(_item):
            raise DuplicateJob("x")

        self.scheduler.submit = duplicate
        self.assertEqual(self.scheduler.run_now(item["id"])["status"], "skipped_duplicate")

    def test_validation(self):
        bad_payloads = [
            {"project_path": "/p", "frequency": "daily 03:00", "scan_type": "nuclei_http"},  # uzak hedef zamanlanamaz
            {"project_path": "/p", "frequency": "daily 03:00", "scope": {"preset": "skipped"}},
            {"project_path": "/p", "frequency": "her gün"},
            {"project_path": "/p", "frequency": "daily 03:00", "unknown": 1},
            {"project_path": "/p", "frequency": "daily 03:00", "scan_type": "project_changed", "base_ref": "--upload-pack=x"},
        ]
        for fields in bad_payloads:
            with self.subTest(fields=fields), self.assertRaises(sch.ScheduleError):
                sch.apply_action("create", {"schedule": fields}, validate_path=lambda p: p, now=self.now)
        with self.assertRaises(sch.ScheduleError):
            sch.apply_action("timezone", {"timezone": "Mars/Olympus"}, validate_path=lambda p: p)
        item = self.make(scan_type="secrets_gitleaks", scope={"preset": "all"})
        self.assertNotIn("scope", item)  # kapsam yalnız proje analizinde
        self.assertEqual(sch.job_request(item), ("/api/tool-runs/gitleaks", {"project_path": "/p", "confirm_local": True}))
        self.assertTrue(all(not t["key"].startswith("nuclei") for t in sch.available_scan_types()))


class _Hook(BaseHTTPRequestHandler):
    received: list = []
    status = 200

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        type(self).received.append(json.loads(self.rfile.read(length)))
        self.send_response(type(self).status)
        if type(self).status == 302:
            self.send_header("Location", "http://8.8.8.8/")
        self.end_headers()

    def log_message(self, *_args):
        pass


class NotificationTests(_Env, unittest.TestCase):
    def setUp(self):
        super().setUp()
        _Hook.received = []
        _Hook.status = 200
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Hook)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)
        self.hook = f"http://127.0.0.1:{self.httpd.server_address[1]}/sniper"

    def settings(self, **channels):
        base = notifications.default_settings()
        for name, value in channels.items():
            base["channels"][name].update(value)
        return base

    def test_center_unread_and_mark_read(self):
        item = notifications.emit("scan_failed", "medium", "Tarama başarısız", "x")
        self.assertEqual(item["channels"], {"center": "stored"})
        self.assertIsNone(notifications.emit("unknown_event", "low", "t", "m"))
        listed = notifications.list_items()
        self.assertEqual((listed["unread"], len(listed["items"])), (1, 1))
        self.assertEqual(notifications.mark_read("all"), 1)
        self.assertEqual(notifications.list_items(unread_only=True)["items"], [])
        with self.assertRaises(notifications.NotificationError):
            notifications.mark_read(["../x"])

    def test_webhook_local_only_and_no_redirects(self):
        for url in ("http://8.8.8.8/x", "http://169.254.169.254/latest", "ftp://127.0.0.1/", "http://u:p@127.0.0.1/"):
            with self.subTest(url=url), self.assertRaises(notifications.NotificationError):
                notifications.save_settings(self.settings(webhook={"enabled": True, "url": url}))
        notifications.save_settings(self.settings(webhook={"enabled": True, "url": self.hook}))
        item = notifications.emit("scan_failed", "medium", "Başlık", "İleti", data={"job_id": "job_x"})
        self.assertEqual(item["channels"]["webhook"], "sent")
        self.assertEqual(_Hook.received[0]["title"], "Başlık")
        self.assertEqual(_Hook.received[0]["source"], "sniper")
        _Hook.status = 302
        item = notifications.emit("scan_failed", "medium", "B2", "İ2")
        self.assertEqual(item["channels"]["webhook"], "failed:http_302")
        self.assertEqual(len(_Hook.received), 2)  # yönlendirme izlenmedi

    def test_quiet_hours_and_critical_override(self):
        settings = self.settings(webhook={"enabled": True, "url": self.hook})
        settings["quiet_hours"] = {"enabled": True, "start": "22:00", "end": "08:00", "allow_critical": True}
        notifications.save_settings(settings)
        night = at("2026-10-20T21:30:00")  # İstanbul 00:30
        self.assertEqual(notifications.emit("scan_failed", "medium", "t", "m", now=night)["channels"]["webhook"], "quiet_hours")
        self.assertEqual(notifications.emit("new_findings", "critical", "t", "m", now=night)["channels"]["webhook"], "sent")
        day = at("2026-10-20T09:30:00")
        self.assertEqual(notifications.emit("scan_failed", "medium", "t", "m", now=day)["channels"]["webhook"], "sent")

    def test_smtp_password_never_leaks(self):
        secret = "S3cret-Parola-123"
        sent = {}

        class FakeSMTP:
            def __init__(self, host, port):
                sent["addr"] = (host, port)

            def __enter__(self):
                return self

            def __exit__(self, *_a):
                return False

            def starttls(self, **_k):
                sent["tls"] = True

            def login(self, user, password):
                sent["login"] = (user, password)

            def send_message(self, message):
                sent["subject"] = message["Subject"]

        settings = self.settings(smtp={"enabled": True, "host": "127.0.0.1", "port": 2525, "username": "ben",
                                       "from_addr": "sniper@ornek.local", "to": ["ben@ornek.local"]})
        public = notifications.save_settings(settings, smtp_password=secret)
        self.assertTrue(public["channels"]["smtp"]["password_set"])
        self.assertNotIn(secret, json.dumps(public))
        path = Path(self.tmp.name) / notifications.SMTP_PASSWORD_FILE
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        self.assertNotIn(secret, (Path(self.tmp.name) / notifications.SETTINGS_FILE).read_text())
        item = notifications.emit("scan_failed", "medium", "Konu\r\nBcc: x@y.z", "m", smtp_factory=FakeSMTP)
        self.assertEqual(item["channels"]["smtp"], "sent")
        self.assertEqual(sent["login"], ("ben", secret))
        self.assertNotIn("\n", sent["subject"])

        class Exploding(FakeSMTP):
            def login(self, user, password):
                raise RuntimeError(f"sunucu reddetti: {password}")

        item = notifications.emit("scan_failed", "medium", "t", "m", smtp_factory=Exploding)
        self.assertEqual(item["channels"]["smtp"], "failed:RuntimeError")
        everything = json.dumps(notifications.list_items()) + json.dumps(notifications.public_settings())
        self.assertNotIn(secret, everything)
        notifications.save_settings(notifications.load_settings(), smtp_password="")
        self.assertFalse(path.exists())

    def test_desktop_silently_skipped_when_unavailable(self):
        notifications.save_settings(self.settings(desktop={"enabled": True}))
        with mock.patch.object(notifications.shutil, "which", return_value=None):
            self.assertEqual(notifications.emit("scan_failed", "low", "t", "m")["channels"]["desktop"], "unavailable")

    def test_project_audit_events(self):
        from storage import Store

        store = Store(Path(self.tmp.name) / "t.db")
        # Bulgu takibi yalnız var olan ve kapsamdaki dosyalar için "düzeldi" der (kök yoksa "doğrulanamadı").
        project = Path(self.tmp.name) / "proj"
        project.mkdir()
        for name in ("a.py", "b.py", "c.py"):
            (project / name).write_text("x = 1\n")

        def audit(findings, **extra):
            return store.create_project_audit({
                "created_at": "2026-10-20T00:00:00Z", "project_path": str(project), "project_name": "proj", "score": 50,
                "grade": "D", "file_count": 1, "bytes_scanned": 1, "findings": findings, "checks": [], "limitations": [],
                **extra})

        sqli = {"category": "data_query", "severity": "critical", "title": "SQL", "file": "a.py", "line": 3, "reference": "CWE-89"}
        xss = {"category": "web", "severity": "high", "title": "XSS", "file": "b.py", "line": 9, "reference": "CWE-79"}
        low = {"category": "web", "severity": "low", "title": "Başlık", "file": "c.py", "line": 1, "reference": "CWE-693"}
        first = audit([sqli, low])
        events = notifications.on_project_audit_created(store, first)
        self.assertEqual([e["event"] for e in events], ["new_findings"])
        self.assertEqual(events[0]["data"]["counts"]["critical"], 1)
        second = audit([xss, low])
        events = {e["event"]: e for e in notifications.on_project_audit_created(store, second)}
        self.assertEqual(events["new_findings"]["data"]["baseline_id"], first["id"])
        self.assertEqual(events["new_findings"]["severity"], "high")
        self.assertIn("1 bulgu düzeldi", events["fixed_findings"]["title"])
        partial = audit([low], scope={"skipped_only": True}, base_audit_id=second["id"])
        self.assertEqual(notifications.on_project_audit_created(store, partial), [])  # kısmi tarama düzelme üretmez
        changes = notifications.project_audit_changes(store, partial)
        self.assertEqual(changes["baseline_id"], second["id"])

    def test_scan_failed_event(self):
        item = notifications.on_scan_failed("/api/project-audits", "job_1", "expired", schedule={"id": "sch_1", "name": "Gece"})
        self.assertIn("Zamanlanmış tarama “Gece” süre sınırını aştı", item["title"])


class ApiTests(unittest.TestCase):
    """Gerçek sunucu: plan oluşturma, şimdi çalıştırma → iş kuyruğu → proje analizi → bildirim ve plan durumu."""

    def setUp(self):
        import server
        from storage import Store

        self.server = server
        self.data = tempfile.TemporaryDirectory()
        self.addCleanup(self.data.cleanup)
        # Proje kökü ev dizini altında olmalı (iş alt sürecinde de doğrulanır).
        self.project_parent = tempfile.mkdtemp(prefix=".sniper-ops-test-", dir=Path.home())
        self.addCleanup(shutil.rmtree, self.project_parent, True)
        self.project = Path(self.project_parent) / "proj"
        self.project.mkdir()
        (self.project / "app.py").write_text(
            'import os\nfrom flask import request\n\ndef run():\n    os.system("ping " + request.args["h"])\n')
        patch = mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": self.data.name})
        patch.start()
        self.addCleanup(patch.stop)
        self.previous_store = server.STORE
        server.STORE = Store(Path(self.data.name) / "sniper-test.db")
        server.SCHEDULER = None
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.server.STORE = self.previous_store
        self.server.SCHEDULER = None

    def call(self, path, body=None):
        request = urllib.request.Request(self.base + path, method="POST" if body is not None else "GET",
                                         data=json.dumps(body).encode() if body is not None else None,
                                         headers={"Content-Type": "application/json"} if body is not None else {})
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    def test_schedule_run_now_end_to_end(self):
        status, data = self.call("/api/schedules")
        self.assertEqual((status, data["schedules"], data["timezone"]), (200, [], "Europe/Istanbul"))
        create = {"action": "create", "schedule": {"name": "Deneme", "project_path": str(self.project), "frequency": "hourly"}}
        self.assertEqual(self.call("/api/schedules", create)[0], 400)  # onaysız (23. tur: 400)
        status, data = self.call("/api/schedules", {**create, "confirm": True})
        self.assertEqual(status, 200, data)
        schedule_id = data["changed"]["id"]
        self.assertEqual(self.call("/api/schedules", {"confirm": True, "action": "create",
                                                      "schedule": {"project_path": "/etc", "frequency": "hourly"}})[0], 400)
        status, outcome = self.call("/api/schedules", {"confirm": True, "action": "run-now", "id": schedule_id})
        self.assertEqual((status, outcome["status"]), (202, "submitted"), outcome)
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            job = self.server.JOBS.get(outcome["job_id"])
            if job and job["state"] not in {"queued", "running"}:
                break
            time.sleep(0.3)
        self.assertEqual(job["state"], "succeeded", job)
        time.sleep(0.3)  # on_finish kancası
        schedule = self.call("/api/schedules")[1]["schedules"][0]
        self.assertEqual((schedule["last_status"], schedule["run_count"]), ("succeeded", 1))
        center = self.call("/api/notifications")[1]
        self.assertEqual(center["unread"], 1)
        self.assertEqual(center["items"][0]["event"], "new_findings")
        self.assertEqual(self.call("/api/notifications", {"action": "mark-read", "ids": "all"})[1]["marked"], 1)
        settings = self.call("/api/notification-settings")[1]
        settings_body = {"confirm": True, "settings": {"channels": {"webhook": {"enabled": True, "url": "http://1.1.1.1/"}}}}
        self.assertEqual(self.call("/api/notification-settings", settings_body)[0], 400)
        self.assertFalse(settings["channels"]["smtp"]["password_set"])
        with self.server.STORE._connect() as db:
            actions = [row[0] for row in db.execute("SELECT action FROM audit_log ORDER BY id")]
        self.assertIn("schedule.created", actions)
        self.assertIn("schedule.run", actions)
        self.assertEqual(self.call("/api/schedules", {"confirm": True, "action": "delete", "id": schedule_id})[1]["schedules"], [])


if __name__ == "__main__":
    unittest.main()
