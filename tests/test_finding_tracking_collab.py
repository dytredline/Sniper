"""Bulgu takibi iş birliği (16. tur): sorumlu atama (giriş açık/kapalı), son tarih ve gecikme, yorum dizisi,
"bana atananlar", denetim kaydı, bildirimler (atama + son tarih), zamanlayıcı denetimi, rol/CSRF kapısı,
yönetici özeti/HTML rapor ve eski veritabanının şema yükseltmesi."""
from __future__ import annotations

import datetime as dt
import http.client
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest import mock

from http.server import ThreadingHTTPServer

import auth
import finding_tracking as ft
import i18n_server
import notifications
import project_analyzer
from project_audit_diff import render_project_audit_html
from project_executive_summary import build_project_executive_summary, render_section_html
import scheduler
import server
from storage import Store

STRONG = "doğru-at-pil-zımba-42"


def finding(file="app.py", line=10, title="Doğrulanmış veri akışı: istek girdisi SQL sorgusuna ulaşıyor (SQL enjeksiyonu)",
            severity="critical"):
    return {"category": "data_query", "severity": severity, "reference": "CWE-89", "file": file, "line": line,
            "title": title, "evidence": "Hassas değer kaydedilmedi.", "recommendation": "Parametre bağlayın."}


def make_audit(store: Store, root: Path, findings: list[dict], day: int = 1) -> dict:
    return store.create_project_audit({
        "created_at": f"2026-10-{day:02d}T10:00:00Z", "project_path": str(root), "project_name": root.name,
        "score": 60, "grade": "D", "file_count": 2, "bytes_scanned": 10, "findings": findings, "scope": {},
        "skipped_files": {},
    })


def tracked_ids(store: Store, root: Path) -> list[str]:
    return [item["id"] for item in sorted(store.list_tracked_findings(str(root)), key=lambda item: item["file"])]


def audit_rows(store: Store) -> list[tuple[str, dict]]:
    with sqlite3.connect(store.path) as db:
        return [(a, json.loads(d)) for a, d in db.execute("SELECT action, details_json FROM audit_log ORDER BY id")]


class _Project(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.data_dir = base / "data"
        self.data_dir.mkdir()
        self.root = base / "proj"
        self.root.mkdir()
        for name in ("app.py", "views.py"):
            (self.root / name).write_text("x = 1\n")
        env = mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(self.data_dir)})
        env.start()
        self.addCleanup(env.stop)
        self.store = Store(self.data_dir / "sniper.db")
        self.audit = make_audit(self.store, self.root, [finding("app.py"), finding("views.py", 4, severity="medium",
                                                                                    title="Günlüğe hassas veri yazma olasılığı")])
        self.first, self.second = tracked_ids(self.store, self.root)
        self.today = ft.today_local()


class SchemaUpgradeTests(unittest.TestCase):
    def test_old_database_gets_columns_and_comment_table_without_touching_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "eski.db"
            old_schema = ft.SCHEMA.split("CREATE TABLE IF NOT EXISTS tracked_finding_comments")[0]
            with sqlite3.connect(path) as db:
                db.executescript(old_schema)
                db.execute("INSERT INTO tracked_findings(id, project_path, fingerprint, status, severity, category, reference, "
                           "title, file, line, first_seen_at, first_audit_id, last_seen_at, last_audit_id, finding_json) "
                           "VALUES ('trk_eski', '/p', 'fp', 'open', 'high', 'c', 'CWE-1', 't', 'a.py', 3, 'x', 'prj_1', 'x', 'prj_1', '{}')")
            Store(path)
            Store(path)  # ikinci açılış: ALTER tekrarlanmaz
            with sqlite3.connect(path) as db:
                db.row_factory = sqlite3.Row
                columns = {row[1] for row in db.execute("PRAGMA table_info(tracked_findings)")}
                self.assertTrue({name for name, _ in ft.COLLAB_COLUMNS} <= columns)
                row = db.execute("SELECT * FROM tracked_findings WHERE id = 'trk_eski'").fetchone()
                self.assertEqual((row["status"], row["assignee_name"], row["due_date"], row["due_notice"]), ("open", "", None, ""))
                self.assertIsNotNone(db.execute("SELECT 1 FROM sqlite_master WHERE name = 'tracked_finding_comments'").fetchone())


class StoreCollabTests(_Project):
    def test_assign_due_comments_events_and_audit_log(self):
        result = self.store.assign_tracked_finding(self.first, None, ft.clean_assignee_name("  Ayşe   Yılmaz "))
        self.assertTrue(result["changed"])
        self.assertEqual(result["finding"]["assignee_name"], "Ayşe Yılmaz")
        self.assertFalse(self.store.assign_tracked_finding(self.first, None, "Ayşe Yılmaz")["changed"])  # aynı → kayıt yok
        past = (self.today - dt.timedelta(days=3)).isoformat()
        item = self.store.set_tracked_finding_due(self.first, ft.parse_due_date(past))["finding"]
        self.assertTrue(item["overdue"])
        self.assertEqual(item["due_in_days"], -3)
        comment = self.store.add_tracked_finding_comment(self.first, None, "", "  Satır 1\nsatır 2 <b>kalın değil</b>  ")
        self.assertEqual(comment["body"], "Satır 1\nsatır 2 <b>kalın değil</b>")
        detail = self.store.get_tracked_finding(self.first)
        self.assertEqual([c["id"] for c in detail["comments"]], [comment["id"]])
        self.assertEqual([e["event"] for e in detail["events"]][-3:], ["assigned", "due_changed", "comment_added"])
        self.store.delete_tracked_finding_comment(self.first, comment["id"], None, False)  # giriş kapalı: tek yerel kullanıcı
        self.assertEqual(self.store.get_tracked_finding(self.first)["comments"], [])
        actions = [a for a, _d in audit_rows(self.store)]
        for action in ("tracked_finding.assigned", "tracked_finding.due_changed", "tracked_finding.comment_added",
                       "tracked_finding.comment_deleted"):
            self.assertEqual(actions.count(action), 1, action)
        added = next(d for a, d in audit_rows(self.store) if a == "tracked_finding.comment_added")
        self.assertNotIn("Satır", json.dumps(added, ensure_ascii=False))  # yorum metni denetim kaydına kopyalanmaz
        self.assertTrue(self.store.verify_audit_chain()["verified"])
        # Kaldırma: ikisi boş → atanmamış
        self.assertEqual(self.store.assign_tracked_finding(self.first, None, "")["finding"]["assignee_name"], "")

    def test_validation(self):
        for bad in ("", "x" * 81, "a\x07b", 5):
            with self.subTest(bad=bad), self.assertRaises(ft.TrackingError):
                ft.clean_assignee_name(bad)
        for bad in ("2026-13-01", "20261001", "1999-01-01", 3):
            with self.subTest(bad=bad), self.assertRaises(ft.TrackingError):
                ft.parse_due_date(bad)
        self.assertIsNone(ft.parse_due_date(None))
        for bad in ("", "   ", "y" * 4001, "a\x00b", ["x"]):
            with self.subTest(bad=bad), self.assertRaises(ft.TrackingError):
                self.store.add_tracked_finding_comment(self.first, None, "", bad)
        with self.assertRaises(LookupError):
            self.store.assign_tracked_finding("trk_yok", None, "Ali")
        with self.assertRaises(LookupError):
            self.store.delete_tracked_finding_comment(self.first, 999, None, False)

    def test_comment_delete_permission_when_login_enabled(self):
        comment = self.store.add_tracked_finding_comment(self.first, "usr_a", "ali", "not")
        with self.assertRaises(PermissionError):
            self.store.delete_tracked_finding_comment(self.first, comment["id"], "usr_b", False)
        self.store.delete_tracked_finding_comment(self.first, comment["id"], "usr_b", True)  # yönetici
        own = self.store.add_tracked_finding_comment(self.first, "usr_a", "ali", "kendi notum")
        self.store.delete_tracked_finding_comment(self.first, own["id"], "usr_a", False)

    def test_assigned_list_filters_summary_and_reports(self):
        self.store.assign_tracked_finding(self.first, None, "Ali")
        self.store.assign_tracked_finding(self.second, None, "Veli")
        self.store.set_tracked_finding_due(self.first, (self.today - dt.timedelta(days=1)).isoformat())
        self.store.set_tracked_finding_due(self.second, (self.today + dt.timedelta(days=3)).isoformat())
        self.assertEqual([i["id"] for i in self.store.list_assigned_findings(assignee_name="ali")], [self.first])  # büyük/küçük harf
        self.assertEqual(len(self.store.list_assigned_findings()), 2)
        self.assertEqual([i["id"] for i in self.store.list_assigned_findings(overdue_only=True)], [self.first])
        self.assertEqual([i["id"] for i in self.store.list_assigned_findings(severities={"medium"})], [self.second])
        self.assertEqual(self.store.list_assigned_findings(statuses={"fixed"}), [])
        with self.assertRaises(ft.TrackingError):
            self.store.list_assigned_findings(severities={"x"})
        # Düzelen bulgu gecikmiş sayılmaz.
        self.store.set_tracked_finding_status(self.first, "risk_accepted", "")
        self.assertFalse(self.store.get_tracked_finding(self.first)["overdue"])
        self.store.set_tracked_finding_status(self.first, "open", "")
        summary = self.store.tracked_project_summary(str(self.root))
        self.assertEqual(summary["ownership"], {"assigned_active": 2, "unassigned_active": 0, "overdue": 1, "due_soon": 1})
        self.assertEqual([d["id"] for d in summary["deadlines"]], [self.first, self.second])
        audit = self.store.get_project_audit(self.audit["id"])
        executive = build_project_executive_summary(self.store, audit)
        self.assertEqual(executive["ownership"]["overdue"], 1)
        self.assertEqual({item.get("assignee_name") for item in executive["top_findings"]}, {"Ali", "Veli"})
        section = render_section_html(executive)
        self.assertIn("Sahiplik", section)
        self.assertIn("Son tarihler", section)
        self.assertIn("(gecikmiş)", section)
        page = render_project_audit_html(audit, section)
        self.assertIn("Sorumlu: Ali", page)
        self.assertIn("(gecikmiş)", page)
        # İngilizce rapor: yeni dizgeler çevrilir.
        english = i18n_server.localize_html(page, "en")
        for text in ("Ownership", "Due dates", "Owner: Ali"):
            self.assertIn(text, english)

    def test_html_report_escapes_owner(self):
        self.store.assign_tracked_finding(self.first, None, "<script>x</script>")
        page = render_project_audit_html(self.store.get_project_audit(self.audit["id"]))
        self.assertNotIn("<script>x", page)
        self.assertIn("&lt;script&gt;x", page)


class DueNotificationTests(_Project):
    def test_reminders_once_per_stage_and_reset_on_date_change(self):
        self.store.assign_tracked_finding(self.first, None, "Ali")
        self.store.set_tracked_finding_due(self.first, (self.today - dt.timedelta(days=2)).isoformat())
        self.store.set_tracked_finding_due(self.second, (self.today + dt.timedelta(days=1)).isoformat())
        emitted = notifications.check_due_dates(self.store)
        titles = sorted(item["title"] for item in emitted)
        self.assertEqual(titles, ["1 bulgunun son tarihi geçti", "1 bulgunun son tarihi yaklaşıyor"])
        overdue = next(item for item in emitted if "geçti" in item["title"])
        self.assertEqual(overdue["event"], "finding_due")
        self.assertIn("Ali", overdue["details"][0])
        self.assertEqual(notifications.check_due_dates(self.store), [])  # aynı aşama tekrar bildirilmez
        self.store.set_tracked_finding_due(self.second, (self.today - dt.timedelta(days=1)).isoformat())
        again = notifications.check_due_dates(self.store)
        self.assertEqual([item["title"] for item in again], ["1 bulgunun son tarihi geçti"])
        far = (self.today + dt.timedelta(days=20)).isoformat()
        self.store.set_tracked_finding_due(self.second, far)
        self.assertEqual(notifications.check_due_dates(self.store), [])

    def test_disabled_event_and_settings_validation(self):
        self.store.set_tracked_finding_due(self.first, (self.today - dt.timedelta(days=2)).isoformat())
        notifications.save_settings({"events": {"finding_due": {"enabled": False, "days_before": 2}}})
        self.assertEqual(notifications.check_due_dates(self.store), [])
        for bad in (-1, 31, "2", True):
            with self.subTest(bad=bad), self.assertRaises(notifications.NotificationError):
                notifications.validate_settings({"events": {"finding_due": {"enabled": True, "days_before": bad}}})
        defaults = notifications.default_settings()["events"]
        self.assertTrue(defaults["finding_assigned"]["enabled"] and defaults["finding_due"]["enabled"])

    def test_assignment_notification(self):
        item = self.store.assign_tracked_finding(self.first, None, "Ali")["finding"]
        notice = notifications.on_finding_assigned(item, actor={"username": "yonetici"})
        self.assertEqual(notice["title"], "Bulgu atandı: Ali")
        self.assertIn("yonetici tarafından", notice["message"])
        self.assertEqual(notice["severity"], "critical")
        self.assertIsNone(notifications.on_finding_assigned({**item, "assignee_name": ""}))


class SchedulerPeriodicTests(unittest.TestCase):
    def test_periodic_runs_hourly_and_survives_errors(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": tmp}):
            clock = [dt.datetime(2026, 10, 20, 9, 0, tzinfo=dt.timezone.utc)]
            calls = []

            def periodic(now):
                calls.append(now)
                raise RuntimeError("denetim hatası")

            sched = scheduler.Scheduler(submit=lambda _plan: "job", job_state=lambda _job: None, clock=lambda: clock[0],
                                        periodic=periodic)
            with mock.patch("traceback.print_exc"):
                sched.tick()
                clock[0] += dt.timedelta(minutes=30)
                sched.tick()
                clock[0] += dt.timedelta(minutes=31)
                sched.tick()
            self.assertEqual(len(calls), 2)


class Client:
    def __init__(self, port: int):
        self.port = port
        self.cookies: dict[str, str] = {}
        self.send_csrf = True

    def request(self, method: str, path: str, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        headers = {"Host": f"127.0.0.1:{self.port}"}
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
            if self.send_csrf and auth.CSRF_COOKIE in self.cookies:
                headers[auth.CSRF_HEADER] = self.cookies[auth.CSRF_COOKIE]
        conn.request(method, path, body=data, headers=headers)
        response = conn.getresponse()
        raw = response.read()
        for name, value in response.getheaders():
            if name.lower() == "set-cookie":
                cookie, _, flags = value.partition(";")
                key, _, val = cookie.partition("=")
                if "Max-Age=0" in flags:
                    self.cookies.pop(key, None)
                else:
                    self.cookies[key] = val
        conn.close()
        return response.status, (json.loads(raw) if raw else {})

    def get(self, path):
        return self.request("GET", path)

    def post(self, path, body):
        return self.request("POST", path, body)


class ApiTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.data_dir = base / "data"
        self.data_dir.mkdir()
        self.root = base / "proj"
        self.root.mkdir()
        (self.root / "app.py").write_text("x = 1\n")
        self.previous_store = server.STORE
        server.STORE = Store(self.data_dir / "sniper-test.db")
        for patch in (
            mock.patch.object(server, "DATA_DIR", self.data_dir),
            mock.patch.object(server, "LIMITER", server.RateLimiter(limit=100000)),
            mock.patch.object(project_analyzer, "_allowed_roots", return_value=(base,)),
            mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(self.data_dir)}),
        ):
            patch.start()
            self.addCleanup(patch.stop)
        auth._MANAGERS.clear()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.port = self.httpd.server_address[1]
        make_audit(server.STORE, self.root, [finding("app.py")])
        self.tracked = tracked_ids(server.STORE, self.root)[0]
        self.base = f"/api/finding-tracking/{self.tracked}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        server.STORE = self.previous_store
        auth._MANAGERS.clear()

    def client(self) -> Client:
        return Client(self.port)

    def notices(self) -> list[dict]:
        return notifications.list_items(limit=100)["items"]


class ApiLoginDisabledTests(ApiTestBase):
    def test_free_text_owner_due_comments_and_assigned_view(self):
        c = self.client()
        self.assertEqual(c.post(f"{self.base}/assign", {"assignee_name": "Ali"})[0], 400)  # onay yok
        status, body = c.post(f"{self.base}/assign", {"confirm": True, "assignee_name": " Ali  Kaya "})
        self.assertEqual(status, 200, body)
        self.assertEqual(body["assignee_name"], "Ali Kaya")
        self.assertEqual([n["event"] for n in self.notices()], ["finding_assigned"])
        self.assertEqual(c.post(f"{self.base}/assign", {"confirm": True, "assignee_id": "usr_x"})[0], 400)
        self.assertEqual(c.post(f"{self.base}/assign", {"confirm": True, "x": 1})[0], 400)
        self.assertEqual(c.post("/api/finding-tracking/trk_yok/assign", {"confirm": True, "assignee_name": "A"})[0], 404)
        status, body = c.post(f"{self.base}/due", {"confirm": True, "due_date": "2020-01-01"})
        self.assertEqual(status, 200, body)
        self.assertTrue(body["overdue"])
        self.assertEqual(c.post(f"{self.base}/due", {"confirm": True, "due_date": "01.01.2020"})[0], 400)
        self.assertEqual(c.post(f"{self.base}/due", {"confirm": True})[0], 400)
        status, comment = c.post(f"{self.base}/comments", {"confirm": True, "body": "<img src=x onerror=alert(1)>"})
        self.assertEqual(status, 201, comment)
        self.assertEqual(comment["body"], "<img src=x onerror=alert(1)>")  # düz metin saklanır; arayüz textContent ile yazar
        self.assertEqual(c.post(f"{self.base}/comments", {"confirm": True, "body": "x" * 4001})[0], 400)
        detail = c.get(self.base)[1]
        self.assertEqual(len(detail["comments"]), 1)
        status, people = c.get("/api/finding-tracking/assignees")
        self.assertEqual((status, people["auth_enabled"], people["names"]), (200, False, ["Ali Kaya"]))
        status, mine = c.get("/api/finding-tracking/assigned?assignee=ali%20kaya&overdue=1")
        self.assertEqual((status, mine["total"], mine["overdue"]), (200, 1, 1))
        self.assertEqual(c.get("/api/finding-tracking/assigned?assignee=Veli")[1]["total"], 0)
        self.assertEqual(c.get("/api/finding-tracking/assigned")[1]["total"], 1)  # boş: tüm atananlar
        self.assertEqual(c.get("/api/finding-tracking/assigned?assignee=me")[0], 400)
        self.assertEqual(c.get("/api/finding-tracking/assigned?severity=x")[0], 400)
        status, _ = c.post(f"{self.base}/comments/{comment['id']}/delete", {"confirm": True})
        self.assertEqual(status, 200)
        self.assertEqual(c.post(f"{self.base}/comments/{comment['id']}/delete", {"confirm": True})[0], 404)
        self.assertEqual(c.post(f"{self.base}/comments/abc/delete", {"confirm": True})[0], 404)
        status, body = c.post(f"{self.base}/assign", {"confirm": True, "assignee_name": None})
        self.assertEqual((status, body["assignee_name"]), (200, ""))
        actions = [a for a, _ in audit_rows(server.STORE)]
        self.assertEqual(actions.count("tracked_finding.assigned"), 2)
        self.assertTrue(server.STORE.verify_audit_chain()["verified"])


class ApiLoginEnabledTests(ApiTestBase):
    def login(self, username: str, password: str) -> Client:
        c = self.client()
        status, body = c.post("/api/auth/login", {"username": username, "password": password})
        self.assertEqual(status, 200, body)
        return c

    def test_roles_assignment_by_user_and_comment_permissions(self):
        manager = auth.manager_for(self.data_dir)
        manager.create_admin_and_enable("yonetici", STRONG)
        admin = self.login("yonetici", STRONG)
        for name, role in (("okuyucu1", "reader"), ("analist1", "analyst"), ("analist2", "analyst")):
            self.assertEqual(admin.post("/api/auth/users", {"username": name, "password": STRONG + role, "role": role})[0], 201)
        reader = self.login("okuyucu1", STRONG + "reader")
        a1 = self.login("analist1", STRONG + "analyst")
        a2 = self.login("analist2", STRONG + "analyst")
        a1_id = manager.find_user_id("analist1")

        self.assertEqual(auth.required_level("POST", f"{self.base}/assign"), "analyst")
        self.assertEqual(auth.required_level("POST", f"{self.base}/comments/3/delete"), "analyst")
        self.assertEqual(auth.required_level("GET", "/api/finding-tracking/assigned"), "read")
        self.assertEqual(self.client().get("/api/finding-tracking/assigned")[0], 401)
        self.assertEqual(reader.get(self.base)[0], 200)
        self.assertEqual(reader.post(f"{self.base}/assign", {"confirm": True, "assignee_id": a1_id})[0], 403)
        self.assertEqual(reader.post(f"{self.base}/comments", {"confirm": True, "body": "x"})[0], 403)
        a1.send_csrf = False
        self.assertEqual(a1.post(f"{self.base}/assign", {"confirm": True, "assignee_id": a1_id})[0], 403)  # CSRF
        a1.send_csrf = True

        self.assertEqual(a1.post(f"{self.base}/assign", {"confirm": True, "assignee_name": "Ali"})[0], 400)
        self.assertEqual(a1.post(f"{self.base}/assign", {"confirm": True, "assignee_id": "usr_yok"})[0], 400)
        status, body = a2.post(f"{self.base}/assign", {"confirm": True, "assignee_id": a1_id})
        self.assertEqual(status, 200, body)
        self.assertEqual((body["assignee_id"], body["assignee_name"]), (a1_id, "analist1"))
        notice = self.notices()[0]
        self.assertEqual((notice["event"], notice["data"]["assignee_id"]), ("finding_assigned", a1_id))
        self.assertIn("analist2 tarafından", notice["message"])
        assigned = next(d for a, d in audit_rows(server.STORE) if a == "tracked_finding.assigned")
        self.assertEqual(assigned["actor"]["username"], "analist2")

        status, people = reader.get("/api/finding-tracking/assignees")
        self.assertTrue(people["auth_enabled"])
        self.assertEqual({u["username"] for u in people["users"]}, {"yonetici", "okuyucu1", "analist1", "analist2"})
        self.assertEqual(a1.get("/api/finding-tracking/assigned")[1]["total"], 1)  # varsayılan: bana atananlar
        self.assertEqual(a2.get("/api/finding-tracking/assigned")[1]["total"], 0)
        self.assertEqual(a2.get("/api/finding-tracking/assigned?assignee=all")[1]["total"], 1)
        self.assertEqual(a2.get(f"/api/finding-tracking/assigned?assignee={a1_id}")[1]["total"], 1)

        status, comment = a1.post(f"{self.base}/comments", {"confirm": True, "body": "Bakıyorum."})
        self.assertEqual(status, 201, comment)
        self.assertEqual((comment["author_id"], comment["author_name"]), (a1_id, "analist1"))
        self.assertEqual(a2.post(f"{self.base}/comments/{comment['id']}/delete", {"confirm": True})[0], 403)
        self.assertEqual(admin.post(f"{self.base}/comments/{comment['id']}/delete", {"confirm": True})[0], 200)
        own = a2.post(f"{self.base}/comments", {"confirm": True, "body": "kendi"})[1]
        self.assertEqual(a2.post(f"{self.base}/comments/{own['id']}/delete", {"confirm": True})[0], 200)
        self.assertEqual(a1.post(f"{self.base}/due", {"confirm": True, "due_date": "2099-12-31"})[0], 200)
        self.assertTrue(server.STORE.verify_audit_chain()["verified"])


if __name__ == "__main__":
    unittest.main()
