"""Portföy, SLA ve dışa aktarım (17. tur): SLA politikası, yeni bulguya otomatik son tarih, risk kabulü bitişi ve
yeniden açma, SLA ihlali bildirimi, MTTR/eğilim/risk puanı, DefectDojo/Jira/CSV dışa aktarımı (formül enjeksiyonu),
rol/CSRF kapısı ve eski veritabanının şema yükseltmesi."""
from __future__ import annotations

import csv
import datetime as dt
import http.client
import io
import json
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
import threading
import unittest
from unittest import mock

from http.server import ThreadingHTTPServer

import auth
import finding_tracking as ft
import notifications
import portfolio
import project_analyzer
import server
from storage import Store

STRONG = "doğru-at-pil-zımba-42"


def finding(file="app.py", line=10, title="Doğrulanmış veri akışı: istek girdisi SQL sorgusuna ulaşıyor (SQL enjeksiyonu)",
            severity="critical", reference="CWE-89"):
    return {"category": "data_query", "severity": severity, "reference": reference, "file": file, "line": line,
            "title": title, "evidence": "Hassas değer kaydedilmedi.", "recommendation": "Parametre bağlayın."}


def make_audit(store: Store, root: Path, findings: list[dict], when: str = "2026-10-01T10:00:00Z") -> dict:
    return store.create_project_audit({
        "created_at": when, "project_path": str(root), "project_name": root.name, "score": 60, "grade": "D",
        "file_count": 2, "bytes_scanned": 10, "findings": findings, "scope": {}, "skipped_files": {},
    })


def audit_actions(store: Store) -> list[str]:
    with sqlite3.connect(store.path) as db:
        return [row[0] for row in db.execute("SELECT action FROM audit_log ORDER BY id")]


class _Env(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.data_dir = base / "data"
        self.data_dir.mkdir()
        self.root = base / "proj"
        self.root.mkdir()
        for name in ("app.py", "views.py", "lib.py"):
            (self.root / name).write_text("x = 1\n")
        env = mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(self.data_dir)})
        env.start()
        self.addCleanup(env.stop)
        self.store = Store(self.data_dir / "sniper.db")

    def ids(self) -> dict[str, str]:
        return {item["file"]: item["id"] for item in self.store.list_tracked_findings(str(self.root))}


class PolicyTests(_Env):
    def test_defaults_validation_and_private_file(self):
        policy, custom = portfolio.load_policy()
        self.assertFalse(custom)
        self.assertEqual(policy["days"], {"critical": 7, "high": 30, "medium": 90, "low": 180, "info": None})
        self.assertFalse(policy["auto_due_date"])
        for bad in ([], {"x": 1}, {"days": {"critical": 0}}, {"days": {"critical": "7"}}, {"days": {"nope": 3}},
                    {"days": {"critical": 60, "high": 30}}, {"auto_due_date": 1}, {"risk_acceptance_days": -1},
                    {"risk_acceptance_days": 99999}, {"days": {"critical": True}}):
            with self.subTest(bad=bad), self.assertRaises(portfolio.PolicyError):
                portfolio.validate_policy(bad)
        saved = portfolio.save_policy({"days": {"critical": 3, "high": 14, "medium": None, "low": None},
                                       "auto_due_date": True, "risk_acceptance_days": 60})
        self.assertEqual(portfolio.load_policy(), (saved, True))
        mode = stat.S_IMODE(os.stat(self.data_dir / portfolio.POLICY_FILE).st_mode)
        self.assertEqual(mode, 0o600)
        (self.data_dir / portfolio.POLICY_FILE).write_text("{bozuk")
        self.assertEqual(portfolio.load_policy()[1], False)
        self.assertEqual(portfolio.reset_policy()["days"]["critical"], 7)


class SchemaUpgradeTests(unittest.TestCase):
    def test_old_database_gets_new_columns_without_touching_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "eski.db"
            with sqlite3.connect(path) as db:
                db.executescript(ft.SCHEMA)
                db.execute("INSERT INTO tracked_findings(id, project_path, fingerprint, status, severity, category, reference, "
                           "title, file, line, first_seen_at, first_audit_id, last_seen_at, last_audit_id, finding_json) "
                           "VALUES ('trk_eski', '/p', 'fp', 'risk_accepted', 'high', 'c', 'CWE-1', 't', 'a.py', 3, 'x', 'prj_1', 'x', 'prj_1', '{}')")
            Store(path)
            Store(path)  # ikinci açılış: ALTER tekrarlanmaz
            with sqlite3.connect(path) as db:
                db.row_factory = sqlite3.Row
                columns = {row[1] for row in db.execute("PRAGMA table_info(tracked_findings)")}
                self.assertTrue({"risk_expires_at", "sla_notice"} <= columns)
                row = db.execute("SELECT * FROM tracked_findings WHERE id = 'trk_eski'").fetchone()
                self.assertEqual((row["status"], row["risk_expires_at"], row["sla_notice"]), ("risk_accepted", None, ""))


class AutoDueAndRiskTests(_Env):
    def test_auto_due_date_only_when_policy_enabled(self):
        make_audit(self.store, self.root, [finding("app.py")], "2026-10-01T10:00:00Z")
        self.assertIsNone(self.store.list_tracked_findings(str(self.root))[0]["due_date"])
        portfolio.save_policy({"days": {"critical": 7, "high": 30, "medium": 90, "low": 180}, "auto_due_date": True})
        make_audit(self.store, self.root, [finding("app.py"), finding("views.py", severity="medium", title="Orta bulgu")],
                   "2026-10-02T10:00:00Z")
        items = {item["file"]: item for item in self.store.list_tracked_findings(str(self.root))}
        self.assertIsNone(items["app.py"]["due_date"])  # eski bulgu: değişmez
        self.assertEqual(items["views.py"]["due_date"], "2026-12-31")  # 2 Ekim + 90 gün
        events = [e["event"] for e in self.store.get_tracked_finding(items["views.py"]["id"])["events"]]
        self.assertEqual(events, ["new", "due_changed"])
        # Uygula: son tarihi olmayan etkin bulguya ilk görülme + SLA
        result = self.store.apply_sla_due_dates(portfolio.load_policy()[0])
        self.assertEqual(result["updated"], 1)
        self.assertEqual(self.store.list_tracked_findings(str(self.root), {"open"})[0]["due_date"] or "",
                         self.store.get_tracked_finding(items["app.py"]["id"])["due_date"])
        self.assertEqual(self.store.get_tracked_finding(items["app.py"]["id"])["due_date"], "2026-10-08")
        self.assertIn("tracked_finding.sla_due_applied", audit_actions(self.store))

    def test_risk_acceptance_expiry_validation_default_and_reopen(self):
        make_audit(self.store, self.root, [finding("app.py"), finding("views.py", severity="low", title="Düşük")])
        ids = self.ids()
        today = ft.today_local()
        later = (today + dt.timedelta(days=10)).isoformat()
        for bad in ("2020-01-01", today.isoformat(), "10.10.2030", "2099-01-01", "2030-02-30"):
            with self.subTest(bad=bad), self.assertRaises(ft.TrackingError):
                self.store.set_tracked_finding_status(ids["app.py"], "risk_accepted", "", bad)
        with self.assertRaises(ft.TrackingError):
            self.store.set_tracked_finding_status(ids["app.py"], "false_positive", "", later)
        item = self.store.set_tracked_finding_status(ids["app.py"], "risk_accepted", "geçici", later)
        self.assertEqual(item["risk_expires_at"], later)
        # politika varsayılanı: süre verilmezse bugün + gün
        portfolio.save_policy({"risk_acceptance_days": 30})
        item = self.store.set_tracked_finding_status(ids["views.py"], "risk_accepted", "", None)
        self.assertEqual(item["risk_expires_at"], (today + dt.timedelta(days=30)).isoformat())
        # başka duruma geçince bitiş silinir
        item = self.store.set_tracked_finding_status(ids["views.py"], "open", "", None)
        self.assertIsNone(item["risk_expires_at"])
        # süre dolunca yeniden açılır (tarih bugün ya da geçmişte)
        self.assertEqual(self.store.expire_risk_acceptances(today), [])
        expired = self.store.expire_risk_acceptances(today + dt.timedelta(days=10))
        self.assertEqual([e["id"] for e in expired], [ids["app.py"]])
        detail = self.store.get_tracked_finding(ids["app.py"])
        self.assertEqual((detail["status"], detail["risk_expires_at"]), ("reopened", None))
        self.assertEqual(detail["events"][-1]["event"], "risk_expired")
        self.assertIn("tracked_finding.risk_expired", audit_actions(self.store))
        self.assertTrue(self.store.verify_audit_chain()["verified"])

    def test_triage_acceptance_gets_policy_default_expiry(self):
        audit = make_audit(self.store, self.root, [finding("app.py")])
        portfolio.save_policy({"risk_acceptance_days": 14})
        self.store.update_project_audit_finding_triage(audit["id"], 0, disposition="accepted_risk", note="")
        item = self.store.list_tracked_findings(str(self.root))[0]
        self.assertEqual((item["status"], item["risk_expires_at"]),
                         ("risk_accepted", (ft.today_local() + dt.timedelta(days=14)).isoformat()))


class OverviewTests(_Env):
    def test_counts_sla_mttr_trend_and_risk_order(self):
        other = Path(self.tmp.name) / "diger"
        other.mkdir()
        (other / "a.py").write_text("x = 1\n")
        today = ft.today_local()
        old = (today - dt.timedelta(days=40)).isoformat() + "T10:00:00Z"
        recent = (today - dt.timedelta(days=3)).isoformat() + "T10:00:00Z"
        make_audit(self.store, self.root, [finding("app.py"), finding("views.py", severity="medium", title="Orta"),
                                           finding("lib.py", severity="low", title="Düşük")], old)
        # ikinci analiz: lib.py düzeldi, app.py ve views.py sürüyor
        make_audit(self.store, self.root, [finding("app.py"), finding("views.py", severity="medium", title="Orta")], recent)
        make_audit(self.store, other, [finding("a.py", severity="low", title="Diğer düşük")], recent)
        policy = portfolio.load_policy()[0]
        data = self.store.portfolio_overview(policy, weeks=8)
        self.assertEqual(data["totals"]["projects"], 2)
        first = data["projects"][0]
        self.assertEqual(first["project_path"], str(self.root))  # kritik bulgu: en riskli
        self.assertEqual(first["active_by_severity"]["critical"], 1)
        self.assertEqual(first["sla_breached"], 1)  # kritik: 40 gün > 7 gün; orta: 40 < 90
        self.assertEqual(first["fixed"], 1)
        self.assertEqual(first["fixed_recent"], 1)
        self.assertAlmostEqual(first["mttr_days"], 37.0, delta=0.1)
        self.assertEqual(first["risk_score"], 10 + 2 + 2.0)  # kritik + orta + ihlal ağırlığı
        self.assertEqual(data["top_risk"][0], str(self.root))
        self.assertEqual(data["sla"]["active_breached"], 1)
        self.assertEqual(data["sla"]["fixed_within_sla_ratio"], 1.0)  # düşük: 37 gün ≤ 180
        self.assertEqual(data["mttr"]["by_severity"]["low"]["count"], 1)
        trend = data["trend"]
        self.assertEqual(len(trend), 8)
        self.assertEqual(trend[-1]["week_end"], today.isoformat())
        self.assertEqual(sum(w["fixed"] for w in trend), 1)
        self.assertEqual(sum(w["new"] for w in trend), 4)  # 40 gün önce 3 (8 haftalık pencere içinde) + diğer projede 1
        old_week = [w for w in trend if w["new"] == 3]
        self.assertEqual(len(old_week), 1)
        self.assertEqual(trend[-1]["active"], 3)

    def test_trend_counts_week_of_event(self):
        today = ft.today_local()
        when = (today - dt.timedelta(days=8)).isoformat() + "T10:00:00Z"
        make_audit(self.store, self.root, [finding("app.py")], when)
        trend = self.store.portfolio_overview(portfolio.load_policy()[0], weeks=3)["trend"]
        self.assertEqual([w["new"] for w in trend], [0, 1, 0])
        self.assertEqual([w["active"] for w in trend], [0, 1, 1])


class SlaNotificationTests(_Env):
    def test_breach_notified_once_and_risk_expiry_notified(self):
        today = ft.today_local()
        old = (today - dt.timedelta(days=20)).isoformat() + "T10:00:00Z"
        make_audit(self.store, self.root, [finding("app.py"), finding("views.py", severity="low", title="Düşük")], old)
        ids = self.ids()
        self.store.set_tracked_finding_status(ids["views.py"], "risk_accepted", "", (today + dt.timedelta(days=1)).isoformat())
        out = notifications.check_sla(self.store)
        self.assertEqual([b["id"] for b in out["breached"]], [ids["app.py"]])
        self.assertEqual(out["expired"], [])
        self.assertEqual([n["event"] for n in notifications.list_items()["items"]], ["sla_breach"])
        again = notifications.check_sla(self.store)
        self.assertEqual((again["breached"], again["notices"]), ([], []))  # aynı SLA günü için bir kez
        tomorrow = dt.datetime.combine(today + dt.timedelta(days=1), dt.time(12), tzinfo=dt.timezone.utc)
        later = notifications.check_sla(self.store, now=tomorrow)
        self.assertEqual([e["id"] for e in later["expired"]], [ids["views.py"]])
        self.assertIn("risk_expired", [n["event"] for n in notifications.list_items()["items"]])
        # açık son tarihi olan bulgu SLA ihlali olarak ayrıca bildirilmez (finding_due bildirir)
        self.store.set_tracked_finding_due(ids["app.py"], "2020-01-01")
        self.assertEqual(self.store.sla_breach_candidates(portfolio.load_policy()[0], today), [])

    def test_disabled_event_type_still_reopens_expired_acceptance(self):
        make_audit(self.store, self.root, [finding("app.py")])
        tracked = self.ids()["app.py"]
        today = ft.today_local()
        self.store.set_tracked_finding_status(tracked, "risk_accepted", "", (today + dt.timedelta(days=1)).isoformat())
        notifications.save_settings({"events": {"risk_expired": {"enabled": False}, "sla_breach": {"enabled": False}}})
        later = dt.datetime.combine(today + dt.timedelta(days=2), dt.time(12), tzinfo=dt.timezone.utc)
        out = notifications.check_sla(self.store, now=later)
        self.assertEqual(len(out["expired"]), 1)
        self.assertEqual(out["notices"], [])
        self.assertEqual(self.store.get_tracked_finding(tracked)["status"], "reopened")


class ExportFormatTests(_Env):
    def setUp(self):
        super().setUp()
        make_audit(self.store, self.root, [
            finding("app.py"),
            finding("views.py", severity="medium", title="=HYPERLINK(\"http://x\",\"tıkla\")", reference="CWE-79"),
            finding("lib.py", severity="low", title="@SUM(1+1)", reference=""),
        ])
        ids = self.ids()
        self.store.set_tracked_finding_status(ids["lib.py"], "false_positive", "-2+3 nedeni", None)
        self.store.assign_tracked_finding(ids["app.py"], None, "+Ali")

    def rows(self, statuses):
        return self.store.portfolio_export_rows(portfolio.load_policy()[0], project_path=None, statuses=statuses)

    def test_defectdojo_json(self):
        body, ctype, ext = portfolio.render_export("defectdojo", self.rows(set(ft.STATUSES)))
        self.assertEqual((ctype.split(";")[0], ext), ("application/json", "json"))
        data = json.loads(body)
        by_title = {f["title"]: f for f in data["findings"]}
        crit = next(f for f in data["findings"] if f["severity"] == "Critical")
        self.assertEqual((crit["cwe"], crit["file_path"], crit["line"], crit["active"], crit["static_finding"]),
                         (89, "app.py", 10, True, True))
        self.assertTrue(crit["unique_id_from_tool"])
        self.assertIn("sla_expiration_date", crit)
        fp = by_title["@SUM(1+1)"]
        self.assertEqual((fp["false_p"], fp["active"], fp["severity"]), (True, False, "Low"))
        self.assertNotIn("cwe", fp)

    def test_jira_and_plain_csv_escape_formulas(self):
        body, ctype, ext = portfolio.render_export("jira", self.rows(set(ft.ACTIVE_STATUSES)))
        text = body.decode("utf-8").lstrip("﻿")
        rows = list(csv.reader(io.StringIO(text)))
        self.assertEqual(rows[0][:4], ["Summary", "Issue Type", "Priority", "Description"])
        self.assertEqual(rows[0].count("Labels"), 2)
        priorities = sorted(r[2] for r in rows[1:])
        self.assertEqual(priorities, ["Highest", "Medium"])
        owner = [r[7] for r in rows[1:] if r[2] == "Highest"][0]
        self.assertEqual(owner, "'+Ali")
        body, _ctype, _ext = portfolio.render_export("csv", self.rows(set(ft.STATUSES)))
        rows = list(csv.reader(io.StringIO(body.decode("utf-8").lstrip("﻿"))))
        header = rows[0]
        titles = [r[header.index("title")] for r in rows[1:]]
        self.assertIn("'=HYPERLINK(\"http://x\",\"tıkla\")", titles)
        self.assertIn("'@SUM(1+1)", titles)
        notes = [r[header.index("status_note")] for r in rows[1:]]
        self.assertIn("'-2+3 nedeni", notes)
        for row in rows[1:]:
            for cell in row:
                self.assertFalse(cell[:1] in {"=", "+", "-", "@"}, cell)
        with self.assertRaises(ft.TrackingError):
            portfolio.render_export("xml", [])
        with self.assertRaises(ft.TrackingError):
            portfolio.parse_status_filter("open,bozuk")
        self.assertEqual(portfolio.parse_status_filter("suppressed"), {"risk_accepted", "false_positive"})


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------
class Client:
    def __init__(self, port: int):
        self.port = port
        self.cookies: dict[str, str] = {}
        self.send_csrf = True

    def raw(self, method: str, path: str, body=None):
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
        headers = dict(response.getheaders())
        conn.close()
        return response.status, headers, raw

    def get(self, path):
        status, _headers, raw = self.raw("GET", path)
        return status, (json.loads(raw) if raw else {})

    def post(self, path, body):
        status, _headers, raw = self.raw("POST", path, body)
        return status, (json.loads(raw) if raw else {})


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
        make_audit(server.STORE, self.root, [finding("app.py")], "2026-09-01T10:00:00Z")
        self.tracked = server.STORE.list_tracked_findings(str(self.root))[0]["id"]

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        server.STORE = self.previous_store
        auth._MANAGERS.clear()


class ApiLoginDisabledTests(ApiTestBase):
    def test_overview_policy_apply_status_expiry_and_export(self):
        c = Client(self.port)
        status, data = c.get("/api/portfolio")
        self.assertEqual(status, 200, data)
        self.assertEqual((data["totals"]["projects"], data["totals"]["sla_breached"]), (1, 1))
        self.assertEqual(c.get("/api/portfolio?weeks=0")[0], 400)
        self.assertEqual(c.get("/api/portfolio?weeks=abc")[0], 400)
        status, pol = c.get("/api/portfolio/sla-policy")
        self.assertEqual((status, pol["customized"]), (200, False))
        self.assertEqual(c.post("/api/portfolio/sla-policy", {"policy": {}})[0], 400)  # onay yok
        self.assertEqual(c.post("/api/portfolio/sla-policy", {"confirm": True})[0], 400)
        self.assertEqual(c.post("/api/portfolio/sla-policy", {"confirm": True, "policy": {"days": {"critical": 0}}})[0], 400)
        status, pol = c.post("/api/portfolio/sla-policy", {"confirm": True, "policy": {"risk_acceptance_days": 15}})
        self.assertEqual((status, pol["customized"], pol["policy"]["risk_acceptance_days"]), (200, True, 15))
        status, applied = c.post("/api/portfolio/sla-policy/apply", {"confirm": True})
        self.assertEqual((status, applied["updated"]), (200, 1))
        self.assertEqual(c.post("/api/portfolio/sla-policy/apply", {"confirm": True, "x": 1})[0], 400)
        later = (dt.date.today() + dt.timedelta(days=20)).isoformat()
        status, item = c.post(f"/api/finding-tracking/{self.tracked}/status",
                              {"confirm": True, "status": "risk_accepted", "expires_at": later})
        self.assertEqual((status, item.get("risk_expires_at")), (200, later), item)
        self.assertEqual(c.post(f"/api/finding-tracking/{self.tracked}/status",
                                {"confirm": True, "status": "risk_accepted", "expires_at": "2001-01-01"})[0], 400)
        status, headers, raw = c.raw("GET", "/api/portfolio/export?format=csv&status=all")
        self.assertEqual(status, 200)
        self.assertIn("attachment", headers.get("Content-Disposition", ""))
        self.assertTrue(headers.get("Content-Type", "").startswith("text/csv"))
        self.assertIn("risk_expires_at", raw.decode("utf-8"))
        status, headers, raw = c.raw("GET", f"/api/portfolio/export?format=defectdojo&project_path={self.root}")
        self.assertEqual((status, json.loads(raw)["findings"]), (200, []))  # risk kabulü etkin değil
        self.assertEqual(c.get("/api/portfolio/export?format=pdf")[0], 400)
        self.assertEqual(c.get("/api/portfolio/export?format=csv&status=bozuk")[0], 400)
        status, _ = c.post("/api/portfolio/sla-policy", {"confirm": True, "reset": True})
        self.assertEqual(status, 200)
        actions = audit_actions(server.STORE)
        for action in ("sla_policy.changed", "tracked_finding.sla_due_applied", "portfolio.exported"):
            self.assertIn(action, actions)
        self.assertTrue(server.STORE.verify_audit_chain()["verified"])


class ApiLoginEnabledTests(ApiTestBase):
    def login(self, username: str, password: str) -> Client:
        c = Client(self.port)
        status, body = c.post("/api/auth/login", {"username": username, "password": password})
        self.assertEqual(status, 200, body)
        return c

    def test_roles_and_csrf(self):
        self.assertEqual(auth.required_level("GET", "/api/portfolio"), "read")
        self.assertEqual(auth.required_level("GET", "/api/portfolio/sla-policy"), "read")
        self.assertEqual(auth.required_level("GET", "/api/portfolio/export"), "analyst")
        self.assertEqual(auth.required_level("POST", "/api/portfolio/sla-policy"), "admin")
        self.assertEqual(auth.required_level("POST", "/api/portfolio/sla-policy/apply"), "admin")
        manager = auth.manager_for(self.data_dir)
        manager.create_admin_and_enable("yonetici", STRONG)
        admin = self.login("yonetici", STRONG)
        for name, role in (("okuyucu1", "reader"), ("analist1", "analyst")):
            self.assertEqual(admin.post("/api/auth/users", {"username": name, "password": STRONG + role, "role": role})[0], 201)
        reader = self.login("okuyucu1", STRONG + "reader")
        analyst = self.login("analist1", STRONG + "analyst")
        self.assertEqual(Client(self.port).get("/api/portfolio")[0], 401)
        self.assertEqual(reader.get("/api/portfolio")[0], 200)
        self.assertEqual(reader.get("/api/portfolio/sla-policy")[0], 200)
        self.assertEqual(reader.raw("GET", "/api/portfolio/export?format=csv")[0], 403)
        self.assertEqual(analyst.raw("GET", "/api/portfolio/export?format=jira")[0], 200)
        self.assertEqual(analyst.post("/api/portfolio/sla-policy", {"confirm": True, "reset": True})[0], 403)
        self.assertEqual(analyst.post("/api/portfolio/sla-policy/apply", {"confirm": True})[0], 403)
        admin.send_csrf = False
        self.assertEqual(admin.post("/api/portfolio/sla-policy", {"confirm": True, "reset": True})[0], 403)
        admin.send_csrf = True
        self.assertEqual(admin.post("/api/portfolio/sla-policy", {"confirm": True, "reset": True})[0], 200)
        self.assertEqual(admin.post("/api/portfolio/sla-policy/apply", {"confirm": True})[0], 200)
        later = (dt.date.today() + dt.timedelta(days=5)).isoformat()
        self.assertEqual(reader.post(f"/api/finding-tracking/{self.tracked}/status",
                                     {"confirm": True, "status": "risk_accepted", "expires_at": later})[0], 403)
        self.assertEqual(analyst.post(f"/api/finding-tracking/{self.tracked}/status",
                                      {"confirm": True, "status": "risk_accepted", "expires_at": later})[0], 200)


class SchedulerHookTests(ApiTestBase):
    def test_periodic_due_check_runs_sla_check(self):
        with mock.patch.object(notifications, "check_sla", wraps=notifications.check_sla) as spy:
            server._due_date_check(dt.datetime.now(dt.timezone.utc))
        spy.assert_called_once()
        self.assertEqual([n["event"] for n in notifications.list_items()["items"]], ["sla_breach"])


if __name__ == "__main__":
    unittest.main()
