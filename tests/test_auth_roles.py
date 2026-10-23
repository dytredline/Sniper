"""İsteğe bağlı arayüz girişi: kapalıyken eski davranış, kurulum, oturum, CSRF, roller, kilitleme, TOTP,
denetim kaydında kullanıcı, iş kuyruğu yetki bağlamı ve uzak dinleme koşulu."""
from __future__ import annotations

import http.client
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest import mock

from http.server import ThreadingHTTPServer

import auth
import auth_routes
import mcp_scan_requests
import project_analyzer
import request_context
import server
from scanner import normalize_target
from storage import Store

STRONG = "doğru-at-pil-zımba-42"
VULN = 'import os\nfrom flask import request\n\ndef run():\n    os.system("ping " + request.args["h"])\n'


class Client:
    """Çerezleri saklayan basit istemci; CSRF çerezini başlık olarak geri yollar."""

    def __init__(self, port: int):
        self.port = port
        self.cookies: dict[str, str] = {}
        self.send_csrf = True
        self.last_headers: list[tuple[str, str]] = []

    def request(self, method: str, path: str, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        hdrs = {"Host": f"127.0.0.1:{self.port}"}
        if self.cookies:
            hdrs["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            hdrs["Content-Type"] = "application/json"
            if self.send_csrf and auth.CSRF_COOKIE in self.cookies:
                hdrs[auth.CSRF_HEADER] = self.cookies[auth.CSRF_COOKIE]
        hdrs.update(headers or {})
        conn.request(method, path, body=data, headers=hdrs)
        response = conn.getresponse()
        raw = response.read()
        self.last_headers = response.getheaders()
        for name, value in self.last_headers:
            if name.lower() == "set-cookie":
                cookie, _, flags = value.partition(";")
                key, _, val = cookie.partition("=")
                if "Max-Age=0" in flags:
                    self.cookies.pop(key, None)
                else:
                    self.cookies[key] = val
        conn.close()
        try:
            payload = json.loads(raw) if raw else {}
        except ValueError:
            payload = {"_raw": raw[:200]}
        return response.status, payload

    def get(self, path):
        return self.request("GET", path)

    def post(self, path, body):
        return self.request("POST", path, body)


class AuthTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.data_dir = base / "data"
        self.data_dir.mkdir()
        self.project = base / "proj"
        self.project.mkdir()
        (self.project / "app.py").write_text(VULN)
        self.previous_store = server.STORE
        server.STORE = Store(self.data_dir / "sniper-test.db")
        for patch in (
            mock.patch.object(server, "DATA_DIR", self.data_dir),
            mock.patch.object(project_analyzer, "_allowed_roots", return_value=(base,)),
            mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(self.data_dir)}),
        ):
            patch.start()
            self.addCleanup(patch.stop)
        auth._MANAGERS.clear()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.port = self.httpd.server_address[1]

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        server.STORE = self.previous_store

    def client(self) -> Client:
        return Client(self.port)

    def manager(self) -> auth.AuthManager:
        return auth.manager_for(self.data_dir)

    def enable_with_admin(self) -> Client:
        self.manager().create_admin_and_enable("yonetici", STRONG)
        admin = self.client()
        status, body = admin.post("/api/auth/login", {"username": "yonetici", "password": STRONG})
        self.assertEqual(status, 200, body)
        return admin

    def add_user(self, admin: Client, username: str, role: str) -> Client:
        status, body = admin.post("/api/auth/users", {"username": username, "password": STRONG + role, "role": role})
        self.assertEqual(status, 201, body)
        user = self.client()
        status, body = user.post("/api/auth/login", {"username": username, "password": STRONG + role})
        self.assertEqual(status, 200, body)
        return user

    def audit_rows(self):
        with sqlite3.connect(server.STORE.path) as db:
            return [(a, json.loads(d)) for a, d in db.execute("SELECT action, details_json FROM audit_log ORDER BY id")]


class DisabledByDefaultTests(AuthTestBase):
    def test_nothing_changes_and_no_file_is_created(self):
        c = self.client()
        self.assertEqual(c.get("/api/auth/status")[1]["enabled"], False)
        self.assertEqual(c.get("/api/dashboard")[0], 200)
        self.assertEqual(c.get("/")[0], 200)
        self.assertEqual(c.post("/api/project-audits", {"project_path": str(self.project)})[0], 201)
        self.assertEqual(c.post("/api/auth/login", {"username": "x", "password": "y"})[0], 409)
        self.assertEqual(c.post("/api/auth/users", {"username": "abc", "password": STRONG, "role": "admin"})[0], 409)
        self.assertFalse((self.data_dir / auth.AUTH_DB_NAME).exists())
        self.assertTrue(all("actor" not in d for _a, d in self.audit_rows()))


class SetupAndSessionTests(AuthTestBase):
    def test_setup_token_flow(self):
        c = self.client()
        self.assertEqual(c.post("/api/auth/setup/begin", {})[0], 403)  # açık onay yok
        status, body = c.post("/api/auth/setup/begin", {"confirm": True})
        self.assertEqual(status, 200)
        token_file = Path(body["token_file"])
        self.assertEqual(os.stat(token_file).st_mode & 0o777, 0o600)
        self.assertNotIn("token", body)
        token = json.loads(token_file.read_text())["token"]
        self.assertEqual(c.post("/api/auth/setup/complete", {"token": "yanlis", "username": "yonetici", "password": STRONG})[0], 401)
        self.assertEqual(c.post("/api/auth/setup/complete", {"token": token, "username": "yonetici", "password": "kisa"})[0], 400)
        status, body = c.post("/api/auth/setup/complete", {"token": token, "username": "yonetici", "password": STRONG})
        self.assertEqual(status, 201, body)
        cookies = [v for k, v in c.last_headers if k.lower() == "set-cookie"]
        session_cookie = next(v for v in cookies if v.startswith(auth.SESSION_COOKIE + "="))
        self.assertIn("HttpOnly", session_cookie)
        self.assertIn("SameSite=Strict", session_cookie)
        self.assertFalse(token_file.exists())
        self.assertEqual(os.stat(self.data_dir / auth.AUTH_DB_NAME).st_mode & 0o777, 0o600)
        self.assertTrue(c.get("/api/auth/status")[1]["authenticated"])
        self.assertEqual(c.post("/api/auth/setup/begin", {"confirm": True})[0], 409)
        enabled = [d for a, d in self.audit_rows() if a == "auth.enabled"]
        self.assertEqual(enabled[0]["actor"]["username"], "yonetici")
        self.assertNotIn(STRONG, json.dumps(self.audit_rows(), ensure_ascii=False))

    def test_enabled_requires_session(self):
        self.manager().create_admin_and_enable("yonetici", STRONG)
        c = self.client()
        self.assertEqual(c.get("/api/dashboard")[0], 401)
        self.assertEqual(c.post("/api/project-audits", {"project_path": str(self.project)})[0], 401)
        status, _ = c.get("/")
        self.assertEqual(status, 302)
        self.assertIn(("Location", "/login.html"), c.last_headers)
        self.assertEqual(c.get("/login.html")[0], 200)
        self.assertEqual(c.get("/auth.css")[0], 200)
        self.assertEqual(c.get("/app.js")[0], 302)
        self.assertEqual(c.get("/api/health")[0], 200)
        self.assertEqual(c.get("/api/auth/status")[1], {**c.get("/api/auth/status")[1], "enabled": True, "authenticated": False})
        c.cookies[auth.SESSION_COOKIE] = "uydurma"
        self.assertEqual(c.get("/api/dashboard")[0], 401)

    def test_login_logout_and_csrf(self):
        admin = self.enable_with_admin()
        self.assertEqual(admin.get("/api/dashboard")[0], 200)
        admin.send_csrf = False
        self.assertEqual(admin.post("/api/scan-scope", {"confirm": True, "scope": {}})[0], 403)
        admin.send_csrf = True
        self.assertEqual(admin.post("/api/scan-scope", {"confirm": True, "scope": {}})[0], 200)
        stolen = dict(admin.cookies)
        self.assertEqual(admin.post("/api/auth/logout", {})[0], 200)
        replay = self.client()
        replay.cookies = stolen
        self.assertEqual(replay.get("/api/dashboard")[0], 401)

    def test_session_idle_and_absolute_expiry(self):
        admin = self.enable_with_admin()
        with sqlite3.connect(self.data_dir / auth.AUTH_DB_NAME) as db:
            db.execute("UPDATE auth_sessions SET last_seen = last_seen - ?", (auth.session_idle_seconds() + 5,))
        self.assertEqual(admin.get("/api/dashboard")[0], 401)
        admin = self.client()
        admin.post("/api/auth/login", {"username": "yonetici", "password": STRONG})
        with sqlite3.connect(self.data_dir / auth.AUTH_DB_NAME) as db:
            db.execute("UPDATE auth_sessions SET created_at = created_at - ?", (auth.session_max_seconds() + 5,))
        self.assertEqual(admin.get("/api/dashboard")[0], 401)

    def test_lockout_and_ip_limit(self):
        self.manager().create_admin_and_enable("yonetici", STRONG)
        c = self.client()
        for _ in range(auth.LOCK_THRESHOLD):
            self.assertEqual(c.post("/api/auth/login", {"username": "yonetici", "password": "yanlis-parola-123"})[0], 401)
        self.assertEqual(c.post("/api/auth/login", {"username": "yonetici", "password": STRONG})[0], 429)
        user_id = self.manager().find_user_id("yonetici")
        self.manager().update_user(user_id, unlock=True)
        self.assertEqual(c.post("/api/auth/login", {"username": "yonetici", "password": STRONG})[0], 200)
        # Olmayan kullanıcı ile aynı hata (kullanıcı adı sızmaz).
        status, body = c.post("/api/auth/login", {"username": "olmayan", "password": STRONG})
        self.assertEqual((status, body["error"]), (401, "Kullanıcı adı veya parola hatalı."))
        failed = [d for a, d in self.audit_rows() if a == "auth.login_failed"]
        self.assertTrue(failed and all("password" not in d for d in failed))

    def test_password_change_and_role_change_revoke_sessions(self):
        admin = self.enable_with_admin()
        analyst = self.add_user(admin, "analist1", "analyst")
        other = self.client()
        other.post("/api/auth/login", {"username": "analist1", "password": STRONG + "analyst"})
        status, _ = analyst.post("/api/auth/password", {"current_password": STRONG + "analyst", "new_password": STRONG + "yeni"})
        self.assertEqual(status, 200)
        self.assertEqual(analyst.get("/api/dashboard")[0], 200)  # bu tarayıcı yeni oturum aldı
        self.assertEqual(other.get("/api/dashboard")[0], 401)
        user_id = self.manager().find_user_id("analist1")
        self.assertEqual(admin.post(f"/api/auth/users/{user_id}", {"role": "reader"})[0], 200)
        self.assertEqual(analyst.get("/api/dashboard")[0], 401)


class RoleTests(AuthTestBase):
    def test_policy_table(self):
        self.assertEqual(auth.required_level("GET", "/api/dashboard"), "read")
        self.assertEqual(auth.required_level("GET", "/api/auth/users"), "admin")
        self.assertEqual(auth.required_level("GET", "/api/mcp-scan-requests"), "admin")
        self.assertEqual(auth.required_level("POST", "/api/project-audits"), "analyst")
        self.assertEqual(auth.required_level("POST", "/api/project-audits/x/findings/0/triage"), "analyst")
        self.assertEqual(auth.required_level("POST", "/api/business-logic/audit"), "analyst")
        self.assertEqual(auth.required_level("POST", "/api/tool-runs/semgrep"), "admin")
        self.assertEqual(auth.required_level("POST", "/api/sandbox-targets"), "admin")
        self.assertEqual(auth.required_level("POST", "/api/yeni/bilinmeyen-rota"), "admin")  # güvenli varsayılan
        self.assertEqual(auth.required_level("POST", "/api/finding-tracking/backfill"), "admin")
        self.assertEqual(auth.required_level("POST", "/api/auth/password"), "self")

    def test_reader_analyst_admin(self):
        admin = self.enable_with_admin()
        reader = self.add_user(admin, "okuyucu1", "reader")
        analyst = self.add_user(admin, "analist1", "analyst")
        for c in (reader, analyst, admin):
            self.assertEqual(c.get("/api/dashboard")[0], 200)
            self.assertEqual(c.get("/api/auth/me")[0], 200)
        self.assertEqual(reader.post("/api/project-audits", {"project_path": str(self.project)})[0], 403)
        self.assertEqual(reader.get("/api/auth/users")[0], 403)
        status, audit = analyst.post("/api/project-audits", {"project_path": str(self.project)})
        self.assertEqual(status, 201, audit)
        self.assertEqual(analyst.post("/api/scan-scope", {"confirm": True, "scope": {}})[0], 403)
        self.assertEqual(analyst.post("/api/auth/users", {"username": "x12", "password": STRONG, "role": "admin"})[0], 403)
        self.assertEqual(admin.post("/api/scan-scope", {"confirm": True, "scope": {}})[0], 200)
        # Okuyucu kendi parolasını değiştirebilir (self düzeyi).
        self.assertEqual(reader.post("/api/auth/password", {"current_password": STRONG + "reader", "new_password": STRONG + "r2"})[0], 200)
        # Denetim kaydında kullanıcı; zincir sağlam.
        completed = [d for a, d in self.audit_rows() if a == "project_audit.completed"]
        self.assertEqual(completed[-1]["actor"], {"id": self.manager().find_user_id("analist1"), "username": "analist1", "role": "analyst"})
        self.assertTrue(server.STORE.verify_audit_chain()["verified"])

    def test_mcp_approval_queue_and_target_catalog_are_admin_only(self):
        admin = self.enable_with_admin()
        reader = self.add_user(admin, "okuyucu2", "reader")
        analyst = self.add_user(admin, "analist2", "analyst")
        analyst_id = self.manager().find_user_id("analist2")
        target = server.STORE.create_target(normalize_target("https://private-target.example"))
        engagement = server.STORE.create_engagement(
            target_id=target["id"], name="Özel hedef", authorization_ref="AUTH-PRIVATE",
            scope_notes="Yalnız kayıtlı hedef", out_of_scope="", test_window="", special_approvals={},
        )
        item = mcp_scan_requests.create_request(
            server.STORE, "nuclei_http_authorized",
            {"target_id": target["id"], "engagement_id": engagement["id"]},
            requester={"id": analyst_id, "username": "analist2", "role": "analyst"},
            confirm_request=True,
        )
        for client in (reader, analyst):
            status, body = client.get("/api/mcp-scan-requests")
            self.assertEqual(status, 403, body)
            encoded = json.dumps(body)
            self.assertNotIn(item["id"], encoded)
            self.assertNotIn("private-target.example", encoded)
            self.assertNotIn(target["id"], encoded)
        status, body = admin.get("/api/mcp-scan-requests")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["requests"][0]["id"], item["id"])
        self.assertIn(target["id"], json.dumps(body["catalog"]))

    def test_last_admin_and_self_demotion_protected(self):
        admin = self.enable_with_admin()
        admin_id = self.manager().find_user_id("yonetici")
        self.assertEqual(admin.post(f"/api/auth/users/{admin_id}", {"role": "reader"})[0], 400)
        with self.assertRaises(auth.AuthError):
            self.manager().update_user(admin_id, disabled=True)


class TotpTests(AuthTestBase):
    def test_rfc6238_vector(self):
        secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # "12345678901234567890"
        self.assertEqual(auth.totp_code(secret, 59 // 30), "287082")
        self.assertEqual(auth.totp_code(secret, 1111111109 // 30), "081804")

    def test_enroll_login_replay_and_recovery(self):
        admin = self.enable_with_admin()
        status, data = admin.post("/api/auth/totp/begin", {})
        self.assertEqual(status, 200)
        self.assertTrue(data["otpauth_uri"].startswith("otpauth://totp/Sniper%3Ayonetici?secret="))
        secret = data["secret"]
        step = int(time.time() // 30)
        status, done = admin.post("/api/auth/totp/confirm", {"code": auth.totp_code(secret, step)})
        self.assertEqual(status, 200, done)
        codes = done["recovery_codes"]
        self.assertEqual(len(codes), 10)
        self.assertEqual(admin.post("/api/auth/logout", {})[0], 200)

        c = self.client()
        status, first = c.post("/api/auth/login", {"username": "yonetici", "password": STRONG})
        self.assertEqual((status, first.get("totp_required")), (200, True))
        self.assertNotIn(auth.SESSION_COOKIE, c.cookies)
        # Etkinleştirmede kullanılan adımın kodu yeniden kullanılamaz.
        self.assertEqual(c.post("/api/auth/login/totp", {"challenge": first["challenge"], "code": auth.totp_code(secret, step)})[0], 401)
        status, _ = c.post("/api/auth/login/totp", {"challenge": first["challenge"], "code": auth.totp_code(secret, step + 1)})
        self.assertEqual(status, 200)
        self.assertEqual(c.get("/api/dashboard")[0], 200)

        d = self.client()
        _s, second = d.post("/api/auth/login", {"username": "yonetici", "password": STRONG})
        self.assertEqual(d.post("/api/auth/login/totp", {"challenge": second["challenge"], "recovery_code": codes[0].upper()})[0], 200)
        e = self.client()
        _s, third = e.post("/api/auth/login", {"username": "yonetici", "password": STRONG})
        self.assertEqual(e.post("/api/auth/login/totp", {"challenge": third["challenge"], "recovery_code": codes[0]})[0], 401)
        self.assertEqual(d.get("/api/auth/me")[1]["recovery_codes_left"], 9)

    def test_challenge_attempt_limit(self):
        admin = self.enable_with_admin()
        secret = admin.post("/api/auth/totp/begin", {})[1]["secret"]
        admin.post("/api/auth/totp/confirm", {"code": auth.totp_code(secret, int(time.time() // 30))})
        c = self.client()
        challenge = c.post("/api/auth/login", {"username": "yonetici", "password": STRONG})[1]["challenge"]
        for _ in range(auth.CHALLENGE_MAX_ATTEMPTS):
            self.assertEqual(c.post("/api/auth/login/totp", {"challenge": challenge, "code": "000000"})[0], 401)
        good = auth.totp_code(secret, int(time.time() // 30) + 1)
        self.assertEqual(c.post("/api/auth/login/totp", {"challenge": challenge, "code": good})[0], 401)


class JobQueueAuthTests(AuthTestBase):
    def test_inner_route_checked_and_actor_carried(self):
        admin = self.enable_with_admin()
        analyst = self.add_user(admin, "analist1", "analyst")
        reader = self.add_user(admin, "okuyucu1", "reader")
        job = {"route": "/api/tool-runs/openssl-x509-loopback", "payload": {}}
        self.assertEqual(reader.post("/api/jobs", job)[0], 403)
        self.assertEqual(analyst.post("/api/jobs", job)[0], 403)  # iç rota yönetici ister
        seen = {}
        original = server._run_post_capture

        def spy(srv, client, headers, route, payload):
            seen["actor"] = request_context.current_actor()
            seen["headers"] = [k.lower() for k, _ in headers]
            return original(srv, client, headers, route, payload)

        with mock.patch.object(server, "_run_post_capture", spy):
            status, created = admin.post("/api/jobs", job)
            self.assertEqual(status, 202, created)
            for _ in range(100):
                if admin.get(f"/api/jobs/{created['id']}")[1].get("state") in {"succeeded", "failed", "completed", "done", "error"}:
                    break
                time.sleep(0.05)
        self.assertEqual(seen["actor"]["username"], "yonetici")
        self.assertNotIn("cookie", seen["headers"])
        self.assertNotIn(auth.CSRF_HEADER.lower(), seen["headers"])
        self.assertEqual(analyst.post(f"/api/jobs/{created['id']}/cancel", {})[0], 403)
        created_log = [d for a, d in self.audit_rows() if a == "job.created"]
        self.assertEqual(created_log[-1]["actor"]["username"], "yonetici")


class RemoteBindTests(unittest.TestCase):
    def test_remote_requires_enabled_auth_and_ack(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = {"SNIPER_ALLOW_REMOTE": "1", "SNIPER_REMOTE_AUTH_ACK": "1", "SNIPER_DATA_DIR": tmp}
            self.assertIn("giriş etkin değil", server.remote_bind_refusal("0.0.0.0", env))
            auth.AuthManager(Path(tmp)).create_admin_and_enable("yonetici", STRONG)
            self.assertIsNone(server.remote_bind_refusal("0.0.0.0", env))
            env.pop("SNIPER_REMOTE_AUTH_ACK")
            self.assertIn("kimlik doğrulama yok", server.remote_bind_refusal("0.0.0.0", env))


class CliTests(unittest.TestCase):
    def test_disable_and_reset(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = auth.AuthManager(Path(tmp))
            manager.create_admin_and_enable("yonetici", STRONG)
            self.assertTrue(manager.enabled())
            manager.disable_auth()
            self.assertFalse(manager.enabled())
            manager.enable_auth()
            user_id = manager.find_user_id("yonetici")
            manager.update_user(user_id, password=STRONG + "2")
            self.assertEqual(manager.authenticate("yonetici", STRONG + "2", "t")[0], "session")


if __name__ == "__main__":
    unittest.main()
