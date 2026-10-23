"""Yetkili genel Playwright rotasının HTTP sözleşmesi.

Testler hiçbir dış hedefe bağlanmaz. Başarılı koşu, tarayıcı çalıştırıcısını
yalnız API/denetim sözleşmesini sınamak için yama ile değiştirir.
"""
from __future__ import annotations

import http.client
import http.server
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest import mock

from http.server import ThreadingHTTPServer

import server
import playwright_authorized as pwa
from storage import Store
from tool_sandbox import SandboxUnavailable, chromium_dir, require_authorized_renderer_sandbox


class PlaywrightAuthorizedAPITests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="pw-authorized-api-")
        self.addCleanup(self.tmp.cleanup)
        self.data = Path(self.tmp.name)
        os.chmod(self.data, 0o700)
        self.previous_store = server.STORE
        server.STORE = Store(self.data / "sniper-test.db")
        self.env = mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(self.data), "SNIPER_QUIET": "1"})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)

    def tearDown(self) -> None:
        server.STORE = self.previous_store

    def post(self, path: str, payload: object) -> tuple[int, dict]:
        conn = http.client.HTTPConnection("127.0.0.1", self.httpd.server_address[1], timeout=30)
        raw = json.dumps(payload).encode("utf-8")
        conn.request("POST", path, raw, {"Content-Type": "application/json"})
        response = conn.getresponse()
        body = json.loads(response.read())
        conn.close()
        return response.status, body

    def test_existing_playwright_sandbox_route_remains_a_control(self) -> None:
        status, body = self.post("/api/tool-runs/playwright-sandbox", {"confirm": False})
        self.assertEqual(status, 400, body)

    def test_general_route_requires_exact_per_run_authorization(self) -> None:
        base = {"target": "https://Example.COM:443", "paths": ["/"]}
        for value in (None, False, 1, "true"):
            payload = dict(base)
            if value is not None:
                payload["confirm_authorized"] = value
            status, body = self.post("/api/tool-runs/playwright-authorized", payload)
            self.assertEqual(status, 400, (value, body))

    def test_unregistered_http_target_gets_audited_receipt(self) -> None:
        completed = {
            "format": "playwright-authorized-v1", "status": "completed",
            "target": "http://127.0.0.1:32123", "paths": ["/"],
            "reflection_probe": False, "driver_sha256": "a" * 64,
            "relay": {"connections": 1, "refused": 0, "bytes": 100},
            "isolation": {"bwrap_namespaces": True, "network": "relay_only",
                          "seccomp_denylist": True, "chromium_internal_sandbox": True},
            "limits": {"timeout_s": 10, "max_connections": 2000, "max_bytes": 134217728,
                       "max_paths": 10},
            "cleanup": {"ephemeral_workdir_removed": True}, "findings": [],
            "facts": {"format": "sniper-playwright-facts-v1", "pages": [], "cookies": []},
        }
        payload = {"target": "HTTP://127.0.0.1:32123/", "paths": ["/"], "timeout_s": 10,
                   "reflection_probe": False, "screenshot": False, "ignore_https_errors": False,
                   "confirm_authorized": True}
        with mock.patch.object(server, "run_playwright_authorized", return_value=completed, create=True) as runner:
            status, body = self.post("/api/tool-runs/playwright-authorized", payload)
        self.assertEqual(status, 200, body)
        runner.assert_called_once()
        self.assertEqual(body["authorization_receipt"]["consent_version"],
                         "sniper-playwright-authorized-consent-v1")
        self.assertEqual(body["authorization_receipt"]["actor"]["username"], "yerel")
        self.assertEqual(body["authorization_receipt"]["confirmed_at_utc"][-6:], "+00:00")
        self.assertTrue(body["authorization_receipt"]["confirm_authorized"])
        self.assertRegex(body["authorization_receipt"]["run_id"], r"^pwauth_[0-9a-f]{16}$")
        self.assertRegex(body["authorization_receipt"]["target_sha256"], r"^[0-9a-f]{64}$")
        with sqlite3.connect(server.STORE.path) as db:
            rows = db.execute(
                "SELECT action, entity_id, details_json FROM audit_log "
                "WHERE action LIKE 'playwright_authorized.%' ORDER BY id"
            ).fetchall()
        self.assertEqual([row[0] for row in rows],
                         ["playwright_authorized.consent", "playwright_authorized.completed"])
        consent = json.loads(rows[0][2])
        self.assertEqual(consent["actor"]["username"], "yerel")
        self.assertNotIn("127.0.0.1", rows[0][2])

    def test_http_runtime_reports_exact_renderer_prerequisite_without_target_request(self) -> None:
        requests = []

        class Fixture(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                requests.append(self.path)
                self.send_response(204)
                self.end_headers()

            def log_message(self, *_args) -> None:
                pass

        fixture = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
        threading.Thread(target=fixture.serve_forever, daemon=True).start()
        self.addCleanup(fixture.server_close)
        self.addCleanup(fixture.shutdown)
        payload = {"confirm_authorized": True,
                   "target": f"http://127.0.0.1:{fixture.server_address[1]}", "paths": ["/"],
                   "timeout_s": 5, "reflection_probe": False, "screenshot": False,
                   "ignore_https_errors": False}
        with mock.patch.dict(os.environ, {"SNIPER_SANDBOX_LAUNCH": "direct"}), \
                mock.patch.object(
                    server,
                    "run_playwright_authorized",
                    side_effect=SandboxUnavailable("chromium_setuid_sandbox_missing"),
                ):
            status, body = self.post("/api/tool-runs/playwright-authorized", payload)
        self.assertEqual(status, 503, body)
        self.assertIn("chromium_setuid_sandbox_missing", body["error"])
        self.assertEqual(body["authorization_receipt"]["consent_version"],
                         "sniper-playwright-authorized-consent-v1")
        self.assertEqual(requests, [])
        with sqlite3.connect(server.STORE.path) as db:
            rows = db.execute(
                "SELECT action, details_json FROM audit_log WHERE action LIKE 'playwright_authorized.%' ORDER BY id"
            ).fetchall()
        self.assertEqual([row[0] for row in rows],
                         ["playwright_authorized.consent", "playwright_authorized.unavailable"])
        self.assertEqual(json.loads(rows[1][1])["prerequisite"], "chromium_setuid_sandbox_missing")
        self.assertNotIn("127.0.0.1", rows[1][1])


class PlaywrightAuthorizedContractTests(unittest.TestCase):
    def test_target_is_normalized_without_registration_or_address_allowlist(self) -> None:
        self.assertEqual(pwa.normalize_authorized_target("HTTPS://Example.COM.:443/")["normalized"],
                         "https://example.com")
        self.assertEqual(pwa.normalize_authorized_target("http://10.20.30.40:8080")["normalized"],
                         "http://10.20.30.40:8080")
        self.assertEqual(pwa.normalize_authorized_target("http://127.0.0.1:32123")["kind"], "authorized")
        for bad in ("ftp://example.com", "https://u:p@example.com", "https://example.com/a",
                    "https://example.com/?token=x", "https://example.com/#x", "http://0.0.0.0"):
            with self.assertRaises(ValueError, msg=bad):
                pwa.normalize_authorized_target(bad)

    def test_budget_and_exact_fields_are_enforced(self) -> None:
        base = {"confirm_authorized": True, "target": "https://example.com"}
        self.assertEqual(pwa.authorized_params(base)["timeout"], 20)
        for bad in ({**base, "extra": True}, {**base, "timeout_s": True}, {**base, "timeout_s": 61},
                    {**base, "paths": []}, {**base, "paths": ["/"] * 11},
                    {**base, "paths": ["//other.example"]}, {**base, "screenshot": "yes"}):
            with self.assertRaises(ValueError, msg=str(bad)):
                pwa.authorized_params(bad)

    def test_authorized_driver_requires_chromium_internal_sandbox(self) -> None:
        authorized = pwa.AUTHORIZED_DRIVER.read_text(encoding="utf-8")
        legacy = (Path(pwa.AUTHORIZED_DRIVER).parent / "sandbox_playwright_driver.cjs").read_text(encoding="utf-8")
        self.assertIn("chromiumSandbox: true", authorized)
        self.assertNotIn("chromiumSandbox: false", authorized)
        self.assertIn("chromiumSandbox: false", legacy)

    def test_renderer_sandbox_contract_rejects_a_missing_setuid_helper(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pw-missing-setuid-") as temporary:
            with self.assertRaisesRegex(SandboxUnavailable, "^chromium_setuid_sandbox_missing$"):
                require_authorized_renderer_sandbox(Path(temporary))


class PlaywrightAuthorizedRuntimeTests(unittest.TestCase):
    def test_loopback_runtime_fails_closed_when_renderer_sandbox_prerequisite_is_absent(self) -> None:
        # Pinli Chromium ağacında setuid helper sonradan kurulursa bu makineye özgü eksik-önkoşul
        # kanıtı artık geçerli değildir; o durumda ayrı başarılı runtime testi gerekir.
        try:
            browser_dir = chromium_dir()
        except SandboxUnavailable as exc:
            self.skipTest(f"Bu mimaride pinli Chromium runtime yok: {exc}")
        if (browser_dir / "chrome-sandbox").exists():
            self.skipTest("Chromium setuid sandbox mevcut; başarılı yetkili runtime kanıtı gerekli")
        requests = []

        class Fixture(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                requests.append(self.path)
                body = b"<html><title>fixture</title></html>"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args) -> None:
                pass

        fixture = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
        threading.Thread(target=fixture.serve_forever, daemon=True).start()
        self.addCleanup(fixture.server_close)
        self.addCleanup(fixture.shutdown)
        with tempfile.TemporaryDirectory(prefix="pw-authorized-runtime-") as tmp:
            data = Path(tmp)
            os.chmod(data, 0o700)
            with mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(data), "SNIPER_SANDBOX_LAUNCH": "direct"}):
                with self.assertRaises(SandboxUnavailable) as caught:
                    pwa.run_playwright_authorized({
                        "confirm_authorized": True,
                        "target": f"http://127.0.0.1:{fixture.server_address[1]}",
                        "paths": ["/"], "timeout_s": 5,
                    })
            self.assertEqual(str(caught.exception), "chromium_setuid_sandbox_missing")
            self.assertEqual(requests, [], "renderer sandbox yokken hedefe tek istek bile çıkmamalı")
            run_root = data / "sandbox-runs"
            self.assertFalse(list(run_root.glob("playwright-*")) if run_root.exists() else [])


if __name__ == "__main__":
    unittest.main()
