from __future__ import annotations

import http.client
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

import auth
import community_release_info
import server
import ui_assets
from storage import Store


class VulKillBrandRuntimeTests(unittest.TestCase):
    def test_community_version_payload_exposes_vulkill_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "version.py").write_text('__version__ = "1.0.0"\n', encoding="utf-8")
            payload = community_release_info.system_version_payload(
                root,
                root / "data",
                root / "backups",
            )
        self.assertEqual(payload["product_name"], "VulKill")
        self.assertEqual(payload["product_slug"], "vulkill")

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.data_dir = Path(self.tmp.name) / "data"
        self.data_dir.mkdir()
        self.previous_store = server.STORE
        server.STORE = Store(self.data_dir / "brand-test.db")
        for patcher in (
            mock.patch.object(server, "DATA_DIR", self.data_dir),
            mock.patch.object(server, "LIMITER", server.RateLimiter(limit=100000)),
            mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(self.data_dir)}),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        auth._MANAGERS.clear()
        ui_assets._CACHE.clear()
        self.httpd = server.VulKillHTTPServer(("127.0.0.1", 0), server.VulKillHandler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)
        self.port = self.httpd.server_address[1]

    def tearDown(self) -> None:
        server.STORE = self.previous_store

    def get(self, path: str) -> tuple[int, bytes, dict[str, str]]:
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        connection.request("GET", path, headers={"Host": f"127.0.0.1:{self.port}"})
        response = connection.getresponse()
        body = response.read()
        headers = {name.lower(): value for name, value in response.getheaders()}
        connection.close()
        return response.status, body, headers

    def test_control_home_still_serves_with_security_headers(self) -> None:
        status, body, headers = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn(b"<!doctype html>", body.lower())
        self.assertEqual(headers.get("x-content-type-options"), "nosniff")

    def test_runtime_home_login_and_version_expose_vulkill_identity(self) -> None:
        home_status, home, _ = self.get("/")
        login_status, login, _ = self.get("/login.html")
        version_status, raw_version, _ = self.get("/api/system/version")

        self.assertEqual((home_status, login_status, version_status), (200, 200, 200))
        self.assertIn(b"<title>VulKill", home)
        self.assertIn(b">VULKILL 1.0<", home)
        self.assertNotIn(b"Sniper", home)
        self.assertIn(b"<title>VulKill", login)
        self.assertNotIn(b"Sniper", login)
        version = json.loads(raw_version)
        self.assertEqual(version["product_name"], "VulKill")
        self.assertEqual(version["product_slug"], "vulkill")

    def test_public_discovery_surfaces_use_vulkill_in_every_locale(self) -> None:
        root = Path(__file__).resolve().parents[1]
        surfaces = (
            root / "README.md",
            root / "llms.txt",
            root / "docs" / "README.ja.md",
            root / "docs" / "README.ko.md",
            root / "docs" / "README.zh-CN.md",
            root / ".github" / "pull_request_template.md",
        )
        for surface in surfaces:
            with self.subTest(surface=surface.relative_to(root)):
                text = surface.read_text(encoding="utf-8")
                self.assertIn("VulKill", text)
                self.assertNotIn("Sniper", text)


if __name__ == "__main__":
    unittest.main()
