"""17. tur W3-UI: ilk yükleme paketleri (ui_assets) ve /api/bootstrap ön yüklemesi.

* index.html sunulurken defer'li klasik betikler tek pakete, stiller tek stil paketine dönüşür; kaynak index.html değişmez.
* Paket sırası belge sırasıdır; IIFE dosyaları try ile sarılır, global bildirimli app.js olduğu gibi kalır,
  "use strict" korunur; SNIPER_UI_BUNDLE=0 paketlemeyi kapatır.
* /api/bootstrap her alt yolu kendi oturum/rol denetiminden geçirir, doğrudan GET ile aynı gövdeyi verir,
  hız sınırına tek istek sayılır, giriş açıkken oturumsuz 401.
"""
from __future__ import annotations

import http.client
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

from http.server import ThreadingHTTPServer

import auth
import project_analyzer
import server
import ui_assets
from storage import Store

APP = Path(__file__).resolve().parents[1]
STATIC = APP / "static"
STRONG = "doğru-at-pil-zımba-42"


def _node() -> str | None:
    return os.environ.get("SNIPER_NODE_BINARY") or shutil.which("node")


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.static = Path(self.tmp.name)
        (self.static / "a.js").write_text('"use strict";\n// açıklama\n(function () { window.__order = (window.__order || []).concat("a"); })();\n')
        (self.static / "app.js").write_text("const shared = 1;\nfunction helper() { return shared; }\n")
        (self.static / "b.js").write_text("(() => { window.__order = (window.__order || []).concat('b'); })()")  # sonda \n yok
        (self.static / "c.js").write_text("const notIife = 2;\n")  # IIFE değil: sarılmamalı
        (self.static / "m.js").write_text("export const x = 1;\n")
        (self.static / "s1.css").write_text(".a { color: red; }\n")
        (self.static / "s2.css").write_text(".a { color: blue; }\n")
        self.index = (
            '<!doctype html><head>\n'
            '  <link rel="stylesheet" href="/s1.css?v=3">\n'
            '  <script src="/a.js?v=1" defer></script>\n'
            '  <script src="/app.js?v=29" defer></script>\n'
            '  <script type="module" src="/m.js?v=1"></script>\n'
            '  <script src="/static/b.js?v=2" defer></script>\n'
            '  <script src="/c.js" defer></script>\n'
            '  <script src="/yok.js?v=1" defer></script>\n'
            '  <link rel="stylesheet" href="/static/s2.css?v=1"><script src="/c.js?v=9" defer></script>\n'
            '</head><body></body>\n')
        (self.static / "index.html").write_text(self.index)
        ui_assets._CACHE.clear()

    def test_rewrite_keeps_order_modules_and_missing_files(self):
        bundle = ui_assets.build(self.static, self.index)
        html = bundle.html
        self.assertEqual(html.count("__bundle/ui-"), 2)
        self.assertNotIn('src="/a.js', html)
        self.assertNotIn("s1.css", html)
        self.assertIn('<script type="module" src="/m.js?v=1"></script>', html)
        self.assertIn('src="/yok.js?v=1"', html, "bulunamayan dosya etiketi olduğu gibi kalır")
        js = bundle.js.decode()
        order = [m.group(1) for m in re.finditer(r"/\* --- (\S+) --- \*/", js)]
        self.assertEqual(order, ["a.js", "app.js", "b.js", "c.js", "c.js"])
        self.assertIn('(function () {\n"use strict";', js)
        self.assertNotIn("try {\nconst shared", js, "global bildirimli app.js sarılmaz")
        self.assertIn("const notIife = 2;\n;\n", js, "IIFE olmayan dosya sarılmaz")
        self.assertIn("})()\n} catch (error) { setTimeout(() => { throw error; }); }", js)
        css = bundle.css.decode()
        self.assertLess(css.index("color: red"), css.index("color: blue"))

    def test_disable_switch_and_cache_invalidation(self):
        with mock.patch.dict(os.environ, {"SNIPER_UI_BUNDLE": "0"}):
            self.assertEqual(ui_assets.rewrite_index(self.static, self.index.encode()), self.index.encode())
        first = ui_assets.build(self.static, self.index)
        (self.static / "b.js").write_text("(() => { window.changed = 1; })();\n")
        second = ui_assets.build(self.static, self.index)
        self.assertNotEqual(first.js_hash, second.js_hash)
        body, ctype, exact = ui_assets.bundle_asset(self.static, f"/static/__bundle/ui-{second.js_hash}.js")
        self.assertTrue(exact and ctype.startswith("application/javascript"))
        self.assertFalse(ui_assets.bundle_asset(self.static, f"/static/__bundle/ui-{first.js_hash}.js")[2])
        self.assertIsNone(ui_assets.bundle_asset(self.static, "/static/__bundle/../server.py"))

    def test_real_index_bundle_is_valid_javascript(self):
        bundle = ui_assets.build(STATIC, (STATIC / "index.html").read_text(encoding="utf-8"))
        html = bundle.html
        self.assertEqual(len(re.findall(r"<script src=\"/[^\"]+\" defer>", html)), 1, "tek klasik paket")
        self.assertEqual(html.count('type="module"'), 2)
        self.assertIn('href="data:,"', html, "favicon isteği yok")
        node = _node()
        if not node:
            self.skipTest("node yok")
        target = Path(self.tmp.name) / "bundle.js"
        target.write_bytes(bundle.js)
        result = subprocess.run([node, "--check", str(target)], capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr[:500])

    def test_bootstrap_paths_match_client_list(self):
        source = (STATIC / "boot_prefetch.js").read_text(encoding="utf-8")
        listed = re.findall(r'"(/api/[^"]+)"', source.split("const BOOT_PATHS = [", 1)[1].split("];", 1)[0])
        self.assertEqual(tuple(listed), ui_assets.BOOTSTRAP_PATHS)
        index = (STATIC / "index.html").read_text(encoding="utf-8")
        self.assertLess(index.index("/auth.js"), index.index("/boot_prefetch.js"))
        self.assertLess(index.index("/boot_prefetch.js"), index.index("/app.js"))

    def test_no_inline_style_attributes_in_templates(self):
        app_js = (STATIC / "app.js").read_text(encoding="utf-8")
        self.assertIsNone(re.search(r'<[a-z][^<>]*\sstyle="', app_js), "CSP style-src 'self' satır içi stili reddeder; data-style kullanın")
        self.assertIn("function applyDataStyles", app_js)


class _Client:
    def __init__(self, port: int):
        self.port = port
        self.cookies: dict[str, str] = {}

    def request(self, method: str, path: str, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        headers = {"Host": f"127.0.0.1:{self.port}"}
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
            if auth.CSRF_COOKIE in self.cookies:
                headers[auth.CSRF_HEADER] = self.cookies[auth.CSRF_COOKIE]
        conn.request(method, path, body=data, headers=headers)
        response = conn.getresponse()
        raw = response.read()
        for name, value in response.getheaders():
            if name.lower() == "set-cookie":
                cookie, _, _flags = value.partition(";")
                key, _, val = cookie.partition("=")
                self.cookies[key] = val
        conn.close()
        return response.status, raw, dict((k.lower(), v) for k, v in response.getheaders())

    def json(self, method, path, body=None):
        status, raw, _ = self.request(method, path, body)
        return status, (json.loads(raw) if raw else {})


class _ServerBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.data_dir = Path(self.tmp.name) / "data"
        self.data_dir.mkdir()
        self.previous_store = server.STORE
        server.STORE = Store(self.data_dir / "sniper-test.db")
        for patch in (mock.patch.object(server, "DATA_DIR", self.data_dir),
                      mock.patch.object(server, "LIMITER", server.RateLimiter(limit=100000)),
                      mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(self.data_dir)})):
            patch.start()
            self.addCleanup(patch.stop)
        auth._MANAGERS.clear()
        ui_assets._CACHE.clear()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.port = self.httpd.server_address[1]

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        server.STORE = self.previous_store


class BootstrapApiTests(_ServerBase):
    def test_bootstrap_matches_direct_gets(self):
        c = _Client(self.port)
        status, data = c.json("GET", "/api/bootstrap")
        self.assertEqual(status, 200)
        self.assertEqual(set(data["responses"]), set(ui_assets.BOOTSTRAP_PATHS))
        for path in ("/api/targets", "/api/scans?limit=200", "/api/scan-scope", "/api/taint-rules"):
            entry = data["responses"][path]
            self.assertEqual(entry["status"], 200, path)
            self.assertEqual(entry["body"], c.json("GET", path)[1], path)
        # Ana yanıt bozulmadı: tek JSON, alt isteklerin başlıkları sızmadı.
        raw_status, raw, headers = c.request("GET", "/api/bootstrap")
        self.assertEqual(headers["content-type"], "application/json; charset=utf-8")
        self.assertEqual(raw.count(b"HTTP/1."), 0)

    def test_counts_once_for_rate_limit(self):
        limiter = server.RateLimiter(limit=3)
        with mock.patch.object(server, "LIMITER", limiter):
            c = _Client(self.port)
            self.assertEqual(c.json("GET", "/api/bootstrap")[0], 200)
            self.assertEqual(len(limiter.events["127.0.0.1"]), 1)

    def test_auth_gates_bootstrap_and_each_subpath(self):
        manager = auth.manager_for(self.data_dir)
        manager.create_admin_and_enable("yonetici", STRONG)
        anonymous = _Client(self.port)
        self.assertEqual(anonymous.json("GET", "/api/bootstrap")[0], 401)
        admin = _Client(self.port)
        self.assertEqual(admin.json("POST", "/api/auth/login", {"username": "yonetici", "password": STRONG})[0], 200)
        self.assertEqual(admin.json("POST", "/api/auth/users", {"username": "okur", "password": STRONG + "r", "role": "reader"})[0], 201)
        reader = _Client(self.port)
        self.assertEqual(reader.json("POST", "/api/auth/login", {"username": "okur", "password": STRONG + "r"})[0], 200)
        status, data = reader.json("GET", "/api/bootstrap")
        self.assertEqual(status, 200)
        for path, entry in data["responses"].items():
            direct = reader.json("GET", path)
            self.assertEqual(entry["status"], direct[0], path)
        # Bir alt yolun gereken düzeyi yükseltilirse okuyucu için pakete girmez (alt yol ayrıca denetleniyor).
        with mock.patch.object(auth, "_ANALYST_GET", auth._ANALYST_GET | {"/api/dashboard"}):
            status, data = reader.json("GET", "/api/bootstrap")
            self.assertEqual(data["responses"]["/api/dashboard"], {"status": 403})
            self.assertEqual(admin.json("GET", "/api/bootstrap")[1]["responses"]["/api/dashboard"]["status"], 200)

    def test_index_served_bundled_and_bundle_cacheable(self):
        c = _Client(self.port)
        status, raw, _ = c.request("GET", "/")
        self.assertEqual(status, 200)
        html = raw.decode()
        match = re.search(r'src="(/static/__bundle/ui-[0-9a-f]{16}\.js)"', html)
        self.assertTrue(match)
        self.assertNotIn('src="/app.js', html)
        status, body, headers = c.request("GET", match.group(1))
        self.assertEqual(status, 200)
        self.assertIn("immutable", headers["cache-control"])
        self.assertIn("function applyDataStyles", body.decode())
        css = re.search(r'href="(/static/__bundle/ui-[0-9a-f]{16}\.css)"', html).group(1)
        self.assertEqual(c.request("GET", css)[0], 200)
        with mock.patch.dict(os.environ, {"SNIPER_UI_BUNDLE": "0"}):
            expected = server._inject_local_home_config((STATIC / "index.html").read_bytes())
            self.assertEqual(c.request("GET", "/")[1], expected)
            self.assertIn(b'<meta name="sniper-local-home" content="', expected)


class ReportCspTests(unittest.TestCase):
    def test_hash_policy_and_fallback(self):
        import base64, hashlib
        doc = "<html><head><style>body { color: red; }</style></head><body><p>x</p></body></html>"
        digest = base64.b64encode(hashlib.sha256(b"body { color: red; }").digest()).decode()
        csp = ui_assets.report_csp(doc)
        self.assertIn(f"style-src 'sha256-{digest}'", csp)
        self.assertNotIn("unsafe-inline", csp)
        self.assertIn("unsafe-inline", ui_assets.report_csp(doc.replace("<p>", '<p style="color:blue">')))
        self.assertIn("style-src 'none'", ui_assets.report_csp("<html><body>x</body></html>"))


class ProjectReportCspApiTests(_ServerBase):
    def test_project_reports_use_hash_csp_without_style_attributes(self):
        project = Path(self.tmp.name) / "proj"
        (project / "routes").mkdir(parents=True)
        (project / "app.py").write_text("from flask import Flask, request\napp = Flask(__name__)\n@app.route('/x')\n"
                                        "def x():\n    import os\n    os.system(request.args['h'])\n    return 'ok'\n")
        with mock.patch.object(project_analyzer, "_allowed_roots", return_value=(Path(self.tmp.name),)):
            c = _Client(self.port)
            status, audit = c.json("POST", "/api/project-audits", {"project_path": str(project)})
            self.assertEqual(status, 201, audit)
            for suffix in ("report.html", "executive-summary.html", "report.html?lang=en"):
                status, raw, headers = c.request("GET", f"/api/project-audits/{audit['id']}/{suffix}")
                self.assertEqual(status, 200, suffix)
                csp = headers["content-security-policy"]
                self.assertNotIn("unsafe-inline", csp, suffix)
                self.assertIn("'sha256-", csp, suffix)
                self.assertIsNone(re.search(rb"<[a-zA-Z][^<>]*\sstyle\s*=", raw), suffix)


if __name__ == "__main__":
    unittest.main()
