"""Yalıtılmış Playwright tarayıcı testi: girdi doğrulama, hedef listesi, seccomp filtresi, pinler, bulgu üretimi ve
(pinli bwrap + Node + Chromium + playwright-core varsa) gerçek uçtan uca çalıştırma.

Gerçek çalıştırma yalnız kendi 127.0.0.1 fikstürüne gider; tarayıcının başka yerel porta (Sniper) ve dış kökene
ulaşamadığı da doğrulanır. Bileşenler yoksa atlanır."""
from __future__ import annotations

import http.server
import os
from pathlib import Path
import re
import sys
import tempfile
import threading
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import sandbox_browser_tests as sbt  # noqa: E402
import sandbox_seccomp  # noqa: E402
import sandbox_targets as st  # noqa: E402
import tool_pins  # noqa: E402
import tool_sandbox as ts  # noqa: E402
from verified_exec import VerificationError  # noqa: E402


class _DataDir(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="sbx-pw-")
        self.data = Path(self.tmp.name)
        os.chmod(self.data, 0o700)
        self.env_patch = mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(self.data), "SNIPER_PORT": "8787"})
        self.env_patch.start()

    def tearDown(self) -> None:
        self.env_patch.stop()
        self.tmp.cleanup()


class ParamTests(_DataDir):
    def test_target_must_allow_playwright(self) -> None:
        st.add_local_target(3000, ["k6"])
        with self.assertRaises(st.TargetError):
            sbt._params({"confirm": True, "target": "http://127.0.0.1:3000"})
        st.set_target_tools("local:3000", ["k6", "playwright"])
        self.assertEqual(sbt._params({"confirm": True, "target": "http://127.0.0.1:3000"})["paths"], ["/"])
        with self.assertRaises(st.TargetError):
            st.set_target_tools("local:9999", ["playwright"])
        with self.assertRaises(st.TargetError):
            st.set_target_tools("local:3000", ["curl"])

    def test_inputs_are_validated(self) -> None:
        st.add_local_target(3000, ["playwright"])
        ok = {"confirm": True, "target": "http://127.0.0.1:3000"}
        for bad in ({**ok, "confirm": False}, {**ok, "script": "x"}, {**ok, "paths": []}, {**ok, "paths": ["/"] * 11},
                    {**ok, "paths": ["javascript:alert(1)"]}, {**ok, "paths": ["/a/../b"]}, {**ok, "paths": ["/a?x=1"]},
                    {**ok, "paths": ["//evil.com"]}, {**ok, "reflection_probe": "yes"}, {**ok, "timeout_s": 61},
                    {**ok, "timeout_s": True}):
            with self.assertRaises(ValueError, msg=str(bad)):
                sbt._params(bad)
        params = sbt._params({**ok, "paths": ["/", "/", "/giris"], "reflection_probe": True})
        self.assertEqual(params["paths"], ["/", "/giris"])

    def test_plan_probe_is_random_and_harmless(self) -> None:
        st.add_local_target(3000, ["playwright"])
        params = sbt._params({"confirm": True, "target": "http://127.0.0.1:3000", "reflection_probe": True})
        plan_a, probe_a = sbt._plan(params)
        _, probe_b = sbt._plan(params)
        self.assertNotEqual(probe_a["tag"], probe_b["tag"])
        self.assertRegex(probe_a["tag"], r"^sniper-x[0-9a-f]{12}$")
        self.assertNotIn("script", probe_a["payload"].lower())
        self.assertIn(b'"base_url": "http://127.0.0.1:3000"', plan_a)


class SeccompTests(unittest.TestCase):
    def test_numbers_match_kernel_headers(self) -> None:
        header = Path("/usr/include/asm-generic/unistd.h")
        if not header.is_file():
            self.skipTest("asm-generic/unistd.h yok")
        text = header.read_text()
        for name, number in sandbox_seccomp.DENIED_SYSCALLS["aarch64"].items():
            match = re.search(rf"^#define __NR(?:3264)?_{name}\s+(\d+)\s*$", text, re.M)
            self.assertIsNotNone(match, name)
            self.assertEqual(int(match.group(1)), number, name)

    def test_program_shape(self) -> None:
        program = sandbox_seccomp.build_filter("aarch64")
        count = len(set(sandbox_seccomp.DENIED_SYSCALLS["aarch64"].values()))
        self.assertEqual(len(program), 8 * (4 + count + 2))
        self.assertEqual(program[-16:-8], sandbox_seccomp._stmt(0x06, sandbox_seccomp.SECCOMP_RET_ALLOW))
        self.assertEqual(program[-8:], sandbox_seccomp._stmt(0x06, sandbox_seccomp.SECCOMP_RET_ERRNO | 1))
        with self.assertRaises(sandbox_seccomp.SeccompUnsupported):
            sandbox_seccomp.build_filter("mips")

    def test_bwrap_argv_carries_seccomp(self) -> None:
        argv = ts.bwrap_argv(9, [], seccomp_fd=12)
        self.assertEqual(argv[argv.index("--seccomp") + 1], "12")
        self.assertNotIn("--seccomp", ts.bwrap_argv(9, []))
        self.assertIn("--disable-userns", argv)


class TreePinTests(unittest.TestCase):
    def setUp(self) -> None:
        # Ağaç denetimi grup/diğer yazılabilir öğeleri reddeder; ortam umask'ından (ör. 0002) bağımsız olsun.
        old = os.umask(0o022)
        self.addCleanup(os.umask, old)

    def test_tree_hash_rejects_unsafe_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "pkg"
            (root / "lib").mkdir(parents=True)
            (root / "lib" / "a.js").write_text("1")
            first = tool_pins.tree_sha256(root)
            (root / "lib" / "a.js").write_text("2")
            self.assertNotEqual(first, tool_pins.tree_sha256(root))
            (root / "lib" / "a.js").chmod(0o666)
            with self.assertRaises(VerificationError):
                tool_pins.tree_sha256(root)
            (root / "lib" / "a.js").chmod(0o644)
            (root / "link").symlink_to(root / "lib" / "a.js")
            with self.assertRaises(VerificationError):
                tool_pins.tree_sha256(root)

    def test_verified_tree_requires_pinned_digest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            os.chmod(tmp, 0o755)
            (Path(tmp) / "index.js").write_text("module.exports = 1;\n")
            with mock.patch.dict(os.environ, {"SNIPER_PLAYWRIGHT_CORE_DIR": tmp}):
                with self.assertRaises(VerificationError) as caught:
                    tool_pins.verified_tree("playwright-core")
            self.assertEqual(caught.exception.reason, "tree_digest_mismatch")

    def test_browser_pins_present(self) -> None:
        for tool in ("node", "chromium"):
            self.assertTrue(tool_pins.PINS[tool].digests["aarch64"])


class FindingTests(unittest.TestCase):
    def test_findings_from_facts(self) -> None:
        facts = {"pages": [
            {"path": "/", "probe": False, "status": 200, "headers": {"content-security-policy": None},
             "disclosure_headers": {"x-powered-by": "Express"}, "forms": {"password_forms": 1, "password_get_forms": 1},
             "mixed_content": 0, "page_errors": 0, "error": None},
            {"path": "/", "probe": True, "reflection": {"element_injected": True, "raw_text_reflected": True}},
            {"path": "/b", "probe": True, "reflection": {"element_injected": False, "raw_text_reflected": True}},
            {"path": "/c", "probe": False, "status": None, "error": "net::ERR"},
        ], "cookies": [{"name": "sid", "secure": False, "http_only": False, "same_site": "None"}]}
        codes = {(f["code"], f["path"]) for f in sbt.derive_findings(facts, https=True)}
        for expected in (("missing_csp", "/"), ("missing_hsts", "/"), ("version_disclosure", "/"),
                         ("password_get_form", "/"), ("reflected_html_injection", "/"), ("reflected_parameter", "/b"),
                         ("cookie_without_httponly", "/"), ("cookie_without_secure", "/"),
                         ("cookie_samesite_none_insecure", "/")):
            self.assertIn(expected, codes)
        self.assertNotIn(("password_over_http", "/"), codes)
        self.assertFalse(any(path == "/c" for _, path in codes))
        http_codes = {f["code"] for f in sbt.derive_findings(facts, https=False)}
        self.assertIn("password_over_http", http_codes)
        self.assertNotIn("missing_hsts", http_codes)


def _browser_ready() -> str | None:
    try:
        ts.open_bwrap().close()
        ts.open_node().close()
        ts.chromium_dir()
        ts.playwright_core_dir()
        sandbox_seccomp.build_filter()
    except (ts.SandboxUnavailable, sandbox_seccomp.SeccompUnsupported) as exc:
        return str(exc)
    return None


class _App(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        from urllib.parse import parse_qs, urlsplit
        probe = parse_qs(urlsplit(self.path).query).get("sniper_probe", [""])[0]
        sniper = os.environ.get("SNIPER_PORT", "8787")
        body = (f"<html><head><title>fikstur</title></head><body><p>{probe}</p>"
                f"<form method='get'><input type='password' name='p'></form>"
                f"<script>fetch('http://127.0.0.1:{sniper}/').then(()=>document.title='SIZINTI')"
                f".catch(()=>document.title='ENGELLENDI');fetch('https://example.com/').catch(()=>{{}});</script>"
                f"</body></html>").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Set-Cookie", "sid=1; Path=/")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args) -> None:
        pass


@unittest.skipIf(_browser_ready() is not None, f"tarayıcı sandbox bileşenleri yok: {_browser_ready()}")
class RealBrowserTests(_DataDir):
    def test_end_to_end_findings_and_isolation(self) -> None:
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _App)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        port = server.server_address[1]
        st.add_local_target(port, ["playwright"])
        with mock.patch.dict(os.environ, {"SNIPER_SANDBOX_LAUNCH": "direct"}):
            result = sbt.run_playwright_sandbox({"confirm": True, "target": f"http://127.0.0.1:{port}",
                                                 "paths": ["/"], "reflection_probe": True, "timeout_s": 15})
        codes = {f["code"] for f in result["findings"]}
        self.assertIn("reflected_html_injection", codes)
        self.assertIn("password_get_form", codes)
        self.assertIn("cookie_without_httponly", codes)
        first = result["facts"]["pages"][0]
        self.assertEqual(first["status"], 200)
        # Sniper portuna ve dış kökene erişim yok: yalnız aktarıcı üzerinden seçilen hedef.
        self.assertEqual(first["title"], "ENGELLENDI")
        self.assertIn("https://example.com", first["external_origins"])
        self.assertGreater(result["relay"]["connections"], 0)
        self.assertEqual(result["isolation"]["network"], "relay_only")
        self.assertNotIn("screenshot_png_base64", result["facts"])


if __name__ == "__main__":
    unittest.main()
