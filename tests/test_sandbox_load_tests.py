"""Yalıtılmış k6/Schemathesis: Sniper içinden yönetilen hedefler (kapsam seçenekleri, kritik yerel servisler,
sahipliği doğrulanmış uzak hedefler), yük profilleri, API + denetim kaydı ve gerçek bubblewrap ile yalıtım
(başka port, dış adres, yönlendirme, ev/veri dizini, yetenekler, iç içe userns, süre aşımı).

Uzak doğrulama sahte HTTP/DNS işlevleriyle sınanır (gerçek ağa çıkılmaz). Gerçek bwrap testleri pinli
/opt/sniper-bwrap/bwrap ve k6 yoksa atlanır; yalnız kendi 127.0.0.1 fikstürlerine trafik gönderir."""
from __future__ import annotations

import http.server
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import sandbox_load_tests as slt  # noqa: E402
import sandbox_targets as st  # noqa: E402
import tool_sandbox as ts  # noqa: E402


class _DataDir(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="sbx-")
        self.data = Path(self.tmp.name)
        os.chmod(self.data, 0o700)
        self.env_patch = mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(self.data), "SNIPER_PORT": "8787",
                                                      "SNIPER_K6_ALLOWED_PORTS": "", "SNIPER_SCHEMATHESIS_ALLOWED_PORTS": ""})
        self.env_patch.start()

    def tearDown(self) -> None:
        self.env_patch.stop()
        self.tmp.cleanup()


class TargetModelTests(_DataDir):
    def test_scopes_default_and_local_targets(self) -> None:
        self.assertEqual(st.read_settings()["scopes"], {"local": True, "critical": False, "remote_verified": False})
        st.add_local_target(3000, ["k6"], "web")
        st.add_local_target(4000)
        ids = [t["id"] for t in st.read_settings()["targets"]]
        self.assertEqual(ids, ["local:3000", "local:4000"])
        self.assertEqual(st.resolve_run_target("k6", "http://127.0.0.1:3000")["port"], 3000)
        with self.assertRaises(st.TargetError):
            st.resolve_run_target("schemathesis", "http://127.0.0.1:3000")
        for bad in ("http://127.0.0.1:3001", "https://127.0.0.1:3000", "http://localhost:3000", "http://127.0.0.1:3000/x",
                    "http://user@127.0.0.1:3000", "ftp://127.0.0.1:3000", 3000):
            with self.assertRaises(st.TargetError, msg=bad):
                st.resolve_run_target("k6", bad)
        self.assertTrue(st.remove_target("local:3000"))
        self.assertFalse(st.remove_target("local:3000"))
        self.assertEqual(os.stat(self.data / st.FILE_NAME).st_mode & 0o777, 0o600)

    def test_any_local_port_is_accepted_but_critical_needs_its_scope(self) -> None:
        st.add_local_target(80)
        st.add_local_target(65535)
        for port in (8787, 18090, 20129, 22, 5901):
            with self.assertRaises(st.ScopeDisabled, msg=port):
                st.add_local_target(port)
        st.set_scope("critical", True)
        entry = st.add_local_target(18090, ["k6"])
        self.assertTrue(entry["critical"])
        self.assertEqual(st.resolve_run_target("k6", "http://127.0.0.1:18090")["critical"], True)
        st.set_scope("critical", False)
        with self.assertRaises(st.ScopeDisabled):
            st.resolve_run_target("k6", "http://127.0.0.1:18090")
        st.set_scope("local", False)
        with self.assertRaises(st.ScopeDisabled):
            st.resolve_run_target("k6", "http://127.0.0.1:80")
        with self.assertRaises(st.ScopeDisabled):
            st.add_local_target(3000)
        for bad in (0, 70000, "3000", True, 3000.0):
            with self.assertRaises(st.TargetError, msg=bad):
                st.add_local_target(bad)
        with self.assertRaises(st.TargetError):
            st.set_scope("everything", True)

    def test_hand_edited_critical_entry_without_flag_is_dropped(self) -> None:
        path = self.data / st.FILE_NAME
        path.write_text(json.dumps({"scopes": {"local": True, "critical": True}, "targets": [
            {"kind": "local", "port": 8787, "tools": ["k6"]}, {"kind": "local", "port": 3000, "tools": ["k6", "x"]},
            {"kind": "local", "port": 4000, "tools": ["k6"]}, {"kind": "remote", "host": "1.2.3.4", "port": 443,
                                                              "tools": ["k6"], "scheme": "https"}]}))
        os.chmod(path, 0o600)
        self.assertEqual([t["id"] for t in st.read_settings()["targets"]], ["local:4000"])
        os.chmod(path, 0o666)
        with self.assertRaises(st.TargetError):
            st.read_settings()

    def test_environment_seed_skips_critical_ports(self) -> None:
        with mock.patch.dict(os.environ, {"SNIPER_K6_ALLOWED_PORTS": "3000,8787", "SNIPER_SCHEMATHESIS_ALLOWED_PORTS": "8788"}):
            self.assertEqual([t["id"] for t in st.read_settings()["targets"]], ["local:3000", "local:8788"])

    def test_presets(self) -> None:
        table = st.presets()
        self.assertEqual({k: (v["vus"], v["duration_s"]) for k, v in table.items() if v["builtin"]},
                         {"hafif": (1, 10), "orta": (10, 60), "yogun": (50, 300)})
        st.set_preset("ozel", 7, 20)
        st.set_preset("gece", 100, 600)
        self.assertEqual(st.presets()["gece"]["vus"], 100)
        for args in (("hafif", 2, 2), ("Bad!", 1, 1), ("x", 201, 10), ("x", 1, 601), ("x", 0, 10)):
            with self.assertRaises(st.TargetError, msg=args):
                st.set_preset(*args)
        with self.assertRaises(st.TargetError):
            st.remove_preset("orta")
        self.assertTrue(st.remove_preset("gece"))
        self.assertEqual(st.resolve_preset(None, {"critical": True})["name"], "hafif")
        self.assertEqual(st.resolve_preset(None, {"critical": False})["name"], "orta")
        self.assertEqual(st.resolve_preset("ozel", {"critical": False})["vus"], 7)
        with self.assertRaises(st.TargetError):
            st.resolve_preset("yok", {"critical": False})
        self.assertEqual(st.set_limits({"st_max_examples": 50})["st_max_examples"], 50)
        with self.assertRaises(st.TargetError):
            st.set_limits({"st_max_examples": 201})


class RemoteVerificationTests(_DataDir):
    def test_remote_host_rules(self) -> None:
        self.assertEqual(st.remote_host("Api.Ornek.COM."), "api.ornek.com")
        for bad in ("1.2.3.4", "[::1]", "::1", "localhost", "printer.local", "x", "a..b.com", "exa mple.com", "srv.internal"):
            with self.assertRaises(st.TargetError, msg=bad):
                st.remote_host(bad)

    def test_runtime_proof_is_loopback_only(self) -> None:
        st.set_scope("remote_verified", True)
        default = st.start_verification("api.ornek.com")
        self.assertNotIn("runtime_proof", default["tools"])
        for tools in (["runtime_proof"], ["k6", "runtime_proof"]):
            with self.assertRaisesRegex(st.TargetError, "yalnız loopback"):
                st.start_verification("kanit.ornek.com", tools=tools)

        item = self._start()
        entry = st.check_verification(item["id"], http_fetch=lambda h, i: item["token"].encode(), dns_txt=lambda n: [])
        with self.assertRaisesRegex(st.TargetError, "yalnız loopback"):
            st.set_target_tools(entry["id"], ["runtime_proof"])

    def _start(self) -> dict:
        st.set_scope("remote_verified", True)
        return st.start_verification("api.ornek.com", 443, "https", ["k6"], "api")

    def test_verification_requires_scope_and_token(self) -> None:
        with self.assertRaises(st.ScopeDisabled):
            st.start_verification("api.ornek.com")
        item = self._start()
        self.assertEqual(item["http_url"], f"https://api.ornek.com/.well-known/sniper-verify/{item['id']}")
        self.assertEqual(item["dns_name"], "_sniper-verify.api.ornek.com")
        calls = []

        def wrong_http(host: str, token_id: str) -> bytes:
            calls.append((host, token_id))
            return b"baska"

        with self.assertRaises(st.VerificationFailed):
            st.check_verification(item["id"], http_fetch=wrong_http, dns_txt=lambda name: ["sniper-verify=yanlis"])
        self.assertEqual(calls, [("api.ornek.com", item["id"])])
        with self.assertRaises(st.TargetError):
            st.resolve_run_target("k6", "https://api.ornek.com:443")
        entry = st.check_verification(item["id"], http_fetch=lambda h, i: (item["token"] + "\n").encode(),
                                      dns_txt=lambda name: [])
        self.assertEqual(entry["verification"]["method"], "http")
        self.assertEqual(st.resolve_run_target("k6", "https://api.ornek.com")["kind"], "remote")
        self.assertNotIn("token", json.dumps(st.status()))

    def test_dns_txt_fallback_and_periodic_reverification(self) -> None:
        item = self._start()

        def no_http(host: str, token_id: str) -> bytes:
            raise st.VerificationFailed("yok")

        seen = []

        def txt(name: str) -> list[str]:
            seen.append(name)
            return ["v=spf1 -all", f"sniper-verify={item['token']}"]

        entry = st.check_verification(item["id"], http_fetch=no_http, dns_txt=txt)
        self.assertEqual((entry["verification"]["method"], seen), ("dns", ["_sniper-verify.api.ornek.com"]))
        later = int(time.time()) + st.REVERIFY_SECONDS + 1
        self.assertEqual(st.reverify_due(now=int(time.time()), http_fetch=no_http, dns_txt=lambda n: []), [])
        result = st.reverify_due(now=later, http_fetch=no_http, dns_txt=lambda n: [])
        self.assertEqual([r["ok"] for r in result], [False])
        with self.assertRaises(st.ScopeDisabled):
            st.resolve_run_target("k6", "https://api.ornek.com")
        result = st.reverify_due(now=later + st.REVERIFY_SECONDS, http_fetch=no_http, dns_txt=txt)
        self.assertEqual([r["ok"] for r in result], [True])
        self.assertEqual(st.resolve_run_target("k6", "https://api.ornek.com")["host"], "api.ornek.com")

    def test_remote_resolution_must_be_global(self) -> None:
        def fake(addresses):
            return lambda host, port, type=0: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port)) for a in addresses]
        self.assertEqual(ts.resolve_remote("api.ornek.com", 443, fake(["93.184.216.34"])), "93.184.216.34")
        for bad in (["127.0.0.1"], ["10.0.0.5"], ["93.184.216.34", "192.168.1.1"], ["169.254.169.254"], []):
            with self.assertRaises(ts.SandboxUnavailable, msg=bad):
                ts.resolve_remote("api.ornek.com", 443, fake(bad))


class InputValidationTests(_DataDir):
    def test_k6_params(self) -> None:
        st.add_local_target(3000, ["k6"])
        ok = {"confirm": True, "target": "http://127.0.0.1:3000", "path": "/api/x", "preset": "orta"}
        self.assertEqual(slt._k6_params(ok)["preset"]["vus"], 10)
        bad = [{**ok, "confirm": False}, {**ok, "target": "http://127.0.0.1:3001"}, {**ok, "path": "//evil"},
               {**ok, "path": "/a/../b"}, {**ok, "method": "POST"}, {**ok, "preset": "sinirsiz"}, {**ok, "vus": 5},
               {**ok, "script": "x"}]
        for payload in bad:
            with self.assertRaises(ValueError, msg=payload):
                slt._k6_params(payload)

    def test_schema_validation(self) -> None:
        schema = {"openapi": "3.0.3", "info": {"title": "t", "version": "1"}, "servers": [{"url": "http://1.2.3.4"}],
                  "paths": {"/": {"get": {"responses": {"200": {"$ref": "#/components/responses/ok"}}}}}}
        self.assertNotIn("servers", json.loads(slt.validated_schema(schema)))
        for bad in ({"paths": {}}, {"openapi": "4.0.0", "paths": {}}, {**schema, "paths": {"/": {"$ref": "http://evil/x.json"}}}):
            with self.assertRaises(ValueError):
                slt.validated_schema(bad)

    def test_helper_unit_and_bwrap_flags(self) -> None:
        command = " ".join(ts._helper_command(Path("/w"), "u", 30, "systemd-run"))
        self.assertIn("NoNewPrivileges=yes", command)
        for namespacing in ("PrivateTmp", "ProtectSystem", "ProtectHome", "PrivateNetwork"):
            self.assertNotIn(namespacing, command)
        argv = ts.bwrap_argv(5, [])
        for flag in ("--unshare-user", "--unshare-net", "--unshare-pid", "--disable-userns", "--die-with-parent", "--clearenv"):
            self.assertIn(flag, argv)
        self.assertEqual(argv[argv.index("--cap-drop") + 1], "ALL")
        self.assertNotIn("--cap-add", argv)
        self.assertNotIn("/home", argv)
        low = ts.bwrap_argv(5, [], low_port=True)
        self.assertEqual(low[low.index("--cap-add") + 1], "CAP_NET_BIND_SERVICE")
        self.assertEqual(ts.hosts_file("api.ornek.com"), b"127.0.0.1 localhost\n127.0.0.1 api.ornek.com\n")


class SandboxApiTests(_DataDir):
    def setUp(self) -> None:
        super().setUp()
        import server
        from http.server import ThreadingHTTPServer
        from storage import Store
        self.server = server
        self.previous_store = server.STORE
        server.STORE = Store(self.data / "sniper.db")
        self.http = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.http.daemon_threads = True
        self.thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.thread.start()
        self.origin = f"http://127.0.0.1:{self.http.server_port}"
        self.opener = build_opener(ProxyHandler({}))

    def tearDown(self) -> None:
        self.http.shutdown()
        self.http.server_close()
        self.thread.join(timeout=3)
        self.server.STORE = self.previous_store
        super().tearDown()

    def call(self, route: str, payload: dict | None = None) -> tuple[int, dict]:
        data = None if payload is None else json.dumps(payload).encode()
        req = Request(self.origin + route, method="GET" if payload is None else "POST", data=data,
                      headers={"Content-Type": "application/json"})
        try:
            with self.opener.open(req, timeout=10) as response:
                return response.status, json.loads(response.read())
        except HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def actions(self) -> list[tuple[str, str]]:
        return [(row["action"], row["entity_id"]) for row in self.server.STORE.recent_audit_log(50)]

    def test_single_confirmation_scope_and_local_targets_are_audited(self) -> None:
        status, body = self.call("/api/sandbox-targets")
        self.assertEqual((status, body["scopes"]["critical"], body["local_host"]), (200, False, "127.0.0.1"))
        status, _ = self.call("/api/sandbox-targets", {"action": "add-local", "port": 3000})
        self.assertEqual(status, 400)  # 23. tur: eksik onay = 400
        status, body = self.call("/api/sandbox-targets", {"confirm": True, "action": "add-local", "port": 3000, "tools": ["k6"]})
        self.assertEqual((status, [t["id"] for t in body["targets"]]), (201, ["local:3000"]))
        status, _ = self.call("/api/sandbox-targets", {"confirm": True, "action": "add-local", "port": 8787})
        self.assertEqual(status, 403)  # kritik kapsam kapalı
        status, body = self.call("/api/sandbox-targets", {"confirm": True, "action": "scope", "scope": "critical", "enabled": True})
        self.assertEqual((status, body["scopes"]["critical"]), (200, True))
        self.assertIn("Uyarı", body["warning"])
        status, body = self.call("/api/sandbox-targets", {"confirm": True, "action": "add-local", "port": 8787})
        self.assertEqual((status, body["added"]["critical"]), (201, True))
        self.assertIn("warning", body)
        status, _ = self.call("/api/sandbox-targets", {"confirm": True, "action": "add-local", "port": 3001, "host": "10.0.0.1"})
        self.assertEqual(status, 400)
        status, _ = self.call("/api/sandbox-targets", {"confirm": True, "action": "remove", "id": "local:3000"})
        self.assertEqual(status, 200)
        status, _ = self.call("/api/sandbox-targets", {"confirm": True, "action": "preset-set", "name": "ozel", "vus": 3, "duration_s": 9})
        self.assertEqual(status, 200)
        actions = self.actions()
        for expected in (("sandbox_target.added", "local:3000"), ("sandbox_scope.changed", "critical"),
                         ("sandbox_target.added", "local:8787"), ("sandbox_target.removed", "local:3000"),
                         ("sandbox_preset.set", "ozel")):
            self.assertIn(expected, actions)
        self.assertTrue(self.server.STORE.verify_audit_chain()["verified"] if hasattr(self.server.STORE, "verify_audit_chain") else True)

    def test_remote_verification_single_button(self) -> None:
        status, _ = self.call("/api/sandbox-targets", {"confirm": True, "action": "verify-start", "host": "api.ornek.com"})
        self.assertEqual(status, 403)
        self.call("/api/sandbox-targets", {"confirm": True, "action": "scope", "scope": "remote_verified", "enabled": True})
        status, _ = self.call("/api/sandbox-targets", {"confirm": True, "action": "verify-start", "host": "93.184.216.34"})
        self.assertEqual(status, 400)
        status, body = self.call("/api/sandbox-targets", {"confirm": True, "action": "verify-start", "host": "api.ornek.com", "tools": ["k6"]})
        self.assertEqual(status, 201)
        verification = body["verification"]
        token = verification["http_body"]
        with mock.patch.object(st, "fetch_http_token", side_effect=st.VerificationFailed("yok")), \
                mock.patch.object(st, "_dns_query_txt", return_value=[]):
            status, _ = self.call("/api/sandbox-targets", {"confirm": True, "action": "verify", "id": verification["id"]})
        self.assertEqual(status, 422)
        with mock.patch.object(st, "fetch_http_token", return_value=token.encode()) as fetched, \
                mock.patch.object(st, "_dns_query_txt", return_value=[]):
            status, body = self.call("/api/sandbox-targets", {"confirm": True, "action": "verify", "id": verification["id"]})
        self.assertEqual((status, body["verified"]["id"]), (200, "remote:api.ornek.com:443"))
        fetched.assert_called_once_with("api.ornek.com", verification["id"])
        self.assertIn(("sandbox_target.verified", "remote:api.ornek.com:443"), self.actions())
        self.assertIn(("sandbox_target.verification_failed", verification["id"]), self.actions())

    def test_runs_refuse_unlisted_or_disabled_targets_before_launching(self) -> None:
        with mock.patch.object(ts.subprocess, "run") as launched:
            status, _ = self.call("/api/tool-runs/k6-sandbox", {"confirm": True, "target": "http://127.0.0.1:3000"})
            self.assertEqual(status, 400)
            self.call("/api/sandbox-targets", {"confirm": True, "action": "add-local", "port": 3000, "tools": ["k6"]})
            for target in ("http://127.0.0.1:3001", "http://10.0.0.1:3000", "https://api.ornek.com"):
                status, _ = self.call("/api/tool-runs/k6-sandbox", {"confirm": True, "target": target})
                self.assertEqual(status, 400, target)
            status, _ = self.call("/api/tool-runs/schemathesis-sandbox",
                                  {"confirm": True, "target": "http://127.0.0.1:3000", "schema": {"openapi": "3.0.0", "paths": {}}})
            self.assertEqual(status, 400)
            self.call("/api/sandbox-targets", {"confirm": True, "action": "scope", "scope": "local", "enabled": False})
            status, _ = self.call("/api/tool-runs/k6-sandbox", {"confirm": True, "target": "http://127.0.0.1:3000"})
            self.assertEqual(status, 403)
            status, _ = self.call("/api/tool-runs/k6-sandbox", {"target": "http://127.0.0.1:3000"})
            self.assertEqual(status, 400)
            launched.assert_not_called()


def _real_sandbox_available() -> bool:
    try:
        ts.open_bwrap().close()
        ts.open_k6().close()
    except ts.SandboxUnavailable:
        return False
    return ts.launch_mode() == "direct" or ts.SYSTEMD_RUN.is_file()


class _Fixture:
    def __init__(self, redirect_to: int | None = None) -> None:
        self.hits = 0
        fixture = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                fixture.hits += 1
                if redirect_to and self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", f"http://127.0.0.1:{redirect_to}/hit")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *_args: object) -> None:
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


PROBE = b"""import json, os, socket, urllib.request
def tcp(host, port):
    try:
        socket.create_connection((host, port), timeout=2).close()
        return "ok"
    except OSError as exc:
        return "err:%s" % exc.errno
allowed, other = int(os.environ["ALLOWED"]), int(os.environ["OTHER"])
result = {"allowed": tcp("127.0.0.1", allowed), "other": tcp("127.0.0.1", other),
          "external": tcp("1.1.1.1", 443), "home": os.path.exists("/home"), "data": os.path.exists(os.environ["DATA"]),
          "caps": open("/proc/self/status").read().split("CapEff:")[1].split()[0]}
try:
    result["redirect"] = urllib.request.urlopen("http://127.0.0.1:%d/redirect" % allowed, timeout=3).status
except Exception as exc:
    result["redirect"] = type(exc).__name__
try:
    os.unshare(os.CLONE_NEWUSER)
    result["userns"] = "ok"
except OSError:
    result["userns"] = "denied"
json.dump(result, open("/out/probe.json", "w"))
"""


@unittest.skipUnless(_real_sandbox_available(), "pinli bwrap/k6 yok")
class RealSandboxIsolationTests(_DataDir):
    def test_only_the_selected_target_is_reachable(self) -> None:
        other = _Fixture()
        allowed = _Fixture(redirect_to=other.port)
        try:
            st.add_local_target(allowed.port, ["k6"])

            def reader(work: Path) -> dict:
                raw = ts.read_output(work, "probe.json", 4096)
                return json.loads(raw) if raw else {}

            outer = ts.run_job("k6", f"http://127.0.0.1:{allowed.port}", argv=["/usr/bin/python3", "-I", "/job/probe.py"],
                               env={"PATH": "/usr/bin", "ALLOWED": str(allowed.port), "OTHER": str(other.port),
                                    "DATA": str(self.data)},
                               timeout=20, files={"probe.py": PROBE}, max_connections=10, max_bytes=1 << 20, reader=reader)
        finally:
            allowed.close()
            other.close()
        probe = outer["parsed"]
        self.assertEqual(probe["allowed"], "ok")
        self.assertNotEqual(probe["other"], "ok")       # listede olmayan yerel port
        self.assertNotEqual(probe["external"], "ok")    # dış adres (ağ ad alanında rota yok)
        self.assertNotEqual(probe["redirect"], 200)     # 302 ile başka porta yönlendirme ulaşamaz
        self.assertEqual(other.hits, 0)
        self.assertFalse(probe["home"])
        self.assertFalse(probe["data"])
        self.assertEqual(probe["caps"], "0000000000000000")
        self.assertEqual(probe["userns"], "denied")
        self.assertGreaterEqual(outer["relay"]["connections"], 1)

    def test_timeout_kills_the_tool_and_cleans_up(self) -> None:
        fixture = _Fixture()
        try:
            st.add_local_target(fixture.port, ["k6"])
            outer = ts.run_job("k6", f"http://127.0.0.1:{fixture.port}", argv=["/usr/bin/sleep", "317"],
                               env={"PATH": "/usr/bin"}, timeout=5, files={}, max_connections=1, max_bytes=1024)
        finally:
            fixture.close()
        self.assertTrue(outer["inner"]["timed_out"])
        left = subprocess.run(["pgrep", "-u", str(os.getuid()), "-f", "sleep 31[7]"], capture_output=True, text=True)
        self.assertEqual(left.stdout.strip(), "")
        self.assertEqual(list((self.data / "sandbox-runs").glob("k6-*")), [])

    def test_k6_preset_end_to_end(self) -> None:
        fixture = _Fixture()
        try:
            st.add_local_target(fixture.port, ["k6"])
            st.set_preset("deneme", 2, 2)
            result = slt.run_k6_sandbox({"confirm": True, "target": f"http://127.0.0.1:{fixture.port}", "path": "/",
                                         "preset": "deneme"})
        finally:
            fixture.close()
        self.assertEqual(result["preset"], {"name": "deneme", "vus": 2, "duration_s": 2})
        self.assertGreater(result["summary"]["http_requests"], 2)
        self.assertEqual(result["relay"]["refused"], 0)
        self.assertEqual(fixture.hits, result["summary"]["http_requests"])
        self.assertEqual(result["target"]["kind"], "local")


if __name__ == "__main__":
    unittest.main()
