import json
import os
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener


class AuthorizedTargetParserTests(unittest.TestCase):
    def test_normalizes_one_run_http_origins_without_registration(self) -> None:
        import authorized_tool_targets

        self.assertEqual(
            authorized_tool_targets.parse_authorized_target("k6", "HTTPS://Api.Example.COM:443/")["normalized"],
            "https://api.example.com:443",
        )
        self.assertEqual(
            authorized_tool_targets.parse_authorized_target("schemathesis", "http://127.0.0.1:49123")["normalized"],
            "http://127.0.0.1:49123",
        )

    def test_rejects_ambiguous_or_malformed_targets(self) -> None:
        import authorized_tool_targets

        for target in (
            "https://user:secret@example.com",
            "https://example.com/api",
            "https://example.com?next=elsewhere",
            "https://example.com#fragment",
            " https://example.com",
            "https://example.com\\@elsewhere.test",
            "http://2130706433",
            "ftp://example.com",
        ):
            with self.subTest(target=target), self.assertRaises(ValueError):
                authorized_tool_targets.parse_authorized_target("k6", target)

    def test_run_confirmed_hostname_may_resolve_to_public_or_private_unicast(self) -> None:
        import tool_sandbox

        def resolver(address: str):
            return lambda _host, port, type=0: [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port)),
            ]

        self.assertEqual(tool_sandbox.resolve_authorized_host("api.example.test", 443, resolver("203.0.113.10")),
                         "203.0.113.10")
        self.assertEqual(tool_sandbox.resolve_authorized_host("api.internal", 8080, resolver("10.20.30.40")),
                         "10.20.30.40")
        with self.assertRaises(tool_sandbox.SandboxUnavailable):
            tool_sandbox.resolve_authorized_host("multicast.test", 80, resolver("224.0.0.1"))


class AuthorizedTargetApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.data = Path(self.tmp.name)
        self.env = mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(self.data)}, clear=False)
        self.env.start()

        import server
        from http.server import ThreadingHTTPServer
        from storage import Store

        self.server_module = server
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
        self.server_module.STORE = self.previous_store
        self.env.stop()
        self.tmp.cleanup()

    def post(self, route: str, payload: dict) -> tuple[int, dict]:
        request = Request(
            self.origin + route,
            method="POST",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        try:
            with self.opener.open(request, timeout=10) as response:
                return response.status, json.loads(response.read())
        except HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_k6_requires_exact_authorized_confirmation_and_returns_audit_receipt(self) -> None:
        result = {
            "format": "k6-authorized-target-v1",
            "status": "completed",
            "normalized_target": "http://127.0.0.1:49123",
            "relay": {"connections": 3, "refused": 0, "bytes": 600},
            "summary": {"http_requests": 3},
        }
        payload = {
            "confirm_authorized": True,
            "target": "HTTP://127.0.0.1:49123/",
            "path": "/health",
            "method": "GET",
            "preset": "hafif",
        }
        with mock.patch.object(self.server_module, "run_k6_authorized", return_value=result) as run:
            status, body = self.post("/api/tool-runs/k6-authorized", payload)
        self.assertEqual(status, 200)
        run.assert_called_once_with(payload)
        self.assertEqual(body["normalized_target"], "http://127.0.0.1:49123")
        self.assertEqual(
            set(body["authorization_receipt"]),
            {"actor", "confirmed_at", "consent_version", "normalized_target"},
        )
        self.assertEqual(body["authorization_receipt"]["actor"], "yerel")
        self.assertEqual(body["authorization_receipt"]["consent_version"], "authorized-target-v1")
        self.assertRegex(body["authorization_receipt"]["confirmed_at"], r"^\d{4}-\d\d-\d\dT")
        event = self.server_module.STORE.recent_audit_log(1)[0]
        self.assertEqual(event["action"], "authorized_tool_run.completed")
        self.assertEqual(event["details"]["normalized_target"], "http://127.0.0.1:49123")

        for confirmation in (False, 1, "true", None):
            rejected = dict(payload)
            rejected["confirm_authorized"] = confirmation
            status, _ = self.post("/api/tool-runs/k6-authorized", rejected)
            self.assertEqual(status, 400)
        status, _ = self.post("/api/tool-runs/k6-authorized", {**payload, "script": "user supplied"})
        self.assertEqual(status, 400)

    def test_schemathesis_uses_the_same_authorized_target_receipt(self) -> None:
        payload = {
            "confirm_authorized": True,
            "target": "http://localhost:49123",
            "schema": {"openapi": "3.0.3", "info": {"title": "t", "version": "1"}, "paths": {}},
            "max_examples": 3,
            "max_time_s": 10,
        }
        result = {
            "format": "schemathesis-authorized-target-v1",
            "status": "completed",
            "normalized_target": "http://localhost:49123",
            "relay": {"connections": 1, "refused": 0, "bytes": 100},
            "summary": {"testcases": 1},
        }
        with mock.patch.object(self.server_module, "run_schemathesis_authorized", return_value=result):
            status, body = self.post("/api/tool-runs/schemathesis-authorized", payload)
        self.assertEqual(status, 200)
        self.assertEqual(body["authorization_receipt"]["normalized_target"], "http://localhost:49123")

    def test_existing_registered_route_and_payload_are_unchanged_control(self) -> None:
        status, _ = self.post(
            "/api/tool-runs/k6-sandbox",
            {"confirm_authorized": True, "target": "http://127.0.0.1:49123"},
        )
        self.assertEqual(status, 400)


def _real_k6_sandbox_available() -> bool:
    try:
        import tool_sandbox
        tool_sandbox.open_bwrap().close()
        tool_sandbox.open_k6().close()
        return tool_sandbox.launch_mode() == "direct" or tool_sandbox.SYSTEMD_RUN.is_file()
    except Exception:
        return False


@unittest.skipUnless(_real_k6_sandbox_available(), "pinli bwrap/k6 yok")
class AuthorizedK6RuntimeTests(unittest.TestCase):
    def test_unregistered_loopback_target_runs_through_the_single_target_relay(self) -> None:
        from tests.test_sandbox_load_tests import _Fixture
        import sandbox_load_tests
        import sandbox_targets

        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": directory}, clear=False):
            fixture = _Fixture()
            try:
                sandbox_targets.set_preset("kanit", 2, 2)
                self.assertEqual(sandbox_targets.status()["targets"], [])
                result = sandbox_load_tests.run_k6_authorized({
                    "confirm_authorized": True,
                    "target": f"http://127.0.0.1:{fixture.port}",
                    "path": "/",
                    "method": "GET",
                    "preset": "kanit",
                })
            finally:
                fixture.close()
        self.assertEqual(result["format"], "k6-authorized-target-v1")
        self.assertEqual(result["target"]["kind"], "loopback")
        self.assertGreater(result["summary"]["http_requests"], 0)
        self.assertEqual(result["relay"]["refused"], 0)
        self.assertEqual(fixture.hits, result["summary"]["http_requests"])


def _real_schemathesis_sandbox_available() -> bool:
    try:
        import tool_sandbox
        tool_sandbox.open_bwrap().close()
        tool_sandbox.schemathesis_venv()
        return tool_sandbox.launch_mode() == "direct" or tool_sandbox.SYSTEMD_RUN.is_file()
    except Exception:
        return False


@unittest.skipUnless(_real_schemathesis_sandbox_available(), "pinli bwrap/Schemathesis yok")
class AuthorizedSchemathesisRuntimeTests(unittest.TestCase):
    def test_unregistered_loopback_schema_runs_through_the_single_target_relay(self) -> None:
        from tests.test_sandbox_load_tests import _Fixture
        import sandbox_load_tests
        import sandbox_targets

        schema = {
            "openapi": "3.0.3",
            "info": {"title": "fixture", "version": "1"},
            "paths": {"/": {"get": {"responses": {"200": {"description": "ok"}}}}},
        }
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": directory}, clear=False):
            fixture = _Fixture()
            try:
                self.assertEqual(sandbox_targets.status()["targets"], [])
                result = sandbox_load_tests.run_schemathesis_authorized({
                    "confirm_authorized": True,
                    "target": f"http://127.0.0.1:{fixture.port}",
                    "schema": schema,
                    "max_examples": 1,
                    "max_time_s": 10,
                })
            finally:
                fixture.close()
        self.assertEqual(result["format"], "schemathesis-authorized-target-v1")
        self.assertEqual(result["target"]["kind"], "loopback")
        self.assertGreater(result["relay"]["connections"], 0)
        self.assertEqual(result["relay"]["refused"], 0)
        self.assertGreater(result["summary"]["testcase_count"], 0)
        self.assertGreater(fixture.hits, 0)
        self.assertLessEqual(fixture.hits, result["relay"]["connections"])


if __name__ == "__main__":
    unittest.main()
