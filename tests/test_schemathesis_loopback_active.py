from __future__ import annotations

import json
import os
import socket
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import schemathesis_loopback_active as active
import server
from storage import Store

ROUTE = "/api/tool-runs/schemathesis-loopback"
SAVED_ROUTE = "/api/tool-reports/schemathesis-junit/summary"
REPORT = b'<testsuite><testcase name="GET /api/ping"/></testsuite>'


def schema():
    return {"openapi": "3.0.3", "info": {"title": "Synthetic", "version": "1"},
            "paths": {"/api/ping": {"get": {"operationId": "ping", "responses": {
                "200": {"description": "OK", "content": {"application/json": {
                    "schema": {"type": "object", "properties": {"ok": {"type": "boolean"}}}}}}}}}}}


class Ping(BaseHTTPRequestHandler):
    calls = None
    def do_GET(self):
        self.calls.append(self.path)
        body = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *_):
        pass


def relay_request(socket_path: Path, path: str) -> dict:
    raw = json.dumps({"method": "GET", "path": path}, separators=(",", ":")).encode()
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(3)
        sock.connect(str(socket_path))
        sock.sendall(len(raw).to_bytes(4, "big") + raw)
        head = sock.recv(4)
        assert len(head) == 4
        size = int.from_bytes(head, "big")
        body = b""
        while len(body) < size:
            body += sock.recv(size-len(body))
    return json.loads(body)


class LoopbackApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=Path.home())
        self.root = Path(self.tmp.name)
        self.old_store = server.STORE
        server.STORE = Store(self.root / "sniper.db")
        self.old_ports = os.environ.get("SNIPER_SCHEMATHESIS_ALLOWED_PORTS")
        self.old_work = active.WORK_PARENT
        active.WORK_PARENT = self.root / "work"
        Ping.calls = []
        self.fixture = ThreadingHTTPServer(("127.0.0.1", 0), Ping)
        self.fixture.daemon_threads = True
        self.fixture_thread = threading.Thread(target=self.fixture.serve_forever, daemon=True)
        self.fixture_thread.start()
        self.port = self.fixture.server_address[1]
        os.environ["SNIPER_SCHEMATHESIS_ALLOWED_PORTS"] = str(self.port)
        self.api = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.api.daemon_threads = True
        self.api_thread = threading.Thread(target=self.api.serve_forever, daemon=True)
        self.api_thread.start()
        self.url = f"http://127.0.0.1:{self.api.server_address[1]}"

    def tearDown(self):
        self.api.shutdown(); self.api.server_close(); self.api_thread.join(timeout=2)
        self.fixture.shutdown(); self.fixture.server_close(); self.fixture_thread.join(timeout=2)
        server.STORE = self.old_store
        active.WORK_PARENT = self.old_work
        if self.old_ports is None:
            os.environ.pop("SNIPER_SCHEMATHESIS_ALLOWED_PORTS", None)
        else:
            os.environ["SNIPER_SCHEMATHESIS_ALLOWED_PORTS"] = self.old_ports
        self.tmp.cleanup()

    def post(self, route, body):
        request = Request(self.url + route, method="POST", data=json.dumps(body).encode(),
                          headers={"Content-Type": "application/json"})
        try:
            with urlopen(request, timeout=8) as response:
                return response.status, json.loads(response.read())
        except HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def body(self):
        return {"confirm_local": True, "target_url": f"http://127.0.0.1:{self.port}", "schema": schema()}

    def fake_container(self, work, relay):
        response = relay_request(work / "relay.sock", "/api/ping")
        self.assertEqual(response["status"], 200)
        (work / "report.xml").write_bytes(REPORT)

    def test_consent_allowlist_and_schema_fail_before_any_target_request(self):
        for changed in ({"confirm_local": False}, {"target_url": "http://localhost:1234"},
                        {"target_url": "http://127.0.0.1:1"}, {"flags": ["--url"]},
                        {"target_url": f"http://127.0.0.1:{self.port}/"}):
            request = self.body(); request.update(changed)
            code, _ = self.post(ROUTE, request)
            self.assertEqual(code, 400)
        request = self.body(); del request["confirm_local"]
        self.assertEqual(self.post(ROUTE, request)[0], 400)
        unsafe = self.body(); unsafe["schema"]["paths"]["/api/ping"]["get"]["parameters"] = []
        self.assertEqual(self.post(ROUTE, unsafe)[0], 400)
        self.assertEqual(Ping.calls, [])

    def test_aggregate_runtime_result_and_saved_import_control(self):
        with patch.object(active, "_docker_ready"), patch.object(active, "_execute_container", self.fake_container):
            code, result = self.post(ROUTE, self.body())
        self.assertEqual(code, 200)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["scope"], "approved-loopback")
        self.assertEqual(result["request_count"], 1)
        self.assertEqual(result["testcase_count"], 1)
        self.assertEqual(result["outcome_counts"]["passed"], 1)
        self.assertEqual(Ping.calls, ["/api/ping"])
        self.assertNotIn(str(self.port), json.dumps(result))
        saved_code, saved = self.post(SAVED_ROUTE, {"report": REPORT.decode()})
        self.assertEqual(saved_code, 200)
        self.assertEqual(saved["testcase_count"], 1)

    def test_schema_discovery_probe_is_suppressed_without_backend_delivery(self):
        probes = []
        def probe_then_run(work, relay):
            probes.append(relay_request(work / "relay.sock", "/"))
            probes.append(relay_request(work / "relay.sock", "/api/ping"))
            (work / "report.xml").write_bytes(REPORT)
        with patch.object(active, "_docker_ready"), patch.object(active, "_execute_container", probe_then_run):
            code, result = self.post(ROUTE, self.body())
        self.assertEqual(code, 200)
        self.assertEqual([item["status"] for item in probes], [404, 200])
        self.assertEqual(result["request_count"], 1)
        self.assertEqual(Ping.calls, ["/api/ping"])

    def test_25th_request_is_not_delivered_and_never_clean(self):
        responses = []
        def exceed(work, relay):
            for _ in range(25):
                responses.append(relay_request(work / "relay.sock", "/api/ping")["status"])
            (work / "report.xml").write_bytes(REPORT)
        with patch.object(active, "_docker_ready"), patch.object(active, "_execute_container", exceed):
            code, result = self.post(ROUTE, self.body())
        self.assertEqual(code, 502)
        self.assertEqual(responses, [200]*24 + [429])
        self.assertEqual(len(Ping.calls), 24)
        self.assertNotIn("completed", json.dumps(result))

    def test_alternate_origin_is_blocked_before_target_delivery(self):
        received = []
        def escape(work, relay):
            received.append(relay_request(work / "relay.sock", "http://127.0.0.1:9/api/ping"))
            (work / "report.xml").write_bytes(REPORT)
        with patch.object(active, "_docker_ready"), patch.object(active, "_execute_container", escape):
            code, _ = self.post(ROUTE, self.body())
        self.assertEqual(code, 502)
        self.assertEqual(received[0]["status"], 403)
        self.assertEqual(Ping.calls, [])

    def test_missing_docker_or_empty_allowlist_fails_closed(self):
        with patch.object(active, "DOCKER_EXE", self.root / "absent-docker"):
            self.assertEqual(self.post(ROUTE, self.body())[0], 503)
        os.environ.pop("SNIPER_SCHEMATHESIS_ALLOWED_PORTS")
        self.assertEqual(self.post(ROUTE, self.body())[0], 503)
        self.assertEqual(Ping.calls, [])


if __name__ == "__main__":
    unittest.main()
