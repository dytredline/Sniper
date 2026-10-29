from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
import unittest
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import schemathesis_active as active
import server
from storage import Store


ROUTE = "/api/tool-runs/schemathesis-local"
OLD_ROUTE = "/api/tool-reports/schemathesis-junit/summary"
FAKE_CLI = '''#!/usr/bin/python3
import json, os, sys
from urllib.request import urlopen
args = sys.argv[1:]
def value(flag): return args[args.index(flag) + 1]
origin = value("--url")
config = value("--config-file")
report = value("--report-junit-path")
schema = args[args.index("run") + 1]
trace = {"argv": args, "origin": origin, "config_bytes": len(open(config, "rb").read()),
         "config_mode": oct(os.stat(config).st_mode & 0o777),
         "schema_mode": oct(os.stat(schema).st_mode & 0o777),
         "schema": json.load(open(schema)), "cwd": os.getcwd(),
         "env_keys": sorted(os.environ)}
with open(TRACE_PATH, "w") as out: json.dump(trace, out)
with urlopen(origin + "/api/ping", timeout=2) as response:
    assert response.status == 200
with open(report, "w") as out:
    out.write('<testsuite name="private-url: https://secret.invalid/"><testcase name="GET /api/ping"/></testsuite>')
'''


def synthetic_schema(origin):
    return {"openapi": "3.0.3", "info": {"title": "Synthetic API", "version": "1.0"},
            "servers": [{"url": origin}], "paths": {"/api/ping": {"get": {
                "operationId": "syntheticPing", "responses": {"200": {"description": "OK",
                    "content": {"application/json": {"schema": {"type": "object",
                        "properties": {"ok": {"type": "boolean", "enum": [True]}},
                        "required": ["ok"]}}}}}}}}}


class PingHandler(BaseHTTPRequestHandler):
    calls = None

    def do_GET(self):
        self.calls.append((self.command, self.path))
        body = b'{"ok":true}'
        self.send_response(200 if self.path == "/api/ping" else 404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


class SchemathesisSyntheticLocalApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.root = Path(self.temp.name)
        self.old_store = server.STORE
        self.old_exe = active.ST_EXECUTABLE
        self.old_hash = active.ST_EXECUTABLE_SHA256
        self.old_work = active.WORK_PARENT
        self.old_origin = os.environ.get("SNIPER_SCHEMATHESIS_LOCAL_ORIGIN")
        server.STORE = Store(self.root / "data" / "sniper.db")

        PingHandler.calls = []
        self.fixture = ThreadingHTTPServer(("127.0.0.1", 0), PingHandler)
        self.fixture.daemon_threads = True
        self.fixture_thread = threading.Thread(target=self.fixture.serve_forever, daemon=True)
        self.fixture_thread.start()
        self.origin = f"http://127.0.0.1:{self.fixture.server_address[1]}"
        os.environ["SNIPER_SCHEMATHESIS_LOCAL_ORIGIN"] = self.origin

        self.api = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.api.daemon_threads = True
        self.api_thread = threading.Thread(target=self.api.serve_forever, daemon=True)
        self.api_thread.start()
        self.api_url = f"http://127.0.0.1:{self.api.server_address[1]}"

        self.trace = self.root / "fake-trace.json"
        self.fake = self.root / "fake-st"
        self.fake.write_text(FAKE_CLI.replace("TRACE_PATH", repr(str(self.trace))))
        self.fake.chmod(0o700)
        active.ST_EXECUTABLE = self.fake
        active.ST_EXECUTABLE_SHA256 = hashlib.sha256(self.fake.read_bytes()).hexdigest()
        active.WORK_PARENT = self.root / "private"

    def tearDown(self):
        self.api.shutdown()
        self.api.server_close()
        self.api_thread.join(timeout=2)
        self.fixture.shutdown()
        self.fixture.server_close()
        self.fixture_thread.join(timeout=2)
        server.STORE = self.old_store
        active.ST_EXECUTABLE = self.old_exe
        active.ST_EXECUTABLE_SHA256 = self.old_hash
        active.WORK_PARENT = self.old_work
        if self.old_origin is None:
            os.environ.pop("SNIPER_SCHEMATHESIS_LOCAL_ORIGIN", None)
        else:
            os.environ["SNIPER_SCHEMATHESIS_LOCAL_ORIGIN"] = self.old_origin
        self.temp.cleanup()

    def post(self, path, payload):
        request = Request(self.api_url + path, method="POST",
                          data=json.dumps(payload).encode("utf-8"),
                          headers={"Content-Type": "application/json"})
        with urlopen(request, timeout=8) as response:
            return response.status, json.loads(response.read())

    def reject(self, payload, expected=400):
        with self.assertRaises(HTTPError) as error:
            self.post(ROUTE, payload)
        self.assertEqual(error.exception.code, expected)
        body = error.exception.read().decode()
        self.assertLess(len(body.encode()), 2048)
        self.assertNotIn(self.origin, body)
        self.assertNotIn(str(self.root), body)

    def test_explicit_consent_and_exact_body_precede_child_or_target(self):
        schema = synthetic_schema(self.origin)
        for payload in ({"schema": schema}, {"confirm_local": False, "schema": schema},
                        {"confirm_local": True, "schema": schema, "target_url": self.origin},
                        {"confirm_local": True, "schema": schema, "flags": ["--url"]}):
            with self.subTest(payload=list(payload)):
                self.reject(payload)
        self.assertFalse(self.trace.exists())
        self.assertEqual(PingHandler.calls, [])

    def test_real_subprocess_result_is_aggregate_and_argv_is_fixed(self):
        code, result = self.post(ROUTE, {"confirm_local": True, "schema": synthetic_schema(self.origin)})
        self.assertEqual(code, 200)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["scope"], "synthetic-fixture-only")
        self.assertEqual(result["format"], "schemathesis-junit-xml")
        self.assertEqual(result["suite_count"], 1)
        self.assertEqual(result["testcase_count"], 1)
        self.assertEqual(result["outcome_counts"], {"passed": 1, "failed": 0,
                                                     "errors": 0, "skipped": 0})
        raw = '<testsuite name="private-url: https://secret.invalid/"><testcase name="GET /api/ping"/></testsuite>'
        self.assertEqual(result["report_sha256"], hashlib.sha256(raw.encode()).hexdigest())
        self.assertNotIn("secret.invalid", json.dumps(result))
        self.assertNotIn(self.origin, json.dumps(result))
        self.assertEqual(PingHandler.calls, [("GET", "/api/ping")])
        trace = json.loads(self.trace.read_text())
        args = trace["argv"]
        for flag, value in (("--url", self.origin), ("--workers", "1"),
                            ("--phases", "fuzzing"), ("--max-examples", "1"),
                            ("--max-time", "8"), ("--request-retries", "0"),
                            ("--max-redirects", "0"), ("--rate-limit", "1/s")):
            self.assertEqual(args[args.index(flag) + 1], value)
        self.assertEqual(trace["config_bytes"], 0)
        self.assertEqual(trace["config_mode"], "0o600")
        self.assertEqual(trace["schema_mode"], "0o600")
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", trace["env_keys"])
        self.assertEqual(trace["schema"], synthetic_schema(self.origin))
        self.assertFalse(list(active.WORK_PARENT.glob("run-*")))

    def test_schema_ref_target_override_and_extra_operation_rejected(self):
        base = synthetic_schema(self.origin)
        variants = []
        changed = deepcopy(base)
        changed["servers"] = [{"url": "https://elsewhere.invalid"}]
        variants.append(changed)
        changed = deepcopy(base)
        changed["paths"]["/api/ping"]["get"]["responses"]["200"]["content"] = {
            "application/json": {"schema": {"$ref": "https://elsewhere.invalid/schema"}}}
        variants.append(changed)
        changed = deepcopy(base)
        changed["paths"]["/api/other"] = changed["paths"]["/api/ping"]
        variants.append(changed)
        changed = deepcopy(base)
        changed["paths"]["/api/ping"]["post"] = changed["paths"]["/api/ping"]["get"]
        variants.append(changed)
        for schema in variants:
            with self.subTest(schema=schema):
                self.reject({"confirm_local": True, "schema": schema})
        self.assertFalse(self.trace.exists())
        self.assertEqual(PingHandler.calls, [])

    def test_missing_runtime_busy_and_invalid_report_fail_closed(self):
        schema = synthetic_schema(self.origin)
        active.ST_EXECUTABLE = self.root / "missing-st"
        self.reject({"confirm_local": True, "schema": schema}, expected=503)
        self.assertEqual(PingHandler.calls, [])
        active.ST_EXECUTABLE = self.fake
        active._SCANNER_LOCK.acquire()
        try:
            self.reject({"confirm_local": True, "schema": schema}, expected=503)
        finally:
            active._SCANNER_LOCK.release()
        self.assertEqual(PingHandler.calls, [])
        self.fake.write_text('#!/usr/bin/python3\nimport sys\nsys.exit(3)\n')
        self.fake.chmod(0o700)
        active.ST_EXECUTABLE_SHA256 = hashlib.sha256(self.fake.read_bytes()).hexdigest()
        self.reject({"confirm_local": True, "schema": schema}, expected=502)
        self.assertFalse(list(active.WORK_PARENT.glob("run-*")))

    def test_group_or_other_writable_runtime_is_rejected_before_target(self):
        self.fake.chmod(0o770)
        self.reject({"confirm_local": True, "schema": synthetic_schema(self.origin)}, expected=503)
        self.assertFalse(self.trace.exists())
        self.assertEqual(PingHandler.calls, [])

    def test_saved_junit_control_and_dtd_negative_remain_separate(self):
        good = '<testsuite><testcase name="GET /api/ping"/></testsuite>'
        code, result = self.post(OLD_ROUTE, {"report": good})
        self.assertEqual(code, 200)
        self.assertEqual(result["testcase_count"], 1)
        self.assertEqual(result["outcome_counts"]["passed"], 1)
        with self.assertRaises(HTTPError) as error:
            self.post(OLD_ROUTE, {"report": '<!DOCTYPE testsuite><testsuite/>'})
        self.assertEqual(error.exception.code, 400)
        self.assertFalse(self.trace.exists())
        self.assertEqual(PingHandler.calls, [])


if __name__ == "__main__":
    unittest.main()
