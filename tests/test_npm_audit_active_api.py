import fcntl
import json
import os
import subprocess
import tempfile
import threading
import unittest
from contextlib import contextmanager
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import npm_audit_active
import server
from storage import Store


class NpmAuditActiveApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.base = Path(self.temp.name)
        self.data = self.base / "data"
        self.data.mkdir()
        self.project = self.base / "project"
        self.project.mkdir()
        self.previous_store = server.STORE
        self.previous_data = os.environ.get("SNIPER_DATA_DIR")
        server.STORE = Store(self.data / "sniper.db")
        os.environ["SNIPER_DATA_DIR"] = str(self.data)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        server.STORE = self.previous_store
        if self.previous_data is None:
            os.environ.pop("SNIPER_DATA_DIR", None)
        else:
            os.environ["SNIPER_DATA_DIR"] = self.previous_data
        self.temp.cleanup()

    def request(self, payload, route="/api/tool-runs/npm-audit-local"):
        data = json.dumps(payload).encode()
        request = Request(self.url + route, data=data, method="POST",
                          headers={"Content-Type": "application/json"})
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, response.read().decode()
        except HTTPError as exc:
            return exc.code, exc.read().decode()

    def write_lock(self, spec="4.17.20", *, resolved="https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"):
        lock = {
            "name": "private-project-marker",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "private-project-marker", "version": "1.0.0",
                     "dependencies": {"lodash": spec}},
                "node_modules/lodash": {"version": "4.17.20", "resolved": resolved},
            },
        }
        (self.project / "package-lock.json").write_text(json.dumps(lock))

    def consent(self):
        return {"confirm_local": True, "confirm_registry": True, "project_path": str(self.project)}

    @contextmanager
    def fake_audit(self, report):
        calls = []

        class _FakePinnedNode:
            argv0 = "/opt/node/bin/node"
            path = Path("/opt/node/bin/node")

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def popen_kwargs(self, **kwargs):
                return kwargs

            def close(self):
                pass

        def fake_run(cmd, *, cwd, env, stdout, stderr, timeout, check, stdin=None, **_extra):
            calls.append({"cmd": cmd, "cwd": str(cwd), "env": env, "timeout": timeout})
            stdout.write(json.dumps(report).encode())
            return subprocess.CompletedProcess(cmd, 0)

        with patch.object(npm_audit_active, "open_pinned", return_value=_FakePinnedNode()), patch.object(
            npm_audit_active, "_pinned_runtime", return_value=Path("/opt/node/lib/npm-cli.js")
        ), patch.object(npm_audit_active.subprocess, "run", side_effect=fake_run):
            yield calls

    def test_runtime_result_redacted_and_fixed_command(self):
        self.write_lock()
        report = {"auditReportVersion": 2, "vulnerabilities": {
            "lodash": {"severity": "high", "title": "private-advisory-marker"}
        }}
        with self.fake_audit(report) as calls:
            code, body = self.request(self.consent())
        self.assertEqual(code, 200)
        result = json.loads(body)
        self.assertEqual(result["profile"], "local-npm-audit-v1")
        self.assertEqual(result["affected_package_count"], 1)
        self.assertEqual(result["package_severity_counts"]["high"], 1)
        self.assertRegex(result["report_sha256"], r"^[0-9a-f]{64}$")
        for secret in ("lodash", "private-project-marker", "private-advisory-marker", str(self.project)):
            self.assertNotIn(secret, body)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["cmd"][1:4], ["--jitless", "/opt/node/lib/npm-cli.js", "audit"])
        self.assertIn("--registry=https://registry.npmjs.org", calls[0]["cmd"])
        self.assertIn("--ignore-scripts", calls[0]["cmd"])
        self.assertNotIn("HTTPS_PROXY", calls[0]["env"])
        self.assertNotIn("HTTP_PROXY", calls[0]["env"])

    def test_clean_runtime_result(self):
        self.write_lock(spec="4.17.21")
        with self.fake_audit({"auditReportVersion": 2, "vulnerabilities": {}}):
            code, body = self.request(self.consent())
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body)["affected_package_count"], 0)

    def test_missing_consent_and_extra_fields_rejected(self):
        self.write_lock()
        for payload in (
            {"confirm_local": True, "project_path": str(self.project)},
            {"confirm_local": True, "confirm_registry": False, "project_path": str(self.project)},
            self.consent() | {"registry": "https://example.invalid"},
        ):
            with self.subTest(payload=payload):
                code, _ = self.request(payload)
                self.assertEqual(code, 400)

    def test_symlink_and_foreign_resolved_rejected(self):
        self.write_lock()
        target = self.project / "real-lock.json"
        (self.project / "package-lock.json").rename(target)
        (self.project / "package-lock.json").symlink_to(target)
        code, _ = self.request(self.consent())
        self.assertEqual(code, 400)
        (self.project / "package-lock.json").unlink()
        self.write_lock(resolved="https://evil.invalid/pkg.tgz")
        code, _ = self.request(self.consent())
        self.assertEqual(code, 400)

    def test_legacy_v2_foreign_origin_and_local_spec_rejected(self):
        lock = {
            "lockfileVersion": 2,
            "packages": {
                "": {"dependencies": {"lodash": "4.17.20"}},
                "node_modules/lodash": {"version": "4.17.20"},
            },
            "dependencies": {
                "lodash": {"version": "4.17.20", "resolved": "https://evil.invalid/pkg.tgz"}
            },
        }
        (self.project / "package-lock.json").write_text(json.dumps(lock))
        code, _ = self.request(self.consent())
        self.assertEqual(code, 400)
        lock["dependencies"]["lodash"]["resolved"] = "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"
        lock["packages"][""]["dependencies"]["lodash"] = "file:../private"
        (self.project / "package-lock.json").write_text(json.dumps(lock))
        code, _ = self.request(self.consent())
        self.assertEqual(code, 400)

    def test_unconfigured_runtime_bounded_503(self):
        self.write_lock()
        with patch.dict(os.environ, {
            "SNIPER_NODE_BINARY": "", "SNIPER_NPM_CLI": "",
            "SNIPER_NODE_SHA256": "", "SNIPER_NPM_CLI_SHA256": "",
        }):
            code, body = self.request(self.consent())
        self.assertEqual(code, 503)
        self.assertNotIn("package-lock", body)

    def test_busy_lock_bounded_503(self):
        self.write_lock()
        fd = os.open(self.data / "npm-audit.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            code, _ = self.request(self.consent())
            self.assertEqual(code, 503)
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def test_health_preserved(self):
        with urlopen(self.url + "/api/health", timeout=5) as response:
            self.assertEqual(json.load(response)["status"], "ok")


if __name__ == "__main__":
    unittest.main()
