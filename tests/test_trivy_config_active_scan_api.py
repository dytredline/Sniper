from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import server
import trivy_config_active
from storage import Store


class TrivyDockerfileConfigApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.base = Path(self.temp.name)
        self.project = self.base / "project"
        self.project.mkdir()
        (self.project / "Dockerfile").write_text("FROM scratch\nUSER 1000\nHEALTHCHECK CMD [\"/bin/true\"]\n")
        self.binary = self.base / "fake-trivy"
        self.binary.write_text(
            f"#!{sys.executable}\n"
            "import json,sys\n"
            "from pathlib import Path\n"
            "a=sys.argv[1:]; out=Path(a[a.index('--output')+1]); source=Path(a[-1])\n"
            "bad='USER 1000' not in (source/'Dockerfile').read_text()\n"
            "findings=[{'ID':'DS-0002'}] if bad else []\n"
            "row={'Target':'Dockerfile','Class':'config','Type':'dockerfile','MisconfSummary':{'Successes':1,'Failures':len(findings)},'Misconfigurations':findings}\n"
            "out.write_text(json.dumps({'SchemaVersion':2,'Results':[row]}))\n"
        )
        self.binary.chmod(self.binary.stat().st_mode | stat.S_IXUSR)
        self.old_env = os.environ.copy()
        self.old_digest = trivy_config_active.EXPECTED_TRIVY_SHA256
        os.environ["SNIPER_TRIVY_BINARY"] = str(self.binary)
        os.environ["SNIPER_DATA_DIR"] = str(self.base)
        trivy_config_active.EXPECTED_TRIVY_SHA256 = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        self.old_store, self.old_limiter = server.STORE, server.LIMITER
        server.STORE = Store(self.base / "sniper.db")
        server.LIMITER = server.RateLimiter()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.httpd.server_port}/api/tool-runs/trivy-dockerfile-config"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=3)
        server.STORE, server.LIMITER = self.old_store, self.old_limiter
        trivy_config_active.EXPECTED_TRIVY_SHA256 = self.old_digest
        os.environ.clear()
        os.environ.update(self.old_env)
        self.temp.cleanup()

    def post(self, body):
        request = Request(self.url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read())
        except HTTPError as error:
            try:
                return error.code, json.loads(error.read())
            finally:
                error.close()

    def request_body(self):
        return {"confirm_local": True, "project_path": str(self.project)}

    def test_runtime_result_changes_with_dockerfile_behavior(self):
        status, clean = self.post(self.request_body())
        self.assertEqual(status, 200)
        self.assertEqual(clean["profile"], "local-dockerfile-config-v1")
        self.assertEqual(clean["finding_counts"]["misconfigurations"], 0)
        (self.project / "Dockerfile").write_text("FROM scratch\nRUN echo hello\n")
        status, bad = self.post(self.request_body())
        self.assertEqual(status, 200)
        self.assertEqual(bad["finding_counts"]["misconfigurations"], 1)
        self.assertNotEqual(clean["report_sha256"], bad["report_sha256"])
        self.assertNotIn(str(self.project), json.dumps(bad))
        self.assertNotIn("DS-0002", json.dumps(bad))

    def test_rejects_missing_consent_and_nonlocal_path(self):
        self.assertEqual(self.post({"project_path": str(self.project)})[0], 400)
        self.assertEqual(self.post({"confirm_local": True, "project_path": "/etc"})[0], 400)

    def test_rejects_symlinked_dockerfile(self):
        source = self.project / "Dockerfile"
        source.rename(self.project / "real.Dockerfile")
        source.symlink_to(self.project / "real.Dockerfile")
        self.assertEqual(self.post(self.request_body())[0], 400)

    def test_rejects_binary_hash_mismatch(self):
        trivy_config_active.EXPECTED_TRIVY_SHA256 = "0" * 64
        self.assertEqual(self.post(self.request_body())[0], 503)


@unittest.skipUnless(os.environ.get("TRIVY_CONFIG_TEST_BINARY"), "real Trivy binary not supplied")
class RealTrivyDockerfileConfigTests(unittest.TestCase):
    def test_real_binary_positive_and_negative_controls(self):
        old_env = os.environ.copy()
        with tempfile.TemporaryDirectory(dir=Path.home()) as directory:
            root = Path(directory)
            project = root / "project"
            project.mkdir()
            os.environ["SNIPER_DATA_DIR"] = str(root)
            os.environ["SNIPER_TRIVY_BINARY"] = os.environ["TRIVY_CONFIG_TEST_BINARY"]
            try:
                file = project / "Dockerfile"
                file.write_text('FROM scratch\nUSER 1000\nHEALTHCHECK CMD ["/bin/true"]\n')
                clean = trivy_config_active.run_local_trivy_dockerfile(str(project))
                file.write_text("FROM scratch\nRUN echo hello\n")
                bad = trivy_config_active.run_local_trivy_dockerfile(str(project))
                self.assertEqual(clean["finding_counts"]["misconfigurations"], 0)
                self.assertGreaterEqual(bad["finding_counts"]["misconfigurations"], 1)
            finally:
                os.environ.clear()
                os.environ.update(old_env)
