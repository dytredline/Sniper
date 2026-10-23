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


class TrivyKubernetesConfigApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.base = Path(self.temp.name)
        self.project = self.base / "project"
        self.project.mkdir()
        self.manifest = self.project / "pod.yaml"
        self.manifest.write_text(self.source(privileged=False, host_network=False))
        self.binary = self.base / "fake-trivy"
        self.binary.write_text(
            f"#!{sys.executable}\n"
            "import json,sys\n"
            "from pathlib import Path\n"
            "a=sys.argv[1:]; assert a[0]=='config'\n"
            "assert a[a.index('--misconfig-scanners')+1]=='kubernetes'\n"
            "assert '--skip-check-update' in a and '--skip-version-check' in a\n"
            "assert '--config=' in a and '--ignorefile=' in a\n"
            "source=Path(a[-1]); assert [p.name for p in source.iterdir()]==['manifest.yaml']\n"
            "data=(source/'manifest.yaml').read_text()\n"
            "bad='privileged: true' in data; host='hostNetwork: true' in data\n"
            "items=[{'ID':'KSV-0017'}] if bad else []\n"
            "items += [{'ID':'KSV-0009'}] if host else []\n"
            "row={'Target':'manifest.yaml','Class':'config','Type':'kubernetes','MisconfSummary':{'Successes':1,'Failures':len(items)},'Misconfigurations':items}\n"
            "Path(a[a.index('--output')+1]).write_text(json.dumps({'SchemaVersion':2,'Results':[row]}))\n"
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
        self.url = f"http://127.0.0.1:{self.httpd.server_port}/api/tool-runs/trivy-kubernetes-config"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=3)
        server.STORE, server.LIMITER = self.old_store, self.old_limiter
        trivy_config_active.EXPECTED_TRIVY_SHA256 = self.old_digest
        os.environ.clear()
        os.environ.update(self.old_env)
        self.temp.cleanup()

    @staticmethod
    def source(*, privileged: bool, host_network: bool) -> str:
        return (
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: demo\nspec:\n"
            f"  hostNetwork: {str(host_network).lower()}\n"
            "  containers:\n  - name: web\n    image: nginx:latest\n"
            f"    securityContext:\n      privileged: {str(privileged).lower()}\n"
        )

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
        return {"confirm_local": True, "project_path": str(self.project), "manifest_name": "pod.yaml"}

    def test_runtime_result_tracks_kubernetes_manifest(self):
        status, control = self.post(self.request_body())
        self.assertEqual(status, 200)
        self.assertEqual(control["profile"], "local-kubernetes-manifest-config-v1")
        self.assertEqual(control["finding_counts"]["misconfigurations"], 0)
        self.manifest.write_text(self.source(privileged=True, host_network=False))
        status, privileged = self.post(self.request_body())
        self.assertEqual(status, 200)
        self.assertEqual(privileged["finding_counts"]["misconfigurations"], 1)
        self.assertNotEqual(control["report_sha256"], privileged["report_sha256"])
        self.assertNotIn(str(self.project), json.dumps(privileged))
        self.assertNotIn("KSV-0017", json.dumps(privileged))
        self.manifest.write_text(self.source(privileged=False, host_network=True))
        status, host_network = self.post(self.request_body())
        self.assertEqual(status, 200)
        self.assertEqual(host_network["finding_counts"]["misconfigurations"], 1)
        self.assertNotEqual(host_network["report_sha256"], privileged["report_sha256"])

    def test_rejects_missing_consent_and_nonlocal_path(self):
        self.assertEqual(self.post({"project_path": str(self.project), "manifest_name": "pod.yaml"})[0], 400)
        self.assertEqual(self.post({"confirm_local": True, "project_path": "/etc", "manifest_name": "pod.yaml"})[0], 400)

    def test_rejects_filename_traversal_and_symlink(self):
        body = self.request_body()
        for name in ("../pod.yaml", "/etc/passwd", "pod.yaml/../x.yaml", "pod.json", "..hidden.yaml"):
            self.assertEqual(self.post({**body, "manifest_name": name})[0], 400, name)
        self.manifest.rename(self.project / "real.yaml")
        self.manifest.symlink_to(self.project / "real.yaml")
        self.assertEqual(self.post(body)[0], 400)

    def test_rejects_binary_hash_mismatch(self):
        trivy_config_active.EXPECTED_TRIVY_SHA256 = "0" * 64
        self.assertEqual(self.post(self.request_body())[0], 503)
