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


class TrivyKubernetesBatchApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.base = Path(self.temp.name)
        self.project = self.base / "project"
        self.project.mkdir()
        self.binary = self.base / "fake-trivy"
        self.binary.write_text(
            f"#!{sys.executable}\n"
            "import json,sys\n"
            "from pathlib import Path\n"
            "a=sys.argv[1:]; assert a[0]=='config'\n"
            "assert a[a.index('--misconfig-scanners')+1]=='kubernetes'\n"
            "assert '--skip-check-update' in a and '--skip-version-check' in a\n"
            "assert '--config=' in a and '--ignorefile=' in a\n"
            "source=Path(a[-1]); assert source.is_dir()\n"
            "files=[p.name for p in source.iterdir() if p.is_file()]; files.sort()\n"
            "items=[]\n"
            "for f in files:\n"
            "  d=(source/f).read_text()\n"
            "  if 'privileged: true' in d: items.append({'ID':'KSV-0017'})\n"
            "  if 'hostNetwork: true' in d: items.append({'ID':'KSV-0009'})\n"
            "rows=[]\n"
            "for f in files:\n"
            "  d=(source/f).read_text()\n"
            "  mis=[x for x in items if x['ID']=='KSV-0017' and 'privileged: true' in d]\n"
            "  mis+=[x for x in items if x['ID']=='KSV-0009' and 'hostNetwork: true' in d]\n"
            "  rows.append({'Target':f,'Class':'config','Type':'kubernetes','MisconfSummary':{'Successes':1,'Failures':len(mis)},'Misconfigurations':mis})\n"
            "Path(a[a.index('--output')+1]).write_text(json.dumps({'SchemaVersion':2,'Results':rows}))\n"
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
        self.url = f"http://127.0.0.1:{self.httpd.server_port}/api/tool-runs/trivy-kubernetes-config-batch"

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

    def test_batch_route_present_in_candidate_returns_200_with_zero_findings(self):
        manifest = self.project / "pod.yaml"
        manifest.write_text(self.source(privileged=False, host_network=False))
        status, result = self.post({"confirm_local": True, "project_path": str(self.project), "manifest_names": ["pod.yaml"]})
        self.assertEqual(status, 200)
        self.assertEqual(result["profile"], "local-kubernetes-manifest-config-batch-v1")
        self.assertEqual(result["finding_counts"]["misconfigurations"], 0)
        self.assertIn("report_sha256", result)

    def test_batch_route_aggregates_two_misconfigurations(self):
        manifest1 = self.project / "pod1.yaml"
        manifest2 = self.project / "pod2.yaml"
        manifest1.write_text(self.source(privileged=True, host_network=False))
        manifest2.write_text(self.source(privileged=False, host_network=True))
        status, result = self.post({"confirm_local": True, "project_path": str(self.project), "manifest_names": ["pod1.yaml", "pod2.yaml"]})
        self.assertEqual(status, 200)
        self.assertEqual(result["profile"], "local-kubernetes-manifest-config-batch-v1")
        self.assertEqual(result["finding_counts"]["misconfigurations"], 2)
        self.assertIn("report_sha256", result)

    def test_digest_changes_with_different_findings(self):
        manifest = self.project / "pod.yaml"
        manifest.write_text(self.source(privileged=False, host_network=False))
        _, result0 = self.post({"confirm_local": True, "project_path": str(self.project), "manifest_names": ["pod.yaml"]})
        manifest.write_text(self.source(privileged=True, host_network=False))
        _, result1 = self.post({"confirm_local": True, "project_path": str(self.project), "manifest_names": ["pod.yaml"]})
        self.assertEqual(result0["finding_counts"]["misconfigurations"], 0)
        self.assertEqual(result1["finding_counts"]["misconfigurations"], 1)
        self.assertNotEqual(result0["report_sha256"], result1["report_sha256"])

    def test_response_excludes_filename_path_and_finding_id(self):
        manifest = self.project / "pod.yaml"
        manifest.write_text(self.source(privileged=True, host_network=True))
        _, result = self.post({"confirm_local": True, "project_path": str(self.project), "manifest_names": ["pod.yaml"]})
        result_json = json.dumps(result)
        self.assertNotIn(str(self.project), result_json)
        self.assertNotIn("pod.yaml", result_json)
        self.assertNotIn("KSV-0017", result_json)
        self.assertNotIn("KSV-0009", result_json)

    def test_rejects_missing_consent(self):
        status, _ = self.post({"project_path": str(self.project), "manifest_names": ["pod.yaml"]})
        self.assertEqual(status, 400)

    def test_rejects_duplicate_manifest_names(self):
        status, _ = self.post({"confirm_local": True, "project_path": str(self.project), "manifest_names": ["pod.yaml", "pod.yaml"]})
        self.assertEqual(status, 400)

    def test_rejects_invalid_unhashable_manifest_names(self):
        status, _ = self.post({"confirm_local": True, "project_path": str(self.project), "manifest_names": ["pod.yaml", ["nested"]]} )
        self.assertEqual(status, 400)

    def test_rejects_traversal_and_symlink_names(self):
        manifest = self.project / "pod.yaml"
        manifest.write_text(self.source(privileged=False, host_network=False))
        body = {"confirm_local": True, "project_path": str(self.project), "manifest_names": []}
        for name in ("../pod.yaml", "pod.yaml/../x.yaml", "pod.json", "..hidden.yaml"):
            status, _ = self.post({**body, "manifest_names": [name]})
            self.assertEqual(status, 400, name)
        manifest.rename(self.project / "real.yaml")
        manifest.symlink_to(self.project / "real.yaml")
        status, _ = self.post({**body, "manifest_names": ["pod.yaml"]})
        self.assertEqual(status, 400)

    def test_rejects_unknown_keys_in_payload(self):
        status, _ = self.post({"confirm_local": True, "project_path": str(self.project), "manifest_names": ["pod.yaml"], "extra": True})
        self.assertEqual(status, 400)

    def test_rejects_non_list_manifest_names(self):
        status, _ = self.post({"confirm_local": True, "project_path": str(self.project), "manifest_names": "pod.yaml"})
        self.assertEqual(status, 400)

    def test_rejects_empty_manifest_names_list(self):
        status, _ = self.post({"confirm_local": True, "project_path": str(self.project), "manifest_names": []})
        self.assertEqual(status, 400)

    def test_rejects_too_many_manifest_names(self):
        names = [f"pod{i}.yaml" for i in range(9)]
        for name in names:
            (self.project / name).write_text(self.source(privileged=False, host_network=False))
        status, _ = self.post({"confirm_local": True, "project_path": str(self.project), "manifest_names": names})
        self.assertEqual(status, 400)

    def test_rejects_non_string_manifest_name(self):
        status, _ = self.post({"confirm_local": True, "project_path": str(self.project), "manifest_names": [123]})
        self.assertEqual(status, 400)

    def test_rejects_non_string_project_path(self):
        status, _ = self.post({"confirm_local": True, "project_path": 123, "manifest_names": ["pod.yaml"]})
        self.assertEqual(status, 400)

    def test_rejects_empty_project_path(self):
        status, _ = self.post({"confirm_local": True, "project_path": "  ", "manifest_names": ["pod.yaml"]})
        self.assertEqual(status, 400)
