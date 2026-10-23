import hashlib
import json
import os
import stat
import sys
import tempfile
import threading
from http import HTTPStatus
from pathlib import Path
from unittest import TestCase

from http.server import ThreadingHTTPServer
from project_analyzer import ProjectRejected
from storage import Store
import server
import trivy_config_active


class TestTrivyTerraformConfigAPI(TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.base = Path(self.temp.name)
        self.project = self.base / "project"
        self.project.mkdir()
        (self.project / "main.tf").write_text(
            "variable \"test\" { default = \"value\" }\n"
        )
        self.binary = self.base / "fake-trivy"
        self.binary.write_text(
            f"#!{sys.executable}\n"
            "import json,sys\n"
            "from pathlib import Path\n"
            "a=sys.argv[1:]; out=Path(a[a.index('--output')+1]); source=Path(a[-1])\n"
            "tf=[p for p in source.iterdir() if p.suffix=='.tf']; assert len(tf)==1\n"
            "data=tf[0].read_text()\n"
            "bad='aws_s3_bucket' in data\n"
            "findings=[{'ID':'AWS-001'}] if bad else []\n"
            "row1={'Target':'.','Class':'config','Type':'terraform','MisconfSummary':{'Successes':1,'Failures':0},'Misconfigurations':[]}\n"
            "row2={'Target':tf[0].name,'Class':'config','Type':'terraform','MisconfSummary':{'Successes':1,'Failures':len(findings)},'Misconfigurations':findings}\n"
            "out.write_text(json.dumps({'SchemaVersion':2,'Results':[row1,row2]}))\n"
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
        self.url = f"http://127.0.0.1:{self.httpd.server_port}/api/tool-runs/trivy-terraform-config"

    def tearDown(self):
        try:
            try:
                self.httpd.shutdown()
            except Exception:
                pass
            finally:
                self.httpd.server_close()
                self.thread.join(timeout=5.0)
        finally:
            try:
                os.environ.clear()
                os.environ.update(self.old_env)
            finally:
                try:
                    server.STORE, server.LIMITER = self.old_store, self.old_limiter
                finally:
                    try:
                        trivy_config_active.EXPECTED_TRIVY_SHA256 = self.old_digest
                    finally:
                        try:
                            self.temp.cleanup()
                        except Exception:
                            pass

    def post(self, body):
        import urllib.request
        req = urllib.request.Request(self.url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def request_body(self):
        return {"confirm_local": True, "project_path": str(self.project), "terraform_file": "main.tf"}

    def test_runtime_result_changes_with_terraform_behavior(self):
        status, clean = self.post(self.request_body())
        self.assertEqual(status, 200)
        self.assertEqual(clean["profile"], "local-terraform-config-v1")
        self.assertEqual(clean["finding_counts"]["misconfigurations"], 0)
        (self.project / "main.tf").write_text(
            "resource \"aws_s3_bucket\" \"example\" {\n  bucket = \"example-bucket\"\n}\n"
        )
        status, bad = self.post(self.request_body())
        self.assertEqual(status, 200)
        self.assertEqual(bad["finding_counts"]["misconfigurations"], 1)
        self.assertNotEqual(clean["report_sha256"], bad["report_sha256"])
        self.assertNotIn(str(self.project), json.dumps(bad))
        self.assertNotIn("AWS-001", json.dumps(bad))

    def test_trivy_config_scan_fails_on_invalid_misconf_summary(self):
        import json
        import os
        from pathlib import Path
        import hashlib
        import stat
        import sys

        summaries_to_test = [
            [],
            {'Failures': []},
            {'Failures': False}
        ]

        for summary in summaries_to_test:
            # Build a closure that captures the current `summary`
            def fake_popen(*args, **kwargs):
                class FakePopen:
                    def __init__(self):
                        self.returncode = 0
                        self.stdout = None
                        self.stderr = None
                        self.stdin = None

                    def wait(self, timeout=None):
                        return 0

                    def communicate(self, input=None):
                        return (b'', b'')

                result = FakePopen()
                # Find --output argument
                output_path = None
                for i, arg in enumerate(args[0]):
                    if arg == '--output' and i + 1 < len(args[0]):
                        output_path = args[0][i + 1]
                        break

                if output_path:
                    os.makedirs(os.path.dirname(output_path), exist_ok=True)
                    with open(output_path, 'w') as output_file:
                        row1 = {
                            'Target': '.',
                            'Class': 'config',
                            'Type': 'terraform',
                            'MisconfSummary': summary,
                            'Misconfigurations': []
                        }
                        row2 = {
                            'Target': 'main.tf',
                            'Class': 'config',
                            'Type': 'terraform',
                            'MisconfSummary': {'Successes': 1, 'Failures': 0},
                            'Misconfigurations': []
                        }
                        json.dump({'SchemaVersion': 2, 'Results': [row1, row2]}, output_file)

                return result

            # Temporarily patch
            original_popen = trivy_config_active.subprocess.Popen
            try:
                trivy_config_active.subprocess.Popen = fake_popen
                status, parsed_body = self.post(self.request_body())
                self.assertEqual(status, 502)
                self.assertEqual(parsed_body, {'error': 'Trivy yapılandırma taraması başarısız oldu.', 'status': 502})
            finally:
                trivy_config_active.subprocess.Popen = original_popen

    def test_clean_root_only_report_and_duplicate_root_validation(self):
        clean_report = {
            "SchemaVersion": 2,
            "Results": [{
                "Target": ".",
                "Class": "config",
                "Type": "terraform",
                "MisconfSummary": {"Successes": 51, "Failures": 0},
                "Misconfigurations": None,
            }],
        }
        duplicate_report = {
            "SchemaVersion": 2,
            "Results": [clean_report["Results"][0], dict(clean_report["Results"][0])],
        }

        def post_report(report):
            def fake_popen(command, **kwargs):
                class FakeProcess:
                    def wait(self, timeout=None):
                        return 0

                output_path = Path(command[command.index("--output") + 1])
                output_path.write_text(json.dumps(report), encoding="utf-8")
                return FakeProcess()

            original_popen = trivy_config_active.subprocess.Popen
            try:
                trivy_config_active.subprocess.Popen = fake_popen
                return self.post(self.request_body())
            finally:
                trivy_config_active.subprocess.Popen = original_popen

        status, body = post_report(clean_report)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["finding_counts"]["misconfigurations"], 0)
        self.assertNotIn("Target", body)
        response_text = json.dumps(body)
        self.assertNotIn("main.tf", response_text)
        self.assertNotIn(str(self.project), response_text)

        status, body = post_report(duplicate_report)
        self.assertEqual(status, 502, body)

    def test_rejects_missing_consent_and_nonlocal_path(self):
        self.assertEqual(self.post({"project_path": str(self.project)})[0], 400)
        self.assertEqual(self.post({"confirm_local": True, "project_path": "/etc"})[0], 400)

    def test_rejects_filename_traversal_and_symlink(self):
        body = self.request_body()
        for name in ("../main.tf", "/etc/passwd", "main.tf/../x.tf", "main.json", ".hidden.tf", "main"):
            self.assertEqual(self.post({**body, "terraform_file": name})[0], 400, name)
        (self.project / "main.tf").rename(self.project / "held.txt")
        backslash_name = "odd\\name.tf"
        (self.project / backslash_name).write_text('resource "x" "y" {}\n')
        self.assertEqual(self.post({**body, "terraform_file": backslash_name})[0], 400)
        (self.project / backslash_name).unlink()
        (self.project / "held.txt").rename(self.project / "main.tf")
        (self.project / "main.tf").rename(self.project / "real.tf")
        (self.project / "main.tf").symlink_to(self.project / "real.tf")
        self.assertEqual(self.post(body)[0], 400)

    def test_rejects_binary_hash_mismatch(self):
        trivy_config_active.EXPECTED_TRIVY_SHA256 = "0" * 64
        self.assertEqual(self.post(self.request_body())[0], 503)

    def test_rejects_missing_keys(self):
        for missing in ("confirm_local", "project_path", "terraform_file"):
            body = self.request_body()
            del body[missing]
            self.assertEqual(self.post(body)[0], 400, missing)

    def test_rejects_extra_keys(self):
        body = self.request_body()
        body["extra"] = "value"
        self.assertEqual(self.post(body)[0], 400)

    def test_rejects_empty_terraform_file(self):
        body = self.request_body()
        body["terraform_file"] = ""
        self.assertEqual(self.post(body)[0], 400)

    def test_rejects_non_tf_extension(self):
        (self.project / "main.txt").write_text("test")
        body = self.request_body()
        body["terraform_file"] = "main.txt"
        self.assertEqual(self.post(body)[0], 400)

    def test_rejects_oversized_file(self):
        (self.project / "main.tf").write_text("x" * 1_000_001)
        self.assertEqual(self.post(self.request_body())[0], 400)

    def test_rejects_empty_file(self):
        (self.project / "main.tf").write_text("")
        self.assertEqual(self.post(self.request_body())[0], 400)

    def test_rejects_hidden_file(self):
        (self.project / ".main.tf").write_text("test")
        body = self.request_body()
        body["terraform_file"] = ".main.tf"
        self.assertEqual(self.post(body)[0], 400)

    def test_rejects_nested_path(self):
        subdir = self.project / "subdir"
        subdir.mkdir()
        (subdir / "main.tf").write_text("test")
        body = self.request_body()
        body["terraform_file"] = "subdir/main.tf"
        self.assertEqual(self.post(body)[0], 400)

    def test_rejects_absolute_path(self):
        body = self.request_body()
        body["terraform_file"] = "/etc/hosts"
        self.assertEqual(self.post(body)[0], 400)

    def test_rejects_backslash_path(self):
        body = self.request_body()
        body["terraform_file"] = "main\\\\.tf"
        self.assertEqual(self.post(body)[0], 400)

