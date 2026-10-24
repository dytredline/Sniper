import hashlib
import json
import os
import stat
import subprocess
import tempfile
import threading
import unittest
from unittest import mock
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import server
import nuclei_active
from nuclei_active import run_nuclei_loopback
from storage import Store


class TestNucleiActiveApi(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.base = Path(self.temp.name)
        self.old_store = server.STORE
        self.old_limiter = server.LIMITER
        self.old_env = os.environ.copy()
        server.STORE = Store(self.base / "data" / "sniper.db")
        server.LIMITER = server.RateLimiter()
        os.environ["SNIPER_DATA_DIR"] = str(self.base / "data")
        self.binary = self.base / "fake-nuclei"
        self.binary.write_text("#!/bin/sh\nprintf '%s\\n' '{\"template-id\":\"sniper-local-powered-by-v1\",\"type\":\"http\",\"info\":{\"severity\":\"info\"},\"matched-at\":\"PRIVATE_MARKER_723\"}'\n")
        self.binary.chmod(self.binary.stat().st_mode | stat.S_IXUSR)
        os.environ["SNIPER_NUCLEI_BINARY"] = str(self.binary)
        os.environ["SNIPER_NUCLEI_SHA256"] = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.httpd.server_port}/api/tool-runs/nuclei-loopback"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=3)
        server.STORE = self.old_store
        server.LIMITER = self.old_limiter
        os.environ.clear()
        os.environ.update(self.old_env)
        self.temp.cleanup()

    def post(self, body):
        request = Request(self.url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
        with urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read())

    def test_aggregate_response_has_no_finding_or_target(self):
        status, response = self.post({"confirm_local": True, "target": "127.0.0.1:12345"})
        self.assertEqual(status, 200)
        self.assertEqual(response["format"], "nuclei-loopback-v1")
        self.assertEqual(response["profile"], "local-powered-by-v1")
        self.assertEqual(response["record_count"], 1)
        self.assertEqual(response["severity_counts"]["info"], 1)
        self.assertEqual(response["unique_template_count"], 1)
        self.assertNotIn("PRIVATE_MARKER_723", json.dumps(response))
        self.assertNotIn("12345", json.dumps(response))

    def test_target_and_consent_rejections(self):
        for body in (
            {"target": "127.0.0.1:12345"},
            {"confirm_local": True, "target": "8.8.8.8:80"},
            {"confirm_local": True, "target": "127.0.0.1:0"},
            {"confirm_local": True, "target": "127.0.0.1:65536"},
            {"confirm_local": True, "target": "127.0.0.1:80/path"},
        ):
            with self.subTest(body=body), self.assertRaises(HTTPError) as error:
                self.post(body)
            self.assertEqual(error.exception.code, 400)

    def test_missing_and_mismatched_binary_are_rejected(self):
        os.environ.pop("SNIPER_NUCLEI_BINARY")
        with self.assertRaises(HTTPError) as error:
            self.post({"confirm_local": True, "target": "127.0.0.1:12345"})
        self.assertEqual(error.exception.code, 503)
        os.environ["SNIPER_NUCLEI_BINARY"] = str(self.binary)
        os.environ["SNIPER_NUCLEI_SHA256"] = "0" * 64
        with self.assertRaises(HTTPError) as error:
            self.post({"confirm_local": True, "target": "127.0.0.1:12345"})
        self.assertEqual(error.exception.code, 503)

    def test_malformed_tool_output_is_rejected(self):
        self.binary.write_text("#!/bin/sh\nprintf 'not-json\\n'\n")
        self.binary.chmod(self.binary.stat().st_mode | stat.S_IXUSR)
        os.environ["SNIPER_NUCLEI_SHA256"] = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        with self.assertRaises(HTTPError) as error:
            self.post({"confirm_local": True, "target": "127.0.0.1:12345"})
        self.assertEqual(error.exception.code, 502)

    def test_verified_binary_path_swap_never_executes_replacement(self):
        marker = self.base / "replacement-executed"
        trusted_popen = subprocess.Popen

        def replace_then_start(command, *args, **kwargs):
            self.binary.unlink()
            self.binary.write_text(
                "#!/bin/sh\n"
                f"printf attacked > {marker}\n"
                "printf '%s\\n' '{\"template-id\":\"sniper-local-powered-by-v1\","
                "\"type\":\"http\",\"info\":{\"severity\":\"info\"}}'\n",
                encoding="utf-8",
            )
            self.binary.chmod(0o700)
            return trusted_popen(command, *args, **kwargs)

        with mock.patch("nuclei_active.subprocess.Popen", side_effect=replace_then_start):
            result = run_nuclei_loopback("127.0.0.1:12345")

        self.assertFalse(marker.exists())
        self.assertEqual(result["record_count"], 1)

    def test_verified_template_path_swap_never_reaches_nuclei(self):
        marker = self.base / "replacement-template-read"
        template = self.base / "trusted-template.yaml"
        template.write_text("id: trusted-template\n", encoding="utf-8")
        trusted_digest = hashlib.sha256(template.read_bytes()).hexdigest()
        self.binary.write_text(
            "#!/bin/sh\n"
            "template=''\n"
            "while [ \"$#\" -gt 0 ]; do\n"
            "  if [ \"$1\" = '-t' ]; then template=$2; shift 2; else shift; fi\n"
            "done\n"
            "case \"$template\" in *.yaml) ;; *) exit 7;; esac\n"
            f"if grep -q ATTACKER \"$template\"; then printf attacked > {marker}; fi\n"
            "printf '%s\\n' '{\"template-id\":\"sniper-local-powered-by-v1\","
            "\"type\":\"http\",\"info\":{\"severity\":\"info\"}}'\n",
            encoding="utf-8",
        )
        self.binary.chmod(0o700)
        os.environ["SNIPER_NUCLEI_SHA256"] = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        trusted_popen = subprocess.Popen

        def replace_then_start(command, *args, **kwargs):
            template.unlink()
            template.write_text("id: ATTACKER\n", encoding="utf-8")
            return trusted_popen(command, *args, **kwargs)

        with mock.patch.object(nuclei_active, "TEMPLATE", template), \
                mock.patch.object(nuclei_active, "TEMPLATE_SHA256", trusted_digest), \
                mock.patch("nuclei_active.subprocess.Popen", side_effect=replace_then_start):
            result = run_nuclei_loopback("127.0.0.1:12345")

        self.assertFalse(marker.exists())
        self.assertEqual(result["record_count"], 1)


@unittest.skipUnless(os.environ.get("NUCLEI_TEST_BINARY"), "real Nuclei binary not provided")
class TestRealNucleiBehavior(unittest.TestCase):
    def test_header_present_and_absent_controls(self):
        binary = Path(os.environ["NUCLEI_TEST_BINARY"])
        previous = os.environ.copy()
        class Fixture(BaseHTTPRequestHandler):
            present = False

            def do_GET(self):
                self.send_response(200)
                if self.present:
                    self.send_header("X-Powered-By", "runtime-marker")
                self.end_headers()
                self.wfile.write(b"fixture")

            def log_message(self, *_args):
                pass

        with tempfile.TemporaryDirectory(dir=Path.home()) as directory:
            os.environ["SNIPER_DATA_DIR"] = directory
            os.environ["SNIPER_NUCLEI_BINARY"] = str(binary)
            os.environ["SNIPER_NUCLEI_SHA256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
            httpd = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
            httpd.daemon_threads = True
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()
            try:
                Fixture.present = True
                positive = run_nuclei_loopback(f"127.0.0.1:{httpd.server_port}")
                Fixture.present = False
                negative = run_nuclei_loopback(f"127.0.0.1:{httpd.server_port}")
                self.assertEqual(positive["record_count"], 1)
                self.assertEqual(positive["severity_counts"]["info"], 1)
                self.assertEqual(negative["record_count"], 0)
                self.assertEqual(negative["severity_counts"]["info"], 0)
            finally:
                httpd.shutdown()
                httpd.server_close()
                thread.join(timeout=3)
                os.environ.clear()
                os.environ.update(previous)


if __name__ == "__main__":
    unittest.main()
