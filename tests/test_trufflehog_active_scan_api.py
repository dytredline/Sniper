from __future__ import annotations

import json
import os
import stat
import tempfile
import threading
import unittest
from tests.pin_helpers import pin_test_binary
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError

import server
from storage import Store


class TruffleHogActiveScanApiTests(unittest.TestCase):
    def setUp(self):
        # Create isolated temp dirs under home
        self.temp_base = tempfile.TemporaryDirectory(dir=Path.home(), prefix="sniper_trufflehog_test_")
        self.base = Path(self.temp_base.name)
        self.data_dir = self.base / "data"
        self.data_dir.mkdir(parents=True)
        self.bin_dir = self.base / "bin"
        self.bin_dir.mkdir(parents=True)

        # Create fake trufflehog binary
        self.fake_bin = self.bin_dir / "trufflehog"
        self._write_fake_trufflehog_binary()

        # Set environment (parent process only)
        self.old_trufflehog_bin = os.environ.get("SNIPER_TRUFFLEHOG_BINARY")
        self.old_data_dir = os.environ.get("SNIPER_DATA_DIR")
        os.environ["SNIPER_TRUFFLEHOG_BINARY"] = str(self.fake_bin)
        os.environ["SNIPER_DATA_DIR"] = str(self.data_dir)

        # Setup server
        self.previous_store = server.STORE
        server.STORE = Store(self.base / "sniper.db")
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.httpd.server_address[1]}"

        # Create test project with secret marker
        self.project_dir = self.base / "project"
        self.project_dir.mkdir(parents=True)
        self.marker = self.project_dir / "secret-marker"
        self.marker.write_text("# This is a placeholder; the fake trufflehog binary checks marker presence\n")
        self.txt_file = self.project_dir / "clean.txt"
        self.txt_file.write_text("clean content\n")

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        server.STORE = self.previous_store
        if self.old_trufflehog_bin is not None:
            os.environ["SNIPER_TRUFFLEHOG_BINARY"] = self.old_trufflehog_bin
        elif "SNIPER_TRUFFLEHOG_BINARY" in os.environ:
            del os.environ["SNIPER_TRUFFLEHOG_BINARY"]
        if self.old_data_dir is not None:
            os.environ["SNIPER_DATA_DIR"] = self.old_data_dir
        elif "SNIPER_DATA_DIR" in os.environ:
            del os.environ["SNIPER_DATA_DIR"]
        if "_SNIPER_FAKE_EXITCODE" in os.environ:
            del os.environ["_SNIPER_FAKE_EXITCODE"]
        self.temp_base.cleanup()

    def _write_fake_trufflehog_binary(self):
        content = '''#!/usr/bin/env python3
import sys
import json
import os
from pathlib import Path

def main():
    args = sys.argv[1:]
    # Expect: trufflehog --no-update --no-verification --results=unverified --json --concurrency=1 filesystem INPUT
    if not ("--no-update" in args and "--no-verification" in args and "--results=unverified" in args and "--json" in args and "--concurrency=1" in args and "filesystem" in args):
        sys.exit(1)

    input_dir = None
    for i, arg in enumerate(args):
        if arg == "filesystem" and i + 1 < len(args):
            input_dir = Path(args[i + 1])
            break
    if input_dir is None:
        sys.exit(1)

    exitcode = 0
    if "_SNIPER_FAKE_EXITCODE" in os.environ:
        try:
            exitcode = int(os.environ["_SNIPER_FAKE_EXITCODE"])
        except ValueError:
            exitcode = 0

    # Malformed mode: print invalid JSON and exit 0
    if exitcode == 2:
        print("not valid jsonl")
        sys.stdout.flush()
        sys.exit(0)

    # Secret mode: emit one valid JSON record and exit 0
    if exitcode == 0 and (input_dir / "secret-marker").is_file():
        record = {
            "DetectorName": "Github",
            "Verified": False,
            "Raw": "test-gh-token-abc123",
            "Metadata": {}
        }
        print(json.dumps(record))
        sys.exit(0)

    # Clean mode: no output, exit 0
    sys.exit(0)

if __name__ == "__main__":
    main()
'''.strip()
        self.fake_bin.write_text(content)
        self.fake_bin.chmod(0o755)
        pin_test_binary(self, "trufflehog", self.fake_bin)

    def request_json(self, path, payload=None):
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        request = Request(
            self.base_url + path,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"} if body else {},
        )
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read())
        except HTTPError as e:
            return e.code, json.loads(e.read())

    def test_positive_scan_returns_200_with_aggregates(self):
        status, body = self.request_json(
            "/api/tool-runs/trufflehog-filesystem",
            {
                "confirm_local": True,
                "project_path": str(self.project_dir),
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["format"], "trufflehog-native-json-records")
        self.assertEqual(body["profile"], "local-filesystem-no-verification-v1")
        self.assertEqual(body["total_findings"], 1)
        self.assertEqual(body["verified_findings"], 0)
        self.assertEqual(body["unverified_findings"], 1)
        self.assertEqual(body["detectors_triggered"], 1)
        self.assertIn("report_sha256", body)
        self.assertTrue(len(body["report_sha256"]) == 64 and all(c in "0123456789abcdef" for c in body["report_sha256"]))

    def test_clean_scan_returns_zero(self):
        self.marker.unlink(missing_ok=True)
        status, body = self.request_json(
            "/api/tool-runs/trufflehog-filesystem",
            {
                "confirm_local": True,
                "project_path": str(self.project_dir),
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["format"], "trufflehog-native-json-records")
        self.assertEqual(body["profile"], "local-filesystem-no-verification-v1")
        self.assertEqual(body["total_findings"], 0)
        self.assertEqual(body["detectors_triggered"], 0)
        self.assertIn("report_sha256", body)
        self.assertTrue(len(body["report_sha256"]) == 64 and all(c in "0123456789abcdef" for c in body["report_sha256"]))

    def test_missing_confirm_local_returns_400(self):
        status, body = self.request_json(
            "/api/tool-runs/trufflehog-filesystem",
            {
                "confirm_local": False,
                "project_path": str(self.project_dir),
            },
        )
        self.assertEqual(status, 400)
        self.assertIn("confirm_local tam olarak true olmalı", body["error"])

    def test_missing_binary_returns_503(self):
        old_bin = os.environ.get("SNIPER_TRUFFLEHOG_BINARY")
        del os.environ["SNIPER_TRUFFLEHOG_BINARY"]
        try:
            status, body = self.request_json(
                "/api/tool-runs/trufflehog-filesystem",
                {
                    "confirm_local": True,
                    "project_path": str(self.project_dir),
                },
            )
            self.assertEqual(status, 503)
            self.assertIn("ikilisi yapılandırılmamış", body["error"])  # tool_pins Türkçe iletisi
        finally:
            if old_bin is not None:
                os.environ["SNIPER_TRUFFLEHOG_BINARY"] = old_bin

    def test_malformed_jsonl_returns_502(self):
        os.environ["_SNIPER_FAKE_EXITCODE"] = "2"
        try:
            status, body = self.request_json(
                "/api/tool-runs/trufflehog-filesystem",
                {
                    "confirm_local": True,
                    "project_path": str(self.project_dir),
                },
            )
            self.assertEqual(status, 502)
            self.assertIn("TruffleHog çalıştırması başarısız oldu", body["error"])
        finally:
            if "_SNIPER_FAKE_EXITCODE" in os.environ:
                del os.environ["_SNIPER_FAKE_EXITCODE"]

    def test_private_markers_not_leaked(self):
        status, body = self.request_json(
            "/api/tool-runs/trufflehog-filesystem",
            {
                "confirm_local": True,
                "project_path": str(self.project_dir),
            },
        )
        self.assertEqual(status, 200)
        self.assertNotIn("test-gh-token-abc123", str(body))
        self.assertNotIn("secret-marker", str(body))
        self.assertNotIn(str(self.project_dir), str(body))

    def test_extra_key_scanner_args_rejected_without_runner_call(self):
        from unittest.mock import patch

        calls = []

        def stub_trufflehog_fs(project_path):
            calls.append(project_path)
            return {"tool": "trufflehog-filesystem", "total_findings": 0}

        with patch.object(server, "run_local_trufflehog_filesystem", side_effect=stub_trufflehog_fs):
            status, body = self.request_json(
                "/api/tool-runs/trufflehog-filesystem",
                {
                    "confirm_local": True,
                    "project_path": "/tmp/sniper-stub",
                    "scanner_args": ["--only-verified"],
                },
            )
            self.assertEqual(status, 400)
            self.assertEqual(calls, [])
            self.assertIn("fazla veya eksik alan", body.get("error", ""))

            status_ok, body_ok = self.request_json(
                "/api/tool-runs/trufflehog-filesystem",
                {"confirm_local": True, "project_path": "/tmp/sniper-stub"},
            )
            self.assertEqual(status_ok, 200)
            self.assertEqual(calls, ["/tmp/sniper-stub"])
            self.assertEqual(body_ok.get("tool"), "trufflehog-filesystem")

    def test_non_object_payload_rejected_without_runner_call(self):
        from unittest.mock import patch

        calls = []
        with patch.object(server, "run_local_trufflehog_filesystem", side_effect=lambda p: calls.append(p)):
            status, _ = self.request_json("/api/tool-runs/trufflehog-filesystem", ["not", "an", "object"])
            self.assertEqual(status, 400)
            self.assertEqual(calls, [])

    def test_sibling_git_history_exact_key_control(self):
        from unittest.mock import patch

        calls = []

        def stub_git_history(project_path):
            calls.append(project_path)
            return {"tool": "trufflehog-git-history", "total_findings": 0}

        with patch.object(server, "run_local_trufflehog_git_history", side_effect=stub_git_history):
            status_extra, body_extra = self.request_json(
                "/api/tool-runs/trufflehog-git-history",
                {
                    "confirm_local": True,
                    "project_path": "/tmp/sniper-stub",
                    "scanner_args": ["--only-verified"],
                },
            )
            self.assertEqual(status_extra, 400)
            self.assertEqual(calls, [])
            self.assertIn("Yalnız confirm_local ve project_path bekleniyor", body_extra.get("error", ""))

            status_ok, body_ok = self.request_json(
                "/api/tool-runs/trufflehog-git-history",
                {"confirm_local": True, "project_path": "/tmp/sniper-stub"},
            )
            self.assertEqual(status_ok, 200)
            self.assertEqual(calls, ["/tmp/sniper-stub"])
            self.assertEqual(body_ok.get("tool"), "trufflehog-git-history")
