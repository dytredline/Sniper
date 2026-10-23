import hashlib
import json
import os
import stat
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from socket import socket, AF_INET, SOCK_STREAM
from urllib.request import Request, urlopen
from urllib.error import HTTPError

import server
from storage import Store


class TestTestsslActiveScanApi(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.base = Path(self.temp.name)
        self.previous_store = server.STORE
        self.previous_env = os.environ.copy()
        server.STORE = Store(self.base / "data" / "sniper.db")
        os.environ["SNIPER_DATA_DIR"] = str(self.base / "data")
        os.environ["SNIPER_HOST"] = "127.0.0.1"

        # Create synthetic testssl executable
        self.testssl_bin = self.base / "synthetic_testssl.sh"
        self.testssl_bin.write_text("""#!/bin/bash
set -e
# Locate --jsonfile argument and write to its immediate next positional
json_file=""
for arg in "$@"; do
  if [ -z "$json_file" ]; then
    if [ "$arg" = "--jsonfile" ]; then
      json_file="SET"
      continue
    fi
  else
    # arg is the --jsonfile target
    echo "$arg" > /dev/stderr
    cat > "$arg" << 'JSON'
[
  {"id":"1","ip":"127.0.0.1","port":"443","severity":"OK","finding":"TLSv1.2","cve":"","cwe":"","hint":""},
  {"id":"2","ip":"127.0.0.1","port":"443","severity":"OK","finding":"TLSv1.3","cve":"","cwe":"","hint":"PRIVATE_MARKER_7721"}
]
JSON
    break
  fi
done
if [ -z "$json_file" ]; then
  echo "Missing --jsonfile" >&2
  exit 1
fi
""")
        self.testssl_bin.chmod(self.testssl_bin.stat().st_mode | stat.S_IXUSR)

        # Compute real hash for hash check
        self.testssl_hash = hashlib.sha256(self.testssl_bin.read_bytes()).hexdigest()
        os.environ["SNIPER_TESTSSL_BINARY"] = str(self.testssl_bin)
        os.environ["SNIPER_TESTSSL_SHA256"] = self.testssl_hash

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.httpd.server_address[1]}"

        # Start synthetic TLS server on loopback
        self.tls_server = socket(AF_INET, SOCK_STREAM)
        self.tls_server.setsockopt(1, 2, 1)  # SO_REUSEADDR
        self.tls_server.bind(("127.0.0.1", 0))
        self.tls_server.listen(1)
        self.tls_port = self.tls_server.getsockname()[1]

    def tearDown(self):
        try:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.thread.join(timeout=2)
        finally:
            server.STORE = self.previous_store
            os.environ.clear()
            os.environ.update(self.previous_env)
            self.temp.cleanup()
            self.tls_server.close()

    def request_json(self, path, payload):
        body = json.dumps(payload).encode("utf-8")
        request = Request(
            self.base_url + path,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urlopen(request, timeout=5) as response:
                return json.loads(response.read())
        except HTTPError as e:
            raise e

    def test_missing_confirm_local_returns_400(self):
        payload = {"target": f"127.0.0.1:{self.tls_port}"}
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-runs/testssl-protocols", payload)
        self.assertEqual(cm.exception.code, 400)

    def test_non_loopback_target_returns_400(self):
        payload = {
            "confirm_local": True,
            "target": "8.8.8.8:443"
        }
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-runs/testssl-protocols", payload)
        self.assertEqual(cm.exception.code, 400)

    def test_missing_target_port_zero_returns_400(self):
        payload = {
            "confirm_local": True,
            "target": "127.0.0.1:0"
        }
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-runs/testssl-protocols", payload)
        self.assertEqual(cm.exception.code, 400)

    def test_missing_binary_returns_503(self):
        del os.environ["SNIPER_TESTSSL_BINARY"]
        payload = {
            "confirm_local": True,
            "target": f"127.0.0.1:{self.tls_port}"
        }
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-runs/testssl-protocols", payload)
        self.assertEqual(cm.exception.code, 503)

    def test_missing_sha256_returns_503(self):
        del os.environ["SNIPER_TESTSSL_SHA256"]
        payload = {
            "confirm_local": True,
            "target": f"127.0.0.1:{self.tls_port}"
        }
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-runs/testssl-protocols", payload)
        self.assertEqual(cm.exception.code, 503)

    def test_active_scan_returns_200_with_summary(self):
        payload = {
            "confirm_local": True,
            "target": f"127.0.0.1:{self.tls_port}"
        }
        result = self.request_json("/api/tool-runs/testssl-protocols", payload)

        self.assertEqual(result["format"], "testssl-loopback-v1")
        self.assertEqual(result["record_count"], 2)
        self.assertEqual(result["severity_counts"], {"INFO": 0, "OK": 2, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0, "WARN": 0, "DEBUG": 0, "FATAL": 0})
        self.assertEqual(sum(result["severity_counts"].values()), result["record_count"])
        self.assertIn("report_sha256", result)
        self.assertTrue(isinstance(result["report_sha256"], str) and len(result["report_sha256"]) == 64)
        self.assertIn("elapsed_seconds", result)
        self.assertTrue(isinstance(result["elapsed_seconds"], (int, float)) and result["elapsed_seconds"] >= 0)

        # Check no private data leaked
        result_json_str = json.dumps(result)
        self.assertNotIn("127.0.0.1", result_json_str)
        self.assertNotIn("443", result_json_str)
        self.assertNotIn("PRIVATE_MARKER_7721", result_json_str)

    def test_parser_error_yields_generic_http502(self):
        # Inject malformed JSON via fake binary
        self.testssl_bin.write_text("""#!/bin/bash
set -e
target_file=""
for arg in "$@"; do
  if [ -z "$target_file" ]; then
    if [ "$arg" = "--jsonfile" ]; then
      target_file="SET"
      continue
    fi
  else
    echo '[{"malformed": }]' > "$arg"
    break
  fi
done
""")
        self.testssl_bin.chmod(self.testssl_bin.stat().st_mode | stat.S_IXUSR)
        self.testssl_hash = hashlib.sha256(self.testssl_bin.read_bytes()).hexdigest()
        os.environ["SNIPER_TESTSSL_SHA256"] = self.testssl_hash

        payload = {
            "confirm_local": True,
            "target": f"127.0.0.1:{self.tls_port}"
        }
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-runs/testssl-protocols", payload)
        self.assertEqual(cm.exception.code, 502)


if __name__ == "__main__":
    unittest.main()
