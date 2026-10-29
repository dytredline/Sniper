import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scanner import normalize_target, run_baseline_scan  # noqa: E402


class TargetHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        if self.path == "/.well-known/security.txt":
            body = b"Contact: mailto:security@example.test\nExpires: 2030-01-01T00:00:00Z"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
        else:
            body = b"<html><title>Local test target</title></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Permissions-Policy", "camera=()")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class EndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), TargetHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    @patch.dict(os.environ, {"SNIPER_ALLOW_PRIVATE_TARGETS": "1"})
    def test_safe_scan_without_ownership_file(self):
        port = self.server.server_address[1]
        target = normalize_target(f"http://127.0.0.1:{port}")
        result = run_baseline_scan(target)
        self.assertEqual(result["metadata"]["page_title"], "Local test target")
        self.assertEqual(result["scope"]["methods"], ["GET"])
        self.assertFalse(result["scope"]["exploitation"])


if __name__ == "__main__":
    unittest.main()
