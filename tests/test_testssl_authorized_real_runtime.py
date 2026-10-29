import hashlib
import json
import os
import socketserver
import ssl
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

from testssl_authorized_active import run_testssl_authorized


REAL_TESTSSL = Path("/home/community-user/.local/state/sniper-tool-runtimes/testssl-3.2.4/testssl.sh")
REAL_TESTSSL_SHA256 = "9a42b203edaf8cfdd19cdca7c3cf16c78668bdc88cd656cf2cae0ec6e43129e4"


class _TlsHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            with self.server.tls_context.wrap_socket(self.request, server_side=True) as stream:
                stream.settimeout(0.25)
                try:
                    stream.recv(1024)
                except (OSError, TimeoutError):
                    pass
        except (OSError, ssl.SSLError):
            pass


class _ThreadedTlsServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


@unittest.skipUnless(
    os.environ.get("SNIPER_RUN_REAL_TESTSSL_LOOPBACK") == "1",
    "gerçek pinli testssl loopback doğrulaması açıkça etkin değil",
)
class TestsslAuthorizedRealRuntimeTests(unittest.TestCase):
    def test_pinned_testssl_protocols_profile_runs_only_against_temporary_loopback_tls(self):
        self.assertEqual(hashlib.sha256(REAL_TESTSSL.read_bytes()).hexdigest(), REAL_TESTSSL_SHA256)
        with tempfile.TemporaryDirectory(dir=Path.home()) as raw_temp:
            base = Path(raw_temp)
            key = base / "key.pem"
            certificate = base / "certificate.pem"
            subprocess.run(
                [
                    "/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-subj", "/CN=localhost", "-days", "1", "-keyout", str(key), "-out", str(certificate),
                ],
                check=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=20,
            )
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certificate, key)
            server = _ThreadedTlsServer(("127.0.0.1", 0), _TlsHandler)
            server.tls_context = context
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            previous_env = os.environ.copy()
            try:
                os.environ["SNIPER_DATA_DIR"] = str(base / "data")
                os.environ["SNIPER_TESTSSL_BINARY"] = str(REAL_TESTSSL)
                os.environ["SNIPER_TESTSSL_SHA256"] = REAL_TESTSSL_SHA256
                port = server.server_address[1]
                result = run_testssl_authorized(f"127.0.0.1:{port}", profile="protocols")
            finally:
                os.environ.clear()
                os.environ.update(previous_env)
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)

        canonical_target = f"127.0.0.1:{port}"
        self.assertEqual(result["format"], "testssl-authorized-v1")
        self.assertEqual(result["profile"], "authorized-protocols-v1")
        self.assertGreater(result["record_count"], 0)
        self.assertEqual(sum(result["severity_counts"].values()), result["record_count"])
        self.assertEqual(result["target_sha256"], hashlib.sha256(canonical_target.encode()).hexdigest())
        self.assertEqual(result["resolved_ip_sha256"], hashlib.sha256(b"127.0.0.1").hexdigest())
        self.assertRegex(result["report_sha256"], r"^[0-9a-f]{64}$")
        print(json.dumps({
            "format": result["format"],
            "profile": result["profile"],
            "record_count": result["record_count"],
            "severity_counts": result["severity_counts"],
            "report_sha256": result["report_sha256"],
            "target_sha256": result["target_sha256"],
            "resolved_ip_sha256": result["resolved_ip_sha256"],
        }, sort_keys=True))


if __name__ == "__main__":
    unittest.main()
