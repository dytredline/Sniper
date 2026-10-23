import http.client
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import server
from storage import Store


class RequestPreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_store, self.old_limiter = server.STORE, server.LIMITER
        server.STORE = Store(Path(self.temp.name) / "fixture.db")
        server.LIMITER = server.RateLimiter()
        self.httpd = server.SniperHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=3)
        server.STORE, server.LIMITER = self.old_store, self.old_limiter
        self.temp.cleanup()

    def request(self, method, path, *, host=None, headers=None, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        conn.putheader("Host", host if host is not None else f"127.0.0.1:{self.port}")
        for key, value in (headers or {}).items():
            conn.putheader(key, value)
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            conn.putheader("Content-Type", "application/json")
            conn.putheader("Content-Length", str(len(data)))
        conn.endheaders(data)
        response = conn.getresponse()
        payload = response.read()
        conn.close()
        return response.status, payload

    def test_loopback_hosts_are_accepted(self):
        # Loopback adlar her portla (SSH tüneli) ve portsuz kabul edilir.
        for host in (f"127.0.0.1:{self.port}", f"localhost:{self.port}", f"LOCALHOST:{self.port}", f"[::1]:{self.port}",
                     "localhost:18787", "127.0.0.1", "[::1]"):
            with self.subTest(host=host):
                self.assertEqual(self.request("GET", "/api/health", host=host)[0], 200)

    def test_dns_rebinding_hosts_are_rejected_for_all_methods(self):
        for host in ("evil.example:%d" % self.port, "evil.example", "127.0.0.1.nip.io:%d" % self.port,
                     "localhost.evil.example:%d" % self.port, "", "localhost:abc", "[::1]x"):
            with self.subTest(host=host):
                status, body = self.request("GET", "/api/engagements", host=host)
                self.assertIn(status, (400, 421))
                self.assertNotIn(b"engagement", body.lower().replace(b"\xc4\xb1", b""))
                self.assertIn(self.request("POST", "/api/targets", host=host, body={"url": "https://example.com"})[0], (400, 421))

    def test_allowed_hosts_env_extends_names(self):
        with mock.patch.dict(os.environ, {"SNIPER_ALLOWED_HOSTS": "sniper, other"}):
            self.assertEqual(self.request("GET", "/api/health", host=f"sniper:{self.port}")[0], 200)
        self.assertEqual(self.request("GET", "/api/health", host=f"sniper:{self.port}")[0], 421)

    def test_cross_site_api_requests_are_rejected_before_rate_limit(self):
        for site in ("cross-site", "same-site"):
            with self.subTest(site=site):
                status, _ = self.request("GET", "/api/health", headers={"Sec-Fetch-Site": site})
                self.assertEqual(status, 403)
        self.assertEqual(self.request("GET", "/metrics", headers={"Sec-Fetch-Site": "cross-site"})[0], 403)
        for site in ("same-origin", "none"):
            self.assertEqual(self.request("GET", "/api/health", headers={"Sec-Fetch-Site": site})[0], 200)
        # Sayfa gezintisi (statik) çapraz siteden açılabilir.
        self.assertEqual(self.request("GET", "/", headers={"Sec-Fetch-Site": "cross-site"})[0], 200)
        # Reddedilen istekler hız sınırını tüketmez.
        for _ in range(200):
            self.request("GET", "/api/health", headers={"Sec-Fetch-Site": "cross-site"})
        self.assertEqual(self.request("GET", "/api/health")[0], 200)

    def test_inline_audit_accepts_larger_body_but_others_stay_limited(self):
        content = "print('x')\n" * 9000  # ~99 KB
        status, _ = self.request("POST", "/api/privacy-dataflow/audit", body={"raw_content": content, "filename": "a.py"})
        self.assertEqual(status, 200)
        status, body = self.request("POST", "/api/cvss-ssvc/prioritize", body={"vector": "x" * 70_000})
        self.assertEqual(status, 400)
        self.assertIn("çok büyük".encode("utf-8"), body)

    def test_unexpected_exception_returns_generic_500(self):
        with mock.patch.object(server, "runtime_readiness_payload", side_effect=RuntimeError("/home/community-user/path")), \
                mock.patch("traceback.print_exc"):
            status, body = self.request("GET", "/api/tooling/readiness")
        self.assertEqual(status, 500)
        self.assertNotIn(b"/home/community-user/path", body)
        self.assertEqual(self.request("GET", "/api/health")[0], 200)


if __name__ == "__main__":
    unittest.main()
