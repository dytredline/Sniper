"""Hız sınırı: statik arayüz varlıkları sayılmaz, API istekleri sayılır (16. tur)."""
from __future__ import annotations

import contextlib
import http.client
import io
import threading
import unittest

import server


class RateLimitStaticTests(unittest.TestCase):
    def test_static_asset_paths(self):
        for path in ("/", "/login.html", "/static/app.js", "/static/i18n-en.tsv", "/favicon.ico", "/app.js", "/job_queue.js", "/app.css"):
            with self.subTest(path=path):
                self.assertTrue(server._is_static_asset_path(path))
        for path in ("/api/health", "/api/scans", "/static/../server.py", "/staticx/a.js", "/static//etc", "/api/x.js", "/server.py", "/a/b.js"):
            with self.subTest(path=path):
                self.assertFalse(server._is_static_asset_path(path))

    def test_default_limit_and_window(self):
        limiter = server.RateLimiter()
        self.assertEqual((limiter.limit, limiter.window), (240, 60))
        self.assertTrue(all(limiter.allow("a") for _ in range(240)))
        self.assertFalse(limiter.allow("a"))
        self.assertTrue(limiter.allow("b"))

    def test_static_filename_boundary_rejects_before_filesystem_lookup(self):
        httpd = server.VulKillHTTPServer(("127.0.0.1", 0), server.VulKillHandler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        stderr = io.StringIO()
        try:
            statuses = []
            with contextlib.redirect_stderr(stderr):
                for path in (
                    "/static/" + ("a" * 255),       # passing filesystem boundary
                    "/static/" + ("a" * 256),       # first rejected boundary
                    "/static/" + ("a" * 300) + ".js",  # asset edge case
                ):
                    connection = http.client.HTTPConnection("127.0.0.1", httpd.server_port, timeout=5)
                    connection.request("GET", path)
                    response = connection.getresponse()
                    statuses.append(response.status)
                    response.read()
                    connection.close()
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=5)

        self.assertEqual(statuses, [200, 414, 414])
        self.assertNotIn("Traceback", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
