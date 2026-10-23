"""Hız sınırı: statik arayüz varlıkları sayılmaz, API istekleri sayılır (16. tur)."""
from __future__ import annotations

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


if __name__ == "__main__":
    unittest.main()
