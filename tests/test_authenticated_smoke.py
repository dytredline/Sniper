from __future__ import annotations

import io
import json
import unittest

from scripts import authenticated_smoke


class Response:
    status = 200
    def __init__(self, body): self.body = body
    def __enter__(self): return self
    def __exit__(self, *_args): return False
    def read(self, _limit): return json.dumps(self.body).encode()


class AuthenticatedSmokeTests(unittest.TestCase):
    def test_checks_only_three_readonly_loopback_endpoints_without_returning_cookie(self):
        seen = []
        def opener(request, timeout):
            seen.append((request.full_url, request.get_header("Cookie"), timeout))
            return Response({"status": "ok"})
        result = authenticated_smoke.run("http://127.0.0.1:8787", "sniper_session=secret", opener=opener)
        self.assertTrue(result["ok"])
        self.assertEqual([x[0].split("8787", 1)[1] for x in seen], list(authenticated_smoke.ENDPOINTS))
        self.assertNotIn("secret", json.dumps(result))

    def test_rejects_external_targets_and_header_injection(self):
        for url, cookie in (("https://example.com", "x=y"), ("http://127.0.0.1:8787", "x=y\r\nX: z")):
            with self.subTest(url=url), self.assertRaises(ValueError):
                authenticated_smoke.run(url, cookie, opener=lambda *_a, **_k: None)


if __name__ == "__main__":
    unittest.main()
