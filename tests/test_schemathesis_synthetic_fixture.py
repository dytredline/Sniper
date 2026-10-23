"""Runtime contract for the bounded synthetic Schemathesis loopback fixture."""
from __future__ import annotations

import concurrent.futures
import json
import subprocess
import sys
import unittest
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from schemathesis_synthetic_fixture import MAX_REQUESTS, SyntheticPingFixture


def request(origin: str, path: str = "/api/ping", method: str = "GET"):
    req = Request(origin + path, method=method)
    try:
        with urlopen(req, timeout=4) as response:
            return response.status, response.read(), dict(response.headers)
    except HTTPError as error:
        with error:
            return error.code, error.read(), dict(error.headers)


class SyntheticFixtureTests(unittest.TestCase):
    def setUp(self):
        self.fixture = SyntheticPingFixture()
        self.fixture.start()

    def tearDown(self):
        self.fixture.stop()

    def test_loopback_ping_and_no_other_route_or_method(self):
        self.assertEqual(self.fixture.address[0], "127.0.0.1")
        status, body, headers = request(self.fixture.origin)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"ok": True})
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(request(self.fixture.origin, "/api/other")[0], 404)
        self.assertEqual(request(self.fixture.origin, "/api/ping", "POST")[0], 405)
        self.assertEqual(self.fixture.admitted_requests, 3)
        self.assertEqual(self.fixture.handler_invocations, 3)

    def test_25th_request_is_rejected_before_handler(self):
        self.assertEqual(MAX_REQUESTS, 24)
        statuses = [request(self.fixture.origin)[0] for _ in range(MAX_REQUESTS)]
        self.assertEqual(statuses, [200] * MAX_REQUESTS)
        self.assertEqual(self.fixture.handler_invocations, MAX_REQUESTS)
        for _ in range(3):
            status, body, _ = request(self.fixture.origin)
            self.assertEqual(status, 429)
            self.assertEqual(json.loads(body), {"error": "request budget exhausted"})
        self.assertEqual(self.fixture.admitted_requests, MAX_REQUESTS)
        self.assertEqual(self.fixture.handler_invocations, MAX_REQUESTS)
        self.assertEqual(self.fixture.rejected_requests, 3)

    def test_concurrent_clients_share_one_atomic_budget(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            statuses = list(pool.map(lambda _: request(self.fixture.origin)[0], range(40)))
        self.assertEqual(statuses.count(200), MAX_REQUESTS)
        self.assertEqual(statuses.count(429), 16)
        self.assertEqual(self.fixture.admitted_requests, MAX_REQUESTS)
        self.assertEqual(self.fixture.handler_invocations, MAX_REQUESTS)
        self.assertEqual(self.fixture.rejected_requests, 16)

    def test_rejected_method_uses_budget_and_no_restart_reset(self):
        self.assertEqual(request(self.fixture.origin, "/api/ping", "POST")[0], 405)
        statuses = [request(self.fixture.origin)[0] for _ in range(MAX_REQUESTS)]
        self.assertEqual(statuses.count(200), MAX_REQUESTS - 1)
        self.assertEqual(statuses.count(429), 1)
        self.fixture.stop()
        with self.assertRaises(RuntimeError):
            self.fixture.start()
        with self.assertRaises(URLError):
            request(self.fixture.origin)

    def test_cli_starts_synthetic_listener_and_sigterm_closes_it(self):
        module = Path(__file__).resolve().parents[1] / "schemathesis_synthetic_fixture.py"
        child = subprocess.Popen([sys.executable, str(module), "--port", "0"],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            assert child.stdout is not None
            metadata = json.loads(child.stdout.readline())
            self.assertEqual(metadata["max_requests"], MAX_REQUESTS)
            self.assertTrue(metadata["origin"].startswith("http://127.0.0.1:"))
            self.assertEqual(request(metadata["origin"])[0], 200)
            child.terminate()
            stdout, stderr = child.communicate(timeout=5)
            self.assertEqual(child.returncode, 0, stderr)
            self.assertEqual(stdout, "")
            with self.assertRaises(URLError):
                request(metadata["origin"])
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
