import hashlib
import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import server
from storage import Store


class _DirectNucleiJobs:
    def __init__(self):
        self.calls = []

    def start_authorized_origin(self, origin, confirm_authorized):
        self.calls.append((origin, confirm_authorized))
        return {
            "job_id": "0123456789abcdef",
            "state": "starting",
            "profile": "authorized-origin-fixed-http-v1",
            "target_sha256": hashlib.sha256(origin.encode("utf-8")).hexdigest(),
        }


class AuthorizedDirectTargetApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.base = Path(self.temp.name)
        self.previous_store = server.STORE
        self.previous_limiter = server.LIMITER
        server.STORE = Store(self.base / "data" / "sniper.db")
        server.LIMITER = server.RateLimiter()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.httpd.server_port}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=3)
        server.STORE = self.previous_store
        server.LIMITER = self.previous_limiter
        self.temp.cleanup()

    def post(self, path, payload):
        request = Request(
            self.base_url + path,
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read())
        except HTTPError as exc:
            return exc.code, json.loads(exc.read())

    @staticmethod
    def assert_receipt(testcase, receipt):
        testcase.assertEqual(receipt["consent_version"], "direct-target-authorization-v1")
        testcase.assertIs(receipt["confirm_authorized"], True)
        testcase.assertRegex(receipt["confirmed_at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+00:00$")
        testcase.assertEqual(receipt["actor"]["id"], "local-operator")
        testcase.assertEqual(receipt["actor"]["username"], "yerel")

    def test_direct_nmap_accepts_exact_human_consent_without_registered_records(self):
        scan_result = {
            "profile": "authorized-service-light-v1",
            "host_count": 1,
            "up_host_count": 1,
            "open_port_count": 1,
            "open_ports": [8080],
            "service_version": True,
            "open_services": [{"port": 8080, "service": "http"}],
            "report_sha256": "a" * 64,
            "target_sha256": hashlib.sha256(b"example.com").hexdigest(),
        }
        with patch("server.run_authorized_nmap_scan", return_value=scan_result, create=True) as scan:
            status, body = self.post("/api/nmap/authorized-target-scan", {
                "target": "Example.COM.",
                "profile": "service-light",
                "confirm_authorized": True,
            })
        self.assertEqual(status, 200)
        self.assertEqual(body["profile"], "authorized-service-light-v1")
        self.assertNotIn("target", body)
        self.assertNotIn("example.com", json.dumps(body).lower())
        self.assert_receipt(self, body["authorization_receipt"])
        scan.assert_called_once_with("Example.COM.", profile="service-light")
        audit = server.STORE.recent_audit_log(limit=1)[0]
        self.assertEqual(audit["action"], "nmap.direct_authorized.completed")
        self.assertEqual(audit["details"]["authorization_receipt"], body["authorization_receipt"])
        self.assertNotIn("example.com", json.dumps(audit).lower())

    def test_direct_nuclei_accepts_exact_human_consent_without_registered_records(self):
        jobs = _DirectNucleiJobs()
        with patch("server.get_broad_nuclei_jobs", return_value=jobs):
            status, body = self.post("/api/nuclei/authorized-origin-scans", {
                "target_origin": "HTTP://127.0.0.1:18080/",
                "confirm_authorized": True,
            })
        self.assertEqual(status, 202)
        self.assertEqual(body["job_id"], "0123456789abcdef")
        self.assertEqual(body["profile"], "authorized-origin-fixed-http-v1")
        self.assertNotIn("target_origin", body)
        self.assert_receipt(self, body["authorization_receipt"])
        self.assertEqual(jobs.calls, [("HTTP://127.0.0.1:18080/", True)])
        audit = server.STORE.recent_audit_log(limit=1)[0]
        self.assertEqual(audit["action"], "nuclei.direct_authorized.started")
        self.assertEqual(audit["details"]["authorization_receipt"], body["authorization_receipt"])
        self.assertNotIn("18080", json.dumps(audit))

    def test_direct_routes_fail_closed_on_missing_consent_or_extra_controls(self):
        cases = (
            ("/api/nmap/authorized-target-scan", {"target": "127.0.0.1", "profile": "default"}),
            ("/api/nmap/authorized-target-scan", {
                "target": "127.0.0.1", "profile": "default", "confirm_authorized": True,
                "ports": [22],
            }),
            ("/api/nuclei/authorized-origin-scans", {"target_origin": "http://127.0.0.1:8080/"}),
            ("/api/nuclei/authorized-origin-scans", {
                "target_origin": "http://127.0.0.1:8080/", "confirm_authorized": True,
                "template_ids": ["tech-detect"],
            }),
        )
        for path, payload in cases:
            with self.subTest(path=path, payload=payload):
                status, _ = self.post(path, payload)
                self.assertIn(status, (400, 403))

    def test_direct_routes_are_unavailable_when_the_pinned_runtime_is_not_ready(self):
        with patch("server.run_authorized_nmap_scan", side_effect=RuntimeError("not ready")):
            nmap_status, _ = self.post("/api/nmap/authorized-target-scan", {
                "target": "127.0.0.1", "profile": "default", "confirm_authorized": True,
            })
        jobs = _DirectNucleiJobs()
        jobs.start_authorized_origin = lambda *_args: (_ for _ in ()).throw(server.NucleiBroadUnavailable("not ready"))
        with patch("server.get_broad_nuclei_jobs", return_value=jobs):
            nuclei_status, _ = self.post("/api/nuclei/authorized-origin-scans", {
                "target_origin": "http://127.0.0.1:8080", "confirm_authorized": True,
            })
        self.assertEqual(nmap_status, 503)
        self.assertEqual(nuclei_status, 503)


if __name__ == "__main__":
    unittest.main()
