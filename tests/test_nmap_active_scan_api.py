import hashlib
import json
import subprocess
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
import tempfile
import threading
from unittest.mock import patch
from urllib.request import Request, urlopen
from urllib.error import HTTPError

import server
import nmap_active
from scanner import normalize_target
from storage import Store


class NmapActiveScanApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.base = Path(self.temp.name)
        self.previous_store = server.STORE
        server.STORE = Store(self.base / "data" / "sniper.db")
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.scan_called = []

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        server.STORE = self.previous_store
        self.temp.cleanup()

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

    def test_positive_tcp_scan(self):
        target = server.STORE.create_target(normalize_target("https://example.com"))
        engagement = server.STORE.create_engagement(
            target_id=target["id"],
            name="test",
            authorization_ref="REF-123",
            scope_notes="scope",
            out_of_scope="",
            test_window="",
            special_approvals={},
        )
        mock_result = {
            "target_id": target["id"],
            "engagement_id": engagement["id"],
            "profile": "bounded-tcp-connect-v1",
            "host_count": 1,
            "up_host_count": 1,
            "open_port_count": 1,
            "open_ports": [80],
            "report_sha256": hashlib.sha256(b"mock").hexdigest(),
        }

        with patch("server.run_bounded_tcp_connect_scan", return_value=mock_result, create=True) as mock:
            status, body = self.request_json(
                "/api/nmap/tcp-scan",
                {
                    "target_id": target["id"],
                    "engagement_id": engagement["id"],
                    "confirm_authorized": True,
                },
            )
            self.assertEqual(status, 200)
            self.assertEqual(body["target_id"], target["id"])
            self.assertEqual(body["engagement_id"], engagement["id"])
            self.assertEqual(body["profile"], "bounded-tcp-connect-v1")
            self.assertEqual(body["open_port_count"], 1)
            self.assertEqual(body["open_ports"], [80])
            self.assertIn("report_sha256", body)
            mock.assert_called_once_with(
                target_id=target["id"],
                engagement_id=engagement["id"],
                hostname=target["hostname"],
                port=int(target["port"]),
            )

    def test_missing_confirm_authorized_returns_400(self):
        target = server.STORE.create_target(normalize_target("https://example.com"))
        engagement = server.STORE.create_engagement(
            target_id=target["id"],
            name="test",
            authorization_ref="REF-123",
            scope_notes="scope",
            out_of_scope="",
            test_window="",
            special_approvals={},
        )

        with patch("server.run_bounded_tcp_connect_scan", create=True) as mock:
            status, body = self.request_json(
                "/api/nmap/tcp-scan",
                {
                    "target_id": target["id"],
                    "engagement_id": engagement["id"],
                    "confirm_authorized": False,
                },
            )
            self.assertEqual(status, 400)
            self.assertIn("error", body)
            mock.assert_not_called()

    def test_mismatched_engagement_returns_403(self):
        target1 = server.STORE.create_target(normalize_target("https://example.com"))
        target2 = server.STORE.create_target(normalize_target("https://example.org"))
        engagement = server.STORE.create_engagement(
            target_id=target1["id"],
            name="test",
            authorization_ref="REF-123",
            scope_notes="scope",
            out_of_scope="",
            test_window="",
            special_approvals={},
        )

        with patch("server.run_bounded_tcp_connect_scan", create=True) as mock:
            status, body = self.request_json(
                "/api/nmap/tcp-scan",
                {
                    "target_id": target2["id"],
                    "engagement_id": engagement["id"],
                    "confirm_authorized": True,
                },
            )
            self.assertEqual(status, 403)
            self.assertIn("error", body)
            mock.assert_not_called()

    def test_explicit_high_ports_are_sorted_and_forwarded(self):
        target = server.STORE.create_target(normalize_target("https://example.com"))
        engagement = server.STORE.create_engagement(
            target_id=target["id"], name="test", authorization_ref="REF-123",
            scope_notes="authorized TCP ports", out_of_scope="", test_window="",
            special_approvals={},
        )
        result = {
            "target_id": target["id"], "engagement_id": engagement["id"],
            "profile": "bounded-tcp-connect-custom-v1", "host_count": 1,
            "up_host_count": 1, "open_port_count": 1, "open_ports": [42424],
            "report_sha256": hashlib.sha256(b"mock").hexdigest(),
        }
        with patch("server.run_bounded_tcp_connect_scan", return_value=result) as scan:
            status, body = self.request_json("/api/nmap/tcp-scan", {
                "target_id": target["id"], "engagement_id": engagement["id"],
                "confirm_authorized": True, "ports": [42424, 80],
            })
        self.assertEqual(status, 200)
        self.assertEqual(body["profile"], "bounded-tcp-connect-custom-v1")
        self.assertEqual(body["open_ports"], [42424])
        scan.assert_called_once_with(
            target_id=target["id"], engagement_id=engagement["id"],
            hostname=target["hostname"], port=int(target["port"]),
            ports=[80, 42424],
        )

    def test_invalid_explicit_ports_never_start_scan(self):
        target = server.STORE.create_target(normalize_target("https://example.com"))
        engagement = server.STORE.create_engagement(
            target_id=target["id"], name="test", authorization_ref="REF-123",
            scope_notes="authorized TCP ports", out_of_scope="", test_window="",
            special_approvals={},
        )
        for ports in ([], [0], [65536], [True], [80, 80], ["443"], None, list(range(1, 66))):
            with self.subTest(ports=ports), patch("server.run_bounded_tcp_connect_scan") as scan:
                status, _ = self.request_json("/api/nmap/tcp-scan", {
                    "target_id": target["id"], "engagement_id": engagement["id"],
                    "confirm_authorized": True, "ports": ports,
                })
                self.assertEqual(status, 400)
                scan.assert_not_called()

    def test_custom_ports_change_nmap_port_argument_and_filter_result(self):
        xml = (
            '<nmaprun><host><status state="up"/><ports>'
            '<port protocol="tcp" portid="42424"><state state="open"/></port>'
            '<port protocol="tcp" portid="80"><state state="open"/></port>'
            '</ports></host></nmaprun>'
        )
        completed = subprocess.CompletedProcess([], 0, stdout=xml.encode(), stderr=b"")
        with patch("nmap_active._find_nmap_binary", return_value=Path("/fake/nmap")), \
                patch("nmap_active.subprocess.run", return_value=completed) as run:
            _, host_count, up_host_count, open_count, open_ports = nmap_active._run_nmap(
                "203.0.113.9", False, [42424],
            )
        args = run.call_args.args[0]
        self.assertEqual(args[args.index("-p") + 1], "42424")
        self.assertIn("--max-rate", args)
        self.assertEqual((host_count, up_host_count, open_count, open_ports), (1, 1, 1, [42424]))
