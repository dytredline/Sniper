"""Real loopback proofs for bounded extended SSRF callback profiles (R7)."""

from __future__ import annotations

from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlencode, urlsplit

import dast_runtime
import sandbox_targets
from storage import Store


def _request_loopback_callback(value: str) -> None:
    """Issue a bounded fixture callback without accepting an arbitrary host."""
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise OSError("invalid callback") from exc
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.username is not None
        or parsed.password is not None
        or port is None
        or not 1 <= port <= 65535
    ):
        raise OSError("non-loopback callback rejected")
    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query
    connection = HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        connection.request("GET", target)
        response = connection.getresponse()
        response.read(1)
    finally:
        connection.close()


def _dns_query(name: str) -> bytes:
    labels = name.rstrip(".").split(".")
    question = b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels) + b"\x00"
    return b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + question + b"\x00\x01\x00\x01"


class _ExtendedSsrfFixture(BaseHTTPRequestHandler):
    requests: list[tuple[str, str]] = []
    delayed_workers: list[threading.Thread] = []

    @classmethod
    def _http_callback(cls, value: str, *, delay: float = 0.0) -> None:
        def worker() -> None:
            if delay:
                time.sleep(delay)
            try:
                _request_loopback_callback(value)
            except OSError:
                pass

        if delay:
            thread = threading.Thread(target=worker, daemon=True, name="r7-delayed-callback")
            cls.delayed_workers.append(thread)
            thread.start()
        else:
            worker()

    def _finish(self, status: int = 200, *, location: str = "") -> None:
        body = b"fixture-secret-response-body-must-not-be-read"
        self.send_response(status)
        if location:
            self.send_header("Location", location)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_POST(self) -> None:
        type(self).requests.append(("POST", self.path))
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        callback = parse_qs(raw.decode("ascii")).get("url", [""])[0]
        if urlsplit(self.path).path == "/post":
            self._http_callback(callback)
        self._finish(202)

    def do_GET(self) -> None:
        type(self).requests.append(("GET", self.path))
        parsed = urlsplit(self.path)
        callback = parse_qs(parsed.query).get("url", [""])[0]
        if parsed.path == "/redirect":
            self._finish(302, location="/fetch?" + urlencode({"url": callback}))
            return
        if parsed.path == "/redirect-external":
            self._finish(302, location="http://example.com/blocked")
            return
        if parsed.path == "/redirect-large":
            self._finish(302, location="/fetch?url=" + "x" * 2048)
            return
        if parsed.path == "/redirect-chain":
            self._finish(302, location="/redirect-again?" + urlencode({"url": callback}))
            return
        if parsed.path == "/redirect-again":
            self._finish(302, location="/fetch?" + urlencode({"url": callback}))
            return
        if parsed.path == "/fetch":
            self._http_callback(callback)
        elif parsed.path == "/delayed":
            self._http_callback(callback, delay=0.30)
        elif parsed.path == "/dns":
            parts = urlsplit(callback)
            try:
                host, port = parts.hostname, parts.port
                name = parts.path.lstrip("/")
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                    udp.sendto(_dns_query(name), (host or "", int(port or 0)))
            except (OSError, ValueError):
                pass
        elif parsed.path == "/dns-mutated":
            parts = urlsplit(callback)
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                    udp.sendto(_dns_query("wrong.sniper.invalid"), (parts.hostname or "", int(parts.port or 0)))
            except (OSError, ValueError):
                pass
        elif parsed.path == "/slow":
            time.sleep(4)
        self._finish(200)

    def log_message(self, *_args: object) -> None:
        pass


def _audit(store: Store, root: Path) -> dict:
    root.mkdir(exist_ok=True)
    return store.create_project_audit({
        "created_at": "2026-10-27T14:00:00Z",
        "project_path": str(root),
        "project_name": root.name,
        "score": 50,
        "grade": "C",
        "file_count": 1,
        "bytes_scanned": 10,
        "findings": [{
            "title": "URL girdisi ağ istemcisine ulaşıyor",
            "category": "ssrf",
            "severity": "high",
            "reference": "CWE-918",
            "file": "app.py",
            "line": 9,
            "taint_flow": {"sink_kind": "ssrf", "source_label": "request"},
        }],
    })


class ExtendedSsrfRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(self.root / "data")})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.store = Store(self.root / "data/sniper.db")
        _ExtendedSsrfFixture.requests = []
        _ExtendedSsrfFixture.delayed_workers = []
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _ExtendedSsrfFixture)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop)
        self.port = int(self.httpd.server_address[1])
        sandbox_targets.add_local_target(self.port, ["runtime_proof"], "R7 SSRF yerel fikstürü")
        self.target = f"http://127.0.0.1:{self.port}"
        self.audit = _audit(self.store, self.root / "project")

    def _stop(self) -> None:
        for worker in _ExtendedSsrfFixture.delayed_workers:
            worker.join(timeout=2)
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)

    def _run(self, profile: str, path: str) -> dict:
        return dast_runtime.run(
            self.store,
            self.audit["id"],
            0,
            profile_id=profile,
            target=self.target,
            path=path,
            parameter="url",
            confirm_local=True,
        )

    def test_catalog_exposes_four_bounded_local_profiles(self) -> None:
        profiles = {row["id"]: row for row in dast_runtime.catalog()["profiles"]}
        for profile in (
            "ssrf_callback_post", "ssrf_callback_redirect", "ssrf_callback_delayed", "ssrf_callback_dns",
        ):
            self.assertIn(profile, profiles)
            self.assertEqual(profiles[profile]["max_initial_triggers"], 1)
            self.assertEqual(profiles[profile]["max_callback_requests"], 1)
            self.assertLessEqual(profiles[profile]["timeout_seconds"], 5)
            self.assertEqual(profiles[profile]["max_response_body_bytes"], 0)
        self.assertEqual(profiles["ssrf_callback_post"]["request_method"], "POST")
        self.assertEqual(profiles["ssrf_callback_redirect"]["max_redirects"], 1)
        self.assertEqual(profiles["ssrf_callback_dns"]["correlation_kind"], "local_dns_oob")

    def test_real_post_redirect_delayed_and_dns_profiles_confirm_without_leaks(self) -> None:
        cases = (
            ("ssrf_callback_post", "/post", "POST", 1, 0, "http_callback"),
            ("ssrf_callback_redirect", "/redirect", "GET", 2, 1, "http_callback"),
            ("ssrf_callback_delayed", "/delayed", "GET", 1, 0, "http_callback"),
            ("ssrf_callback_dns", "/dns", "GET", 1, 0, "local_dns_oob"),
        )
        for profile, path, method, target_count, redirects, correlation in cases:
            with self.subTest(profile=profile):
                before = len(_ExtendedSsrfFixture.requests)
                proof = self._run(profile, path)
                self.assertEqual(proof["verdict"], "confirmed")
                self.assertEqual(proof["profile_id"], profile)
                self.assertEqual(proof["request_method"], method)
                self.assertEqual(proof["trigger_request_count"], 1)
                self.assertEqual(proof["target_request_count"], target_count)
                self.assertEqual(proof["redirect_count"], redirects)
                self.assertEqual(proof["correlation_kind"], correlation)
                self.assertTrue(proof["callback_observed"])
                self.assertEqual(proof["callback_request_count"], 1)
                self.assertFalse(proof["response_body_read"])
                self.assertTrue(proof["canary_worker_cleaned"])
                self.assertEqual(len(_ExtendedSsrfFixture.requests) - before, target_count)
                serialized = json.dumps(proof, sort_keys=True)
                for forbidden in (
                    "sniper-ssrf-proof", "dns://", "127.0.0.1:",
                    "fixture-secret-response-body-must-not-be-read",
                ):
                    self.assertNotIn(forbidden, serialized)

                stored = self.store.get_project_audit(self.audit["id"])["findings"][0]["runtime_proofs"]
                selected = next(item for item in stored if item["evidence_sha256"] == proof["evidence_sha256"])
                self.assertEqual(selected["profile_id"], profile)
                self.assertEqual(selected["correlation_kind"], correlation)

    def test_redirect_and_dns_ambiguity_fail_closed_without_external_follow(self) -> None:
        external = self._run("ssrf_callback_redirect", "/redirect-external")
        self.assertEqual(external["verdict"], "not_reproduced")
        self.assertFalse(external["redirect_followed"])
        self.assertEqual(external["target_request_count"], 1)
        self.assertEqual(external["redirect_count"], 0)

        oversized = self._run("ssrf_callback_redirect", "/redirect-large")
        self.assertEqual(oversized["verdict"], "not_reproduced")
        self.assertFalse(oversized["redirect_followed"])
        self.assertEqual(oversized["target_request_count"], 1)

        chain = self._run("ssrf_callback_redirect", "/redirect-chain")
        self.assertEqual(chain["verdict"], "not_reproduced")
        self.assertTrue(chain["redirect_followed"])
        self.assertEqual(chain["redirect_count"], 1)
        self.assertEqual(chain["target_request_count"], 2)

        mutated = self._run("ssrf_callback_dns", "/dns-mutated")
        self.assertEqual(mutated["verdict"], "not_reproduced")
        self.assertFalse(mutated["callback_observed"])
        self.assertEqual(mutated["callback_request_count"], 1)

        before = len(_ExtendedSsrfFixture.requests)
        with self.assertRaisesRegex(dast_runtime.DastRuntimeError, "not_run"):
            dast_runtime.run(
                self.store, self.audit["id"], 0, profile_id="ssrf_callback_dynamic",
                target=self.target, path="/fetch", parameter="url", confirm_local=True,
            )
        self.assertEqual(len(_ExtendedSsrfFixture.requests), before)

    def test_real_slow_trigger_hits_deadline_and_leaves_no_canary_worker(self) -> None:
        started = time.monotonic()
        with self.assertRaises(dast_runtime.DastRuntimeUnavailable):
            self._run("ssrf_callback_delayed", "/slow")
        self.assertLess(time.monotonic() - started, 4.0)
        self.assertFalse(any(
            thread.is_alive() and thread.name.startswith("sniper-ssrf-")
            for thread in threading.enumerate()
        ))

    def test_legacy_ssrf_proof_rows_receive_safe_profile_defaults(self) -> None:
        with sqlite3.connect(self.store.path) as db:
            db.execute("DROP TABLE project_ssrf_runtime_proofs")
            db.execute("""
                CREATE TABLE project_ssrf_runtime_proofs (
                    id TEXT PRIMARY KEY,
                    audit_id TEXT NOT NULL REFERENCES project_audits(id) ON DELETE CASCADE,
                    finding_index INTEGER NOT NULL,
                    verdict TEXT NOT NULL,
                    http_status INTEGER NOT NULL,
                    callback_observed INTEGER NOT NULL,
                    callback_request_count INTEGER NOT NULL,
                    evidence_sha256 TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            db.execute(
                "INSERT INTO project_ssrf_runtime_proofs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("rtp_legacy", self.audit["id"], 0, "confirmed", 204, 1, 1, "a" * 64,
                 "2026-10-27T14:01:00Z"),
            )

        migrated = Store(self.store.path)
        proof = migrated.get_project_audit(self.audit["id"])["findings"][0]["runtime_proofs"][0]
        self.assertEqual(proof["profile_id"], "ssrf_callback")
        self.assertEqual(proof["request_method"], "GET")
        self.assertEqual(proof["target_request_count"], 1)
        self.assertEqual(proof["redirect_count"], 0)
        self.assertEqual(proof["correlation_kind"], "http_callback")
        self.assertTrue(proof["canary_worker_cleaned"])


if __name__ == "__main__":
    unittest.main()
