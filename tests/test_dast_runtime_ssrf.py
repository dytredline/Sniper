from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlsplit
from urllib.request import urlopen

import dast_runtime
import sandbox_targets
from storage import Store


class _SsrfFixture(BaseHTTPRequestHandler):
    trigger_requests = 0

    def do_GET(self) -> None:
        type(self).trigger_requests += 1
        parsed = urlsplit(self.path)
        if parsed.path == "/fetch":
            callback = parse_qs(parsed.query).get("url", [""])[0]
            try:
                with urlopen(callback, timeout=2):
                    pass
            except OSError:
                pass
        if parsed.path == "/mutated":
            callback = parse_qs(parsed.query).get("url", [""])[0]
            try:
                with urlopen(callback + "-changed", timeout=2):
                    pass
            except OSError:
                pass
        self.send_response(204)
        self.end_headers()

    def log_message(self, *_args: object) -> None:
        pass


def _audit(store: Store, root: Path, *, reference: str = "CWE-918") -> dict:
    root.mkdir(exist_ok=True)
    finding = {
        "title": "İstek adresine kullanıcı girdisi ulaşıyor",
        "category": "ssrf",
        "severity": "high",
        "reference": reference,
        "file": "app.py",
        "line": 7,
        "taint_flow": {
            "sink_kind": "ssrf" if reference == "CWE-918" else "sql",
            "source_label": "request",
        },
    }
    return store.create_project_audit({
        "created_at": "2026-10-27T12:00:00Z",
        "project_path": str(root),
        "project_name": root.name,
        "score": 55,
        "grade": "C",
        "file_count": 1,
        "bytes_scanned": 10,
        "findings": [finding],
    })


class DastRuntimeSsrfTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(self.root / "data")})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.store = Store(self.root / "data" / "sniper.db")
        _SsrfFixture.trigger_requests = 0
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _SsrfFixture)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop)
        self.port = self.httpd.server_address[1]
        sandbox_targets.add_local_target(self.port, ["runtime_proof"], "SSRF kanıt fikstürü")
        self.target = f"http://127.0.0.1:{self.port}"
        self.audit = _audit(self.store, self.root / "project")

    def _stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)

    def test_callback_profile_confirms_linked_ssrf_without_exposing_canary(self) -> None:
        catalog = dast_runtime.catalog()
        profile = next(row for row in catalog["profiles"] if row["id"] == "ssrf_callback")
        self.assertEqual(profile["finding_reference"], "CWE-918")
        self.assertEqual(profile["max_requests"], 1)
        self.assertEqual(profile["max_callback_requests"], 1)

        proof = dast_runtime.run(
            self.store, self.audit["id"], 0, profile_id="ssrf_callback", target=self.target,
            path="/fetch", parameter="url", confirm_local=True,
        )

        self.assertEqual(proof["verdict"], "confirmed")
        self.assertEqual(proof["proof_type"], "ssrf_callback_loopback")
        self.assertTrue(proof["callback_observed"])
        self.assertEqual(proof["trigger_request_count"], 1)
        self.assertEqual(proof["callback_request_count"], 1)
        self.assertFalse(proof["redirect_followed"])
        self.assertFalse(proof["response_body_read"])
        self.assertTrue(proof["canary_loopback_only"])
        self.assertEqual(_SsrfFixture.trigger_requests, 1)
        serialized = json.dumps(proof)
        self.assertNotIn("sniper-ssrf-proof", serialized)
        self.assertNotIn("127.0.0.1:", serialized)

        stored = self.store.get_project_audit(self.audit["id"])["findings"][0]["runtime_proofs"]
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0]["proof_type"], "ssrf_callback_loopback")
        self.assertTrue(stored[0]["callback_observed"])

    def test_no_callback_is_a_passing_control_not_reproduced(self) -> None:
        proof = dast_runtime.run(
            self.store, self.audit["id"], 0, profile_id="ssrf_callback", target=self.target,
            path="/safe", parameter="url", confirm_local=True,
        )

        self.assertEqual(proof["verdict"], "not_reproduced")
        self.assertFalse(proof["callback_observed"])
        self.assertEqual(proof["callback_request_count"], 0)
        self.assertEqual(_SsrfFixture.trigger_requests, 1)

        mutated = dast_runtime.run(
            self.store, self.audit["id"], 0, profile_id="ssrf_callback", target=self.target,
            path="/mutated", parameter="url", confirm_local=True,
        )
        self.assertEqual(mutated["verdict"], "not_reproduced")
        self.assertFalse(mutated["callback_observed"])
        self.assertEqual(mutated["callback_request_count"], 1)

    def test_wrong_finding_and_non_loopback_target_fail_before_trigger(self) -> None:
        wrong = _audit(self.store, self.root / "wrong", reference="CWE-89")
        for audit_id, target in (
            (wrong["id"], self.target),
            (self.audit["id"], "http://example.com"),
            (self.audit["id"], "http://127.0.0.1:65534"),
        ):
            with self.subTest(audit_id=audit_id, target=target), self.assertRaises(dast_runtime.DastRuntimeError):
                dast_runtime.run(
                    self.store, audit_id, 0, profile_id="ssrf_callback", target=target,
                    path="/fetch", parameter="url", confirm_local=True,
                )
        self.assertEqual(_SsrfFixture.trigger_requests, 0)


if __name__ == "__main__":
    unittest.main()
