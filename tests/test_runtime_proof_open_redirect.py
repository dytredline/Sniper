from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request, urlopen

import runtime_proof
import sandbox_targets
import server
from storage import Store


class _RedirectFixture(BaseHTTPRequestHandler):
    requests = 0

    def do_GET(self) -> None:
        type(self).requests += 1
        parsed = urlsplit(self.path)
        if parsed.path in {"/reflect", "/escaped"}:
            marker = parse_qs(parsed.query).get("q", [""])[0]
            rendered = marker if parsed.path == "/reflect" else marker.replace("<", "&lt;").replace(">", "&gt;")
            body = ("<html><body>" + rendered + "</body></html>").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/go":
            location = parse_qs(parsed.query).get("next", ["/"])[0]
        else:
            location = "/home"
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *_args: object) -> None:
        pass


def _audit(store: Store, root: Path, *, redirect: bool = True) -> dict:
    root.mkdir(exist_ok=True)
    finding = {
        "title": "Kullanıcı girdisiyle açık yönlendirme" if redirect else "SQL enjeksiyonu",
        "category": "data_flow",
        "severity": "high",
        "reference": "CWE-601" if redirect else "CWE-89",
        "file": "app.py",
        "line": 7,
        "taint_flow": {"sink_kind": "redirect" if redirect else "sql", "source_label": "request"},
    }
    return store.create_project_audit({
        "created_at": "2026-10-21T16:00:00Z",
        "project_path": str(root),
        "project_name": root.name,
        "score": 55,
        "grade": "C",
        "file_count": 1,
        "bytes_scanned": 10,
        "findings": [finding],
    })


def _xss_audit(store: Store, root: Path) -> dict:
    root.mkdir(exist_ok=True)
    return store.create_project_audit({
        "created_at": "2026-10-21T16:00:00Z", "project_path": str(root),
        "project_name": root.name, "score": 55, "grade": "C", "file_count": 1, "bytes_scanned": 10,
        "findings": [{"title": "Yansıyan XSS", "category": "data_flow", "severity": "high",
                      "reference": "CWE-79", "file": "app.py", "line": 9,
                      "taint_flow": {"sink_kind": "html", "source_label": "request"}}],
    })


class RuntimeProofCoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data_dir = self.root / "data"
        self.store = Store(self.data_dir / "sniper.db")
        self.env = mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(self.data_dir)})
        self.env.start()
        self.addCleanup(self.env.stop)
        _RedirectFixture.requests = 0
        self.fixture = ThreadingHTTPServer(("127.0.0.1", 0), _RedirectFixture)
        self.fixture.daemon_threads = True
        self.thread = threading.Thread(target=self.fixture.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop_fixture)
        self.port = self.fixture.server_address[1]
        sandbox_targets.add_local_target(self.port, ["runtime_proof"], "kanıt fikstürü")
        self.target = f"http://127.0.0.1:{self.port}"
        self.audit = _audit(self.store, self.root / "project")

    def _stop_fixture(self) -> None:
        self.fixture.shutdown()
        self.fixture.server_close()
        self.thread.join(timeout=2)

    def test_fixed_marker_confirms_redirect_and_persists_sanitized_link(self) -> None:
        proof = runtime_proof.verify_open_redirect(
            self.store, self.audit["id"], 0, target=self.target,
            path="/go", parameter="next", confirm_local=True,
        )
        self.assertEqual(proof["verdict"], "confirmed")
        self.assertEqual(proof["request_count"], 1)
        self.assertEqual(_RedirectFixture.requests, 1)
        self.assertEqual(len(proof["evidence_sha256"]), 64)
        self.assertNotIn("runtime-proof.invalid", json.dumps(proof))
        finding = self.store.get_project_audit(self.audit["id"])["findings"][0]
        self.assertEqual(finding["runtime_proofs"][0]["verdict"], "confirmed")
        self.assertEqual(finding["triage"]["disposition"], "unreviewed")

    def test_safe_redirect_is_not_reproduced(self) -> None:
        proof = runtime_proof.verify_open_redirect(
            self.store, self.audit["id"], 0, target=self.target,
            path="/safe", parameter="next", confirm_local=True,
        )
        self.assertEqual(proof["verdict"], "not_reproduced")
        self.assertEqual(proof["http_status"], 302)

    def test_non_loopback_unregistered_and_wrong_finding_fail_before_request(self) -> None:
        wrong = _audit(self.store, self.root / "other", redirect=False)
        with mock.patch("runtime_proof.http.client.HTTPConnection") as connection:
            for audit_id, target in (
                (self.audit["id"], "http://example.com"),
                (self.audit["id"], "http://127.0.0.1:65534"),
                (wrong["id"], self.target),
            ):
                with self.subTest(audit_id=audit_id, target=target), self.assertRaises(runtime_proof.RuntimeProofError):
                    runtime_proof.verify_open_redirect(
                        self.store, audit_id, 0, target=target,
                        path="/go", parameter="next", confirm_local=True,
                    )
            connection.assert_not_called()

    def test_harmless_html_marker_confirms_reflection_without_script_execution(self) -> None:
        audit = _xss_audit(self.store, self.root / "xss-project")
        proof = runtime_proof.verify_reflected_html(
            self.store, audit["id"], 0, target=self.target, path="/reflect", parameter="q",
            confirm_local=True,
        )
        self.assertEqual(proof["verdict"], "confirmed")
        self.assertTrue(proof["marker_reflected"])
        self.assertTrue(proof["content_type_html"])
        self.assertEqual(proof["request_count"], 1)
        self.assertNotIn("sniper-proof", json.dumps(proof))
        stored = self.store.get_project_audit(audit["id"])["findings"][0]["runtime_proofs"][0]
        self.assertEqual(stored["proof_type"], "reflected_html_loopback")

        escaped = runtime_proof.verify_reflected_html(
            self.store, audit["id"], 0, target=self.target, path="/escaped", parameter="q",
            confirm_local=True,
        )
        self.assertEqual(escaped["verdict"], "not_reproduced")


class RuntimeProofApiTests(RuntimeProofCoreTests):
    def setUp(self) -> None:
        super().setUp()
        self.previous_store = server.STORE
        server.STORE = self.store
        self.addCleanup(setattr, server, "STORE", self.previous_store)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.httpd.daemon_threads = True
        self.http_thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.http_thread.start()
        self.addCleanup(self._stop_http)
        self.base_url = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def _stop_http(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.http_thread.join(timeout=2)

    def post(self, payload: dict) -> tuple[int, dict]:
        req = Request(
            f"{self.base_url}/api/project-audits/{self.audit['id']}/findings/0/runtime-proof/open-redirect",
            data=json.dumps(payload).encode(), method="POST", headers={"Content-Type": "application/json"},
        )
        try:
            with urlopen(req, timeout=5) as response:
                return response.status, json.loads(response.read())
        except HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def post_reflection(self, audit_id: str, payload: dict) -> tuple[int, dict]:
        req = Request(
            f"{self.base_url}/api/project-audits/{audit_id}/findings/0/runtime-proof/reflected-html",
            data=json.dumps(payload).encode(), method="POST", headers={"Content-Type": "application/json"},
        )
        try:
            with urlopen(req, timeout=5) as response:
                return response.status, json.loads(response.read())
        except HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_api_requires_exact_consent_and_returns_runtime_result(self) -> None:
        body = {"target": self.target, "path": "/go", "parameter": "next", "confirm_local": True}
        status, result = self.post(body)
        self.assertEqual(status, 200, result)
        self.assertEqual(result["verdict"], "confirmed")
        status, _ = self.post({**body, "confirm_local": False})
        self.assertEqual(status, 400)
        status, _ = self.post({**body, "url": "http://example.com"})
        self.assertEqual(status, 400)

    def test_reflection_api_is_tied_to_cwe79_and_exact_fields(self) -> None:
        audit = _xss_audit(self.store, self.root / "xss-api-project")
        body = {"target": self.target, "path": "/reflect", "parameter": "q", "confirm_local": True}
        status, result = self.post_reflection(audit["id"], body)
        self.assertEqual(status, 200, result)
        self.assertEqual(result["verdict"], "confirmed")
        self.assertEqual(self.post_reflection(audit["id"], {**body, "script": "alert(1)"})[0], 400)
        self.assertEqual(self.post_reflection(self.audit["id"], body)[0], 400)


if __name__ == "__main__":
    unittest.main()
