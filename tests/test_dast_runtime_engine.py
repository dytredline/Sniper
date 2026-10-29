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

import dast_runtime
import sandbox_targets
import server
from storage import Store


class _DastFixture(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", parse_qs(parsed.query).get("next", ["/"])[0])
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if parsed.path == "/reflect":
            marker = parse_qs(parsed.query).get("q", [""])[0]
            body = ("<html>" + marker + "</html>").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/clickjack-missing":
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if parsed.path == "/clickjack-204":
            self.send_response(204)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            return
        if parsed.path == "/clickjack-empty":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        origin = self.headers.get("Origin", "")
        if parsed.path == "/cors" and origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        if parsed.path == "/clickjack-safe":
            self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
        if parsed.path == "/clickjack-duplicate":
            # Ayrı CSP politikaları birlikte uygulanır. İlki tüm ataları kabul eder, ikincisinde
            # frame-ancestors yoktur; virgülle birleştirip tek directive gibi ayrıştırılmamalıdır.
            self.send_header("Content-Security-Policy", "frame-ancestors *")
            self.send_header("Content-Security-Policy", "default-src 'none'")
        if parsed.path == "/clickjack-invalid-source":
            self.send_header("Content-Security-Policy", "frame-ancestors https://")
        if parsed.path == "/clickjack-valid-host-source":
            self.send_header("Content-Security-Policy", "frame-ancestors https://example.test")
        if parsed.path.startswith("/clickjack"):
            self.send_header("Content-Type", "text/html")
            body = b"<html><body>loopback fixture</body></html>"
        else:
            body = b""
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        pass


def _audit(store: Store, root: Path, reference: str, sink: str | None = None) -> dict:
    root.mkdir(exist_ok=True)
    finding = {"title": reference, "category": "web_hardening", "severity": "high",
               "reference": reference, "file": "app.py", "line": 3}
    if sink:
        finding["taint_flow"] = {"sink_kind": sink, "source_label": "request"}
    return store.create_project_audit({
        "created_at": "2026-10-21T18:00:00Z", "project_path": str(root), "project_name": root.name,
        "score": 60, "grade": "C", "file_count": 1, "bytes_scanned": 10, "findings": [finding],
    })


class DastRuntimeEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data_dir = self.root / "data"
        self.env = mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(self.data_dir)})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.store = Store(self.data_dir / "sniper.db")
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _DastFixture)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop)
        self.port = self.httpd.server_address[1]
        sandbox_targets.add_local_target(self.port, ["runtime_proof"], "DAST fikstürü")
        self.target = f"http://127.0.0.1:{self.port}"

    def _stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)

    def test_catalog_and_bounded_profiles_produce_linked_evidence(self) -> None:
        catalog = dast_runtime.catalog()
        self.assertEqual({row["id"] for row in catalog["profiles"]},
                         {"open_redirect", "reflected_html", "cors_credentials", "clickjacking_headers",
                          "ssrf_callback", "ssrf_callback_post", "ssrf_callback_redirect",
                          "ssrf_callback_delayed", "ssrf_callback_dns"})
        self.assertTrue(all(row["max_requests"] in {1, 2} for row in catalog["profiles"]))
        self.assertEqual(catalog["target_policy"], "registered_noncritical_loopback_only")

        redirect = _audit(self.store, self.root / "redirect", "CWE-601", "redirect")
        reflected = _audit(self.store, self.root / "reflected", "CWE-79", "html")
        cors = _audit(self.store, self.root / "cors", "CWE-942")
        clickjacking = _audit(self.store, self.root / "clickjacking", "CWE-1021")
        cases = (
            (redirect, "open_redirect", "/redirect", "next", "open_redirect_loopback"),
            (reflected, "reflected_html", "/reflect", "q", "reflected_html_loopback"),
            (cors, "cors_credentials", "/cors", "", "cors_credentials_loopback"),
            (clickjacking, "clickjacking_headers", "/clickjack", "", "clickjacking_headers_loopback"),
        )
        for audit, profile, path, parameter, proof_type in cases:
            with self.subTest(profile=profile):
                proof = dast_runtime.run(
                    self.store, audit["id"], 0, profile_id=profile, target=self.target,
                    path=path, parameter=parameter, confirm_local=True,
                )
                self.assertEqual(proof["verdict"], "confirmed")
                self.assertEqual(proof["proof_type"], proof_type)
                self.assertEqual(proof["request_count"], 1)
                self.assertNotIn("runtime-proof.invalid", json.dumps(proof))
                stored = self.store.get_project_audit(audit["id"])["findings"][0]["runtime_proofs"]
                self.assertEqual(stored[0]["proof_type"], proof_type)

    def test_clickjacking_profile_control_does_not_confirm_when_response_is_protected(self) -> None:
        audit = _audit(self.store, self.root / "clickjacking-safe", "CWE-1021")
        proof = dast_runtime.run(
            self.store, audit["id"], 0, profile_id="clickjacking_headers", target=self.target,
            path="/clickjack-safe", parameter="", confirm_local=True,
        )
        self.assertEqual(proof["verdict"], "not_reproduced")
        self.assertTrue(proof["frame_ancestors_present"])
        self.assertTrue(proof["effective_protection"])
        self.assertTrue(proof["content_type_html"])
        self.assertTrue(proof["body_capable"])
        self.assertFalse(proof["body_read"])

        missing = dast_runtime.run(
            self.store, audit["id"], 0, profile_id="clickjacking_headers", target=self.target,
            path="/clickjack-missing", parameter="", confirm_local=True,
        )
        self.assertEqual(missing["http_status"], 404)
        self.assertEqual(missing["verdict"], "not_reproduced")
        self.assertFalse(missing["effective_protection"])

    def test_clickjacking_treats_duplicate_csp_headers_as_separate_policies(self) -> None:
        audit = _audit(self.store, self.root / "clickjacking-duplicate", "CWE-1021")
        proof = dast_runtime.run(
            self.store, audit["id"], 0, profile_id="clickjacking_headers", target=self.target,
            path="/clickjack-duplicate", parameter="", confirm_local=True,
        )
        self.assertEqual(proof["verdict"], "confirmed")
        self.assertTrue(proof["frame_ancestors_present"])
        self.assertFalse(proof["effective_protection"])

    def test_clickjacking_requires_valid_frame_ancestors_source_grammar(self) -> None:
        audit = _audit(self.store, self.root / "clickjacking-source-grammar", "CWE-1021")
        invalid = dast_runtime.run(
            self.store, audit["id"], 0, profile_id="clickjacking_headers", target=self.target,
            path="/clickjack-invalid-source", parameter="", confirm_local=True,
        )
        self.assertEqual(invalid["verdict"], "confirmed")
        self.assertTrue(invalid["frame_ancestors_present"])
        self.assertFalse(invalid["effective_protection"])

        valid = dast_runtime.run(
            self.store, audit["id"], 0, profile_id="clickjacking_headers", target=self.target,
            path="/clickjack-valid-host-source", parameter="", confirm_local=True,
        )
        self.assertEqual(valid["verdict"], "not_reproduced")
        self.assertTrue(valid["effective_protection"])

    def test_clickjacking_does_not_confirm_204_or_declared_empty_html(self) -> None:
        audit = _audit(self.store, self.root / "clickjacking-bodyless", "CWE-1021")
        for path, status in (("/clickjack-204", 204), ("/clickjack-empty", 200)):
            with self.subTest(path=path):
                proof = dast_runtime.run(
                    self.store, audit["id"], 0, profile_id="clickjacking_headers", target=self.target,
                    path=path, parameter="", confirm_local=True,
                )
                self.assertEqual(proof["http_status"], status)
                self.assertEqual(proof["verdict"], "not_reproduced")
                self.assertFalse(proof["effective_protection"])
                self.assertFalse(proof["body_capable"])

    def test_profile_finding_binding_and_parameter_contract_fail_closed(self) -> None:
        cors = _audit(self.store, self.root / "cors-wrong", "CWE-942")
        for profile, parameter in (("open_redirect", "next"), ("cors_credentials", "q"),
                                   ("clickjacking_headers", ""),
                                   ("unknown", "")):
            with self.subTest(profile=profile), self.assertRaises(dast_runtime.DastRuntimeError):
                dast_runtime.run(
                    self.store, cors["id"], 0, profile_id=profile, target=self.target,
                    path="/cors", parameter=parameter, confirm_local=True,
                )


class DastRuntimeApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = server.SniperHandler.__new__(server.SniperHandler)
        self.responses: list[tuple[int, dict]] = []
        self.client._json = lambda body, status=200, **_kw: self.responses.append((int(status), body))
        self.client._error = lambda status, message: self.responses.append((int(status), {"error": message}))

    def test_handler_accepts_only_exact_declarative_profile_fields(self) -> None:
        expected = {"format": "sniper-cors-runtime-proof/1", "verdict": "confirmed"}
        payload = {"profile_id": "cors_credentials", "target": "http://127.0.0.1:3000",
                   "path": "/", "parameter": "", "confirm_local": True}
        with mock.patch.object(dast_runtime, "run", return_value=expected) as run:
            self.client._dast_runtime_proof_post("prj_abc", "0", payload)
        self.assertEqual(self.responses.pop(), (200, expected))
        run.assert_called_once_with(
            server.STORE, "prj_abc", 0, profile_id="cors_credentials", target="http://127.0.0.1:3000",
            path="/", parameter="", confirm_local=True,
        )
        self.client._dast_runtime_proof_post("prj_abc", "0", {**payload, "headers": {"X": "Y"}})
        self.assertEqual(self.responses.pop()[0], 400)


if __name__ == "__main__":
    unittest.main()
