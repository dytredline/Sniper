from __future__ import annotations

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


FOUR_ROUTES = (
    ("/api/tool-runs/semgrep", "run_local_semgrep", "semgrep"),
    ("/api/tool-runs/gitleaks", "run_local_gitleaks", "gitleaks"),
    ("/api/tool-runs/trivy-secret", "run_local_trivy_secret", "trivy-secret"),
    ("/api/tool-runs/trufflehog-filesystem", "run_local_trufflehog_filesystem", "trufflehog-filesystem"),
)


class ActiveLocalExactKeysApiTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(dir=Path.home(), prefix="sniper_task69_exact_keys_")
        self.base = Path(self.temp_dir.name)
        self.previous_store = server.STORE
        server.STORE = Store(self.base / "sniper.db")
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        server.STORE = self.previous_store
        self.temp_dir.cleanup()

    def post_json(self, path: str, payload) -> tuple[int, dict]:
        raw = json.dumps(payload).encode("utf-8")
        req = Request(
            self.base_url + path,
            data=raw,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def test_exact_two_key_controls_succeed_with_single_runner_call(self):
        for route, runner_attr, label in FOUR_ROUTES:
            with self.subTest(route=route):
                calls: list[str] = []

                def stub_runner(project_path: str, _label: str = label) -> dict:
                    calls.append(project_path)
                    return {"stub": _label, "total_findings": 0}

                with patch.object(server, runner_attr, side_effect=stub_runner):
                    status, body = self.post_json(
                        route,
                        {"confirm_local": True, "project_path": "/tmp/sniper-stub"},
                    )
                    self.assertEqual(status, 200)
                    self.assertEqual(calls, ["/tmp/sniper-stub"])
                    self.assertEqual(body.get("stub"), label)

    def test_unknown_scanner_args_rejected_with_zero_runner_calls(self):
        for route, runner_attr, label in FOUR_ROUTES:
            with self.subTest(route=route):
                calls: list[str] = []

                def stub_runner(project_path: str, _label: str = label) -> dict:
                    calls.append(project_path)
                    return {"stub": _label, "total_findings": 0}

                with patch.object(server, runner_attr, side_effect=stub_runner):
                    status, body = self.post_json(
                        route,
                        {
                            "confirm_local": True,
                            "project_path": "/tmp/sniper-stub",
                            "scanner_args": ["--config=auto"],
                        },
                    )
                    self.assertEqual(status, 400)
                    self.assertEqual(calls, [])
                    self.assertIn("fazla veya eksik alan", body.get("error", ""))

    def test_missing_key_or_false_consent_rejected_with_zero_runner_calls(self):
        invalid_payloads = (
            {"project_path": "/tmp/sniper-stub"},
            {"confirm_local": True},
            {"confirm_local": False, "project_path": "/tmp/sniper-stub"},
            {},
        )
        for route, runner_attr, _ in FOUR_ROUTES:
            for payload in invalid_payloads:
                with self.subTest(route=route, payload=payload):
                    calls: list[str] = []
                    with patch.object(server, runner_attr, side_effect=lambda p: calls.append(p)):
                        status, _ = self.post_json(route, payload)
                        self.assertEqual(status, 400)
                        self.assertEqual(calls, [])

    def test_non_object_json_payload_rejected_with_zero_runner_calls(self):
        non_objects = (
            ["confirm_local", "project_path"],
            "not-an-object",
            42,
            True,
        )
        for route, runner_attr, _ in FOUR_ROUTES:
            for payload in non_objects:
                with self.subTest(route=route, payload=payload):
                    calls: list[str] = []
                    with patch.object(server, runner_attr, side_effect=lambda p: calls.append(p)):
                        status, _ = self.post_json(route, payload)
                        self.assertEqual(status, 400)
                        self.assertEqual(calls, [])

    def test_sibling_trufflehog_git_history_control_preserved(self):
        calls: list[str] = []

        def stub_git_history(project_path: str) -> dict:
            calls.append(project_path)
            return {"stub": "git-history", "total_findings": 0}

        with patch.object(server, "run_local_trufflehog_git_history", side_effect=stub_git_history):
            status_extra, body_extra = self.post_json(
                "/api/tool-runs/trufflehog-git-history",
                {
                    "confirm_local": True,
                    "project_path": "/tmp/sniper-stub",
                    "scanner_args": ["--config=auto"],
                },
            )
            self.assertEqual(status_extra, 400)
            self.assertEqual(calls, [])
            self.assertIn("Yalnız confirm_local ve project_path bekleniyor", body_extra.get("error", ""))

            status_ok, body_ok = self.post_json(
                "/api/tool-runs/trufflehog-git-history",
                {"confirm_local": True, "project_path": "/tmp/sniper-stub"},
            )
            self.assertEqual(status_ok, 200)
            self.assertEqual(calls, ["/tmp/sniper-stub"])
            self.assertEqual(body_ok.get("stub"), "git-history")


if __name__ == "__main__":
    unittest.main()
