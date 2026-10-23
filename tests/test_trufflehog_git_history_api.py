from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import threading
import unittest
from tests.pin_helpers import pin_test_binary
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import server
from storage import Store


class GitHistoryHttpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=Path.home(), prefix="sniper_git_http_test_")
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.data = self.root / "data"
        self.data.mkdir()
        self.binary = self.root / "fake-trufflehog"
        self.original_env = {key: os.environ.get(key) for key in ("SNIPER_DATA_DIR", "SNIPER_TRUFFLEHOG_BINARY")}
        os.environ["SNIPER_DATA_DIR"] = str(self.data)
        os.environ["SNIPER_TRUFFLEHOG_BINARY"] = str(self.binary)
        for args in (
            ["init", "-q", str(self.repo)],
            ["-C", str(self.repo), "config", "user.email", "test@example.invalid"],
            ["-C", str(self.repo), "config", "user.name", "Test"],
        ):
            subprocess.run(["/usr/bin/git", *args], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        (self.repo / "harmless.txt").write_text("synthetic local fixture\n")
        for args in (["add", "harmless.txt"], ["commit", "-q", "-m", "fixture"]):
            subprocess.run(["/usr/bin/git", "-C", str(self.repo), *args], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["/usr/bin/git", "-C", str(self.repo), "config", "sniper.untrusted", "source-config-marker"], check=True)
        hook = self.repo / ".git/hooks/pre-commit"
        hook.write_text("#!/bin/sh\nexit 77\n")
        hook.chmod(0o700)
        self._fake("record")
        self.old_store = server.STORE
        server.STORE = Store(self.root / "sniper.db")
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=3)
        server.STORE = self.old_store
        for key, value in self.original_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self.temp.cleanup()

    def _fake(self, mode: str) -> None:
        assert mode in {"record", "clean", "malformed"}
        body = {
            "record": "printf '%s\\n' '{\"DetectorName\":\"Github\",\"Verified\":false,\"Raw\":\"synthetic-secret-must-not-leak\"}'",
            "clean": ":",
            "malformed": "printf '%s\\n' 'not-jsonl'",
        }[mode]
        script = "\n".join((
            "#!/bin/sh",
            "[ \"$1\" = git ] || exit 21",
            "case \"$2\" in file://*) staged=${2#file://} ;; *) exit 22 ;; esac",
            "[ -f \"$staged/.git/index\" ] || exit 23",
            "[ -f \"$staged/.git/config\" ] || exit 24",
            "[ ! -e \"$staged/.git/hooks/pre-commit\" ] || exit 25",
            "grep -q source-config-marker \"$staged/.git/config\" && exit 26",
            "[ \"$GIT_ALLOW_PROTOCOL\" = file ] || exit 27",
            "[ \"$GIT_CONFIG_NOSYSTEM\" = 1 ] || exit 28",
            "case \" $* \" in *' --no-update '* ) : ;; *) exit 29 ;; esac",
            "case \" $* \" in *' --no-verification '* ) : ;; *) exit 30 ;; esac",
            body,
            "exit 0",
        )) + "\n"
        self.binary.write_text(script)
        self.binary.chmod(0o700)
        pin_test_binary(self, "trufflehog", self.binary)

    def _post(self, payload: dict) -> tuple[int, dict]:
        request = Request(
            self.url + "/api/tool-runs/trufflehog-git-history",
            data=json.dumps(payload).encode(), method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urlopen(request, timeout=12) as response:
                return response.status, json.load(response)
        except HTTPError as error:
            return error.code, json.loads(error.read())

    def _valid(self) -> dict:
        return {"confirm_local": True, "project_path": str(self.repo)}

    def test_prior_commit_style_runtime_aggregate_and_redaction(self) -> None:
        status, body = self._post(self._valid())
        self.assertEqual(status, 200)
        self.assertEqual(set(body), {"format", "total_findings", "verified_findings", "unverified_findings", "detectors_triggered", "profile", "report_sha256"})
        self.assertEqual(body["format"], "trufflehog-native-json-records")
        self.assertEqual(body["profile"], "local-git-history-no-verification-v1")
        self.assertEqual((body["total_findings"], body["verified_findings"], body["unverified_findings"], body["detectors_triggered"]), (1, 0, 1, 1))
        self.assertRegex(body["report_sha256"], r"^[0-9a-f]{64}$")
        self.assertNotIn("synthetic-secret-must-not-leak", json.dumps(body))
        self.assertNotIn(str(self.repo), json.dumps(body))

    def test_clean_runtime_aggregate(self) -> None:
        self._fake("clean")
        status, body = self._post(self._valid())
        self.assertEqual(status, 200)
        self.assertEqual((body["total_findings"], body["unverified_findings"], body["detectors_triggered"]), (0, 0, 0))

    def test_invalid_inputs_are_rejected_before_scan(self) -> None:
        invalid = [
            {"confirm_local": False, "project_path": str(self.repo)},
            {**self._valid(), "git_ref": "HEAD"},
            {"confirm_local": True, "project_path": str(self.root / "plain")},
        ]
        (self.root / "plain").mkdir()
        linked = self.root / "linked"
        linked.mkdir()
        (linked / ".git").symlink_to(self.repo / ".git", target_is_directory=True)
        invalid.append({"confirm_local": True, "project_path": str(linked)})
        for payload in invalid:
            with self.subTest(payload_keys=sorted(payload)):
                status, body = self._post(payload)
                self.assertEqual(status, 400)
                self.assertIn("error", body)

    def test_missing_binary_is_503(self) -> None:
        del os.environ["SNIPER_TRUFFLEHOG_BINARY"]
        status, body = self._post(self._valid())
        self.assertEqual(status, 503)
        self.assertEqual(body["error"], "TruffleHog Git geçmişi tarayıcısı kullanılamıyor veya meşgul.")

    def test_malformed_report_is_502(self) -> None:
        self._fake("malformed")
        status, body = self._post(self._valid())
        self.assertEqual(status, 502)
        self.assertEqual(body["error"], "TruffleHog Git geçmişi taraması başarısız oldu.")


if __name__ == "__main__":
    unittest.main()
