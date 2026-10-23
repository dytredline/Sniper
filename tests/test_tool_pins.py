import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import gitleaks_active
import semgrep_active
import tool_pins
import trufflehog_active
from tool_runtime_readiness import runtime_readiness_payload

_HEX = set("0123456789abcdef")


class ToolPinTableTests(unittest.TestCase):
    def test_every_builtin_digest_is_lowercase_sha256_with_provenance(self):
        for tool, pin in tool_pins.PINS.items():
            self.assertTrue(pin.source_url.startswith("https://"), tool)
            for arch, digests in pin.digests.items():
                self.assertIn(arch, {"aarch64", "x86_64"})
                for digest, provenance in digests.items():
                    self.assertEqual(len(digest), 64)
                    self.assertTrue(set(digest) <= _HEX)
                    self.assertTrue(provenance.strip())
        # Semgrep pip paketi: gömülü sabitleme yok, yalnız operatör.
        self.assertEqual(tool_pins.PINS["semgrep"].digests, {})

    def test_operator_env_pin_is_added_and_invalid_values_ignored(self):
        good = "a" * 64
        with mock.patch.dict(os.environ, {"SNIPER_SEMGREP_SHA256": f" {good} ,XYZ,{'b' * 63}"}):
            self.assertEqual(tool_pins.accepted_digests("semgrep"), {good: tool_pins.OPERATOR_PROVENANCE})
        with mock.patch.dict(os.environ, {"SNIPER_SEMGREP_SHA256": ""}):
            self.assertEqual(tool_pins.accepted_digests("semgrep"), {})

    def test_machine_aliases(self):
        for raw, expected in (("arm64", "aarch64"), ("AMD64", "x86_64"), ("aarch64", "aarch64")):
            with mock.patch("platform.machine", return_value=raw):
                self.assertEqual(tool_pins.machine(), expected)


class PinStatusAndRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home(), prefix="sniper_pins_")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.marker = self.root / "ran"
        self.tool = self.root / "tool"
        self.tool.write_text(f"#!/bin/sh\ntouch '{self.marker}'\nexit 0\n")
        self.tool.chmod(0o700)
        self.sha = hashlib.sha256(self.tool.read_bytes()).hexdigest()
        self.project = self.root / "project"
        self.project.mkdir()
        (self.project / "a.py").write_text("x = 1\n")
        self.data = self.root / "data"
        self.data.mkdir()

    def test_pin_status_states_without_paths(self):
        env = {"SNIPER_GITLEAKS_BINARY": str(self.tool), "SNIPER_GITLEAKS_SHA256": ""}
        with mock.patch.dict(os.environ, env), mock.patch.object(tool_pins, "machine", return_value="unknown"):
            self.assertEqual(tool_pins.pin_status("gitleaks")["state"], "unpinned")
        with mock.patch.dict(os.environ, env):
            self.assertEqual(tool_pins.pin_status("gitleaks")["state"], "mismatch")
        with mock.patch.dict(os.environ, {**env, "SNIPER_GITLEAKS_SHA256": self.sha}):
            status = tool_pins.pin_status("gitleaks")
            self.assertEqual(status["state"], "pinned")
            self.assertEqual(status["provenance"], tool_pins.OPERATOR_PROVENANCE)
        with mock.patch.dict(os.environ, {"SNIPER_GITLEAKS_BINARY": str(self.root / "yok")}):
            self.assertEqual(tool_pins.pin_status("gitleaks")["state"], "unavailable")
        self.assertNotIn(str(self.root), json.dumps(status))

    def test_unpinned_gitleaks_and_trufflehog_are_never_started(self):
        env = {"SNIPER_DATA_DIR": str(self.data), "SNIPER_GITLEAKS_BINARY": str(self.tool),
               "SNIPER_TRUFFLEHOG_BINARY": str(self.tool),
               "SNIPER_GITLEAKS_SHA256": "", "SNIPER_TRUFFLEHOG_SHA256": ""}
        with mock.patch.dict(os.environ, env):
            for runner in (gitleaks_active.run_local_gitleaks, trufflehog_active.run_local_trufflehog_filesystem):
                with self.subTest(runner=runner.__name__):
                    with self.assertRaisesRegex(RuntimeError, "uyuşmuyor"):
                        runner(str(self.project))
        self.assertFalse(self.marker.exists())

    def test_unpinned_semgrep_is_refused_and_never_started(self):
        rules = self.root / "rules.yaml"
        rules.write_text("rules:\n  - id: r.eval\n    languages: [python]\n    severity: ERROR\n"
                         "    message: m\n    pattern: eval(...)\n")
        env = {"SNIPER_DATA_DIR": str(self.data), "SNIPER_SEMGREP_BINARY": str(self.tool),
               "SNIPER_SEMGREP_RULES": str(rules), "SNIPER_SEMGREP_SHA256": "",
               "SNIPER_OPENGREP_BINARY": ""}
        # Varsayılan Opengrep kurulumu yok sayılır; yalnız sabitlenmemiş Semgrep kalır.
        with mock.patch.dict(os.environ, env), mock.patch("semgrep_active.configured_binary", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "sabitlenmiş SHA-256 yok"):
                semgrep_active.run_local_semgrep(str(self.project))
        self.assertFalse(self.marker.exists())

    def test_engine_selection_order(self):
        rules = str(semgrep_active.BUILTIN_OPENGREP_RULES)
        with mock.patch.dict(os.environ, {"SNIPER_OPENGREP_BINARY": "/x/og", "SNIPER_SEMGREP_BINARY": "/x/sg",
                                          "SNIPER_SEMGREP_SHA256": "a" * 64, "SNIPER_OPENGREP_RULES": ""}):
            self.assertEqual(semgrep_active.active_engine(), ("opengrep", "/x/og", rules))
        with mock.patch.dict(os.environ, {"SNIPER_OPENGREP_BINARY": "", "SNIPER_SEMGREP_BINARY": "/x/sg",
                                          "SNIPER_SEMGREP_SHA256": "a" * 64, "SNIPER_SEMGREP_RULES": "/x/r.yaml"}):
            self.assertEqual(semgrep_active.active_engine(), ("semgrep", "/x/sg", "/x/r.yaml"))
        with mock.patch.dict(os.environ, {"SNIPER_OPENGREP_BINARY": "", "SNIPER_SEMGREP_BINARY": "/x/sg",
                                          "SNIPER_SEMGREP_SHA256": "", "SNIPER_OPENGREP_RULES": ""}), \
                mock.patch("semgrep_active.configured_binary", return_value="/d/og"):
            self.assertEqual(semgrep_active.active_engine(), ("opengrep", "/d/og", rules))
        with mock.patch.dict(os.environ, {"SNIPER_OPENGREP_BINARY": "", "SNIPER_SEMGREP_BINARY": "",
                                          "SNIPER_SEMGREP_SHA256": ""}), \
                mock.patch("semgrep_active.configured_binary", return_value=None):
            self.assertEqual(semgrep_active.active_engine()[1], None)

    def test_readiness_reports_pin_state_without_paths(self):
        env = {"SNIPER_GITLEAKS_BINARY": str(self.tool), "SNIPER_GITLEAKS_SHA256": "",
               "SNIPER_TRUFFLEHOG_BINARY": str(self.tool), "SNIPER_TRUFFLEHOG_SHA256": self.sha}
        with mock.patch.dict(os.environ, env):
            payload = runtime_readiness_payload()
        pins = {pin["tool"]: pin for pin in payload["binary_pins"]}
        self.assertEqual(pins["gitleaks"]["state"], "mismatch")
        self.assertEqual(pins["trufflehog"]["state"], "pinned")
        gitleaks = next(t for t in payload["tools"] if t["id"] == "gitleaks")
        local = next(p for p in gitleaks["profiles"] if p["route"] == "/api/tool-runs/gitleaks")
        self.assertEqual((local["runtime"], local["reason_code"]), ("unavailable", "binary_digest_mismatch"))
        self.assertNotIn(str(self.root), json.dumps(payload))


if __name__ == "__main__":
    unittest.main()
