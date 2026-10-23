from __future__ import annotations

import os
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import npm_audit_active
import taint_js_ast
import tool_pins
import tool_runtime_autodiscover
from verified_exec import VerificationError


NODE_22_23_2_SHA256 = "1a638b0fe2b68da0489276aca95526c5122fc61ba54d6a2d0d00c1c92ab7b876"
NODE_22_23_4_SHA256 = "7e48183361053f039294fbbc3ba586722fe756bf296d6cb8195356d10819cd16"
NODE_22_23_2 = Path.home() / ".local" / "opt" / "node-v22.23.2-linux-arm64" / "bin" / "node"
NODE_22_23_4 = Path.home() / ".local" / "opt" / "node-v22.23.4-linux-arm64" / "bin" / "node"


class NodeRuntimeSecurityPinTests(unittest.TestCase):
    def test_security_release_is_builtin_and_exact_previous_product_binary_is_revoked(self):
        pin = tool_pins.PINS["node"]
        self.assertEqual(pin.version, "22.23.4")
        self.assertEqual(pin.source_url, "https://nodejs.org/dist/v22.23.4/")
        self.assertEqual(pin.default_binary, NODE_22_23_4)
        self.assertIn(NODE_22_23_4_SHA256, pin.digests["aarch64"])
        self.assertIn(NODE_22_23_2_SHA256, pin.revoked_digests)

        # Ürünün önceki 22.23.2 dağıtımından kaydettiği bu tam ikili özeti ortam sabitlemesiyle geri alınamaz.
        with mock.patch.dict(os.environ, {"SNIPER_NODE_SHA256": NODE_22_23_2_SHA256}):
            accepted = tool_pins.accepted_digests("node")
        self.assertIn(NODE_22_23_4_SHA256, accepted)
        self.assertNotIn(NODE_22_23_2_SHA256, accepted)

    @unittest.skipUnless(NODE_22_23_2.is_file() and NODE_22_23_4.is_file(), "yerel Node geçiş ikilileri yok")
    def test_real_old_binary_is_revoked_and_verified_new_binary_runs(self):
        env = {"SNIPER_NODE_BINARY": "", "SNIPER_NODE_SHA256": NODE_22_23_2_SHA256}
        with mock.patch.dict(os.environ, env), mock.patch.object(tool_pins, "machine", return_value="aarch64"):
            current = tool_pins.pin_status("node", str(NODE_22_23_4))
            previous = tool_pins.pin_status("node", str(NODE_22_23_2))
            self.assertEqual((current["state"], current["reason_code"]), ("pinned", "digest_matches_pin"))
            self.assertEqual((previous["state"], previous["reason_code"]), ("mismatch", "binary_digest_revoked"))
            with self.assertRaisesRegex(VerificationError, "uyuşmuyor"):
                tool_pins.open_pinned("node", str(NODE_22_23_2))
            with tool_pins.open_pinned("node", str(NODE_22_23_4)) as runtime:
                result = subprocess.run(
                    [runtime.argv0, "--version"],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=10,
                    **runtime.popen_kwargs(env={"PATH": "/usr/bin:/bin"}),
                )
        self.assertEqual(result.stdout.strip(), "v22.23.4")

    @unittest.skipUnless(NODE_22_23_2.is_file() and NODE_22_23_4.is_file(), "yerel Node geçiş ikilileri yok")
    def test_autodiscovery_skips_revoked_dropin_candidate(self):
        selected, digest = tool_runtime_autodiscover._first_valid_unrevoked_executable(
            [NODE_22_23_2, NODE_22_23_4], tool_pins.PINS["node"].revoked_digests
        )
        self.assertEqual(selected, NODE_22_23_4)
        self.assertEqual(digest, NODE_22_23_4_SHA256)

    def test_operator_pinned_alternate_build_still_obeys_22_security_floor_and_major(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temp:
            binary = Path(temp) / "node"

            def write_version(version: str) -> str:
                binary.write_text(f"#!/bin/sh\nprintf '%s\\n' 'v{version}'\n", encoding="utf-8")
                binary.chmod(0o700)
                return hashlib.sha256(binary.read_bytes()).hexdigest()

            for version in ("22.23.2", "24.22.1"):
                with self.subTest(version=version):
                    digest = write_version(version)
                    with mock.patch.dict(os.environ, {"SNIPER_NODE_SHA256": digest}):
                        with self.assertRaises(VerificationError) as raised:
                            tool_pins.open_pinned("node", str(binary))
                    self.assertEqual(raised.exception.reason, "binary_version_unsupported")

            digest = write_version("22.23.4")
            with mock.patch.dict(os.environ, {"SNIPER_NODE_SHA256": digest}):
                with tool_pins.open_pinned("node", str(binary)) as verified:
                    self.assertEqual(verified.sha256, digest)

    def test_taint_execution_path_cannot_bypass_version_gate(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temp:
            root = Path(temp)
            node = root / "node"
            node.write_text("#!/bin/sh\nprintf '%s\\n' 'v22.23.2'\n", encoding="utf-8")
            node.chmod(0o700)
            node_sha = hashlib.sha256(node.read_bytes()).hexdigest()
            with mock.patch.dict(os.environ, {
                "SNIPER_NODE_BINARY": str(node), "SNIPER_NODE_SHA256": node_sha,
            }):
                with self.assertRaises(taint_js_ast.JsParserUnavailable):
                    taint_js_ast.NodeParser()

    def test_npm_execution_path_cannot_bypass_version_gate(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temp:
            root = Path(temp)
            node = root / "node"
            node.write_text("#!/bin/sh\nprintf '%s\\n' 'v22.23.2'\n", encoding="utf-8")
            node.chmod(0o700)
            node_sha = hashlib.sha256(node.read_bytes()).hexdigest()
            npm = root / "npm-cli.js"
            npm.write_text("module.exports = {};\n", encoding="utf-8")
            npm_sha = hashlib.sha256(npm.read_bytes()).hexdigest()
            data = root / "data"
            data.mkdir()
            project = root / "project"
            project.mkdir()
            (project / "package-lock.json").write_text(
                '{"name":"p","version":"1.0.0","lockfileVersion":3,'
                '"packages":{"":{"name":"p","version":"1.0.0","dependencies":{"x":"1.0.0"}},'
                '"node_modules/x":{"version":"1.0.0","resolved":"https://registry.npmjs.org/x/-/x-1.0.0.tgz"}}}',
                encoding="utf-8",
            )
            env = {
                "SNIPER_NODE_BINARY": str(node),
                "SNIPER_NODE_SHA256": node_sha,
                "SNIPER_NPM_CLI": str(npm),
                "SNIPER_NPM_CLI_SHA256": npm_sha,
                "SNIPER_DATA_DIR": str(data),
            }
            with mock.patch.dict(os.environ, env), \
                    mock.patch.object(npm_audit_active, "run_in_process_group", side_effect=AssertionError("npm başlatıldı")):
                with self.assertRaises(npm_audit_active.NpmAuditUnavailable):
                    npm_audit_active.run_local_npm_audit_local(str(project))


if __name__ == "__main__":
    unittest.main()
