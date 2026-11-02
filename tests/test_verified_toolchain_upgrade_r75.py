import json
import unittest
from pathlib import Path

import tool_pins
import tool_runtime_autodiscover
import trivy_config_active
import trivy_terraform_active
from tool_runtime_autodiscover import portable_bundle_manifest


ROOT = Path(__file__).resolve().parents[1]


class VerifiedToolchainUpgradeContractTests(unittest.TestCase):
    def test_locked_release_versions_match_the_verified_upgrade_set(self):
        lock = json.loads((ROOT / "COMMUNITY-TOOLS.lock.json").read_text(encoding="utf-8"))
        versions = {name: spec["version"] for name, spec in lock["tools"].items()}
        self.assertEqual(versions["trivy"], "0.76.1")
        self.assertEqual(versions["trufflehog"], "3.99.7")
        self.assertEqual(versions["gitleaks"], "8.30.1")
        self.assertEqual(versions["nuclei"], "3.11.1")
        self.assertEqual(versions["syft"], "1.55.0")
        self.assertEqual(versions["grype"], "0.121.0")

    def test_runtime_pins_reject_superseded_trufflehog_release(self):
        pin = tool_pins.PINS["trufflehog"]
        self.assertEqual(pin.version, "3.99.7")
        self.assertIn("/v3.99.7", pin.source_url)
        self.assertIn(
            "4cdfed417cc07a7cd3b08036ce07c87f26e8db21b82b5c7b90005f06da380a93",
            pin.revoked_digests,
        )
        self.assertIn("c51ee8bd6082eaccfd9cb5ff10d3fe1fc883332a0bb312868aeaff4d988c4493", pin.revoked_digests)
        self.assertIn("b00f2a9f2ff4263160289b144cde0d7a5d96568ea085e55b268d01e82a1dd6f5", pin.digests["aarch64"])

    def test_portable_manifest_advertises_only_the_upgraded_runtime_paths(self):
        components = {item["id"]: item for item in portable_bundle_manifest()["components"]}
        self.assertIn("Trivy 0.76.1", components["trivy"]["name"])
        self.assertIn("runtimes/trivy-0.76.1/trivy", components["trivy"]["bundle_relpath"])
        self.assertIn("TruffleHog 3.99.7", components["trufflehog"]["name"])
        self.assertIn(
            "runtimes/trufflehog-3.99.7/trufflehog",
            components["trufflehog"]["bundle_relpath"],
        )

    def test_hardened_same_release_rebuilds_are_accepted_by_runtime_pins(self):
        expected = {
            "gitleaks": "d26b4da0d011da43fa7e22e309841faad203e0d9869a1127d3a65886a5072166",
            "syft": "a25bda7a97403add93e9a384f70554b212a112e2e66c0989bbc4c35e8c8a319e",
            "grype": "c8dc5f64e3d2c163aa2f4103ee08292cd6addd84f6994dfcd4e5018c68483069",
            "trufflehog": "b00f2a9f2ff4263160289b144cde0d7a5d96568ea085e55b268d01e82a1dd6f5",
        }
        for tool, digest in expected.items():
            with self.subTest(tool=tool):
                self.assertIn(digest, tool_pins.PINS[tool].digests["aarch64"])

    def test_all_trivy_entrypoints_default_to_the_verified_rebuild(self):
        expected = "67ebe2978898505e4cf48ec0c3280907d933e206c290aeeef7a3be0f8d269d84"
        self.assertEqual(trivy_config_active.EXPECTED_TRIVY_SHA256, expected)
        self.assertEqual(trivy_terraform_active.EXPECTED_TRIVY_SHA256, expected)

    def test_verified_toolchain_provenance_is_machine_readable_and_complete(self):
        manifest = json.loads((ROOT / "VERIFIED-TOOLCHAIN.lock.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["schema"], "vulkill-verified-toolchain-v1")
        self.assertEqual(manifest["go"]["version"], "1.27.3")
        self.assertEqual(manifest["security_modules"]["golang.org/x/net"], "v0.62.0")
        self.assertEqual(manifest["security_modules"]["google.golang.org/grpc"], "v1.83.2")
        self.assertEqual(
            set(manifest["tools"]),
            {"trivy", "trufflehog", "gitleaks", "nuclei", "syft", "grype"},
        )
        for tool, record in manifest["tools"].items():
            with self.subTest(tool=tool):
                self.assertRegex(record["binary_sha256"], r"\A[0-9a-f]{64}\Z")
                self.assertEqual(record["go_version"], "go1.27.3")

    def test_residual_advisories_are_explicitly_no_fix_and_not_overclaimed(self):
        manifest = json.loads((ROOT / "VERIFIED-TOOLCHAIN.lock.json").read_text(encoding="utf-8"))
        audit = manifest["sca_audit"]
        self.assertFalse(audit["claims_reachability"])
        self.assertTrue(audit["residual_advisories"])
        for item in audit["residual_advisories"]:
            with self.subTest(advisory=item["id"]):
                self.assertEqual(item["fix_state"], "no_fix_in_database_snapshot")

    def test_autodiscovery_allowlist_uses_only_verified_rebuild_digests(self):
        digests = tool_runtime_autodiscover._verified_toolchain_digests(ROOT, "linux-aarch64")
        self.assertEqual(set(digests), {"trivy", "trufflehog", "gitleaks", "nuclei", "syft", "grype"})
        self.assertEqual(
            digests["nuclei"],
            "06382e2a3e9a849380be98773c9dcdb05772c44185e9e60548a9f002184ef6c1",
        )
        self.assertEqual(tool_runtime_autodiscover._verified_toolchain_digests(ROOT, "linux-x86_64"), {})


if __name__ == "__main__":
    unittest.main()
