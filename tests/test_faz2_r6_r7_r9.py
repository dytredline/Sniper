from __future__ import annotations

import base64
import json
import urllib.request
import unittest

import dast_runtime
import dependency_security
import project_analyzer
import runtime_proof
import storage
import supply_chain_slsa_auditor


class Faz2R6R7R9Tests(unittest.TestCase):
    def test_r6_parse_extended_lockfile_inventory_all_six_formats(self) -> None:
        # 1. Bazel MODULE.bazel.lock
        bazel_raw = json.dumps({
            "lockFileVersion": 11,
            "moduleDepGraph": {
                "<root>": {"name": "", "version": ""},
                "rules_cc@0.0.9": {"name": "rules_cc", "version": "0.0.9"},
            },
            "registryFileHashes": {
                "https://bcr.bazel.build/modules/zlib/1.3.1/MODULE.bazel": "sha256-abc123",
            },
        })
        bazel_res = dependency_security.parse_extended_lockfile_inventory(
            bazel_raw, filename="MODULE.bazel.lock"
        )
        self.assertEqual(bazel_res["format"], "sniper-extended-lockfile-inventory/1")
        self.assertEqual(bazel_res["component_count"], 2)
        purls = {c["purl"] for c in bazel_res["components"]}
        self.assertIn("pkg:bazel/rules_cc@0.0.9", purls)
        self.assertIn("pkg:bazel/zlib@1.3.1", purls)

        # 2. Nix flake.lock
        nix_raw = json.dumps({
            "nodes": {
                "root": {"inputs": {"nixpkgs": "nixpkgs"}},
                "nixpkgs": {
                    "locked": {
                        "owner": "NixOS",
                        "repo": "nixpkgs",
                        "rev": "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678",
                        "type": "github",
                    }
                },
            }
        })
        nix_res = dependency_security.parse_extended_lockfile_inventory(nix_raw, filename="flake.lock")
        self.assertEqual(nix_res["component_count"], 1)
        self.assertEqual(nix_res["components"][0]["ecosystem"], "nix")
        self.assertEqual(
            nix_res["components"][0]["purl"],
            "pkg:nix/nixpkgs@a1b2c3d4e5f60718293a4b5c6d7e8f9012345678",
        )

        # 3. Conan conan.lock
        conan_raw = json.dumps({
            "version": "0.5",
            "requires": ["zlib/1.3.1#rev123", "openssl/3.2.0#rev456"],
            "build_requires": ["cmake/3.28.1#rev789"],
        })
        conan_res = dependency_security.parse_extended_lockfile_inventory(conan_raw, filename="conan.lock")
        self.assertEqual(conan_res["component_count"], 3)
        self.assertEqual(conan_res["components"][0]["purl"], "pkg:conan/zlib@1.3.1")

        # 4. vcpkg vcpkg.json
        vcpkg_raw = json.dumps({
            "name": "demo-app",
            "builtin-baseline": "2026.01.15",
            "dependencies": [
                {"name": "fmt", "version>=": "10.2.1"},
                {"name": "curl", "version": "8.6.0"},
            ],
        })
        vcpkg_res = dependency_security.parse_extended_lockfile_inventory(vcpkg_raw, filename="vcpkg.json")
        self.assertEqual(vcpkg_res["component_count"], 2)
        self.assertEqual(vcpkg_res["components"][0]["purl"], "pkg:vcpkg/fmt@10.2.1")

        # 5. Helm Chart.lock
        helm_raw = (
            "dependencies:\n"
            "- name: redis\n"
            "  repository: https://charts.bitnami.com/bitnami\n"
            "  version: 18.6.1\n"
            "- name: postgresql\n"
            "  repository: https://charts.bitnami.com/bitnami\n"
            "  version: 13.2.24\n"
        )
        helm_res = dependency_security.parse_extended_lockfile_inventory(helm_raw, filename="Chart.lock")
        self.assertEqual(helm_res["component_count"], 2)
        self.assertEqual(helm_res["components"][0]["purl"], "pkg:helm/redis@18.6.1")

        # 6. Go Workspace go.work.sum
        gowork_raw = (
            "golang.org/x/crypto v0.21.0 h1:abc123def456=\n"
            "golang.org/x/net v0.23.0/go.mod h1:xyz987=\n"
        )
        gowork_res = dependency_security.parse_extended_lockfile_inventory(gowork_raw, filename="go.work.sum")
        self.assertEqual(gowork_res["component_count"], 2)
        self.assertEqual(gowork_res["components"][0]["purl"], "pkg:golang/golang.org/x/crypto@v0.21.0")

        # Fail-closed on malformed or >4MB input
        with self.assertRaises(ValueError):
            dependency_security.parse_extended_lockfile_inventory("{not-json", filename="MODULE.bazel.lock")
        with self.assertRaises(ValueError):
            dependency_security.parse_extended_lockfile_inventory("x" * (4 * 1024 * 1024 + 10), filename="go.work.sum")

    def test_r6_verify_offline_workflow_and_sigstore_provenance(self) -> None:
        caller_wf = (
            "name: Release\n"
            "on: [push]\n"
            "jobs:\n"
            "  call-reusable:\n"
            "    uses: org/shared/.github/workflows/deploy.yml@v1\n"
            "    secrets: inherit\n"
        )
        mirror = {
            "org/shared/.github/workflows/deploy.yml@v1": (
                "name: Shared Deploy\n"
                "on: [workflow_call]\n"
                "permissions: write-all\n"
                "jobs:\n"
                "  run-deploy:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - uses: thirdparty/deploy-action@main\n"
            )
        }
        bad_bundle = {
            "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.2",
            "verificationMaterial": {"publicKey": {"hint": "k1"}},
            "messageSignature": {
                "messageDigest": {"algorithm": "SHA2_256", "digest": "aaaa" * 16},
                "signature": "c2lnbmF0dXJl",
            },
            "expected_sha256": "bbbb" * 16,
        }
        res = supply_chain_slsa_auditor.verify_offline_workflow_and_sigstore_provenance(
            caller_wf,
            mirror_workflows=mirror,
            sigstore_bundle=bad_bundle,
        )
        self.assertFalse(res["sigstore_verified"])
        control_ids = {f["control_id"] for f in res["findings"]}
        self.assertIn("SNIPER-SLSA-MIRROR-01", control_ids)
        self.assertIn("SNIPER-SLSA-COSIGN-02", control_ids)

        stmt_b64 = base64.b64encode(
            json.dumps({"subject": [{"name": "pkg.tar.gz", "digest": {"sha256": "abcd" * 16}}]}).encode("utf-8")
        ).decode("ascii")
        good_bundle = {
            "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.2",
            "verificationMaterial": {"x509CertificateChain": {"certificates": [{"rawBytes": "MIIB"}]}},
            "dsseEnvelope": {
                "payloadType": "application/vnd.in-toto+json",
                "payload": stmt_b64,
                "signatures": [{"sig": "MEUCIQD..."}],
            },
            "expected_sha256": "abcd" * 16,
        }
        good_res = supply_chain_slsa_auditor.verify_offline_workflow_and_sigstore_provenance(
            "name: Clean\non: [push]\n",
            sigstore_bundle=good_bundle,
        )
        self.assertTrue(good_res["sigstore_verified"])
        self.assertEqual(good_res["finding_count"], 0)

    def test_r7_loopback_redirect_and_dcr_canary_proof(self) -> None:
        self.assertGreaterEqual(len(dast_runtime._PROFILES), 5)

        def vulnerable_redirect_client(url: str) -> None:
            class _UnsafePostRedirectHandler(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    return urllib.request.Request(
                        newurl,
                        data=req.data,
                        headers=dict(req.header_items()),
                        method=req.get_method(),
                    )

            opener = urllib.request.build_opener(_UnsafePostRedirectHandler())
            req = urllib.request.Request(
                url,
                data=b"grant_type=client_credentials",
                headers={"Authorization": "Bearer super_secret_live_token_123"},
                method="POST",
            )
            with opener.open(req, timeout=2.0) as resp:
                resp.read()

        red_proof = dast_runtime.run_extended_loopback_canary_profile(
            vulnerable_redirect_client,
            scenario="redirect_auth_leak",
        )
        self.assertEqual(red_proof["status"], "RED")
        self.assertTrue(red_proof["canary_reached"])
        self.assertTrue(red_proof["auth_leaked"])
        self.assertTrue(red_proof["post_body_preserved"])
        self.assertTrue(
            any(tok.startswith("[REDACTED_TEST_TOKEN_SHA256:") for tok in red_proof["redacted_tokens"])
        )
        self.assertNotIn("super_secret_live_token_123", json.dumps(red_proof))

        def safe_url_blocker_client(url: str) -> None:
            if "127.0.0.1" in url or "localhost" in url:
                raise ValueError("UrlBlocker: loopback address blocked")

        green_proof = runtime_proof.run_loopback_redirect_and_dcr_canary_proof(
            safe_url_blocker_client,
            scenario="oauth_dcr_metadata_ssrf",
        )
        self.assertEqual(green_proof["status"], "GREEN")
        self.assertFalse(green_proof["canary_reached"])
        self.assertTrue(green_proof["blocked_by_guard"])

    def test_r9_incremental_scan_cone_cache_and_wal_pragmas(self) -> None:
        project_files = {
            "core/auth.py": "def check_token(t): return True\n",
            "api/orders.py": "import core.auth\ndef list_orders(): return core.auth.check_token('x')\n",
            "workers/billing_cron.py": "import api.orders\n",
            "ui/theme.py": "COLOR = 'blue'\n",
            "docs/helper.py": " VERSION = '1.0'\n",
        }
        cache = project_analyzer.IncrementalScanConeCache(project_files)
        cone_res = cache.compute_affected_cone({"core/auth.py"})
        self.assertEqual(
            cone_res["affected_files"],
            ["api/orders.py", "core/auth.py", "workers/billing_cron.py"],
        )
        self.assertEqual(
            cone_res["skipped_unchanged_files"],
            ["docs/helper.py", "ui/theme.py"],
        )
        self.assertGreater(cone_res["reduction_ratio"], 0.0)

        pragmas = storage.get_optimized_wal_pragmas()
        self.assertEqual(pragmas["journal_mode"], "WAL")
        self.assertEqual(pragmas["synchronous"], "NORMAL")
        self.assertGreaterEqual(pragmas["busy_timeout_ms"], 5000)


if __name__ == "__main__":
    unittest.main()
