"""Wave 3 — Bug Bounty & CVE Operation Engines (İş Paketi 3) birim testleri."""

from __future__ import annotations

import base64
import datetime as dt
import json
from pathlib import Path
import sys
import unittest

APP_DIR = Path(__file__).resolve().parents[1]
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

import authz_jvm_dotnet
import cli_reports
import container_scan
import cve_submission_pipeline
import fuzz_runtime
import incremental_scan_plan
import runtime_service_trace
import silent_patch_blame_auditor


class TestWave3DepthAndBountyEngines(unittest.TestCase):
    def test_submission_cooldown_and_status_queue_sorting(self) -> None:
        submissions = [
            {
                "id": "H1-SUB-1",
                "platform": "hackerone",
                "status": "submitted",
                "submitted_at": "2026-10-25T04:30:00Z",
                "priority_rank": 1,
                "severity": "critical",
            },
            {
                "id": "H1-SUB-2",
                "platform": "hackerone",
                "status": "triaged",
                "submitted_at": "2026-10-26T04:30:00Z",
                "priority_rank": 2,
                "severity": "high",
            },
            {
                "id": "H1-QUEUE-LOW",
                "platform": "hackerone",
                "status": "queued_cooldown",
                "priority_rank": 5,
                "severity": "medium",
                "title": "Minor header disclosure",
            },
            {
                "id": "H1-QUEUE-IDOR",
                "platform": "hackerone",
                "status": "queued_cooldown",
                "priority_rank": 3,
                "severity": "critical",
                "title": "Multi-org IDOR in organization GraphQL resolver",
                "cwe": "CWE-862",
            },
            {
                "id": "GHSA-QUEUE-1",
                "platform": "ghsa",
                "status": "queued_cooldown",
                "priority_rank": 4,
                "severity": "high",
                "title": "Symlink traversal in archive extractor",
            },
        ]

        res = cve_submission_pipeline.evaluate_submission_cooldown_and_status(
            submissions,
            now_iso="2026-10-27T04:30:00Z",
            trial_limit_per_window=2,
            cooldown_hours=96,
        )

        self.assertEqual(res["format"], "sniper-submission-queue-status/1")
        self.assertEqual(res["active_window_used"], 2)
        self.assertEqual(res["trial_limit_per_window"], 2)
        self.assertEqual(res["submitted_count"], 2)
        # Earliest active submission (2026-10-25T04:30:00Z) + 96h = 2026-10-29T04:30:00Z
        self.assertEqual(res["next_available_slot_iso"], "2026-10-29T04:30:00Z")
        # GHSA is ready immediately because HackerOne trial cooldown does not block GHSA
        self.assertEqual([item["id"] for item in res["ready_to_submit_now"]], ["GHSA-QUEUE-1"])
        # Remaining H1 queue is sorted with critical multi-org IDOR first
        self.assertEqual(
            [item["id"] for item in res["queued_for_cooldown"]],
            ["H1-QUEUE-IDOR", "H1-QUEUE-LOW"],
        )

    def test_synthesize_standalone_reproducer_script_redacts_tokens(self) -> None:
        finding = {
            "id": "SNIPER-RUBY-SSRF-01",
            "file": "app/services/import_url_service.rb",
            "cwe": "CWE-918",
            "description": "Authenticated request using glpat-SecretToken123456 reaches internal metadata",
        }
        bundle = cve_submission_pipeline.synthesize_standalone_reproducer_script(finding)
        self.assertEqual(bundle["format"], "sniper-standalone-reproducer/1")
        self.assertEqual(bundle["finding_id"], "SNIPER-RUBY-SSRF-01")
        self.assertEqual(bundle["language"], "ruby")
        self.assertEqual(bundle["script_filename"], "reproduce.sh")
        self.assertIn("[REDACTED_TEST_TOKEN_SHA256:", bundle["script_content"])
        self.assertNotIn("glpat-SecretToken123456", bundle["script_content"])
        self.assertEqual(len(bundle["script_sha256"]), 64)

    def test_silent_patch_blame_auditor_detects_silent_guards_and_excludes_explicit_cve(self) -> None:
        commits = [
            {
                "commit": "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4",
                "author_date": "2026-10-20T10:00:00Z",
                "message": "Refactor webhook HTTP client helper options",
                "file": "app/services/webhook_caller.rb",
                "diff": (
                    "--- a/app/services/webhook_caller.rb\n"
                    "+++ b/app/services/webhook_caller.rb\n"
                    "@@ -12,2 +12,3 @@\n"
                    "+  Gitlab::HTTP_V2::UrlBlocker.validate!(target_url)\n"
                ),
            },
            {
                "commit": "b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5",
                "author_date": "2026-10-21T12:00:00Z",
                "message": "Fix CVE-2026-99999 security vulnerability in path loader",
                "file": "pkg/archive/extract.go",
                "diff": (
                    "--- a/pkg/archive/extract.go\n"
                    "+++ b/pkg/archive/extract.go\n"
                    "@@ -40,1 +40,2 @@\n"
                    "+  rel, err := filepath.Rel(baseDir, targetPath)\n"
                ),
            },
            {
                "commit": "c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f6",
                "author_date": "2026-10-22T15:30:00Z",
                "message": "Cleanup TLS transport configuration defaults",
                "file": "internal/transport/tls.go",
                "diff": (
                    "--- a/internal/transport/tls.go\n"
                    "+++ b/internal/transport/tls.go\n"
                    "@@ -18,2 +18,1 @@\n"
                    "-  InsecureSkipVerify: true,\n"
                ),
            },
        ]
        blame_map = {
            "app/services/webhook_caller.rb": {
                "introduced_in_commit": "00112233445566778899aabbccddeeff00112233",
            },
            "internal/transport/tls.go": {
                "18": "ffeeddccbbaa99887766554433221100ffeeddcc",
            },
        }

        audit_res = silent_patch_blame_auditor.audit_silent_security_patches_and_blame(
            commits,
            file_blame_map=blame_map,
        )
        self.assertEqual(audit_res["format"], "sniper-silent-patch-blame-audit/1")
        self.assertEqual(audit_res["scanned_commit_count"], 3)
        self.assertEqual(audit_res["silent_fix_count"], 2)

        f0, f1 = audit_res["findings"]
        self.assertEqual(f0["rule_id"], "SNIPER-SILENT-PATCH-01")
        self.assertEqual(f0["cwe"], "CWE-918")
        self.assertEqual(f0["matched_guard"], "UrlBlocker")
        self.assertEqual(f0["introduced_in_commit"], "00112233445566778899aabbccddeeff00112233")
        self.assertEqual(f0["fixed_in_commit"], "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4")

        self.assertEqual(f1["cwe"], "CWE-295")
        self.assertEqual(f1["introduced_in_commit"], "ffeeddccbbaa99887766554433221100ffeeddcc")

    def test_cli_reports_exporters(self) -> None:
        report = {
            "submissions": [
                {
                    "id": "SUB-101",
                    "platform": "hackerone",
                    "status": "queued_cooldown",
                    "severity": "critical",
                    "priority_rank": 1,
                }
            ],
            "commits": [
                {
                    "commit": "1111222233334444555566667777888899990000",
                    "author_date": "2026-10-24T09:00:00Z",
                    "message": "Update organization lookup filter",
                    "file": "app/finders/group_finder.rb",
                    "diff": "+ scope.in_organization(current_organization)\n",
                }
            ],
        }
        queue_json = json.loads(cli_reports.export_submission_queue_status_json(report))
        self.assertEqual(queue_json["format"], "sniper-submission-queue-status/1")
        self.assertEqual(len(queue_json["ready_to_submit_now"]), 1)

        blame_json = json.loads(cli_reports.export_silent_patches_blame_json(report))
        self.assertEqual(blame_json["format"], "sniper-silent-patch-blame-audit/1")
        self.assertEqual(blame_json["silent_fix_count"], 1)
        self.assertEqual(blame_json["findings"][0]["cwe"], "CWE-862")

    def test_builtin_deterministic_fuzzer_reproduces_crash_and_passes_safe(self) -> None:
        crashing_py = (
            "def parse_packet(raw: str) -> int:\n"
            "    if raw.startswith('MAGIC:') or '../../' in raw:\n"
            "        raise ValueError('unhandled traversal trigger')\n"
            "    return len(raw)\n"
        )
        crash_res = fuzz_runtime.execute_builtin_deterministic_fuzzer(
            crashing_py,
            target_symbol="parse_packet",
            language="python",
            max_runs=32,
            seed=1337,
        )
        self.assertEqual(crash_res["format"], "sniper-builtin-deterministic-fuzz-proof/1")
        self.assertTrue(crash_res["crash_reproduced"])
        self.assertEqual(crash_res["status"], "crash_reproduced")
        self.assertEqual(crash_res["exception_type"], "ValueError")
        self.assertEqual(len(crash_res["crashing_input_sha256"]), 64)

        safe_py = (
            "def parse_safe(raw: str) -> int:\n"
            "    return len(str(raw or ''))\n"
        )
        safe_res = fuzz_runtime.execute_builtin_deterministic_fuzzer(
            safe_py,
            target_symbol="parse_safe",
            language="python",
            max_runs=24,
            seed=1337,
        )
        self.assertFalse(safe_res["crash_reproduced"])
        self.assertEqual(safe_res["status"], "completed_no_crash")
        self.assertEqual(safe_res["runs_executed"], 24)

    def test_signed_trace_manifest_and_freshness_verification(self) -> None:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        priv = Ed25519PrivateKey.generate()
        pub_pem = priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        manifest_body = {
            "format": "sniper-runtime-trace-manifest/1",
            "captured_at": "2026-10-27T04:00:00Z",
            "observations": [{"source": "api", "target": "billing"}],
        }
        canonical_bytes = json.dumps(
            manifest_body, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        sig_b64 = base64.b64encode(priv.sign(canonical_bytes)).decode("ascii")
        signed_manifest = dict(manifest_body, signature_b64=sig_b64)

        ok = runtime_service_trace.verify_signed_trace_manifest_and_freshness(
            signed_manifest,
            public_key_pem=pub_pem,
            max_age_seconds=3600,
            reference_time_iso="2026-10-27T04:30:00Z",
        )
        self.assertEqual(ok["format"], "sniper-signed-trace-manifest-verification/1")
        self.assertTrue(ok["valid"])
        self.assertEqual(ok["freshness_status"], "fresh")
        self.assertEqual(ok["signature_status"], "verified")

        expired = runtime_service_trace.verify_signed_trace_manifest_and_freshness(
            signed_manifest,
            public_key_pem=pub_pem,
            max_age_seconds=600,
            reference_time_iso="2026-10-27T04:30:00Z",
        )
        self.assertFalse(expired["valid"])
        self.assertEqual(expired["freshness_status"], "expired")

    def test_di_interface_resolution_and_incremental_cone_expansion(self) -> None:
        files_map = {
            "src/controllers/InvoiceController.java": (
                "@RestController\n"
                "public class InvoiceController {\n"
                "    private final InvoiceService invoiceService;\n"
                "    @GetMapping(\"/invoices/{id}\")\n"
                "    public Invoice getInvoice(String id) {\n"
                "        return this.invoiceService.loadInvoice(id);\n"
                "    }\n"
                "}\n"
            ),
            "src/services/InvoiceService.java": (
                "public interface InvoiceService {\n"
                "    Invoice loadInvoice(String id);\n"
                "}\n"
            ),
            "src/services/impl/InvoiceServiceImpl.java": (
                "public class InvoiceServiceImpl implements InvoiceService {\n"
                "    public Invoice loadInvoice(String id) {\n"
                "        return invoiceRepo.findById(id);\n"
                "    }\n"
                "}\n"
            ),
            "src/utils/UnrelatedHelper.java": "public class UnrelatedHelper {}\n",
        }
        di_res = authz_jvm_dotnet.resolve_di_interface_implementations(files_map)
        self.assertEqual(di_res["format"], "sniper-di-authz-resolution/1")
        self.assertGreaterEqual(di_res["finding_count"], 1)
        self.assertEqual(di_res["findings"][0]["id"], "SNIPER-AUTHZ-DI-IDOR-01")
        self.assertEqual(di_res["findings"][0]["implementation"], "InvoiceServiceImpl")

        cone_res = incremental_scan_plan.expand_cone_with_di_bindings(
            files_map,
            ["src/services/impl/InvoiceServiceImpl.java"],
        )
        self.assertEqual(cone_res["format"], "sniper-incremental-di-cone/1")
        self.assertIn("src/controllers/InvoiceController.java", cone_res["affected_files"])
        self.assertIn("src/utils/UnrelatedHelper.java", cone_res["skipped_unchanged_files"])

    def test_fulcio_x509_oidc_extension_verifier(self) -> None:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID, ObjectIdentifier

        key = ec.generate_private_key(ec.SECP256R1())
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sigstore-fulcio")])
        now = dt.datetime.now(dt.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(hours=1))
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.UniformResourceIdentifier("https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1.0")]
                ),
                critical=False,
            )
            .add_extension(
                x509.UnrecognizedExtension(
                    ObjectIdentifier("1.3.6.1.4.1.57264.1.8"),
                    b"\x0c\x2bhttps://token.actions.githubusercontent.com",
                ),
                critical=False,
            )
            .add_extension(
                x509.UnrecognizedExtension(
                    ObjectIdentifier("1.3.6.1.4.1.57264.1.12"),
                    b"\x0c\x1bhttps://github.com/org/repo",
                ),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

        ok = container_scan.verify_fulcio_x509_oidc_extensions(
            pem,
            expected_issuer="https://token.actions.githubusercontent.com",
            expected_signer_uri="https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1.0",
            expected_source_repo_uri="https://github.com/org/repo",
        )
        self.assertEqual(ok["format"], "sniper-fulcio-x509-oidc-verification/1")
        self.assertTrue(ok["verified"])
        self.assertEqual(ok["mismatches"], [])

        bad = container_scan.verify_fulcio_x509_oidc_extensions(
            pem,
            expected_issuer="https://accounts.google.com",
            expected_signer_uri="https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1.0",
        )
        self.assertFalse(bad["verified"])
        self.assertIn("issuer", bad["mismatches"])


if __name__ == "__main__":
    unittest.main()
