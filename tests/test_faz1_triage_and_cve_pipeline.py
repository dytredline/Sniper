"""Faz 1.5 (Precision Triage, Shared-State Attack Graph, Keypair Noise Filter, Protocol Reachability)
ve Faz 1.6 (CVE & Bug Bounty Submission Pipeline) birim testleri.
"""

from __future__ import annotations

from ai_triage import classify_finding_evidence_tier
from attack_path_correlator import build_shared_state_attack_graph
from cve_submission_pipeline import (
    build_ghsa_and_hackerone_submission_payloads,
    check_upstream_advisory_and_incomplete_fix,
    validate_fail_closed_red_green_bundle,
)
from dependency_reachability import verify_protocol_and_hook_reachability
from secret_intelligence_auditor import audit_default_keypairs_and_filter_noise


def test_classify_finding_evidence_tier_4_levels() -> None:
    static_res = classify_finding_evidence_tier({"confidence": 0.94, "cwe": "CWE-79"})
    assert static_res["evidence_tier"] == "STATIC_CANDIDATE"
    assert static_res["effective_confidence"] == 0.78
    assert static_res["auto_promote_allowed"] is False

    parity_res = classify_finding_evidence_tier(
        {"confidence": 0.94, "control_id": "SNIPER-PARITY-SIBLING-01"}
    )
    assert parity_res["evidence_tier"] == "VERIFIED_SOURCE_PARITY"
    assert parity_res["effective_confidence"] == 0.90
    assert parity_res["auto_promote_allowed"] is True

    runtime_res = classify_finding_evidence_tier(
        {"confidence": 0.98, "asan_reproduced": True}
    )
    assert runtime_res["evidence_tier"] == "VERIFIED_COMPONENT_RUNTIME"
    assert runtime_res["effective_confidence"] == 0.95
    assert runtime_res["auto_promote_allowed"] is True

    e2e_res = classify_finding_evidence_tier(
        {"confidence": 0.99, "runtime_proof": {"reproduced": True}}
    )
    assert e2e_res["evidence_tier"] == "VERIFIED_PRODUCT_E2E_RED_GREEN"
    assert e2e_res["effective_confidence"] == 0.99
    assert e2e_res["auto_promote_allowed"] is True


def test_build_shared_state_attack_graph_eliminates_combinatorial_explosion() -> None:
    findings = [
        {
            "stage": "entry",
            "cwe": "CWE-601",
            "title": "OAuth redirect_uri validation bypass in :gitlab provider",
            "file": "app/controllers/oauth_controller.rb",
            "line": 42,
        },
        {
            "stage": "impact",
            "cwe": "CWE-287",
            "title": "MCP token exchange hijack via redirect_uri and oauth state",
            "file": "ee/app/services/mcp/token_service.rb",
            "line": 88,
        },
        {
            "stage": "impact",
            "cwe": "CWE-89",
            "title": "Unrelated SQL injection in legacy billing archive",
            "file": "legacy/billing/archive_query.rb",
            "line": 15,
        },
    ]
    graph = build_shared_state_attack_graph(findings, max_chains=10)
    assert graph["format"] == "sniper-shared-state-attack-graph/1"
    assert graph["chain_count"] == 1
    chain = graph["chains"][0]
    assert "oauth" in chain["shared_state_artifacts"]
    assert "redirect_uri" in chain["shared_state_artifacts"]


def test_audit_default_keypairs_and_filter_noise() -> None:
    i18n_res = audit_default_keypairs_and_filter_noise(
        '{"reset_password": "Change your password"}',
        filename="src/i18n/locales/en.json",
    )
    assert i18n_res["finding_count"] == 0
    assert i18n_res["suppressed_noise_count"] >= 1

    java_code = '''
    public class ServerCertificateService {
        private static final String API_KEY = "API_KEY";
        private static final String TEMPLATE = "reset_password.html";
        private static final String KEYSTORE = "ca-keystore.p12";
        private static final String DEFAULT_PASS = "changeit";
    }
    '''
    res = audit_default_keypairs_and_filter_noise(
        java_code,
        filename="ServerCertificateService.java",
    )
    assert res["format"] == "sniper-secret-keypair-precision/1"
    assert res["suppressed_noise_count"] == 2
    assert res["finding_count"] == 1
    assert res["findings"][0]["control_id"] == "SNIPER-SEC-KEYPAIR-01"
    assert res["findings"][0]["cwe"] == "CWE-798"


def test_verify_protocol_and_hook_reachability() -> None:
    go_code = '''
    package main
    import ("crypto/tls"; "net/http")
    func client() {
        cfg := &tls.Config{NextProtos: []string{"http/1.1"}}
        _ = cfg
    }
    '''
    go_res = verify_protocol_and_hook_reachability(
        go_code,
        advisory_id="CVE-2026-39883",
        go_stdlib_version="1.23.6",
    )
    assert go_res["reachable"] is False
    assert go_res["reason"] == "go_http2_alpn_disabled_or_outbound_only"

    rails_code = '''
    Warden::Manager.after_set_user do |user, auth, opts|
      SessionExpireFromInitEnforcer.new(user).enforce!
      throw :warden, :timeout
    end
    # Handled by DeviseFailure
    '''
    rails_res = verify_protocol_and_hook_reachability(
        rails_code,
        framework="rails_devise",
    )
    assert rails_res["reachable"] is True
    assert rails_res["reason"] == "rails_warden_timeout_hook_reaches_devise_failure"


def test_cve_submission_pipeline_advisory_bundle_and_payloads() -> None:
    advisories = [
        {
            "cve_id": "CVE-2026-71270",
            "cwe": "CWE-918",
            "patched_files": ["FileToPdf.java", "ConvertHtmlToPDF.java"],
        }
    ]
    inc_res = check_upstream_advisory_and_incomplete_fix(
        {"file": "ConvertWebsiteToPDF.java", "cwe": "CWE-918"},
        advisories,
    )
    assert inc_res["status"] == "INCOMPLETE_UPSTREAM_FIX"
    assert inc_res["submittable"] is True
    assert inc_res["upstream_cve"] == "CVE-2026-71270"
    assert inc_res["unpatched_file"] == "ConvertWebsiteToPDF.java"

    dup_res = check_upstream_advisory_and_incomplete_fix(
        {"file": "FileToPdf.java", "cwe": "CWE-918"},
        advisories,
    )
    assert dup_res["status"] == "DUPLICATE_UPSTREAM_ADVISORY"
    assert dup_res["submittable"] is False

    valid_bundle = {
        "head_commit": "a" * 40,
        "git_status_clean": True,
        "red_exit_code": 1,
        "green_exit_code": 0,
        "single_patch_only": True,
        "stdout": "Token verified: [REDACTED_TEST_TOKEN_SHA256:9f86d081884c]",
    }
    assert validate_fail_closed_red_green_bundle(valid_bundle)["valid"] is True

    leaked_bundle = dict(valid_bundle, stdout="Leaked glpat-1234567890abcdef")
    leaked_check = validate_fail_closed_red_green_bundle(leaked_bundle)
    assert leaked_check["valid"] is False
    assert "unredacted_secret_token_in_stdout" in leaked_check["errors"]

    payloads = build_ghsa_and_hackerone_submission_payloads(
        [
            {
                "id": "FINDING-1",
                "cwe": "CWE-918",
                "title": "SSRF in ConvertWebsiteToPDF",
                "package": "stirling-pdf",
                "ecosystem": "maven",
                "severity": "high",
                "file": "ConvertWebsiteToPDF.java",
            },
            {
                "id": "FINDING-2",
                "cwe": "CWE-798",
                "title": "Default PKCS#12 Keystore Password",
                "package": "stirling-pdf",
                "ecosystem": "maven",
                "severity": "medium",
                "file": "ServerCertificateService.java",
            },
        ],
        program_handle="gitlab",
        structured_scope_id="55897",
    )
    assert len(payloads["ghsa_payloads"]) == 2
    assert len(payloads["ghsa_payloads"][0]["vulnerabilities"]) == 1
    assert len(payloads["hackerone_payloads"]) == 2
    h1_first = payloads["hackerone_payloads"][0]
    assert h1_first["endpoint"] == "/v1/hackers/reports"
    assert h1_first["structured_scope_id"] == "55897"
    assert h1_first["weakness_id"] == "68"
    assert "FINDING-2" in h1_first["cross_references"]


import unittest


class TestFaz1TriageAndCvePipeline(unittest.TestCase):
    def test_1_evidence_tiers(self) -> None:
        test_classify_finding_evidence_tier_4_levels()

    def test_2_shared_state_attack_graph(self) -> None:
        test_build_shared_state_attack_graph_eliminates_combinatorial_explosion()

    def test_3_default_keypairs_and_noise(self) -> None:
        test_audit_default_keypairs_and_filter_noise()

    def test_4_protocol_and_hook_reachability(self) -> None:
        test_verify_protocol_and_hook_reachability()

    def test_5_cve_submission_pipeline(self) -> None:
        test_cve_submission_pipeline_advisory_bundle_and_payloads()


if __name__ == "__main__":
    unittest.main()

