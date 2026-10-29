"""Wave 6 — Uçtan Uca Bug Bounty ve CVE Gönderim Hazırlık Kokpiti (Bounty Readiness Cockpit).

Statik + sembolik erişilebilirlik (Z3 SAT/UNSAT), upstream CVE/GHSA tekilliği,
sessiz git yama geçmişi (silent patch), loopback çalışma zamanı kanıtları (Repeater/Autorize/Race)
ve Red/Green gizli anahtar hijyenini 5 kapılı deterministik bir triyaj hattında birleştirir.
"""

from __future__ import annotations

import re
from typing import Any

import cve_submission_pipeline
import silent_patch_blame_auditor

FORMAT = "sniper-bounty-readiness-cockpit/1"

_CWE_RE = re.compile(r"^CWE-\d+$", re.IGNORECASE)
_CVSS_VECTOR_RE = re.compile(r"^CVSS:(?:3\.[01]|4\.0)/", re.IGNORECASE)
_RAW_SECRET_RE = re.compile(
    r"(?:glpat-[A-Za-z0-9_\-]{6,}|ghp_[A-Za-z0-9]{6,}|AKIA[0-9A-Z]{8,}|sk-[A-Za-z0-9]{12,})"
)

_DEFAULT_CVSS_BY_SEVERITY: dict[str, str] = {
    "critical": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "high": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "medium": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N",
    "low": "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",
}


def _run_silent_patch_audit(git_commits: list[dict[str, Any]]) -> dict[str, Any]:
    audit_fn = getattr(
        silent_patch_blame_auditor,
        "audit_git_history_for_silent_fixes",
        silent_patch_blame_auditor.audit_silent_security_patches_and_blame,
    )
    return audit_fn(git_commits)


def _has_unredacted_secrets(finding: dict[str, Any], runtime_proof: dict[str, Any] | None) -> bool:
    texts: list[str] = []
    for key in (
        "description",
        "vulnerability_information",
        "evidence",
        "patch",
        "remediation",
        "recommendation",
        "stdout",
        "test_token",
        "token",
    ):
        val = finding.get(key)
        if isinstance(val, str) and val:
            texts.append(val)
    rg_bundle = finding.get("red_green_bundle")
    if isinstance(rg_bundle, dict):
        stdout_val = rg_bundle.get("stdout")
        if isinstance(stdout_val, str) and stdout_val:
            texts.append(stdout_val)
    if isinstance(runtime_proof, dict):
        for val in runtime_proof.values():
            if isinstance(val, str) and val:
                texts.append(val)
    combined = "\n".join(texts)
    return bool(_RAW_SECRET_RE.search(combined))


def evaluate_end_to_end_bounty_readiness(
    finding: dict[str, Any],
    *,
    upstream_advisories: list[dict[str, Any]] | None = None,
    git_commits: list[dict[str, Any]] | None = None,
    runtime_proof: dict[str, Any] | None = None,
    symbolic_proof: dict[str, Any] | None = None,
    program_handle: str = "security-bounty",
    structured_scope_id: str = "scope-01",
) -> dict[str, Any]:
    """5 kapılı triyaj hazırlık hattını çalıştırır; hazırlık puanı, karar ve GHSA/HackerOne/MITRE CVE paketini döndürür."""
    safe_finding = dict(finding) if isinstance(finding, dict) else {}
    blocking_reasons: list[str] = []
    gates: dict[str, dict[str, Any]] = {}

    # -------------------------------------------------------------------------
    # Gate 1: static_and_symbolic_reachability (+25 puan)
    # -------------------------------------------------------------------------
    sym = (
        symbolic_proof
        if isinstance(symbolic_proof, dict)
        else (safe_finding.get("symbolic_proof") if isinstance(safe_finding.get("symbolic_proof"), dict) else None)
    )
    sym_status = str((sym or {}).get("status") or "").strip().upper()
    sym_reachable = (sym or {}).get("reachable")

    if sym_status == "UNSAT" or sym_reachable is False:
        blocking_reasons.append("UNSAT_UNREACHABLE_PATH")
        gates["static_and_symbolic_reachability"] = {
            "gate": "static_and_symbolic_reachability",
            "passed": False,
            "points": 0,
            "max_points": 25,
            "status": "BLOCKED",
            "symbolic_status": sym_status or "UNSAT",
            "reason": "UNSAT_UNREACHABLE_PATH",
        }
    else:
        has_sat = sym_status in {"SAT", "REACHABLE", "FEASIBLE"} or sym_reachable is True
        has_corroboration = bool(
            safe_finding.get("corroborated_engines")
            or safe_finding.get("sibling_parity")
            or safe_finding.get("file")
            or safe_finding.get("cwe")
        )
        gate1_points = 25 if (has_sat or has_corroboration) else 0
        gates["static_and_symbolic_reachability"] = {
            "gate": "static_and_symbolic_reachability",
            "passed": gate1_points > 0,
            "points": gate1_points,
            "max_points": 25,
            "status": "PASSED" if gate1_points > 0 else "INCOMPLETE",
            "symbolic_status": sym_status or ("SAT" if has_sat else "STATIC_CORROBORATED"),
        }

    # -------------------------------------------------------------------------
    # Gate 2: upstream_and_silent_patch_uniqueness (+20 puan)
    # -------------------------------------------------------------------------
    upstream_check = cve_submission_pipeline.check_upstream_advisory_and_incomplete_fix(
        safe_finding,
        upstream_advisories if isinstance(upstream_advisories, list) else [],
    )
    upstream_status = str(upstream_check.get("status") or "NOVEL_CANDIDATE")
    silent_patched_in_head = False
    silent_audit_result: dict[str, Any] | None = None

    if isinstance(git_commits, list) and git_commits:
        silent_audit_result = _run_silent_patch_audit(git_commits)
        silent_findings = silent_audit_result.get("findings") or []
        if silent_findings and not bool(
            safe_finding.get("unpatched_in_current_version") or safe_finding.get("incomplete_fix_bypass")
        ):
            f_file = str(safe_finding.get("file") or "").strip()
            f_cwe = str(safe_finding.get("cwe") or "").strip().upper()
            for sf in silent_findings:
                if not isinstance(sf, dict):
                    continue
                sf_file = str(sf.get("file") or "").strip()
                sf_cwe = str(sf.get("cwe") or "").strip().upper()
                if (not f_file or not sf_file or f_file == sf_file) or (f_cwe and f_cwe == sf_cwe):
                    silent_patched_in_head = True
                    break

    if upstream_status == "DUPLICATE_UPSTREAM_ADVISORY":
        blocking_reasons.append("DUPLICATE_UPSTREAM_ADVISORY")
        gates["upstream_and_silent_patch_uniqueness"] = {
            "gate": "upstream_and_silent_patch_uniqueness",
            "passed": False,
            "points": 0,
            "max_points": 20,
            "status": "BLOCKED",
            "upstream_status": upstream_status,
            "upstream_cve": upstream_check.get("upstream_cve"),
        }
    elif silent_patched_in_head:
        blocking_reasons.append("SILENTLY_PATCHED_IN_HEAD")
        gates["upstream_and_silent_patch_uniqueness"] = {
            "gate": "upstream_and_silent_patch_uniqueness",
            "passed": False,
            "points": 0,
            "max_points": 20,
            "status": "BLOCKED",
            "upstream_status": "SILENTLY_PATCHED_IN_HEAD",
            "silent_patch_audit": silent_audit_result,
        }
    else:
        gate2_points = 20 if upstream_status in {"INCOMPLETE_UPSTREAM_FIX", "NOVEL_CANDIDATE"} else 0
        gates["upstream_and_silent_patch_uniqueness"] = {
            "gate": "upstream_and_silent_patch_uniqueness",
            "passed": gate2_points > 0,
            "points": gate2_points,
            "max_points": 20,
            "status": "PASSED" if gate2_points > 0 else "INCOMPLETE",
            "upstream_status": upstream_status,
        }

    # -------------------------------------------------------------------------
    # Gate 3: loopback_runtime_proof (+30 puan)
    # -------------------------------------------------------------------------
    rt = (
        runtime_proof
        if isinstance(runtime_proof, dict)
        else (safe_finding.get("runtime_proof") if isinstance(safe_finding.get("runtime_proof"), dict) else None)
    )
    rt_reproduced = False
    if isinstance(rt, dict):
        rt_reproduced = bool(
            rt.get("reproduced") is True
            or rt.get("vulnerability_detected") is True
            or rt.get("race_window_reproduced") is True
            or rt.get("authorized_bypass_confirmed") is True
            or rt.get("canary_triggered") is True
            or str(rt.get("status") or "").strip().upper() in {"REPRODUCED", "CONFIRMED", "VULNERABLE"}
        )
    gate3_points = 30 if rt_reproduced else 0
    gates["loopback_runtime_proof"] = {
        "gate": "loopback_runtime_proof",
        "passed": rt_reproduced,
        "points": gate3_points,
        "max_points": 30,
        "status": "PASSED" if rt_reproduced else "MISSING_RUNTIME_PROOF",
    }

    # -------------------------------------------------------------------------
    # Gate 4: cvss_and_cwe_consistency (+15 puan)
    # -------------------------------------------------------------------------
    raw_cwe = str(safe_finding.get("cwe") or "").strip().upper()
    raw_severity = str(safe_finding.get("severity") or "high").strip().lower()
    raw_cvss = str(safe_finding.get("cvss_vector") or safe_finding.get("cvss") or "").strip()

    cwe_valid = bool(_CWE_RE.fullmatch(raw_cwe))
    sev_valid = raw_severity in {"critical", "high", "medium", "low"}
    if not raw_cvss and cwe_valid and sev_valid:
        resolved_cvss = _DEFAULT_CVSS_BY_SEVERITY.get(raw_severity, _DEFAULT_CVSS_BY_SEVERITY["high"])
        cvss_valid = True
    else:
        resolved_cvss = raw_cvss
        cvss_valid = bool(_CVSS_VECTOR_RE.match(raw_cvss))

    gate4_passed = cwe_valid and sev_valid and cvss_valid
    gate4_points = 15 if gate4_passed else 0
    gates["cvss_and_cwe_consistency"] = {
        "gate": "cvss_and_cwe_consistency",
        "passed": gate4_passed,
        "points": gate4_points,
        "max_points": 15,
        "status": "PASSED" if gate4_passed else "INCOMPLETE",
        "cwe": raw_cwe,
        "severity": raw_severity,
        "cvss_vector": resolved_cvss,
    }

    # -------------------------------------------------------------------------
    # Gate 5: red_green_patch_and_secret_hygiene (+10 puan)
    # -------------------------------------------------------------------------
    secret_leaked = _has_unredacted_secrets(safe_finding, rt)
    has_patch_or_remediation = bool(
        safe_finding.get("patch")
        or safe_finding.get("remediation")
        or safe_finding.get("recommendation")
        or safe_finding.get("red_green_bundle")
        or safe_finding.get("file")
    )
    gate5_passed = (not secret_leaked) and has_patch_or_remediation
    gate5_points = 10 if gate5_passed else 0
    gates["red_green_patch_and_secret_hygiene"] = {
        "gate": "red_green_patch_and_secret_hygiene",
        "passed": gate5_passed,
        "points": gate5_points,
        "max_points": 10,
        "status": "PASSED" if gate5_passed else ("SECRET_LEAK_DETECTED" if secret_leaked else "MISSING_PATCH"),
        "secret_hygiene_clean": not secret_leaked,
    }

    # -------------------------------------------------------------------------
    # Toplam Puan, Karar ve GHSA / HackerOne / MITRE CVE Paketi
    # -------------------------------------------------------------------------
    total_points = sum(int(g.get("points", 0)) for g in gates.values())
    readiness_score = max(0, min(100, total_points))

    if blocking_reasons:
        submission_verdict = "BLOCKED_DUPLICATE_OR_UNSAT"
        submission_bundle: dict[str, Any] | None = None
    else:
        if readiness_score >= 80:
            submission_verdict = "READY_FOR_SUBMISSION"
        else:
            submission_verdict = "NEEDS_RUNTIME_PROOF"

        payloads = cve_submission_pipeline.build_ghsa_and_hackerone_submission_payloads(
            [safe_finding],
            program_handle=program_handle,
            structured_scope_id=structured_scope_id,
        )
        reproducer = cve_submission_pipeline.synthesize_standalone_reproducer_script(safe_finding)
        submission_bundle = {
            "format": payloads.get("format", "sniper-cve-submission-payloads/1"),
            "program_handle": program_handle,
            "structured_scope_id": structured_scope_id,
            "ghsa_payloads": payloads.get("ghsa_payloads", []),
            "hackerone_payloads": payloads.get("hackerone_payloads", []),
            "mitre_cve_json5": {
                "dataType": "CVE_RECORD",
                "dataVersion": "5.0",
                "containers": {
                    "cna": {
                        "title": str(safe_finding.get("title") or "Security Vulnerability"),
                        "problemTypes": [
                            {
                                "descriptions": [
                                    {
                                        "type": "CWE",
                                        "cweId": raw_cwe or "CWE-200",
                                        "lang": "en",
                                    }
                                ]
                            }
                        ],
                        "metrics": [
                            {
                                "cvssV3_1": {
                                    "version": "3.1",
                                    "vectorString": resolved_cvss,
                                    "baseSeverity": raw_severity.upper(),
                                }
                            }
                        ],
                    }
                },
            },
            "reproducer_script": reproducer,
        }

    return {
        "format": FORMAT,
        "readiness_score": readiness_score,
        "submission_verdict": submission_verdict,
        "gates": gates,
        "blocking_reasons": blocking_reasons,
        "submission_bundle": submission_bundle,
    }
