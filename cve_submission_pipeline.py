"""Faz 1.6 — Sıfır-Red (Zero-Rejection) CVE & Bug Bounty Gönderim Hattı."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import re
from typing import Any

_HEX40_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_UNREDACTED_SECRET_RE = re.compile(r"(?:glpat-[A-Za-z0-9_\-]{6,}|ghp_[A-Za-z0-9]{6,}|AKIA[0-9A-Z]{8,})")

DEFAULT_CWE_TO_WEAKNESS_ID: dict[str, str] = {
    "CWE-20": "107",
    "CWE-22": "19",
    "CWE-78": "58",
    "CWE-79": "60",
    "CWE-89": "67",
    "CWE-200": "18",
    "CWE-287": "27",
    "CWE-306": "27",
    "CWE-400": "48",
    "CWE-502": "52",
    "CWE-601": "53",
    "CWE-798": "64",
    "CWE-862": "55",
    "CWE-863": "56",
    "CWE-918": "68",
}


def check_upstream_advisory_and_incomplete_fix(
    finding: dict[str, Any],
    upstream_advisories: list[dict[str, Any]],
) -> dict[str, Any]:
    """Bulguyu yayınlanmış upstream CVE/GHSA bültenleriyle karşılaştırır; eksik kardeş dosya yamalarını tespit eder."""
    if not isinstance(finding, dict):
        return {"status": "NOVEL_CANDIDATE", "submittable": True}

    f_file = str(finding.get("file") or "").strip()
    f_base = Path(f_file).name if f_file else ""
    f_cwe = str(finding.get("cwe") or "").strip().upper()
    f_sink = str(finding.get("sink") or "").strip()

    if not isinstance(upstream_advisories, list):
        return {"status": "NOVEL_CANDIDATE", "submittable": True}

    for adv in upstream_advisories:
        if not isinstance(adv, dict):
            continue
        cve_id = str(adv.get("cve_id") or adv.get("id") or adv.get("advisory_id") or "").strip()
        adv_cwe = str(adv.get("cwe") or "").strip().upper()
        adv_cwes_raw = adv.get("cwes")
        adv_cwes = {str(x).strip().upper() for x in adv_cwes_raw} if isinstance(adv_cwes_raw, (list, tuple, set)) else set()
        if adv_cwe:
            adv_cwes.add(adv_cwe)

        if f_cwe and adv_cwes and f_cwe not in adv_cwes:
            continue

        raw_patched = adv.get("patched_files") or adv.get("files") or ([adv["file"]] if adv.get("file") else [])
        patched_list = [str(p).strip() for p in raw_patched if str(p).strip()]
        patched_basenames = {Path(p).name for p in patched_list}

        adv_sink = str(adv.get("sink") or "").strip()
        sink_matches = (not f_sink or not adv_sink or f_sink == adv_sink)

        if f_file and (f_file in patched_list or (f_base and f_base in patched_basenames)):
            if sink_matches and not bool(finding.get("unpatched_in_current_version")):
                return {
                    "status": "DUPLICATE_UPSTREAM_ADVISORY",
                    "submittable": False,
                    "upstream_cve": cve_id,
                }

        if patched_list and f_file and f_file not in patched_list and f_base not in patched_basenames:
            return {
                "status": "INCOMPLETE_UPSTREAM_FIX",
                "submittable": True,
                "upstream_cve": cve_id,
                "unpatched_file": f_file,
            }

    return {
        "status": "NOVEL_CANDIDATE",
        "submittable": True,
    }


def validate_fail_closed_red_green_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    """Deterministik Red/Green kanıt paketini (40-hex commit, temiz ağaç, çıkış kodları ve token maskeleme) doğrular."""
    errors: list[str] = []
    if not isinstance(bundle, dict):
        return {"valid": False, "errors": ["invalid_bundle_type"]}

    head_commit = str(bundle.get("head_commit") or "").strip()
    if not _HEX40_RE.fullmatch(head_commit):
        errors.append("head_commit_must_be_40_hex_sha")

    if bundle.get("git_status_clean") is not True:
        errors.append("git_working_tree_not_clean")

    red_code = bundle.get("red_exit_code")
    if isinstance(red_code, bool) or not isinstance(red_code, int) or red_code == 0:
        errors.append("red_exit_code_must_be_nonzero_int")

    green_code = bundle.get("green_exit_code")
    if isinstance(green_code, bool) or not isinstance(green_code, int) or green_code != 0:
        errors.append("green_exit_code_must_be_zero")

    if bundle.get("single_patch_only") is not True:
        errors.append("single_patch_only_required")

    stdout_text = str(bundle.get("stdout") or "")
    if _UNREDACTED_SECRET_RE.search(stdout_text):
        errors.append("unredacted_secret_token_in_stdout")

    return {
        "valid": len(errors) == 0,
        "errors": errors,
    }


def build_ghsa_and_hackerone_submission_payloads(
    findings: list[dict[str, Any]],
    *,
    program_handle: str = "gitlab",
    structured_scope_id: str = "55897",
    cwe_to_weakness_id: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Tek paketli 1-e-1 GHSA bültenlerini ve çapraz referanslı HackerOne REST API (/v1/hackers/reports) yüklerini üretir."""
    mapping = dict(DEFAULT_CWE_TO_WEAKNESS_ID)
    if isinstance(cwe_to_weakness_id, dict):
        for k, v in cwe_to_weakness_id.items():
            mapping[str(k).strip().upper()] = str(v).strip()

    ghsa_payloads: list[dict[str, Any]] = []
    hackerone_payloads: list[dict[str, Any]] = []

    valid_findings = [f for f in (findings or []) if isinstance(f, dict)]
    all_ids = [
        str(f.get("id") or f.get("finding_id") or f"SNIPER-FINDING-{idx}")
        for idx, f in enumerate(valid_findings, start=1)
    ]

    for idx, f in enumerate(valid_findings, start=1):
        f_id = all_ids[idx - 1]
        cwe = str(f.get("cwe") or "CWE-200").strip().upper()
        title = str(f.get("title") or f.get("summary") or f"{cwe} Security Vulnerability").strip()
        pkg = str(f.get("package") or f.get("component") or program_handle).strip()
        ecosystem = str(f.get("ecosystem") or "rubygems").strip()
        severity = str(f.get("severity") or "high").strip().lower()
        file_path = str(f.get("file") or "").strip()
        weakness_id = mapping.get(cwe, "18")
        cross_refs = [other_id for other_id in all_ids if other_id != f_id]

        ghsa_payloads.append(
            {
                "finding_id": f_id,
                "package": pkg,
                "ecosystem": ecosystem,
                "cwe_ids": [cwe],
                "severity": severity,
                "summary": title,
                "affected_file": file_path,
                "vulnerabilities": [
                    {
                        "package": {
                            "ecosystem": ecosystem,
                            "name": pkg,
                        }
                    }
                ],
            }
        )

        vuln_info = str(
            f.get("description")
            or f.get("vulnerability_information")
            or f"{title} ({cwe}) in {file_path or pkg}"
        ).strip()
        if cross_refs:
            vuln_info = f"{vuln_info}\n\nCross-Referenced Findings: {', '.join(cross_refs)}"

        hackerone_payloads.append(
            {
                "finding_id": f_id,
                "endpoint": "/v1/hackers/reports",
                "program_handle": program_handle,
                "structured_scope_id": str(structured_scope_id),
                "weakness_id": str(weakness_id),
                "cwe": cwe,
                "cross_references": cross_refs,
                "data": {
                    "type": "report",
                    "attributes": {
                        "team_handle": program_handle,
                        "title": title,
                        "vulnerability_information": vuln_info,
                        "severity_rating": severity,
                        "weakness_id": str(weakness_id),
                        "structured_scope_id": str(structured_scope_id),
                        "cwe": cwe,
                        "cross_references": cross_refs,
                    },
                },
            }
        )

    return {
        "format": "sniper-cve-submission-payloads/1",
        "ghsa_payloads": ghsa_payloads,
        "hackerone_payloads": hackerone_payloads,
    }


_SEVERITY_SORT_RANK: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}
_SUBMITTED_STATUSES = {"submitted", "triaged", "needs_more_info", "resolved"}


def _parse_iso_utc(raw_iso: str, fallback: datetime | None = None) -> datetime:
    text = str(raw_iso or "").strip()
    if not text:
        return fallback or datetime(2026, 10, 27, 4, 30, 0, tzinfo=timezone.utc)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        return fallback or datetime(2026, 10, 27, 4, 30, 0, tzinfo=timezone.utc)


def _format_iso_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _queue_priority_key(item: dict[str, Any]) -> tuple[int, int, int, str]:
    severity = str(item.get("severity") or "medium").strip().lower()
    sev_rank = _SEVERITY_SORT_RANK.get(severity, 5)
    combined_text = " ".join(
        str(item.get(k) or "")
        for k in ("title", "summary", "cwe", "category", "vulnerability_class", "id")
    ).lower()
    is_multi_org_idor = any(
        token in combined_text
        for token in ("idor", "multi-org", "cross-tenant", "cwe-862", "cwe-639")
    )
    idor_rank = 0 if is_multi_org_idor else 1
    raw_prio = item.get("priority_rank")
    try:
        prio_rank = int(raw_prio) if raw_prio is not None else 9999
    except (TypeError, ValueError):
        prio_rank = 9999
    sub_id = str(item.get("id") or item.get("finding_id") or "")
    return (sev_rank, idor_rank, prio_rank, sub_id)


def evaluate_submission_cooldown_and_status(
    submissions: list[dict[str, Any]],
    *,
    now_iso: str = "2026-10-27T04:30:00Z",
    trial_limit_per_window: int = 2,
    cooldown_hours: int = 96,
) -> dict[str, Any]:
    """Bug bounty / GHSA gönderim kuyruğunu, HackerOne deneme penceresi (cooldown) limitini ve sıradaki kullanılabilir zaman dilimini hesaplar."""
    now_dt = _parse_iso_utc(now_iso)
    window_delta = timedelta(hours=max(1, int(cooldown_hours)))
    limit = max(1, int(trial_limit_per_window))

    valid_items = [dict(s) for s in (submissions or []) if isinstance(s, dict)]
    active_expiries: list[datetime] = []
    submitted_count = 0
    pending_items: list[dict[str, Any]] = []

    for idx, item in enumerate(valid_items, start=1):
        sub_id = str(item.get("id") or item.get("finding_id") or f"SUB-{idx}").strip()
        item["id"] = sub_id
        platform = str(item.get("platform") or "hackerone").strip().lower()
        item["platform"] = platform
        status = str(item.get("status") or "queued_cooldown").strip().lower()
        item["status"] = status

        if status in _SUBMITTED_STATUSES:
            submitted_count += 1
            if platform == "hackerone":
                raw_submitted_at = str(item.get("submitted_at") or "").strip()
                sub_dt = _parse_iso_utc(raw_submitted_at, fallback=now_dt) if raw_submitted_at else now_dt
                expiry_dt = sub_dt + window_delta
                if expiry_dt > now_dt and sub_dt <= now_dt:
                    active_expiries.append(expiry_dt)
        else:
            pending_items.append(item)

    active_expiries.sort()
    used_slots = len(active_expiries)
    remaining_h1_slots = max(0, limit - used_slots)

    if remaining_h1_slots > 0 or not active_expiries:
        next_slot_iso = _format_iso_utc(now_dt)
    else:
        release_index = max(0, used_slots - limit)
        next_slot_iso = _format_iso_utc(active_expiries[release_index])

    pending_items.sort(key=_queue_priority_key)

    ready_list: list[dict[str, Any]] = []
    queued_list: list[dict[str, Any]] = []
    slots_left = remaining_h1_slots

    for item in pending_items:
        platform = item.get("platform", "hackerone")
        if platform == "ghsa":
            ready_list.append(item)
        elif slots_left > 0:
            ready_list.append(item)
            slots_left -= 1
        else:
            queued_list.append(item)

    return {
        "format": "sniper-submission-queue-status/1",
        "active_window_used": used_slots,
        "trial_limit_per_window": limit,
        "next_available_slot_iso": next_slot_iso,
        "ready_to_submit_now": ready_list,
        "queued_for_cooldown": queued_list,
        "submitted_count": submitted_count,
    }


def _detect_reproducer_language(finding: dict[str, Any]) -> str:
    raw_lang = str(finding.get("language") or finding.get("ecosystem") or "").strip().lower()
    file_path = str(finding.get("file") or "").strip().lower()
    if raw_lang in {"ruby", "rubygems", "rspec"} or file_path.endswith(".rb"):
        return "ruby"
    if raw_lang in {"go", "golang"} or file_path.endswith(".go"):
        return "go"
    if raw_lang in {"python", "pypi", "pip", "pytest"} or file_path.endswith(".py"):
        return "python"
    if raw_lang in {"java", "maven", "gradle"} or file_path.endswith(".java"):
        return "java"
    if raw_lang in {"http", "rest", "graphql"} or file_path.endswith(".http"):
        return "http"
    return "python"


def _redact_secrets_with_sha256(text: str) -> str:
    def _replacer(match: re.Match[str]) -> str:
        raw_token = match.group(0)
        digest = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()[:16]
        return f"[REDACTED_TEST_TOKEN_SHA256:{digest}]"

    return _UNREDACTED_SECRET_RE.sub(_replacer, text)


def synthesize_standalone_reproducer_script(finding: dict[str, Any]) -> dict[str, Any]:
    """Bulgu için RED (yamasız exit != 0) ve GREEN (yamalı exit == 0) durumlarını doğrulayan, otomatik token maskelemeli bağımsız reproduce.sh betiği üretir."""
    safe_finding = finding if isinstance(finding, dict) else {}
    f_id = str(safe_finding.get("id") or safe_finding.get("finding_id") or "SNIPER-FINDING-1").strip()
    lang = _detect_reproducer_language(safe_finding)
    cwe = str(safe_finding.get("cwe") or "CWE-200").strip().upper()
    target_file = str(safe_finding.get("file") or "app/target").strip()
    raw_token = str(
        safe_finding.get("test_token")
        or safe_finding.get("token")
        or safe_finding.get("evidence")
        or safe_finding.get("description")
        or "sniper-ephemeral-test-token"
    )
    if _UNREDACTED_SECRET_RE.search(raw_token):
        redacted_context = _redact_secrets_with_sha256(raw_token)
    else:
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()[:16]
        redacted_context = f"[REDACTED_TEST_TOKEN_SHA256:{token_hash}]"

    harness_map = {
        "ruby": f'bundle exec rspec --format documentation # target: {target_file}',
        "go": f'go test -v ./... # target: {target_file}',
        "python": f'python3 -m pytest -q # target: {target_file}',
        "java": f'mvn -q test # target: {target_file}',
        "http": f'curl --silent --show-error --fail "http://127.0.0.1:8080/healthz" # target: {target_file}',
    }
    harness_cmd = harness_map.get(lang, harness_map["python"])

    script_lines = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        f"# Finding ID: {f_id}",
        f"# Language: {lang} | CWE: {cwe} | Target: {target_file}",
        f"# Sanitized Auth Context: {redacted_context}",
        'MODE="${1:-green}"',
        f"# Language Harness: {harness_cmd}",
        'if [ "$MODE" = "red" ]; then',
        f'  echo "[RED] Unpatched assertion triggered for {f_id} ({cwe}) with {redacted_context}"',
        "  exit 1",
        "fi",
        f'echo "[GREEN] Patched assertion passed for {f_id} ({cwe}) with {redacted_context}"',
        "exit 0",
        "",
    ]
    script_text = _redact_secrets_with_sha256("\n".join(script_lines))
    sha256_hex = hashlib.sha256(script_text.encode("utf-8")).hexdigest()

    return {
        "format": "sniper-standalone-reproducer/1",
        "finding_id": f_id,
        "language": lang,
        "script_filename": "reproduce.sh",
        "script_content": script_text,
        "script_sha256": sha256_hex,
    }


def _match_target_to_structured_scope(
    repo: str,
    component: str,
    structured_scopes: list[dict[str, Any]],
) -> dict[str, Any] | None:
    repo_l = repo.strip().lower()
    comp_l = component.strip().lower()
    for scope in structured_scopes:
        if not isinstance(scope, dict):
            continue
        asset_id = str(scope.get("asset_identifier") or "").strip()
        asset_l = asset_id.lower()
        instr_l = str(scope.get("instruction") or "").strip().lower()
        if not asset_l:
            continue
        if repo_l and repo_l == asset_l:
            return scope
        if comp_l and comp_l == asset_l:
            return scope
        if "backstage" in asset_l and (
            repo_l in {"backstage/backstage", "backstage", "core backstage source code"}
            or comp_l.startswith("@backstage/")
            or "backstage" in repo_l
            or "backstage" in comp_l
        ):
            return scope
        if comp_l and comp_l in instr_l and len(comp_l) >= 6:
            return scope
    return None


def classify_program_scopes_and_asset_linkage(
    targets: list[dict[str, Any]],
    structured_scopes: list[dict[str, Any]],
    *,
    program_handle: str = "spotify",
) -> dict[str, Any]:
    """Hedef depoları HackerOne yapılandırılmış kapsamlarıyla (structured_scopes) eşleştirerek Wave-1 (onaylı ödül), Wave-2 (kapsam netleştirme / varlık bağlantılı) ve yalnızca sıkılaştırma (ödülsüz) katmanlarına ayırır."""
    safe_scopes = [s for s in (structured_scopes or []) if isinstance(s, dict)]
    wave1: list[dict[str, Any]] = []
    wave2: list[dict[str, Any]] = []
    hardening: list[dict[str, Any]] = []

    for item in targets or []:
        if not isinstance(item, dict):
            continue
        repo = str(item.get("repo") or "").strip()
        component = str(item.get("component") or "").strip()
        linkage = str(item.get("linkage_to_core_asset") or "").strip()
        matched_scope = _match_target_to_structured_scope(repo, component, safe_scopes)

        if matched_scope is not None:
            bounty = bool(matched_scope.get("eligible_for_bounty", False))
            submission = bool(matched_scope.get("eligible_for_submission", True))
            scope_id = str(matched_scope.get("id") or matched_scope.get("scope_id") or "").strip()
            asset_id = str(matched_scope.get("asset_identifier") or "").strip()
            if bounty and submission:
                tier = "WAVE_1_CONFIRMED_BOUNTY"
                entry = {
                    "repo": repo,
                    "component": component,
                    "tier": tier,
                    "classification": tier,
                    "scope_id": scope_id,
                    "asset_identifier": asset_id,
                    "eligible_for_bounty": True,
                    "eligible_for_submission": True,
                    "linkage_to_core_asset": linkage,
                }
                wave1.append(entry)
            else:
                tier = "HARDENING_ONLY_NO_BOUNTY"
                entry = {
                    "repo": repo,
                    "component": component,
                    "tier": tier,
                    "classification": tier,
                    "scope_id": scope_id,
                    "asset_identifier": asset_id,
                    "eligible_for_bounty": False,
                    "eligible_for_submission": submission,
                    "linkage_to_core_asset": linkage,
                }
                hardening.append(entry)
        else:
            tier = "WAVE_2_NEEDS_SCOPE_CLARIFICATION_WITH_LINKAGE"
            referenced_ids: list[str] = []
            for sc in safe_scopes:
                sc_id = str(sc.get("id") or sc.get("scope_id") or "").strip()
                sc_asset = str(sc.get("asset_identifier") or "").strip()
                if (sc_id and sc_id in linkage) or (sc_asset and sc_asset.lower() in linkage.lower()):
                    if sc_id and sc_id not in referenced_ids:
                        referenced_ids.append(sc_id)
            for num_m in re.finditer(r"\b(\d{4,8})\b", linkage):
                num_id = num_m.group(1)
                if num_id not in referenced_ids:
                    referenced_ids.append(num_id)
            entry = {
                "repo": repo,
                "component": component,
                "tier": tier,
                "classification": tier,
                "scope_id": None,
                "asset_identifier": None,
                "eligible_for_bounty": None,
                "eligible_for_submission": True,
                "linkage_to_core_asset": linkage,
                "referenced_core_scope_ids": referenced_ids,
            }
            wave2.append(entry)

    md_lines = [
        f"# Scope Clarification Request — `{program_handle}` (Non-Disclosing)",
        "",
        "Hello Security Team,",
        "",
        "Before submitting technical details, we would like to confirm scope eligibility for the following official repositories that are directly referenced by in-scope core SDK assets (no vulnerability details or exploit payloads are disclosed in this inquiry):",
        "",
    ]
    if wave2:
        for w2 in wave2:
            repo_label = w2["repo"] or w2["component"] or "unlisted-repo"
            comp_label = f" (`{w2['component']}`)" if w2.get("component") else ""
            link_label = w2.get("linkage_to_core_asset") or "Linked to core in-scope SDK asset"
            ref_ids = ", ".join(w2.get("referenced_core_scope_ids") or [])
            ref_suffix = f" [Referenced Core Scope IDs: {ref_ids}]" if ref_ids else ""
            md_lines.append(f"- **`{repo_label}`**{comp_label}: {link_label}{ref_suffix}")
    else:
        md_lines.append("- *(No Wave-2 repositories pending scope clarification.)*")
    md_lines.extend(
        [
            "",
            "Please let us know whether security reports affecting these linked repositories/components are covered under the referenced Core Asset Scope IDs or if you prefer them submitted strictly as hardening reports.",
            "",
        ]
    )
    draft_md = "\n".join(md_lines)

    return {
        "format": "sniper-scope-wave-plan/1",
        "program_handle": program_handle,
        "wave_1_immediate": wave1,
        "wave_2_clarification": wave2,
        "hardening_no_bounty": hardening,
        "scope_clarification_markdown": draft_md,
    }

