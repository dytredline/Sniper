"""Faz 3.3 — Sessiz Güvenlik Yaması (Silent Patch) ve Git Blame Denetçisi."""

from __future__ import annotations

import re
from typing import Any

_EXPLICIT_SECURITY_MSG_RE = re.compile(
    r"(?:CVE-\d{4}-\d+|GHSA-[A-Za-z0-9\-]+|\bsecurity\b|\bvulnerability\b)",
    re.IGNORECASE,
)

_ADDED_GUARD_PATTERNS: tuple[tuple[str, re.Pattern[str], str, str], ...] = (
    ("UrlBlocker", re.compile(r"\bUrlBlocker\b"), "CWE-918", "critical"),
    ("WithSSRFFilter", re.compile(r"\bWithSSRFFilter\b"), "CWE-918", "critical"),
    ("--allowed-protocols", re.compile(r"--allowed-protocols\b"), "CWE-918", "high"),
    ("in_organization", re.compile(r"\bin_organization\b"), "CWE-862", "critical"),
    ("Ability.allowed?", re.compile(r"\bAbility\.allowed\?"), "CWE-862", "critical"),
    ("nonReentrant", re.compile(r"\bnonReentrant\b"), "CWE-862", "high"),
    ("NOFOLLOW_LINKS", re.compile(r"\bNOFOLLOW_LINKS\b"), "CWE-59", "high"),
    ("filepath.Rel", re.compile(r"\bfilepath\.Rel\b"), "CWE-22", "high"),
    ("commonpath", re.compile(r"\bcommonpath\b"), "CWE-22", "high"),
    ("DOMPurify.sanitize", re.compile(r"\bDOMPurify\.sanitize\b"), "CWE-79", "high"),
    (
        "verify_signature",
        re.compile(r"\bverify_signature\b(?!\s*[:=]\s*(?:False|false|0))"),
        "CWE-347",
        "high",
    ),
    (
        "parameterized_sql",
        re.compile(r"(?:\bparameterized\b|\bPreparedStatement\b|\bprepare\s*\(|\bbind_param\b)"),
        "CWE-89",
        "critical",
    ),
)

_REMOVED_UNSAFE_PATTERNS: tuple[tuple[str, re.Pattern[str], str, str], ...] = (
    (
        "InsecureSkipVerify: true",
        re.compile(r"InsecureSkipVerify\s*:\s*true", re.IGNORECASE),
        "CWE-295",
        "high",
    ),
    (
        "verify_signature: False",
        re.compile(r"verify_signature\s*[:=]\s*(?:False|false)", re.IGNORECASE),
        "CWE-347",
        "high",
    ),
)


def _extract_added_and_removed_lines(diff_text: str) -> tuple[str, str]:
    added: list[str] = []
    removed: list[str] = []
    has_diff_markers = False
    for raw_line in diff_text.splitlines():
        if raw_line.startswith("+++") or raw_line.startswith("---"):
            has_diff_markers = True
            continue
        if raw_line.startswith("+"):
            has_diff_markers = True
            added.append(raw_line[1:])
        elif raw_line.startswith("-"):
            has_diff_markers = True
            removed.append(raw_line[1:])
    if not has_diff_markers:
        return diff_text, ""
    return "\n".join(added), "\n".join(removed)


def _resolve_introduced_commit(
    file_path: str,
    diff_text: str,
    commit_item: dict[str, Any],
    file_blame_map: dict[str, dict[str, str]] | None,
) -> str | None:
    if isinstance(file_blame_map, dict) and file_path in file_blame_map:
        entry = file_blame_map[file_path]
        if isinstance(entry, str) and entry.strip():
            return entry.strip()
        if isinstance(entry, dict):
            for key in ("introduced_in_commit", "introduced_commit", "commit", "sha", "default"):
                val = entry.get(key)
                if isinstance(val, str) and val.strip():
                    return val.strip()
            for key, val in entry.items():
                if isinstance(val, str) and val.strip() and str(key) in diff_text:
                    return val.strip()
            for val in entry.values():
                if isinstance(val, str) and val.strip():
                    return val.strip()
    fallback = commit_item.get("introduced_in_commit")
    if isinstance(fallback, str) and fallback.strip():
        return fallback.strip()
    return None


def audit_silent_security_patches_and_blame(
    commits: list[dict[str, Any]],
    *,
    file_blame_map: dict[str, dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Git commit geçmişinde güvenlik bülteni/CVE referansı olmadan sessizce eklenen güvenlik yamalarını (SNIPER-SILENT-PATCH-01) ve kaynak commit eşleşmesini tespit eder."""
    valid_commits = [c for c in (commits or []) if isinstance(c, dict)]
    findings: list[dict[str, Any]] = []

    for commit_item in valid_commits:
        commit_sha = str(commit_item.get("commit") or commit_item.get("sha") or "").strip()
        author_date = str(commit_item.get("author_date") or commit_item.get("date") or "").strip()
        message = str(commit_item.get("message") or "").strip()
        file_path = str(commit_item.get("file") or "").strip()
        diff_text = str(commit_item.get("diff") or "")

        if _EXPLICIT_SECURITY_MSG_RE.search(message):
            continue

        added_text, removed_text = _extract_added_and_removed_lines(diff_text)
        matched_guard: str | None = None
        matched_cwe: str | None = None
        severity = "high"

        for guard_name, pattern, cwe, sev in _ADDED_GUARD_PATTERNS:
            if pattern.search(added_text):
                matched_guard = guard_name
                matched_cwe = cwe
                severity = sev
                break

        if matched_guard is None:
            for guard_name, pattern, cwe, sev in _REMOVED_UNSAFE_PATTERNS:
                if pattern.search(removed_text):
                    matched_guard = guard_name
                    matched_cwe = cwe
                    severity = sev
                    break

        if matched_guard is None or matched_cwe is None:
            continue

        introduced_sha = _resolve_introduced_commit(file_path, diff_text, commit_item, file_blame_map)

        finding: dict[str, Any] = {
            "rule_id": "SNIPER-SILENT-PATCH-01",
            "commit": commit_sha,
            "fixed_in_commit": commit_sha,
            "introduced_in_commit": introduced_sha,
            "author_date": author_date,
            "message": message,
            "file": file_path,
            "cwe": matched_cwe,
            "matched_guard": matched_guard,
            "severity": severity,
            "silent_security_fix": True,
        }
        findings.append(finding)

    return {
        "format": "sniper-silent-patch-blame-audit/1",
        "scanned_commit_count": len(valid_commits),
        "silent_fix_count": len(findings),
        "findings": findings,
    }
