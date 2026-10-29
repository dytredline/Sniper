from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from tool_report_dependabot import parse_dependabot_alerts_summary
from tool_report_npm_audit import parse_npm_audit_v2_summary

PLAN_FORMAT = "dependency-remediation-plan-v1"
NETWORK_SYNC_POLICY = "offline_saved_reports_only"
MAX_RAW_REPORT_BYTES = 512 * 1024

ALLOWED_ECOSYSTEMS = frozenset(
    {
        "npm",
        "pip",
        "rubygems",
        "go",
        "maven",
        "cargo",
        "nuget",
        "composer",
        "actions",
        "pub",
        "hex",
        "erlang",
        "swift",
    }
)

ECOSYSTEM_ALIASES: dict[str, str] = {
    "pypi": "pip",
    "python": "pip",
    "crates.io": "cargo",
    "rust": "cargo",
    "packagist": "composer",
    "php": "composer",
    "golang": "go",
    "swifturl": "swift",
    "github-actions": "actions",
    "github actions": "actions",
    "bundler": "rubygems",
    "ruby": "rubygems",
    "gradle": "maven",
    "dart": "pub",
    "elixir": "hex",
}

SEVERITY_RANK: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

PACKAGE_NAME_RE = re.compile(
    r"^(?:@[A-Za-z0-9._-]+/[A-Za-z0-9._-]+|[A-Za-z0-9][A-Za-z0-9._/-]{0,213})$"
)

ACTION_PATCH_AVAILABLE = "review_and_pin_patched_version_manually"
ACTION_NO_PATCH = "evaluate_mitigation_or_replace_dependency"


def _normalize_canonical_severity(raw_severity: Any) -> str:
    if not isinstance(raw_severity, str):
        raise ValueError("Severity bir metin olmalı.")
    lowered = raw_severity.strip().lower()
    if lowered == "moderate":
        return "medium"
    if lowered in SEVERITY_RANK:
        return lowered
    raise ValueError(f"Desteklenmeyen önem değeri: {raw_severity!r}")


def _validate_package_name(raw_name: Any) -> str:
    if not isinstance(raw_name, str):
        raise ValueError("Paket adı bir metin olmalı.")
    if not raw_name or raw_name.strip() != raw_name:
        raise ValueError("Paket adı boş olmayan, boşlukla doldurulmamış bir metin olmalı.")
    if len(raw_name) > 214:
        raise ValueError("Paket adı en fazla 214 karakter olabilir.")
    if "\x00" in raw_name or any(ord(ch) < 33 or ord(ch) == 127 for ch in raw_name):
        raise ValueError("Paket adı boşluk veya denetim karakteri içermemeli.")
    if "\\" in raw_name or ".." in raw_name or "//" in raw_name:
        raise ValueError("Paket adı yol aşımı veya ters eğik çizgi içermemeli.")
    if raw_name.startswith("/") or raw_name.endswith("/"):
        raise ValueError("Paket adı '/' ile başlamamalı veya bitmemeli.")
    if raw_name.lower().startswith("home/") or "/home/" in raw_name.lower():
        raise ValueError("Dosya sistemi yolları paket adı olarak kullanılamaz.")
    if not PACKAGE_NAME_RE.fullmatch(raw_name):
        raise ValueError("Paket adı desteklenmeyen karakterler içeriyor.")
    return raw_name


def _validate_ecosystem(raw_ecosystem: Any) -> str:
    if not isinstance(raw_ecosystem, str):
        raise ValueError("Ecosystem bir metin olmalı.")
    normalized = raw_ecosystem.strip().lower()
    normalized = ECOSYSTEM_ALIASES.get(normalized, normalized)
    if normalized not in ALLOWED_ECOSYSTEMS:
        raise ValueError(f"Desteklenmeyen bağımlılık ekosistemi: {raw_ecosystem!r}")
    return normalized


def _parse_raw_json_object(raw_text: Any, label: str) -> dict[str, Any]:
    if not isinstance(raw_text, str):
        raise ValueError(f"{label} bir JSON metni olmalı.")
    if "\x00" in raw_text:
        raise ValueError(f"{label} NUL baytı içermemeli.")
    try:
        encoded = raw_text.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{label} geçerli UTF-8 olmalı.") from exc
    if len(encoded) > MAX_RAW_REPORT_BYTES:
        raise ValueError(f"{label} azami {MAX_RAW_REPORT_BYTES} bayt boyutunu aşıyor.")
    if not raw_text.strip():
        raise ValueError(f"{label} boş olmamalı.")
    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} bozuk JSON içeriyor.") from exc
    if not isinstance(parsed, dict):
        raise ValueError(f"{label} kökü bir JSON nesnesi olmalı.")
    return parsed


def _extract_npm_audit_advisories(raw_json: str) -> list[dict[str, object]]:
    audit = _parse_raw_json_object(raw_json, "npm_audit_raw")
    if type(audit.get("auditReportVersion")) is not int or audit.get("auditReportVersion") != 2:
        raise ValueError("npm_audit_raw tamsayı auditReportVersion == 2 içermeli.")
    parse_npm_audit_v2_summary(audit)

    vulnerabilities = audit["vulnerabilities"]
    advisories: list[dict[str, object]] = []

    for pkg_key, pkg_entry in vulnerabilities.items():
        pkg_name = _validate_package_name(pkg_key)
        if not isinstance(pkg_entry, dict):
            raise ValueError("Her npm zafiyet girdisi bir JSON nesnesi olmalı.")
        if "name" in pkg_entry and pkg_entry["name"] is not None:
            entry_name = _validate_package_name(pkg_entry["name"])
            if entry_name != pkg_name:
                raise ValueError("npm zafiyet girdisi adı paket anahtarıyla eşleşmiyor.")

        severity = _normalize_canonical_severity(pkg_entry.get("severity"))
        fix_raw = pkg_entry.get("fixAvailable", False)
        if isinstance(fix_raw, bool):
            fixed_available = fix_raw
        elif isinstance(fix_raw, dict):
            if "version" in fix_raw:
                ver = fix_raw.get("version")
                if not isinstance(ver, str) or not ver.strip():
                    raise ValueError("fixAvailable.version varsa boş olmayan bir metin olmalı.")
            fixed_available = True
        elif fix_raw is None:
            fixed_available = False
        else:
            raise ValueError("fixAvailable bir mantıksal değer veya nesne olmalı.")

        advisories.append(
            {
                "ecosystem": "npm",
                "package": pkg_name,
                "severity": severity,
                "fixed_version_available": fixed_available,
            }
        )

    return advisories


def _extract_dependabot_advisories(raw_json: str) -> list[dict[str, object]]:
    payload = _parse_raw_json_object(raw_json, "dependabot_raw")
    parse_dependabot_alerts_summary(payload)

    alerts = payload["alerts"]
    advisories: list[dict[str, object]] = []

    for alert in alerts:
        state = alert.get("state")
        if state != "open":
            continue

        advisory = alert.get("security_advisory", {})
        severity = _normalize_canonical_severity(advisory.get("severity"))

        dep = alert.get("dependency")
        vuln = alert.get("security_vulnerability")

        pkg_obj: dict[str, Any] = {}
        if isinstance(dep, dict) and isinstance(dep.get("package"), dict):
            pkg_obj = dep["package"]
        elif isinstance(vuln, dict) and isinstance(vuln.get("package"), dict):
            pkg_obj = vuln["package"]
        else:
            raise ValueError("Açık Dependabot uyarısı dependency.package veya security_vulnerability.package içermeli.")

        pkg_name = _validate_package_name(pkg_obj.get("name"))
        raw_eco = pkg_obj.get("ecosystem")
        if raw_eco is None and isinstance(vuln, dict) and isinstance(vuln.get("package"), dict):
            raw_eco = vuln["package"].get("ecosystem")
        ecosystem = _validate_ecosystem(raw_eco if raw_eco is not None else "npm")

        fixed_available = False
        if isinstance(vuln, dict):
            first_patched = vuln.get("first_patched_version")
            if first_patched is not None:
                if not isinstance(first_patched, dict):
                    raise ValueError("security_vulnerability.first_patched_version bir nesne olmalı.")
                identifier = first_patched.get("identifier")
                if isinstance(identifier, str) and identifier.strip():
                    fixed_available = True

        advisories.append(
            {
                "ecosystem": ecosystem,
                "package": pkg_name,
                "severity": severity,
                "fixed_version_available": fixed_available,
            }
        )

    return advisories


def build_readonly_dependency_remediation_plan(
    *,
    npm_audit_raw: str | None = None,
    dependabot_raw: str | None = None,
) -> dict[str, object]:
    """Generate a deterministic, read-only dependency remediation plan from saved reports.

    Never mutates package.json/package-lock.json, never runs npm install/npm audit fix,
    and never contacts external registries or GitHub APIs.
    """
    if npm_audit_raw is None and dependabot_raw is None:
        raise ValueError("npm_audit_raw veya dependabot_raw değerlerinden en az biri verilmeli.")

    advisories: list[dict[str, object]] = []
    if npm_audit_raw is not None:
        advisories.extend(_extract_npm_audit_advisories(npm_audit_raw))
    if dependabot_raw is not None:
        advisories.extend(_extract_dependabot_advisories(dependabot_raw))

    severity_totals: dict[str, int] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    grouped: dict[tuple[str, str], dict[str, object]] = {}

    for item in advisories:
        eco = str(item["ecosystem"])
        pkg = str(item["package"])
        sev = str(item["severity"])
        fix_avail = bool(item["fixed_version_available"])

        severity_totals[sev] += 1
        key = (eco, pkg)
        if key not in grouped:
            grouped[key] = {
                "ecosystem": eco,
                "package": pkg,
                "max_severity": sev,
                "fixed_version_available": fix_avail,
            }
        else:
            current = grouped[key]
            cur_sev = str(current["max_severity"])
            if SEVERITY_RANK[sev] > SEVERITY_RANK[cur_sev]:
                current["max_severity"] = sev
            if fix_avail:
                current["fixed_version_available"] = True

    package_actions: list[dict[str, object]] = []
    for entry in grouped.values():
        has_fix = bool(entry["fixed_version_available"])
        package_actions.append(
            {
                "ecosystem": entry["ecosystem"],
                "package": entry["package"],
                "max_severity": entry["max_severity"],
                "fixed_version_available": has_fix,
                "recommended_action": (
                    ACTION_PATCH_AVAILABLE if has_fix else ACTION_NO_PATCH
                ),
            }
        )

    package_actions.sort(
        key=lambda item: (
            -SEVERITY_RANK[str(item["max_severity"])],
            str(item["ecosystem"]),
            str(item["package"]),
        )
    )

    plan_payload: dict[str, object] = {
        "format": PLAN_FORMAT,
        "mutates_lockfile": False,
        "network_sync": NETWORK_SYNC_POLICY,
        "total_advisories": len(advisories),
        "severity_totals": severity_totals,
        "package_actions": package_actions,
    }

    canonical_json = json.dumps(plan_payload, sort_keys=True, separators=(",", ":"))
    plan_sha256 = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

    return {
        **plan_payload,
        "plan_sha256": plan_sha256,
    }
