from __future__ import annotations

import hashlib
import json
from typing import Any

ALLOWED_SEVERITIES = {"info", "low", "moderate", "high", "critical"}
MAX_AFFECTED_PACKAGES = 500


def _normalize_severity(severity: Any) -> str | None:
    if not isinstance(severity, str):
        return None
    normalized = severity.lower().strip()
    if normalized in ALLOWED_SEVERITIES:
        return normalized
    return None


def _count_filtered_by_severity(vulnerabilities: dict[str, Any]) -> dict[str, int]:
    counts = {"info": 0, "low": 0, "moderate": 0, "high": 0, "critical": 0}
    for pkg_entry in vulnerabilities.values():
        if not isinstance(pkg_entry, dict):
            raise ValueError("Her paket girdisi bir nesne olmalı")
        severity_raw = pkg_entry.get("severity", "")
        normalized = _normalize_severity(severity_raw)
        if normalized is None:
            raise ValueError("Paket girdisinde geçersiz veya eksik önem")
        counts[normalized] += 1
    return counts


def parse_npm_audit_v2_summary(audit: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(audit, dict):
        raise ValueError("audit bir JSON nesnesi olmalı")

    version = audit.get("auditReportVersion")
    if not isinstance(version, int) or version != 2:
        raise ValueError("auditReportVersion 2 tamsayısı olmalı")

    vulnerabilities = audit.get("vulnerabilities")
    if not isinstance(vulnerabilities, dict):
        raise ValueError("vulnerabilities bir nesne olmalı")

    if len(vulnerabilities) > MAX_AFFECTED_PACKAGES:
        raise ValueError("Çok fazla etkilenen paket")

    affected_package_count = len(vulnerabilities)
    package_severity_counts = _count_filtered_by_severity(vulnerabilities)

    canonical = json.dumps(audit, sort_keys=True, separators=(",", ":"))
    report_sha256 = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    return {
        "format": "npm-audit-v2",
        "affected_package_count": affected_package_count,
        "package_severity_counts": package_severity_counts,
        "report_sha256": report_sha256,
    }