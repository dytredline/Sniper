from __future__ import annotations

import json
from typing import Any

MAX_RESULTS = 500
MAX_FINDINGS = 500

CLASS_MAP = {
    "os-pkgs",
    "lang-pkgs",
    "config",
    "secret",
    "license",
    "license-file",
    "crypto",
    "custom",
}

SEVERITY_MAP = {
    "critical",
    "high",
    "medium",
    "low",
    "unknown",
}


def parse_trivy_native_json_summary(report: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(report, dict):
        raise ValueError("report bir JSON nesnesi olmalı")

    schema_version = report.get("SchemaVersion")
    if not isinstance(schema_version, int) or schema_version != 2:
        raise ValueError("SchemaVersion 2 tamsayısı olmalı")

    # Key presence check for Results
    if "Results" not in report:
        results = []
    else:
        results = report["Results"]
        if not isinstance(results, list):
            raise ValueError("Results bir JSON dizisi olmalı veya bulunmamalı")
        if len(results) > MAX_RESULTS:
            raise ValueError(f"Çok fazla Results (en fazla {MAX_RESULTS})")

    class_counts = {
        "os-pkgs": 0,
        "lang-pkgs": 0,
        "config": 0,
        "secret": 0,
        "license": 0,
        "license-file": 0,
        "crypto": 0,
        "custom": 0,
        "unknown": 0,
    }

    vuln_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "unknown": 0,
    }

    misconfig_sev_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "unknown": 0,
    }

    finding_counts = {
        "vulnerabilities": 0,
        "misconfigurations": 0,
        "secrets": 0,
        "licenses": 0,
    }

    for result in results:
        if not isinstance(result, dict):
            raise ValueError("Her Result bir nesne olmalı")

        # Class handling: key presence check
        if "Class" not in result:
            cls = "unknown"
        else:
            cls = result["Class"]
            if not isinstance(cls, str):
                raise ValueError("Class bir metin olmalı veya bulunmamalı")
            elif cls not in CLASS_MAP:
                cls = "unknown"
        class_counts[cls] += 1

        # Vulnerabilities handling: key presence check
        if "Vulnerabilities" in result:
            vulns = result["Vulnerabilities"]
            if not isinstance(vulns, list):
                raise ValueError("Vulnerabilities bir dizi olmalı veya bulunmamalı")
            if len(vulns) > MAX_FINDINGS:
                raise ValueError(f"Çok fazla Vulnerabilities (en fazla {MAX_FINDINGS})")
            finding_counts["vulnerabilities"] += len(vulns)
            for v in vulns:
                if not isinstance(v, dict):
                    raise ValueError("Her Vulnerability bir nesne olmalı")
                # Severity handling: key presence check
                if "Severity" not in v:
                    vuln_counts["unknown"] += 1
                else:
                    sev = v["Severity"]
                    if not isinstance(sev, str):
                        raise ValueError("Severity bir metin olmalı veya bulunmamalı")
                    else:
                        sev_lower = sev.lower()
                        if sev_lower not in SEVERITY_MAP:
                            sev_lower = "unknown"
                        vuln_counts[sev_lower] += 1

        # Misconfigurations handling: key presence check
        if "Misconfigurations" in result:
            misconfigs = result["Misconfigurations"]
            if not isinstance(misconfigs, list):
                raise ValueError("Misconfigurations bir dizi olmalı veya bulunmamalı")
            if len(misconfigs) > MAX_FINDINGS:
                raise ValueError(f"Çok fazla Misconfigurations (en fazla {MAX_FINDINGS})")
            finding_counts["misconfigurations"] += len(misconfigs)
            for m in misconfigs:
                if not isinstance(m, dict):
                    raise ValueError("Her Misconfiguration bir nesne olmalı")
                # Misconfiguration severity counting
                if "Severity" not in m:
                    misconfig_sev_counts["unknown"] += 1
                else:
                    sev = m["Severity"]
                    if not isinstance(sev, str):
                        raise ValueError("Misconfiguration Severity bir metin olmalı veya bulunmamalı")
                    else:
                        sev_lower = sev.lower()
                        if sev_lower not in SEVERITY_MAP:
                            sev_lower = "unknown"
                        misconfig_sev_counts[sev_lower] += 1

        # Secrets handling: key presence check
        if "Secrets" in result:
            secrets = result["Secrets"]
            if not isinstance(secrets, list):
                raise ValueError("Secrets bir dizi olmalı veya bulunmamalı")
            if len(secrets) > MAX_FINDINGS:
                raise ValueError(f"Çok fazla Secrets (en fazla {MAX_FINDINGS})")
            finding_counts["secrets"] += len(secrets)
            for s in secrets:
                if not isinstance(s, dict):
                    raise ValueError("Her Secret bir nesne olmalı")

        # Licenses handling: key presence check
        if "Licenses" in result:
            licenses = result["Licenses"]
            if not isinstance(licenses, list):
                raise ValueError("Licenses bir dizi olmalı veya bulunmamalı")
            if len(licenses) > MAX_FINDINGS:
                raise ValueError(f"Çok fazla Licenses (en fazla {MAX_FINDINGS})")
            finding_counts["licenses"] += len(licenses)
            for l in licenses:
                if not isinstance(l, dict):
                    raise ValueError("Her License bir nesne olmalı")

    report_str = json.dumps(report, sort_keys=True, separators=(",", ":"))
    import hashlib
    report_digest = hashlib.sha256(report_str.encode()).hexdigest()

    return {
        "format": "trivy-native-json",
        "schema_version": 2,
        "result_count": len(results),
        "class_counts": class_counts,
        "vuln_counts": vuln_counts,
        "misconfig_sev_counts": misconfig_sev_counts,
        "finding_counts": finding_counts,
        "report_sha256": report_digest,
    }
