from __future__ import annotations

import hashlib
import json
from typing import Any

MAX_RECORDS = 500
SEVERITY_KEYS = ["INFO", "OK", "LOW", "MEDIUM", "HIGH", "CRITICAL", "WARN", "DEBUG", "FATAL"]
REQUIRED_FIELDS = ["id", "ip", "port", "severity", "finding"]
OPTIONAL_FIELDS = ["cve", "cwe", "hint"]


def parse_testssl_json_summary(report: list[dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(report, list):
        raise ValueError("report bir JSON dizisi olmalı")

    if len(report) > MAX_RECORDS:
        raise ValueError(f"Çok fazla kayıt (en fazla {MAX_RECORDS})")

    severity_counts = {key: 0 for key in SEVERITY_KEYS}

    for record in report:
        if not isinstance(record, dict):
            raise ValueError("Her kayıt bir nesne olmalı")

        # Validate required fields
        for field in REQUIRED_FIELDS:
            if field not in record:
                raise ValueError(f"Gerekli alan eksik: {field}")
            if not isinstance(record[field], str):
                raise ValueError(f"'{field}' alanı bir metin olmalı")

        # Validate optional fields if present
        for field in OPTIONAL_FIELDS:
            if field in record and not isinstance(record[field], str):
                raise ValueError(f"'{field}' alanı varsa bir metin olmalı")

        # Validate severity
        severity = record["severity"]
        if severity not in SEVERITY_KEYS:
            raise ValueError("Geçersiz önem")

        severity_counts[severity] += 1

    canonical = json.dumps(report, sort_keys=True, separators=(",", ":"))
    report_sha256 = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    return {
        "format": "testssl-flat-json",
        "record_count": len(report),
        "severity_counts": severity_counts,
        "report_sha256": report_sha256
    }