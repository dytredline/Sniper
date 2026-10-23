from __future__ import annotations

import hashlib
import json
from typing import Any

MAX_FINDINGS = 500
SEVERITY_VALUES = {"info", "low", "medium", "high", "critical", "unknown"}


def parse_nuclei_jsonl_summary(report: list[dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(report, list):
        raise ValueError("report bir JSON dizisi olmalı")

    if len(report) > MAX_FINDINGS:
        raise ValueError(f"Çok fazla bulgu (en fazla {MAX_FINDINGS})")

    record_count = len(report)
    severity_counts = {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0, "unknown": 0}
    unique_templates: set[str] = set()

    for record in report:
        if not isinstance(record, dict):
            raise ValueError("Her kayıt bir nesne olmalı")

        # Validate required fields
        template_id = record.get("template-id")
        if not isinstance(template_id, str) or not template_id:
            raise ValueError("'template-id' alanı boş olmayan bir metin olmalı")

        record_type = record.get("type")
        if not isinstance(record_type, str) or not record_type:
            raise ValueError("'type' alanı boş olmayan bir metin olmalı")

        info = record.get("info")
        if not isinstance(info, dict):
            raise ValueError("'info' alanı bir nesne olmalı")

        # Extract severity from info
        if "severity" not in info:
            # Missing severity key counts as unknown
            severity_counts["unknown"] += 1
        else:
            severity_raw = info["severity"]
            if not isinstance(severity_raw, str):
                raise ValueError("'info.severity' alanı varsa bir metin olmalı")
            # Reject uppercase or mixed-case severity values
            if severity_raw != severity_raw.lower():
                raise ValueError("'info.severity' alanı küçük harf olmalı")
            if severity_raw not in SEVERITY_VALUES:
                raise ValueError("Geçersiz önem değeri")
            severity_counts[severity_raw] += 1

        # Collect unique template IDs
        unique_templates.add(template_id)

    # Compute report SHA-256 using exact format and separators
    report_sha256 = hashlib.sha256(
        json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

    return {
        "format": "nuclei-jsonl",
        "record_count": record_count,
        "severity_counts": severity_counts,
        "unique_template_count": len(unique_templates),
        "report_sha256": report_sha256
    }
