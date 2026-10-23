from __future__ import annotations

import hashlib
import json
from typing import Any

MAX_FINDINGS = 500
SEVERITY_VALUES = {"ERROR", "WARNING", "EXPERIMENT", "INVENTORY", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


def parse_semgrep_native_json_summary(report: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(report, dict):
        raise ValueError("report bir JSON nesnesi olmalı")

    # Validate required top-level keys
    if not isinstance(report.get("results"), list):
        raise ValueError("'results' alanı bir dizi olmalı")
    if not isinstance(report.get("errors"), list):
        raise ValueError("'errors' alanı bir dizi olmalı")
    if not isinstance(report.get("paths"), dict):
        raise ValueError("'paths' alanı bir nesne olmalı")

    # Validate paths.scanned is an array of strings
    paths_scanned = report["paths"].get("scanned")
    if not isinstance(paths_scanned, list):
        raise ValueError("'paths.scanned' alanı bir dizi olmalı")
    for item in paths_scanned:
        if not isinstance(item, str):
            raise ValueError("'paths.scanned' içindeki her öğe bir metin olmalı")

    results = report["results"]
    if len(results) > MAX_FINDINGS:
        raise ValueError(f"Çok fazla bulgu (en fazla {MAX_FINDINGS})")

    # Count results
    result_count = len(results)

    # Initialize severity counts with all allowed values set to zero
    severity_counts = {sev: 0 for sev in SEVERITY_VALUES}

    # Validate each result and count severities
    for result in results:
        if not isinstance(result, dict):
            raise ValueError("Her sonuç bir nesne olmalı")

        # Validate required top-level fields
        if not isinstance(result.get("check_id"), str):
            raise ValueError("'check_id' alanı bir metin olmalı")
        if not isinstance(result.get("path"), str):
            raise ValueError("'path' alanı bir metin olmalı")
        if not isinstance(result.get("start"), dict):
            raise ValueError("'start' alanı bir nesne olmalı")
        if not isinstance(result.get("end"), dict):
            raise ValueError("'end' alanı bir nesne olmalı")
        if not isinstance(result.get("extra"), dict):
            raise ValueError("'extra' alanı bir nesne olmalı")

        start_pos = result["start"]
        if not isinstance(start_pos.get("line"), int) or isinstance(start_pos.get("line"), bool):
            raise ValueError("'start.line' alanı bir tamsayı olmalı")
        if not isinstance(start_pos.get("col"), int) or isinstance(start_pos.get("col"), bool):
            raise ValueError("'start.col' alanı bir tamsayı olmalı")

        end_pos = result["end"]
        if not isinstance(end_pos.get("line"), int) or isinstance(end_pos.get("line"), bool):
            raise ValueError("'end.line' alanı bir tamsayı olmalı")
        if not isinstance(end_pos.get("col"), int) or isinstance(end_pos.get("col"), bool):
            raise ValueError("'end.col' alanı bir tamsayı olmalı")

        extra = result["extra"]
        if not isinstance(extra.get("message"), str):
            raise ValueError("'extra.message' alanı bir metin olmalı")
        # Accept metadata as any JSON value per raw_json schema; null is permitted, missing is invalid
        if "metadata" not in extra:
            raise ValueError("'extra.metadata' alanı bulunmalı")
        if not isinstance(extra.get("fingerprint"), str):
            raise ValueError("'extra.fingerprint' alanı bir metin olmalı")
        if not isinstance(extra.get("lines"), str):
            raise ValueError("'extra.lines' alanı bir metin olmalı")

        severity_raw = extra.get("severity")
        if not isinstance(severity_raw, str):
            raise ValueError("'extra.severity' alanı bir metin olmalı")
        if severity_raw not in SEVERITY_VALUES:
            raise ValueError("Geçersiz önem değeri")
        severity_counts[severity_raw] += 1

    # Compute report SHA-256 using exact format and separators
    report_sha256 = hashlib.sha256(
        json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

    return {
        "format": "semgrep-native-json",
        "result_count": result_count,
        "severity_counts": severity_counts,
        "report_sha256": report_sha256
    }
