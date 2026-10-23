from __future__ import annotations

import json
from typing import Any

MAX_FINDINGS = 500
REQUIRED_FIELDS = ["DetectorName", "Verified"]


def parse_trufflehog_json_summary(report: list[dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(report, list):
        raise ValueError("report bir JSON dizisi olmalı")

    if len(report) > MAX_FINDINGS:
        raise ValueError(f"Çok fazla bulgu (en fazla {MAX_FINDINGS})")

    total_findings = len(report)
    verified_findings = 0
    unverified_findings = 0
    detectors_triggered: set[str] = set()

    for finding in report:
        if not isinstance(finding, dict):
            raise ValueError("Her bulgu bir nesne olmalı")

        # Validate required fields
        for field in REQUIRED_FIELDS:
            if field not in finding:
                raise ValueError(f"Gerekli alan eksik: {field}")

        detector_name = finding.get("DetectorName")
        verified = finding.get("Verified")

        if not isinstance(detector_name, str):
            raise ValueError("'DetectorName' alanı bir metin olmalı")
        if not isinstance(verified, bool):
            raise ValueError("'Verified' alanı bir mantıksal değer olmalı")

        # Count verified/unverified
        if verified:
            verified_findings += 1
        else:
            unverified_findings += 1

        # Collect distinct non-empty detector names
        if detector_name:
            detectors_triggered.add(detector_name)

    return {
        "format": "trufflehog-native-json-records",
        "total_findings": total_findings,
        "verified_findings": verified_findings,
        "unverified_findings": unverified_findings,
        "detectors_triggered": len(detectors_triggered)
    }
