from __future__ import annotations

import json
from typing import Any

MAX_FINDINGS = 500
REQUIRED_FIELDS = ["RuleID", "File", "Match", "Secret"]


def parse_gitleaks_json_summary(report: list[dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(report, list):
        raise ValueError("report bir JSON dizisi olmalı")

    if len(report) > MAX_FINDINGS:
        raise ValueError(f"Çok fazla bulgu (en fazla {MAX_FINDINGS})")

    total_findings = len(report)
    rules_triggered: set[str] = set()
    files_affected: set[str] = set()

    for finding in report:
        if not isinstance(finding, dict):
            raise ValueError("Her bulgu bir nesne olmalı")

        # Validate required fields
        for field in REQUIRED_FIELDS:
            if field not in finding:
                raise ValueError(f"Gerekli alan eksik: {field}")
            if not isinstance(finding[field], str):
                raise ValueError(f"'{field}' alanı bir metin olmalı")

        # Collect distinct non-empty values
        rule_id = finding["RuleID"]
        file_path = finding["File"]
        if rule_id:
            rules_triggered.add(rule_id)
        if file_path:
            files_affected.add(file_path)

    return {
        "format": "gitleaks-native-json",
        "total_findings": total_findings,
        "rules_triggered": len(rules_triggered),
        "files_affected": len(files_affected)
    }
