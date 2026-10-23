from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from tool_report_nuclei import MAX_FINDINGS, parse_nuclei_jsonl_summary

MAX_JSONL_BYTES = 256 * 1024
MAX_EXECUTED_TEMPLATES = 500
TEMPLATE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,127}$")
VERIFICATION_STATE_REQUIRED = "independent_confirmation_required"
COVERAGE_SCOPE_BOUNDED = "bounded_template_subset_only"


def _validate_template_id(template_id: Any) -> str:
    if not isinstance(template_id, str):
        raise ValueError("template_id bir metin olmalı")
    if not TEMPLATE_ID_RE.fullmatch(template_id):
        raise ValueError("template_id ^[a-z0-9][a-z0-9._/-]{0,127}$ ile eşleşmeli")
    if ".." in template_id or "//" in template_id or template_id.endswith("/"):
        raise ValueError("template_id yol aşımı veya boş bölüm içermemeli")
    return template_id


def _validate_executed_template_ids(executed_template_ids: list[str] | None) -> list[str]:
    if executed_template_ids is None:
        return []
    if not isinstance(executed_template_ids, list):
        raise ValueError("executed_template_ids şablon kimliği metinlerinden oluşan bir liste olmalı")
    if len(executed_template_ids) > MAX_EXECUTED_TEMPLATES:
        raise ValueError(f"Çok fazla executed_template_ids (en fazla {MAX_EXECUTED_TEMPLATES})")
    validated = [_validate_template_id(item) for item in executed_template_ids]
    return sorted(set(validated))


def _parse_jsonl_records(raw_jsonl: str) -> list[dict[str, Any]]:
    if not isinstance(raw_jsonl, str):
        raise ValueError("raw_jsonl bir metin olmalı")
    try:
        encoded = raw_jsonl.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError("raw_jsonl geçerli UTF-8 olmalı") from exc
    if len(encoded) > MAX_JSONL_BYTES:
        raise ValueError(f"raw_jsonl azami {MAX_JSONL_BYTES} bayt boyutunu aşıyor")

    raw_lines = raw_jsonl.splitlines()
    if len(raw_lines) > MAX_FINDINGS:
        raise ValueError(f"raw_jsonl içinde çok fazla satır (en fazla {MAX_FINDINGS})")

    records: list[dict[str, Any]] = []
    for line in raw_lines:
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError("Bozuk JSONL satırı") from exc
        if not isinstance(parsed, dict):
            raise ValueError("Her JSONL satırı bir JSON nesnesi olmalı")
        records.append(parsed)

    if len(records) > MAX_FINDINGS:
        raise ValueError(f"Çok fazla bulgu (en fazla {MAX_FINDINGS})")
    return records


def build_nuclei_verification_coverage_summary(
    raw_jsonl: str,
    *,
    executed_template_ids: list[str] | None = None,
) -> dict[str, object]:
    """Build bounded Nuclei verification and template coverage summary."""
    validated_executed = _validate_executed_template_ids(executed_template_ids)
    records = _parse_jsonl_records(raw_jsonl)
    base_summary = parse_nuclei_jsonl_summary(records)

    findings: list[dict[str, object]] = []
    matched_set: set[str] = set()

    for record in records:
        template_id = _validate_template_id(record.get("template-id"))
        record_type = str(record.get("type", "")).strip()
        if not record_type or len(record_type) > 64:
            raise ValueError("'type' alanı en fazla 64 karakterlik boş olmayan bir metin olmalı")
        info = record["info"]
        severity = info.get("severity", "unknown")
        matched_set.add(template_id)
        findings.append(
            {
                "template_id": template_id,
                "type": record_type,
                "severity": severity,
                "verification_state": VERIFICATION_STATE_REQUIRED,
            }
        )

    matched_template_ids = sorted(matched_set)
    unmatched_executed_template_ids = [
        tid for tid in validated_executed if tid not in matched_set
    ]
    finding_count = len(findings)
    unverified_finding_count = sum(
        1 for item in findings if item["verification_state"] == VERIFICATION_STATE_REQUIRED
    )

    summary_fields: dict[str, object] = {
        "format": "nuclei-verification-coverage-v1",
        "coverage_scope": COVERAGE_SCOPE_BOUNDED,
        "verification_policy": VERIFICATION_STATE_REQUIRED,
        "finding_count": finding_count,
        "unverified_finding_count": unverified_finding_count,
        "severity_counts": base_summary["severity_counts"],
        "matched_template_ids": matched_template_ids,
        "executed_template_ids": validated_executed,
        "executed_template_count": len(validated_executed),
        "unmatched_executed_template_ids": unmatched_executed_template_ids,
        "unmatched_executed_template_count": len(unmatched_executed_template_ids),
        "findings": findings,
        "report_sha256": base_summary["report_sha256"],
    }

    summary_sha256 = hashlib.sha256(
        json.dumps(summary_fields, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    return {
        **summary_fields,
        "summary_sha256": summary_sha256,
    }
