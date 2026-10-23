from __future__ import annotations

import hashlib
import json
from typing import Any

MAX_ENDPOINTS = 500
GRADE_ENUM = ["A+", "A", "A-", "B", "C", "D", "E", "F", "T", "M"]
HOST_STATUS_ENUM = ["DNS", "ERROR", "IN_PROGRESS", "READY"]


def _ascii_dns_name(value: Any) -> str:
    """Accept one complete ASCII DNS name; never infer authorization from it."""
    import ipaddress
    import re
    import socket

    if not isinstance(value, str) or not value or not value.isascii():
        raise ValueError("Geçersiz kayıtlı rapor ana makinesi")
    if value.endswith("."):
        value = value[:-1]
    if not value or value.endswith(".") or len(value) > 253:
        raise ValueError("Geçersiz kayıtlı rapor ana makinesi")
    labels = value.lower().split(".")
    if len(labels) < 2 or any(
        len(label) > 63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in labels
    ):
        raise ValueError("Geçersiz kayıtlı rapor ana makinesi")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError("IP adresi bir DNS ana makinesi değil")
    # libc accepts shortened, octal and hexadecimal IPv4 text that ipaddress rejects.
    # Reject those forms before treating the string as a DNS name; no lookup occurs.
    try:
        socket.inet_aton(value)
    except OSError:
        pass
    else:
        raise ValueError("IP adresi bir DNS ana makinesi değil")
    for label in labels:
        if label.startswith("xn--"):
            try:
                decoded = label.encode("ascii").decode("idna")
                if decoded.encode("idna").decode("ascii").lower() != label:
                    raise ValueError("Geçersiz A-label")
            except (UnicodeError, ValueError) as exc:
                raise ValueError("Geçersiz A-label") from exc
    return ".".join(labels)


def preview_ssllabs_target_name(report_host: Any, target: dict[str, Any]) -> dict[str, Any]:
    """Compare normalized names for a narrow standard HTTPS target profile.

    This is a string-consistency preview, never scope or original-IDN proof.
    """
    report_name = _ascii_dns_name(report_host)
    try:
        target_name = _ascii_dns_name(target.get("hostname"))
    except ValueError:
        target_name = None
    supported = (
        target.get("scheme") == "https"
        and target.get("port") == 443
        and target.get("path") == "/"
        and target_name is not None
    )
    consistency = (
        "unsupported_target_profile" if not supported else
        "normalized_hostname_equal" if report_name == target_name else
        "normalized_hostname_different"
    )
    return {
        "hostname_consistency": consistency,
        "normalized_hostname_equal": consistency == "normalized_hostname_equal",
        "scope_verified": False,
        "original_hostname_identity_verified": False,
        "evidence_link_created": False,
    }


def parse_ssllabs_host_summary(report: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(report, dict):
        raise ValueError("report bir JSON nesnesi olmalı")

    # Validate required top-level keys per reviewed brief
    if "status" not in report or not isinstance(report["status"], str):
        raise ValueError("'status' alanı bir metin olmalı")
    if "endpoints" not in report or not isinstance(report["endpoints"], list):
        raise ValueError("'endpoints' alanı bir dizi olmalı")

    status = report["status"]
    if status not in HOST_STATUS_ENUM:
        raise ValueError("Geçersiz ana makine durumu")

    endpoints = report["endpoints"]
    if len(endpoints) > MAX_ENDPOINTS:
        raise ValueError(f"Çok fazla uç nokta (en fazla {MAX_ENDPOINTS})")

    # Validate each endpoint
    for ep in endpoints:
        if not isinstance(ep, dict):
            raise ValueError("Her uç nokta bir nesne olmalı")

    # Count grades (only present and non-null enum grades count; invalid grades reject)
    grade_counts = {g: 0 for g in GRADE_ENUM}
    for ep in endpoints:
        grade = ep.get("grade")
        if grade is not None:
            if not isinstance(grade, str) or grade not in GRADE_ENUM:
                raise ValueError("Geçersiz uç nokta notu")
            grade_counts[grade] += 1

    # Compute report SHA-256 using exact format and separators
    canonical = json.dumps(report, sort_keys=True, separators=(",", ":"))
    report_sha256 = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    return {
        "format": "ssllabs-v4-host",
        "assessment_status": status,
        "endpoint_count": len(endpoints),
        "grade_counts": grade_counts,
        "report_sha256": report_sha256
    }
