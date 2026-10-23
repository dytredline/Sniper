"""Offline scope and boundary verifier for SSL Labs, testssl.sh loopback, and Trivy DB freshness.

Enforces explicit scope boundaries documented in SNIPER-KALAN-ISLER-2026-10-17.md:
- SSL Labs operates strictly on saved host assessment reports; live network queries are disabled.
- testssl.sh active checks are restricted to IPv4 loopback (127.0.0.1:<port>); external HTTPS targets are denied.
- Trivy vulnerability database freshness is evaluated offline from metadata.json timestamps relative to a reference UTC clock.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import math
import re

from tool_report_ssllabs import parse_ssllabs_host_summary

MAX_REPORT_BYTES = 2_000_000
MAX_AGE_LIMIT_HOURS = 87_600
_LOOPBACK_TARGET_RE = re.compile(r"^127\.0\.0\.1:([1-9][0-9]{0,4})\Z", re.ASCII)
_ISO_UTC_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|\+00:00)\Z",
    re.ASCII,
)


def _parse_iso_utc(raw: object, label: str) -> datetime:
    if not isinstance(raw, str):
        raise ValueError(f"Geçersiz {label} zaman damgası")
    match = _ISO_UTC_RE.fullmatch(raw.strip())
    if match is None:
        raise ValueError(f"Geçersiz {label} ISO-8601 UTC zaman damgası")
    base, frac, _tz = match.groups()
    if frac:
        micros = (frac + "000000")[:6]
        iso_str = f"{base}.{micros}+00:00"
    else:
        iso_str = f"{base}+00:00"
    try:
        parsed = datetime.fromisoformat(iso_str)
    except ValueError as exc:
        raise ValueError(f"Geçersiz {label} takvim zaman damgası") from exc
    if parsed.tzinfo != timezone.utc:
        raise ValueError(f"Geçersiz {label} saat dilimi")
    return parsed


def verify_tls_workflow_boundary(
    mode: str,
    *,
    target: str | None = None,
    report_json: str | None = None,
) -> dict[str, object]:
    """Verify SSL Labs offline saved-report boundary or testssl loopback-only target boundary."""
    if not isinstance(mode, str):
        raise ValueError("Geçersiz TLS iş akışı kipi")

    if mode == "ssllabs-saved-report":
        if target is not None:
            raise ValueError("SSL Labs canlı sorguları devre dışı")
        if not isinstance(report_json, str) or not report_json.strip():
            raise ValueError("Kayıtlı SSL Labs report_json alanı gerekli")
        if len(report_json.encode("utf-8")) > MAX_REPORT_BYTES:
            raise ValueError("Kayıtlı SSL Labs report_json azami boyutu aşıyor")
        try:
            parsed_report = json.loads(report_json)
        except ValueError as exc:
            raise ValueError("Geçersiz SSL Labs rapor JSON'u") from exc
        summary = parse_ssllabs_host_summary(parsed_report)
        return {
            **summary,
            "mode": "ssllabs-saved-report",
            "execution_policy": "offline_saved_report_only",
            "live_query_allowed": False,
        }

    if mode == "testssl-loopback":
        if report_json is not None:
            raise ValueError("testssl-loopback için report_json kabul edilmez")
        if not isinstance(target, str) or not target.strip():
            raise ValueError("Harici HTTPS hedefleri testssl loopback kapsamı dışında")
        if not target.startswith("127.0.0.1:"):
            raise ValueError("Harici HTTPS hedefleri testssl loopback kapsamı dışında")
        match = _LOOPBACK_TARGET_RE.fullmatch(target)
        if match is None:
            raise ValueError("testssl için geçersiz loopback portu")
        port = int(match.group(1))
        if not (1 <= port <= 65535):
            raise ValueError("testssl için geçersiz loopback portu")
        return {
            "mode": "testssl-loopback",
            "execution_policy": "loopback_only",
            "approved_host": "127.0.0.1",
            "approved_port": port,
            "target": f"127.0.0.1:{port}",
            "external_https_allowed": False,
        }

    raise ValueError("Desteklenmeyen TLS iş akışı kipi")


def verify_trivy_offline_db_freshness(
    metadata_json: str,
    *,
    reference_utc: str,
    max_age_hours: int = 168,
) -> dict[str, object]:
    """Evaluate offline Trivy vulnerability DB freshness from metadata.json without path disclosure."""
    if (
        not isinstance(max_age_hours, (int, float))
        or isinstance(max_age_hours, bool)
        or not math.isfinite(float(max_age_hours))
        or max_age_hours <= 0
        or max_age_hours > MAX_AGE_LIMIT_HOURS
    ):
        raise ValueError("max_age_hours pozitif bir sayı olmalı")

    if not isinstance(metadata_json, str) or not metadata_json.strip():
        raise ValueError("metadata_json boş olmayan bir JSON metni olmalı")
    if len(metadata_json.encode("utf-8")) > MAX_REPORT_BYTES:
        raise ValueError("metadata_json azami boyutu aşıyor")
    try:
        metadata = json.loads(metadata_json)
    except ValueError as exc:
        raise ValueError("Geçersiz Trivy meta veri JSON'u") from exc
    if not isinstance(metadata, dict):
        raise ValueError("Trivy meta verisi bir JSON nesnesi olmalı")

    version = metadata.get("Version")
    if type(version) is not int or version < 1:
        raise ValueError("Geçersiz Trivy veritabanı Version değeri")

    updated_at = _parse_iso_utc(metadata.get("UpdatedAt"), "UpdatedAt")
    next_update = _parse_iso_utc(metadata.get("NextUpdate"), "NextUpdate")
    reference_dt = _parse_iso_utc(reference_utc, "reference_utc")

    if next_update < updated_at:
        raise ValueError("NextUpdate, UpdatedAt değerinden önce olamaz")
    age_seconds = (reference_dt - updated_at).total_seconds()
    if age_seconds < 0:
        raise ValueError("reference_utc, UpdatedAt değerinden önce olamaz")

    age_hours = age_seconds / 3600.0
    is_fresh = age_hours <= max_age_hours
    return {
        "format": "trivy-db-freshness-v1",
        "schema_version": version,
        "age_hours": round(age_hours, 2),
        "is_fresh": is_fresh,
        "max_age_hours": max_age_hours,
        "freshness_state": "fresh" if is_fresh else "stale_offline_db",
    }
