"""Interpret a saved, local OpenSSL x509 report without executing OpenSSL."""

from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import datetime, timezone

MAX_SINGLE_REPORT_BYTES = 4096
MAX_BATCH_PAYLOAD_BYTES = 65536
MIN_BATCH_REPORTS = 1
MAX_BATCH_REPORTS = 8

_MONTHS = {
    name: index
    for index, name in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1
    )
}
_DATE = re.compile(
    r"^(notBefore|notAfter)=([A-Z][a-z]{2}) +([0-9]{1,2}) "
    r"([0-9]{2}):([0-9]{2}):([0-9]{2}) ([0-9]{4}) GMT$"
)
_FINGERPRINT = re.compile(r"^sha256 Fingerprint=(?:[0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}$")
_FORBIDDEN_LINE_CHARS = ("\x00", "\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029")


def _encode_strict_utf8(value: str, *, max_bytes: int, error_message: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError(error_message)
    if any(ch in value for ch in _FORBIDDEN_LINE_CHARS):
        raise ValueError(error_message)
    if "\r" in value.replace("\r\n", ""):
        raise ValueError(error_message)
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError(error_message) from exc
    if len(encoded) > max_bytes:
        raise ValueError(error_message)
    return encoded


def parse_openssl_x509_summary(report: str, *, now: datetime | None = None) -> dict:
    """Summarize `openssl x509 -noout -dates -fingerprint -sha256` stdout.

    The report is never saved, echoed, or passed to a subprocess. Only the
    three expected lines are accepted so certificate subject/host data cannot
    accidentally be reflected in a response. Exact input UTF-8 bytes are hashed.
    """
    encoded = _encode_strict_utf8(
        report,
        max_bytes=MAX_SINGLE_REPORT_BYTES,
        error_message="Geçersiz OpenSSL x509 raporu.",
    )
    if report.endswith(("\n\n", "\r\n\r\n", "\n\r\n", "\r\n\n")):
        raise ValueError("Geçersiz OpenSSL x509 raporu.")
    lines = report.splitlines()
    if len(lines) != 3:
        raise ValueError("Geçersiz OpenSSL x509 raporu.")
    dates = {}
    fingerprint_seen = False
    for line in lines:
        matched = _DATE.fullmatch(line)
        if matched:
            label, month, day, hour, minute, second, year = matched.groups()
            if label in dates or month not in _MONTHS:
                raise ValueError("Geçersiz OpenSSL x509 raporu.")
            try:
                dates[label] = datetime(
                    int(year),
                    _MONTHS[month],
                    int(day),
                    int(hour),
                    int(minute),
                    int(second),
                    tzinfo=timezone.utc,
                )
            except ValueError as exc:
                raise ValueError("Geçersiz OpenSSL x509 raporu.") from exc
        elif _FINGERPRINT.fullmatch(line) and not fingerprint_seen:
            fingerprint_seen = True
        else:
            raise ValueError("Geçersiz OpenSSL x509 raporu.")
    if set(dates) != {"notBefore", "notAfter"} or not fingerprint_seen:
        raise ValueError("Geçersiz OpenSSL x509 raporu.")
    before, after = dates["notBefore"], dates["notAfter"]
    if before >= after:
        raise ValueError("Geçersiz OpenSSL x509 raporu.")
    instant = now or datetime.now(timezone.utc)
    if instant.tzinfo is None:
        raise ValueError("Geçersiz değerlendirme zamanı.")
    instant = instant.astimezone(timezone.utc)
    remaining = (after - instant).total_seconds()
    if instant < before:
        validity = "not_yet_valid"
    elif remaining <= 0:
        validity = "expired"
    elif remaining <= 30 * 86400:
        validity = "expiring_soon"
    else:
        validity = "valid"
    return {
        "format": "openssl-x509-dates-fingerprint-v1",
        "validity": validity,
        "not_before_utc": before.isoformat().replace("+00:00", "Z"),
        "not_after_utc": after.isoformat().replace("+00:00", "Z"),
        "days_until_expiry": max(0, math.ceil(remaining / 86400)),
        "report_sha256": hashlib.sha256(encoded).hexdigest(),
    }


def count_byte_identical_duplicate_reports(reports: list[str]) -> int:
    """Count extra byte-identical report occurrences in a validated batch.

    Equality compares complete supplied report strings byte-for-byte, not
    certificate fingerprints or parsed validity dates.
    """
    if not isinstance(reports, list) or not (MIN_BATCH_REPORTS <= len(reports) <= MAX_BATCH_REPORTS):
        raise ValueError("Geçersiz OpenSSL x509 rapor grubu.")
    for item in reports:
        if not isinstance(item, str):
            raise ValueError("Geçersiz OpenSSL x509 raporu.")
    return len(reports) - len(set(reports))


def split_openssl_x509_batch_reports(
    raw_batch: str | list[str],
    *,
    preserve_exact_bytes: bool = True,
) -> list[str]:
    """Parse 1..8 saved 3-line OpenSSL x509 reports from a list, JSON wrapper, or text.

    When `preserve_exact_bytes=True` (default), single-report plain text, JSON array
    elements, and blank-line-separated blocks preserve their original line endings and
    terminal newline presence without appending synthetic trailing LF bytes.
    """
    if isinstance(raw_batch, list):
        reports = list(raw_batch)
    elif isinstance(raw_batch, str):
        _encode_strict_utf8(
            raw_batch,
            max_bytes=MAX_BATCH_PAYLOAD_BYTES,
            error_message="Geçersiz OpenSSL x509 rapor grubu.",
        )
        stripped = raw_batch.strip()
        if not stripped:
            raise ValueError("Geçersiz OpenSSL x509 rapor grubu.")
        if stripped.startswith("[") or stripped.startswith("{"):
            try:
                parsed = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError("Geçersiz OpenSSL x509 rapor grubu.") from exc
            if isinstance(parsed, list):
                reports = parsed
            elif isinstance(parsed, dict) and set(parsed.keys()) == {"reports"} and isinstance(parsed.get("reports"), list):
                reports = parsed["reports"]
            else:
                raise ValueError("Geçersiz OpenSSL x509 rapor grubu.")
        elif preserve_exact_bytes:
            if raw_batch.endswith(("\n\n", "\r\n\r\n", "\n\r\n", "\r\n\n")):
                raise ValueError("Geçersiz OpenSSL x509 rapor grubu.")
            # Preserve exact pasted bytes for single 3-line report (including trailing LF/CRLF if present).
            if len(raw_batch.splitlines()) == 3:
                reports = [raw_batch]
            else:
                blocks = re.split(r"(?:\r?\n){2,}", stripped)
                if len(blocks) == 1:
                    lines_keepends = stripped.splitlines(keepends=True)
                    if len(lines_keepends) < 3 or len(lines_keepends) % 3 != 0:
                        raise ValueError("Geçersiz OpenSSL x509 rapor grubu.")
                    reports = [
                        "".join(lines_keepends[idx : idx + 3])
                        for idx in range(0, len(lines_keepends), 3)
                    ]
                else:
                    reports = blocks
        else:
            normalized = raw_batch.replace("\r\n", "\n").strip()
            blocks = re.split(r"\n\s*\n+", normalized)
            if len(blocks) == 1:
                lines = blocks[0].split("\n")
                if len(lines) < 3 or len(lines) % 3 != 0:
                    raise ValueError("Geçersiz OpenSSL x509 rapor grubu.")
                reports = [
                    "\n".join(lines[idx : idx + 3]) + "\n"
                    for idx in range(0, len(lines), 3)
                ]
            else:
                reports = []
                for block in blocks:
                    block_lines = block.split("\n")
                    if len(block_lines) != 3:
                        raise ValueError("Geçersiz OpenSSL x509 rapor grubu.")
                    reports.append("\n".join(block_lines) + "\n")
    else:
        raise ValueError("Geçersiz OpenSSL x509 rapor grubu.")

    if not isinstance(reports, list) or not (MIN_BATCH_REPORTS <= len(reports) <= MAX_BATCH_REPORTS):
        raise ValueError("Geçersiz OpenSSL x509 rapor grubu.")
    for item in reports:
        if not isinstance(item, str):
            raise ValueError("Geçersiz OpenSSL x509 raporu.")
        _encode_strict_utf8(
            item,
            max_bytes=MAX_SINGLE_REPORT_BYTES,
            error_message="Geçersiz OpenSSL x509 raporu.",
        )
        if item.endswith(("\n\n", "\r\n\r\n", "\n\r\n", "\r\n\n")) or len(item.splitlines()) != 3:
            raise ValueError("Geçersiz OpenSSL x509 rapor grubu.")
    canonical_body = json.dumps({"reports": reports}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(canonical_body) > MAX_BATCH_PAYLOAD_BYTES:
        raise ValueError("Geçersiz OpenSSL x509 rapor grubu.")
    return reports


def parse_openssl_x509_batch_summary(
    reports: list[str],
    *,
    now: datetime | None = None,
    include_duplicate_count: bool = False,
) -> dict:
    """Summarize a batch of 1..8 OpenSSL x509 reports.

    Returns format/report_count/validity_counts/batch_sha256 only by default
    (and `duplicate_report_count` when `include_duplicate_count=True`).
    No raw report, per-item dates/fingerprints, or persistence.
    """
    if not isinstance(reports, list):
        raise ValueError("Geçersiz OpenSSL x509 rapor grubu.")
    if not (MIN_BATCH_REPORTS <= len(reports) <= MAX_BATCH_REPORTS):
        raise ValueError("Geçersiz OpenSSL x509 rapor grubu.")
    for r in reports:
        if not isinstance(r, str) or not r or len(r.encode("utf-8", errors="ignore")) > MAX_SINGLE_REPORT_BYTES:
            raise ValueError("Geçersiz OpenSSL x509 raporu.")
        _encode_strict_utf8(
            r,
            max_bytes=MAX_SINGLE_REPORT_BYTES,
            error_message="Geçersiz OpenSSL x509 raporu.",
        )
        if r.endswith(("\n\n", "\r\n\r\n", "\n\r\n", "\r\n\n")) or len(r.splitlines()) != 3:
            raise ValueError("Geçersiz OpenSSL x509 raporu.")

    instant = now or datetime.now(timezone.utc)
    if instant.tzinfo is None:
        raise ValueError("Geçersiz değerlendirme zamanı.")
    instant = instant.astimezone(timezone.utc)

    validity_counts = {"valid": 0, "expiring_soon": 0, "expired": 0, "not_yet_valid": 0}
    for r in reports:
        summary = parse_openssl_x509_summary(r, now=instant)
        validity_counts[summary["validity"]] += 1

    canonical = json.dumps(reports, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    batch_sha256 = hashlib.sha256(canonical).hexdigest()

    result = {
        "format": "openssl-x509-batch-summary-v1",
        "report_count": len(reports),
        "validity_counts": validity_counts,
        "batch_sha256": batch_sha256,
    }
    if include_duplicate_count:
        result["duplicate_report_count"] = count_byte_identical_duplicate_reports(reports)
    return result


def parse_openssl_x509_batch_fidelity_summary(
    raw_batch: str | list[str],
    *,
    now: datetime | None = None,
    preserve_exact_bytes: bool = True,
) -> dict:
    """Summarize 1..8 OpenSSL x509 reports with byte-fidelity preservation and duplicate counts."""
    reports = split_openssl_x509_batch_reports(raw_batch, preserve_exact_bytes=preserve_exact_bytes)
    summary = parse_openssl_x509_batch_summary(
        reports,
        now=now,
        include_duplicate_count=True,
    )
    summary["report_sha256_list"] = [
        hashlib.sha256(item.encode("utf-8")).hexdigest() for item in reports
    ]
    return summary
