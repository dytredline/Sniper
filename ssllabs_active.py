"""Explicitly consented, single-request SSL Labs analyze client.

This uses the upstream `fromCache=on` preference, which may start an assessment
on a cache miss. It is never run by page load or readiness checks."""
from __future__ import annotations

import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import re
import ssl
import threading
from urllib.parse import urlencode

from tool_report_ssllabs import parse_ssllabs_host_summary

API_HOST = "api.ssllabs.com"
API_PATH = "/api/v4/analyze"
MAX_RESPONSE_BYTES = 1024 * 1024
REQUEST_TIMEOUT_SECONDS = 12
_EMAIL = re.compile(r"[^\s@\r\n]+@[^\s@\r\n]+\.[^\s@\r\n]+\Z", re.ASCII)
_OPERATOR_TOKEN = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z", re.ASCII)
_QUERY_LOCK = threading.Lock()


class SSLLabsUnavailable(RuntimeError):
    pass


class SSLLabsBusy(RuntimeError):
    pass


class SSLLabsUpstreamError(RuntimeError):
    def __init__(self, status: int):
        super().__init__("SSL Labs upstream request failed")
        self.status = status


class SSLLabsInvalidResponse(RuntimeError):
    pass


def registered_email() -> str | None:
    """Return a syntactically valid, pre-registered organization email only."""
    value = os.environ.get("SNIPER_SSLLABS_EMAIL", "")
    if not value or len(value) > 254 or not value.isascii() or not _EMAIL.fullmatch(value):
        return None
    return value


def registered_operator_token_digest() -> str | None:
    """Return only a configured SHA-256 digest; the raw operator token stays client-side."""
    value = os.environ.get("SNIPER_SSLLABS_OPERATOR_TOKEN_SHA256", "")
    return value if _OPERATOR_TOKEN.fullmatch(value) else None


def operator_token_matches(candidate: object) -> bool:
    """Constant-time validation of a 64-hex bearer token against its server-side digest."""
    expected = registered_operator_token_digest()
    if not isinstance(candidate, str) or not _OPERATOR_TOKEN.fullmatch(candidate) or expected is None:
        return False
    actual = hashlib.sha256(candidate.encode("ascii")).hexdigest()
    return hmac.compare_digest(actual, expected)


def live_query_enabled() -> bool:
    """Read-only readiness check; configuration does not make a network request."""
    return (os.environ.get("SNIPER_SSLLABS_LIVE_ENABLED") == "true"
            and registered_email() is not None
            and registered_operator_token_digest() is not None)


def normalize_public_hostname(value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or not value.isascii():
        raise ValueError("geçersiz ana makine adı")
    host = value.lower()
    if host.endswith("."):
        host = host[:-1]
    if (not host or len(host) > 253 or host.startswith("*.") or
            any(ch in host for ch in "/:?#@\\%\x00\r\n\t ")):
        raise ValueError("geçersiz ana makine adı")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("IP adresi değerleri desteklenmiyor")
    labels = host.split(".")
    if len(labels) < 2 or any(not _LABEL.fullmatch(label) for label in labels):
        raise ValueError("geçersiz ana makine adı")
    return host


def _safe_summary(report: dict) -> dict:
    if not isinstance(report, dict):
        raise SSLLabsInvalidResponse("geçersiz üst sunucu yanıtı")
    try:
        parsed = parse_ssllabs_host_summary(report)
    except (TypeError, ValueError, RecursionError):
        raise SSLLabsInvalidResponse("geçersiz üst sunucu yanıtı") from None
    endpoints = report["endpoints"]
    for endpoint in endpoints:
        status_message = endpoint.get("statusMessage")
        if status_message is not None and not isinstance(status_message, str):
            raise SSLLabsInvalidResponse("geçersiz üst sunucu yanıtı")
    summary = {
        "format": "ssllabs-v4-host",
        "assessment_status": parsed["assessment_status"],
        "endpoint_count": parsed["endpoint_count"],
        "successful_endpoint_count": sum(
            1 for endpoint in endpoints if endpoint.get("statusMessage") == "Ready"
        ),
        "grade_counts": parsed["grade_counts"],
        "cache_miss_may_start_assessment": True,
    }
    digest_input = {
        key: summary[key]
        for key in (
            "format", "assessment_status", "endpoint_count",
            "successful_endpoint_count", "grade_counts",
        )
    }
    canonical = json.dumps(digest_input, sort_keys=True, separators=(",", ":"))
    summary["summary_sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return summary


def _map_upstream_status(status: int) -> int:
    if status == 429:
        return 429
    if status == 441 or status in {503, 529}:
        return 503
    return 502


def run_ssllabs_cached_query(hostname: str) -> dict:
    """Make at most one fixed-origin API request, only after caller consent."""
    host = normalize_public_hostname(hostname)
    email = registered_email()
    if os.environ.get("SNIPER_SSLLABS_LIVE_ENABLED") != "true" or email is None:
        raise SSLLabsUnavailable("SSL Labs canlı sorgusu yapılandırılmamış")
    if not _QUERY_LOCK.acquire(blocking=False):
        raise SSLLabsBusy("Bir SSL Labs isteği zaten etkin")
    connection = None
    try:
        connection = http.client.HTTPSConnection(
            API_HOST, timeout=REQUEST_TIMEOUT_SECONDS, context=ssl.create_default_context()
        )
        path = API_PATH + "?" + urlencode({"host": host, "fromCache": "on", "all": "done"})
        connection.request("GET", path, headers={"email": email, "Accept": "application/json"})
        response = connection.getresponse()
        status = int(response.status)
        if status != 200:
            raise SSLLabsUpstreamError(_map_upstream_status(status))
        length = response.getheader("Content-Length")
        if length is not None:
            try:
                if int(length) < 0 or int(length) > MAX_RESPONSE_BYTES:
                    raise SSLLabsInvalidResponse("üst sunucu yanıtı çok büyük")
            except ValueError:
                raise SSLLabsInvalidResponse("geçersiz üst sunucu yanıt uzunluğu") from None
        raw = response.read(MAX_RESPONSE_BYTES + 1)
        if not isinstance(raw, (bytes, bytearray)) or len(raw) > MAX_RESPONSE_BYTES:
            raise SSLLabsInvalidResponse("üst sunucu yanıtı çok büyük")
        try:
            report = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            raise SSLLabsInvalidResponse("geçersiz üst sunucu yanıtı") from None
        return _safe_summary(report)
    except SSLLabsUpstreamError:
        raise
    except SSLLabsInvalidResponse:
        raise
    except (OSError, http.client.HTTPException, ssl.SSLError, TimeoutError):
        raise SSLLabsUpstreamError(504) from None
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
        _QUERY_LOCK.release()
