"""Bounded, opt-in SSL Labs API v4 assessment against a stored public TLS hostname.

The Qualys API call runs on Qualys infrastructure. This module does not register
accounts, choose hosts from HTTP input, follow redirects, or expose raw results.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import re
import ssl
import threading
import time
from urllib.parse import urlencode, urlsplit

from tool_report_ssllabs import parse_ssllabs_host_summary
import ssllabs_rate_state as _rate

API_HOST = "api.ssllabs.com"
API_PATH = "/api/v4/analyze"
INFO_PATH = "/api/v4/info"
REQUEST_TIMEOUT_SECONDS = 8
MAX_RESPONSE_BYTES = 2_000_000
MAX_CALLS = 6
MAX_ELAPSED_SECONDS = 100
RESTART_COOLDOWN_SECONDS = 3600
_DOMAIN_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_EMAIL = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_\x60{|}~-]+@[A-Za-z0-9.-]+\Z")
_NONPUBLIC_SUFFIXES = (".localhost", ".local", ".internal", ".test", ".invalid", ".onion")
_RUN_LOCK = threading.Lock()
_LAST_START: dict[str, float] = {}
_BACKOFF_LOCK = threading.Lock()
_BACKOFF_BY_HOST: dict[str, float] = {}
_GLOBAL_BACKOFF_UNTIL = 0.0
SERVICE_BACKOFF_SECONDS = 15 * 60
OVERLOADED_BACKOFF_SECONDS = 30 * 60


class SSLLabsInvalid(ValueError):
    pass


class SSLLabsBusy(RuntimeError):
    pass


class SSLLabsUnavailable(RuntimeError):
    pass


class SSLLabsUpstreamError(RuntimeError):
    pass


class SSLLabsRateLimited(RuntimeError):
    pass


def validate_hostname(hostname: str) -> str:
    """Require a canonical public DNS name, not an IP, URL, or local alias."""
    if not isinstance(hostname, str) or not hostname or len(hostname) > 253:
        raise SSLLabsInvalid("Geçersiz genel DNS ana makine adı.")
    if hostname != hostname.lower() or hostname.endswith(".") or any(ord(c) > 127 for c in hostname):
        raise SSLLabsInvalid("Ana makine adı kanonik ASCII DNS biçiminde olmalı.")
    if any(c in hostname for c in ("/", "\\", ":", "@", "?", "#", "%", " ", "\r", "\n")):
        raise SSLLabsInvalid("Geçersiz ana makine adı sözdizimi.")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise SSLLabsInvalid("IP adresi değerleri desteklenmiyor.")
    labels = hostname.split(".")
    if len(labels) < 2 or any(not _DOMAIN_LABEL.fullmatch(label) for label in labels):
        raise SSLLabsInvalid("Geçersiz genel DNS ana makine adı.")
    if hostname.endswith(_NONPUBLIC_SUFFIXES) or hostname in {"localhost", "localdomain"}:
        raise SSLLabsInvalid("Genel olmayan DNS adı desteklenmiyor.")
    if labels[-1].isdigit() or (len(labels[-1]) < 2 and not labels[-1].startswith("xn--")):
        raise SSLLabsInvalid("Geçersiz genel DNS soneki.")
    return hostname


def validate_registered_email(value: str) -> str:
    if not isinstance(value, str) or len(value) > 254 or not _EMAIL.fullmatch(value):
        raise SSLLabsInvalid("Kayıtlı kurum e-postası yapılandırılmamış.")
    if ".." in value or value.startswith(".") or value.split("@", 1)[1].startswith("."):
        raise SSLLabsInvalid("Kayıtlı kurum e-postası yapılandırılmamış.")
    return value


def validate_stored_tls_target(target: dict) -> str:
    """Reject noncanonical stored targets before the runner can initiate a request."""
    if not isinstance(target, dict):
        raise SSLLabsInvalid("Geçersiz kayıtlı TLS hedefi.")
    from scanner import normalize_target, TargetRejected
    raw = target.get("url")
    if not isinstance(raw, str) or not raw:
        raise SSLLabsInvalid("Geçersiz kayıtlı TLS hedefi.")
    try:
        normalized = normalize_target(raw)
        parsed = urlsplit(raw)
    except (TargetRejected, ValueError) as exc:
        raise SSLLabsInvalid("Geçersiz kayıtlı TLS hedefi.") from exc
    hostname = validate_hostname(normalized.hostname)
    if (
        raw != normalized.url
        or normalized.scheme != "https"
        or normalized.port != 443
        or normalized.path != "/"
        or parsed.query
        or parsed.fragment
        or target.get("scheme") != "https"
        or target.get("hostname") != hostname
        or target.get("port") != 443
        or target.get("path") != "/"
    ):
        raise SSLLabsInvalid("Kayıtlı hedef 443 portunda kanonik bir HTTPS kök kökeni olmalı.")
    return hostname


def _default_transport(url: str, headers: dict[str, str], timeout_seconds: int, allow_redirects: bool):
    """HTTPS-only fixed-origin transport. HTTP 3xx is returned, never followed."""
    parsed = urlsplit(url)
    if (allow_redirects is not False or parsed.scheme != "https" or parsed.hostname != API_HOST
            or parsed.port not in (None, 443) or parsed.path not in (API_PATH, INFO_PATH)
            or parsed.username is not None or parsed.password is not None):
        raise SSLLabsInvalid("Geçersiz SSL Labs API uç noktası.")
    if not isinstance(timeout_seconds, (int, float)) or not 0 < timeout_seconds <= REQUEST_TIMEOUT_SECONDS:
        raise SSLLabsInvalid("Geçersiz istek zaman aşımı.")
    connection = http.client.HTTPSConnection(
        API_HOST, 443, timeout=timeout_seconds, context=ssl.create_default_context()
    )
    try:
        path = parsed.path + ("?" + parsed.query if parsed.query else "")
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        body = response.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES:
            raise SSLLabsUpstreamError("SSL Labs yanıtı boyut sınırını aştı.")
        response_headers = {key.lower(): value for key, value in response.getheaders()}
        if response.status != 200:
            return response.status, response_headers, {}
        try:
            report = json.loads(body)
        except (ValueError, UnicodeDecodeError) as exc:
            raise SSLLabsUpstreamError("Geçersiz SSL Labs yanıtı.") from exc
        return response.status, response_headers, report
    except (OSError, TimeoutError, ssl.SSLError) as exc:
        raise SSLLabsUnavailable("SSL Labs API'si kullanılamıyor.") from exc
    finally:
        connection.close()


def _aggregate(report: object, requested_host: str) -> dict:
    if not isinstance(report, dict):
        raise SSLLabsUpstreamError("Geçersiz SSL Labs yanıtı.")
    upstream_host = report.get("host")
    if upstream_host is not None and upstream_host != requested_host:
        raise SSLLabsUpstreamError("Uyuşmayan SSL Labs yanıtı.")
    # The v4 Host object can be pending before any Endpoint objects exist.
    # Normalize only that pending shape; a completed READY response still has
    # to provide an explicit endpoint array for the saved-report parser.
    if report.get("status") in {"DNS", "IN_PROGRESS", "ERROR"} and "endpoints" not in report:
        report = {**report, "endpoints": []}
    try:
        return parse_ssllabs_host_summary(report)
    except ValueError as exc:
        raise SSLLabsUpstreamError("Geçersiz SSL Labs yanıtı.") from exc


def fetch_ssllabs_info(registered_email, *, transport=None):
    """Fetch only fixed /info and return every validated usage message unchanged."""
    registered_email = validate_registered_email(registered_email)
    call = transport if transport is not None else _default_transport
    try:
        _rate.check_global(time.time())
    except _rate.RateStateUnavailable as exc:
        raise SSLLabsUnavailable("SSL Labs hizmeti geçici olarak kullanılamıyor.") from exc
    url = f"https://{API_HOST}{INFO_PATH}"
    try:
        status, response_headers, report = call(
            url, {"email": registered_email, "Accept": "application/json"},
            REQUEST_TIMEOUT_SECONDS, False,
        )
    except (SSLLabsInvalid, SSLLabsUnavailable, SSLLabsUpstreamError, SSLLabsRateLimited):
        raise
    except Exception as exc:
        raise SSLLabsUnavailable("SSL Labs API'si kullanılamıyor.") from exc
    if status in (503, 529):
        try:
            _rate.info_failure(status, time.time())
        except _rate.RateStateUnavailable as exc:
            raise SSLLabsUnavailable("SSL Labs hizmeti geçici olarak kullanılamıyor.") from exc
        raise SSLLabsUnavailable("SSL Labs hizmeti kullanılamıyor.")
    if status == 429:
        raise SSLLabsRateLimited("SSL Labs hız sınırına ulaşıldı.")
    if status != 200:
        raise SSLLabsUpstreamError("SSL Labs bilgi isteği başarısız oldu.")
    if not isinstance(response_headers, dict) or not isinstance(report, dict):
        raise SSLLabsUpstreamError("Geçersiz SSL Labs bilgi yanıtı.")
    messages = report.get("messages")
    if (not isinstance(messages, list) or len(messages) > 32
            or any(not isinstance(message, str) or len(message) > 4096
                   or "\x00" in message for message in messages)
            or sum(len(message.encode("utf-8")) for message in messages) > 32768):
        raise SSLLabsUpstreamError("Geçersiz SSL Labs bilgi iletileri.")
    return {"messages": list(messages)}


def run_ssllabs_live(hostname, registered_email, *, transport=None, sleep=None):
    """Start at most one assessment per host per durable cooldown, then poll boundedly.

    The test transport receives url, headers, timeout_seconds, allow_redirects
    and returns status, response_headers, host_json. Rate state is claimed
    before transport and finalized after every result, including exceptions.
    """
    hostname = validate_hostname(hostname)
    registered_email = validate_registered_email(registered_email)
    call = transport if transport is not None else _default_transport
    pause = sleep if sleep is not None else time.sleep
    if not _RUN_LOCK.acquire(blocking=False):
        raise SSLLabsBusy("Bir SSL Labs değerlendirmesi zaten sürüyor.")
    token = None
    rate_status = None
    try:
        started_at = time.monotonic()
        try:
            begin_new, token = _rate.begin(hostname, time.time())
        except _rate.RateStateUnavailable as exc:
            raise SSLLabsUnavailable("SSL Labs hizmeti geçici olarak kullanılamıyor.") from exc
        last_aggregate = None
        for index in range(MAX_CALLS):
            if index > 0:
                delay = 5 if index == 1 else 10
                if time.monotonic() + delay + REQUEST_TIMEOUT_SECONDS > started_at + MAX_ELAPSED_SECONDS:
                    break
                pause(delay)
            params = {"host": hostname, "publish": "off", "all": "done"}
            if index == 0 and begin_new:
                params["startNew"] = "on"
            url = f"https://{API_HOST}{API_PATH}?{urlencode(params)}"
            try:
                status, response_headers, report = call(
                    url, {"email": registered_email, "Accept": "application/json"},
                    REQUEST_TIMEOUT_SECONDS, False
                )
            except (SSLLabsInvalid, SSLLabsBusy, SSLLabsUnavailable, SSLLabsUpstreamError, SSLLabsRateLimited):
                raise
            except Exception as exc:
                raise SSLLabsUnavailable("SSL Labs API'si kullanılamıyor.") from exc
            if status == 441:
                raise SSLLabsUnavailable("SSL Labs kaydı kullanılamıyor.")
            if status == 429:
                raise SSLLabsRateLimited("SSL Labs hız sınırına ulaşıldı.")
            if status in (503, 529):
                rate_status = status
                raise SSLLabsUnavailable("SSL Labs hizmeti kullanılamıyor.")
            if status != 200:
                raise SSLLabsUpstreamError("SSL Labs API isteği başarısız oldu.")
            if not isinstance(response_headers, dict):
                raise SSLLabsUpstreamError("Geçersiz SSL Labs yanıt başlıkları.")
            aggregate = _aggregate(report, hostname)
            last_aggregate = aggregate
            if aggregate["assessment_status"] in {"READY", "ERROR"}:
                return aggregate
            if aggregate["assessment_status"] not in {"DNS", "IN_PROGRESS"}:
                raise SSLLabsUpstreamError("Geçersiz SSL Labs değerlendirme durumu.")
        if last_aggregate is None:
            raise SSLLabsUpstreamError("SSL Labs bir değerlendirme döndürmedi.")
        return last_aggregate
    finally:
        try:
            if token is not None:
                _rate.finish(hostname, token, time.time(), rate_status)
        except _rate.RateStateUnavailable as exc:
            raise SSLLabsUnavailable("SSL Labs hizmeti geçici olarak kullanılamıyor.") from exc
        finally:
            _RUN_LOCK.release()
