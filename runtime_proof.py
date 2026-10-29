"""Statik web bulgularını kayıtlı loopback fikstürleriyle güvenle yeniden üretme.

Profiller yalnız ``http://127.0.0.1:<ayrıcalıksız-port>`` hedeflerini kabul eder. SSRF profilleri Sniper'ın açtığı,
tek istek alan geçici loopback HTTP veya yerel DNS-benzeri canary kullanır; dış hedef oluşturmaz. Yalnız açıkça
seçilen profil, aynı şema/host/port ve tam callback sorgusu doğrulandığında en çok bir yönlendirme izleyebilir.
Sonuç bulguyu otomatik kapatmaz; uzman triyajı için yalnız sınırlı çalışma zamanı kanıtı ekler.
"""
from __future__ import annotations

import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import re
import secrets
import socket
import threading
import time
from typing import Any
from urllib.parse import urlencode, urlsplit

import sandbox_targets
import taint_autofix

FORMAT = "sniper-open-redirect-runtime-proof/1"
REFLECTION_FORMAT = "sniper-reflected-html-runtime-proof/1"
CORS_FORMAT = "sniper-cors-runtime-proof/1"
CLICKJACKING_FORMAT = "sniper-clickjacking-runtime-proof/1"
SSRF_FORMAT = "sniper-ssrf-callback-runtime-proof/1"
MAX_RESPONSE_BYTES = 262_144
MAX_SSRF_LOCATION_BYTES = 1024
MAX_SSRF_REQUEST_BODY_BYTES = 1024
SSRF_TRIGGER_TIMEOUT_SECONDS = 3
SSRF_CANARY_HARD_TIMEOUT_SECONDS = 5
SSRF_PROFILE_LIMITS = {
    "ssrf_callback": {"method": "GET", "redirects": 0, "wait_ms": 750, "total_ms": 4000,
                      "correlation": "http_callback"},
    "ssrf_callback_post": {"method": "POST", "redirects": 0, "wait_ms": 750, "total_ms": 4000,
                           "correlation": "http_callback"},
    "ssrf_callback_redirect": {"method": "GET", "redirects": 1, "wait_ms": 750, "total_ms": 5000,
                               "correlation": "http_callback"},
    "ssrf_callback_delayed": {"method": "GET", "redirects": 0, "wait_ms": 1500, "total_ms": 5000,
                              "correlation": "http_callback"},
    "ssrf_callback_dns": {"method": "GET", "redirects": 0, "wait_ms": 1000, "total_ms": 4000,
                          "correlation": "local_dns_oob"},
}
_PATH = re.compile(r"/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,500}\Z")
_PARAMETER = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}\Z")
_ASCII_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_ASCII_ALNUM = _ASCII_LETTERS + "0123456789"
_CSP_PATH_CHARS = frozenset(_ASCII_ALNUM + "._~!$&'()*+,;=:@%/-")


def _valid_csp_scheme_name(value: str) -> bool:
    return bool(value) and value[0] in _ASCII_LETTERS \
        and all(char in _ASCII_ALNUM + "+.-" for char in value[1:])


def _is_csp_scheme_source(value: str) -> bool:
    return value.endswith(":") and _valid_csp_scheme_name(value[:-1])


def _valid_csp_host_source(value: str) -> bool:
    rest = value
    scheme_end = value.find("://")
    if scheme_end >= 0 and _valid_csp_scheme_name(value[:scheme_end]):
        rest = value[scheme_end + 3:]

    path_start = rest.find("/")
    if path_start >= 0:
        if any(char not in _CSP_PATH_CHARS for char in rest[path_start:]):
            return False
        host_port = rest[:path_start]
    else:
        host_port = rest

    port = ""
    if ":" in host_port:
        host_port, port = host_port.rsplit(":", 1)
        if port != "*":
            if not 1 <= len(port) <= 5 or not port.isascii() or not port.isdecimal():
                return False
            if not 1 <= int(port) <= 65535:
                return False

    if host_port.startswith("*."):
        host_port = host_port[2:]
    labels = host_port.split(".")
    if not labels or any(
        not 1 <= len(label) <= 63
        or label[0] not in _ASCII_ALNUM
        or label[-1] not in _ASCII_ALNUM
        or any(char not in _ASCII_ALNUM + "-" for char in label)
        for label in labels
    ):
        return False
    return True


class RuntimeProofError(ValueError):
    """İstek statik bulgu veya güvenli loopback sözleşmesine uymuyor."""


class RuntimeProofUnavailable(RuntimeProofError):
    """Kayıtlı yerel fikstüre bağlanılamadı ya da geçerli HTTP yanıtı alınamadı."""


def _valid_frame_ancestor_source(value: str) -> bool:
    """Recognize a conservative frame-ancestors source subset without repairing malformed values."""
    if value in {"'self'", "'none'", "*"} or _is_csp_scheme_source(value):
        return True
    return _valid_csp_host_source(value)


def _frame_ancestors_policy(policy: str) -> tuple[bool, bool]:
    """Return presence and effective restriction for the first directive in one CSP policy."""
    for directive in policy.split(";"):
        tokens = directive.strip().split()
        if not tokens or tokens[0].casefold() != "frame-ancestors":
            continue
        sources = [token.casefold() for token in tokens[1:]]
        if not sources or any(not _valid_frame_ancestor_source(source) for source in sources):
            return True, False
        if "'none'" in sources:
            return True, sources == ["'none'"]
        return True, "*" not in sources
    return False, False


def _response_body_capable(status: int, content_lengths: list[str]) -> bool:
    """Reject status codes and explicit lengths that prove the GET response has no body."""
    if status in {204, 205}:
        return False
    if not content_lengths:
        return True
    values = [part.strip() for value in content_lengths for part in value.split(",")]
    if not values or any(not re.fullmatch(r"[0-9]{1,20}", value) for value in values):
        return False
    lengths = {int(value) for value in values}
    return len(lengths) == 1 and next(iter(lengths)) > 0


def _target(value: object) -> tuple[str, int]:
    if not isinstance(value, str) or len(value) > 300:
        raise RuntimeProofError("Geçersiz yerel hedef.")
    parts = urlsplit(value)
    try:
        port = parts.port
    except ValueError as exc:
        raise RuntimeProofError("Geçersiz yerel hedef portu.") from exc
    if parts.scheme != "http" or parts.hostname != "127.0.0.1" or port is None \
            or parts.username or parts.password or parts.path not in {"", "/"} or parts.query or parts.fragment:
        raise RuntimeProofError("Kanıt hedefi http://127.0.0.1:<port> biçiminde olmalı.")
    if port < 1024 or port in sandbox_targets.critical_ports():
        raise RuntimeProofError("Ayrıcalıklı veya kritik yerel servis portu kanıt hedefi olamaz.")
    try:
        resolved = sandbox_targets.resolve_run_target("runtime_proof", value)
    except sandbox_targets.TargetError as exc:
        raise RuntimeProofError(str(exc)) from exc
    if resolved.get("kind") != "local" or resolved.get("host") != "127.0.0.1":
        raise RuntimeProofError("Yalnız kayıtlı loopback hedef kullanılabilir.")
    return value, port


def _static_redirect_finding(store, audit_id: object, finding_index: object) -> dict[str, Any]:
    if not isinstance(audit_id, str) or not audit_id.startswith("prj_"):
        raise RuntimeProofError("Geçersiz proje analizi kimliği.")
    if type(finding_index) is not int or finding_index < 0:
        raise RuntimeProofError("Bulgu sırası negatif olmayan tam sayı olmalı.")
    audit = store.get_project_audit(audit_id)
    findings = audit.get("findings") if isinstance(audit, dict) else None
    if not isinstance(findings, list) or finding_index >= len(findings):
        raise RuntimeProofError("Proje analizi veya bulgu bulunamadı.")
    finding = findings[finding_index]
    if not isinstance(finding, dict) or taint_autofix.finding_kind(finding) != "redirect":
        raise RuntimeProofError("Bu profil yalnız statik açık yönlendirme bulgularını doğrular.")
    return finding


def _static_html_finding(store, audit_id: object, finding_index: object) -> dict[str, Any]:
    if not isinstance(audit_id, str) or not audit_id.startswith("prj_"):
        raise RuntimeProofError("Geçersiz proje analizi kimliği.")
    if type(finding_index) is not int or finding_index < 0:
        raise RuntimeProofError("Bulgu sırası negatif olmayan tam sayı olmalı.")
    audit = store.get_project_audit(audit_id)
    findings = audit.get("findings") if isinstance(audit, dict) else None
    if not isinstance(findings, list) or finding_index >= len(findings):
        raise RuntimeProofError("Proje analizi veya bulgu bulunamadı.")
    finding = findings[finding_index]
    if not isinstance(finding, dict) or taint_autofix.finding_kind(finding) != "html":
        raise RuntimeProofError("Bu profil yalnız statik HTML/XSS veri akışı bulgularını doğrular.")
    return finding


def _finding_cwe(finding: dict[str, Any]) -> str:
    raw = str(finding.get("reference") or finding.get("cwe") or finding.get("cwe_id") or "").strip()
    match = re.search(r"CWE-(\d+)", raw, re.IGNORECASE)
    if match:
        return f"CWE-{match.group(1)}"
    if raw.isdigit():
        return f"CWE-{raw}"
    return raw.upper()


def _static_cors_finding(store, audit_id: object, finding_index: object) -> dict[str, Any]:
    if not isinstance(audit_id, str) or not audit_id.startswith("prj_"):
        raise RuntimeProofError("Geçersiz proje analizi kimliği.")
    if type(finding_index) is not int or finding_index < 0:
        raise RuntimeProofError("Bulgu sırası negatif olmayan tam sayı olmalı.")
    audit = store.get_project_audit(audit_id)
    findings = audit.get("findings") if isinstance(audit, dict) else None
    if not isinstance(findings, list) or finding_index >= len(findings):
        raise RuntimeProofError("Proje analizi veya bulgu bulunamadı.")
    finding = findings[finding_index]
    reference = _finding_cwe(finding) if isinstance(finding, dict) else ""
    if not isinstance(finding, dict) or reference != "CWE-942":
        raise RuntimeProofError("Bu profil yalnız statik CWE-942 CORS bulgularını doğrular.")
    return finding


def _static_clickjacking_finding(store, audit_id: object, finding_index: object) -> dict[str, Any]:
    if not isinstance(audit_id, str) or not audit_id.startswith("prj_"):
        raise RuntimeProofError("Geçersiz proje analizi kimliği.")
    if type(finding_index) is not int or finding_index < 0:
        raise RuntimeProofError("Bulgu sırası negatif olmayan tam sayı olmalı.")
    audit = store.get_project_audit(audit_id)
    findings = audit.get("findings") if isinstance(audit, dict) else None
    if not isinstance(findings, list) or finding_index >= len(findings):
        raise RuntimeProofError("Proje analizi veya bulgu bulunamadı.")
    finding = findings[finding_index]
    reference = _finding_cwe(finding) if isinstance(finding, dict) else ""
    if not isinstance(finding, dict) or reference != "CWE-1021":
        raise RuntimeProofError("Bu profil yalnız statik CWE-1021 clickjacking bulgularını doğrular.")
    return finding


def _static_ssrf_finding(store, audit_id: object, finding_index: object) -> dict[str, Any]:
    if not isinstance(audit_id, str) or not audit_id.startswith("prj_"):
        raise RuntimeProofError("Geçersiz proje analizi kimliği.")
    if type(finding_index) is not int or finding_index < 0:
        raise RuntimeProofError("Bulgu sırası negatif olmayan tam sayı olmalı.")
    audit = store.get_project_audit(audit_id)
    findings = audit.get("findings") if isinstance(audit, dict) else None
    if not isinstance(findings, list) or finding_index >= len(findings):
        raise RuntimeProofError("Proje analizi veya bulgu bulunamadı.")
    finding = findings[finding_index]
    if not isinstance(finding, dict) or taint_autofix.finding_kind(finding) != "ssrf":
        raise RuntimeProofError("Bu profil yalnız statik CWE-918 SSRF veri akışı bulgularını doğrular.")
    return finding


class _LoopbackCanary:
    """One-shot loopback correlation worker with explicit bounded cleanup."""

    def __init__(self, reference: str, observed: threading.Event, counts: dict[str, int],
                 stop: threading.Event, worker: threading.Thread, close_resource) -> None:
        self.reference = reference
        self.observed = observed
        self.counts = counts
        self.stop = stop
        self.worker = worker
        self.close_resource = close_resource

    def start(self) -> None:
        self.worker.start()

    def finish(self, wait_ms: int) -> bool:
        self.observed.wait(wait_ms / 1000)
        self.stop.set()
        self.worker.join(timeout=0.4)
        self.close_resource()
        self.worker.join(timeout=0.4)
        return not self.worker.is_alive()


def _allowed_ephemeral_port(port: int) -> bool:
    return 1024 <= port <= 65535 and port not in sandbox_targets.critical_ports()


def _ssrf_http_canary(token: str) -> _LoopbackCanary:
    """Create one HTTP callback observer bound only to an allowed loopback ephemeral port."""
    observed = threading.Event()
    stop = threading.Event()
    counts = {"requests": 0}
    expected_path = f"/sniper-ssrf-proof/{token}"

    class CanaryHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            counts["requests"] = 1
            if self.path == expected_path:
                observed.set()
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()

        def log_message(self, *_args: object) -> None:
            pass

    server = None
    for _attempt in range(16):
        candidate = HTTPServer(("127.0.0.1", 0), CanaryHandler)
        if _allowed_ephemeral_port(int(candidate.server_address[1])):
            server = candidate
            break
        candidate.server_close()
    if server is None:
        raise OSError("allowed loopback callback port unavailable")
    server.timeout = 0.1
    deadline = time.monotonic() + SSRF_CANARY_HARD_TIMEOUT_SECONDS

    def serve_one() -> None:
        while not stop.is_set() and not counts["requests"] and time.monotonic() < deadline:
            server.handle_request()

    worker = threading.Thread(target=serve_one, daemon=True, name="sniper-ssrf-http-canary")
    port = int(server.server_address[1])
    return _LoopbackCanary(
        f"http://127.0.0.1:{port}{expected_path}", observed, counts, stop, worker, server.server_close,
    )


def _dns_question(data: bytes) -> tuple[str, int, int] | None:
    """Parse one uncompressed DNS question; do not accept answer/extra sections or compression."""
    if not 17 <= len(data) <= 512 or data[2] & 0xF8 or data[3] != 0 or data[4:6] != b"\x00\x01" \
            or data[6:12] != b"\x00\x00\x00\x00\x00\x00":
        return None
    labels: list[str] = []
    index = 12
    while index < len(data):
        size = data[index]
        index += 1
        if size == 0:
            break
        if size > 63 or index + size > len(data):
            return None
        label = data[index:index + size]
        if not label.isascii() or not re.fullmatch(rb"[A-Za-z0-9-]{1,63}", label):
            return None
        labels.append(label.decode("ascii").casefold())
        index += size
    if not labels or index + 4 != len(data):
        return None
    qtype, qclass = int.from_bytes(data[index:index + 2], "big"), int.from_bytes(data[index + 2:index + 4], "big")
    return ".".join(labels), qtype, qclass


def _ssrf_dns_canary(token: str) -> _LoopbackCanary:
    """Create one UDP DNS-question correlation observer on loopback only."""
    observed = threading.Event()
    stop = threading.Event()
    counts = {"requests": 0}
    expected_name = f"{token}.sniper.invalid"
    listener = None
    for _attempt in range(16):
        candidate = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        candidate.bind(("127.0.0.1", 0))
        if _allowed_ephemeral_port(int(candidate.getsockname()[1])):
            listener = candidate
            break
        candidate.close()
    if listener is None:
        raise OSError("allowed loopback DNS correlation port unavailable")
    listener.settimeout(0.1)
    deadline = time.monotonic() + SSRF_CANARY_HARD_TIMEOUT_SECONDS

    def receive_one() -> None:
        while not stop.is_set() and not counts["requests"] and time.monotonic() < deadline:
            try:
                packet, peer = listener.recvfrom(513)
            except socket.timeout:
                continue
            except OSError:
                break
            if peer[0] != "127.0.0.1":
                continue
            counts["requests"] = 1
            parsed = _dns_question(packet)
            if parsed == (expected_name, 1, 1):
                observed.set()

    worker = threading.Thread(target=receive_one, daemon=True, name="sniper-ssrf-dns-canary")
    port = int(listener.getsockname()[1])
    return _LoopbackCanary(
        f"dns://127.0.0.1:{port}/{expected_name}", observed, counts, stop, worker, listener.close,
    )


def verify_open_redirect(store, audit_id: object, finding_index: object, *, target: object, path: object,
                         parameter: object, confirm_local: object) -> dict[str, Any]:
    if confirm_local is not True:
        raise RuntimeProofError("Yerel çalışma zamanı kanıtı için confirm_local tam olarak true olmalı.")
    finding = _static_redirect_finding(store, audit_id, finding_index)
    _value, port = _target(target)
    if not isinstance(path, str) or not _PATH.fullmatch(path) or "//" in path or "/../" in path + "/" \
            or "/./" in path + "/":
        raise RuntimeProofError("Kanıt yolu tek, göreli olmayan güvenli HTTP yolu olmalı.")
    if not isinstance(parameter, str) or not _PARAMETER.fullmatch(parameter):
        raise RuntimeProofError("Geçersiz yönlendirme parametresi.")

    token = secrets.token_hex(16)
    marker = f"https://runtime-proof.invalid/sniper-proof/{token}"
    request_target = path + "?" + urlencode({parameter: marker})
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        connection.request("GET", request_target, headers={
            "Host": f"127.0.0.1:{port}",
            "User-Agent": "Sniper-Runtime-Proof/1",
            "Accept": "*/*",
            "Connection": "close",
        })
        response = connection.getresponse()
        status = int(response.status)
        location = response.getheader("Location", "")
        response.close()  # gövde bilinçli olarak okunmaz
    except (OSError, http.client.HTTPException) as exc:
        raise RuntimeProofUnavailable("Kayıtlı yerel hedef geçerli HTTP yanıtı vermedi.") from exc
    finally:
        connection.close()

    matched = location == marker
    evidence = {
        "format": FORMAT,
        "finding_kind": "redirect",
        "verdict": "confirmed" if matched else "not_reproduced",
        "http_status": status,
        "external_location_reflected": matched,
        "request_count": 1,
        "redirect_followed": False,
    }
    digest = hashlib.sha256(json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    proof = {
        **evidence,
        "audit_id": str(audit_id),
        "finding_index": int(finding_index),
        "finding_reference": (str(finding.get("reference") or finding.get("cwe") or finding.get("cwe_id") or "") or _finding_cwe(finding))[:80],
        "evidence_sha256": digest,
    }
    return store.add_project_runtime_proof(str(audit_id), int(finding_index), proof)


def _ssrf_request(port: int, method: str, request_target: str, body: bytes | None,
                  timeout: float) -> tuple[int, list[str]]:
    if timeout <= 0:
        raise RuntimeProofUnavailable("SSRF kanıtı toplam süre sınırını aştı.")
    connection = http.client.HTTPConnection(
        "127.0.0.1", port, timeout=min(float(SSRF_TRIGGER_TIMEOUT_SECONDS), timeout),
    )
    headers = {
        "Host": f"127.0.0.1:{port}",
        "User-Agent": "Sniper-Runtime-Proof/1",
        "Accept": "*/*",
        "Connection": "close",
    }
    if body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        headers["Content-Length"] = str(len(body))
    try:
        connection.request(method, request_target, body=body, headers=headers)
        response = connection.getresponse()
        status = int(response.status)
        locations = [value for name, value in response.getheaders() if name.casefold() == "location"]
        response.close()  # SSRF hedef gövdesi için sınır sıfırdır; bilinçli olarak okunmaz.
        return status, locations
    except (OSError, http.client.HTTPException) as exc:
        raise RuntimeProofUnavailable("Kayıtlı yerel hedef geçerli HTTP yanıtı vermedi.") from exc
    finally:
        connection.close()


def _same_origin_ssrf_redirect(location: str, port: int, parameter: str, callback: str) -> str | None:
    if not isinstance(location, str) or not location or len(location.encode("utf-8", "ignore")) > MAX_SSRF_LOCATION_BYTES:
        return None
    try:
        parts = urlsplit(location)
        redirect_port = parts.port
    except ValueError:
        return None
    if parts.fragment or parts.username or parts.password:
        return None
    if parts.scheme or parts.netloc:
        if parts.scheme != "http" or parts.hostname != "127.0.0.1" or redirect_port != port:
            return None
    elif not location.startswith("/") or location.startswith("//"):
        return None
    if not _PATH.fullmatch(parts.path) or "//" in parts.path or "/../" in parts.path + "/" \
            or "/./" in parts.path + "/":
        return None
    expected_query = urlencode({parameter: callback})
    if parts.query != expected_query:
        return None
    return parts.path + "?" + parts.query


def verify_ssrf_callback(store, audit_id: object, finding_index: object, *, target: object, path: object,
                         parameter: object, confirm_local: object,
                         profile_id: object = "ssrf_callback") -> dict[str, Any]:
    """Measure one bounded local CWE-918 trigger against an internal one-shot correlation canary."""
    if confirm_local is not True:
        raise RuntimeProofError("Yerel çalışma zamanı kanıtı için confirm_local tam olarak true olmalı.")
    finding = _static_ssrf_finding(store, audit_id, finding_index)
    _value, port = _target(target)
    if not isinstance(path, str) or not _PATH.fullmatch(path) or "//" in path or "/../" in path + "/" \
            or "/./" in path + "/":
        raise RuntimeProofError("Kanıt yolu tek, göreli olmayan güvenli HTTP yolu olmalı.")
    if not isinstance(parameter, str) or not _PARAMETER.fullmatch(parameter):
        raise RuntimeProofError("Geçersiz SSRF adres parametresi.")
    if not isinstance(profile_id, str) or profile_id not in SSRF_PROFILE_LIMITS:
        raise RuntimeProofError("Belirsiz veya dinamik SSRF kanıt profili çalıştırılmaz.")
    limits = SSRF_PROFILE_LIMITS[profile_id]

    token = secrets.token_hex(16)
    try:
        canary = _ssrf_dns_canary(token) if limits["correlation"] == "local_dns_oob" \
            else _ssrf_http_canary(token)
    except OSError as exc:
        raise RuntimeProofUnavailable("Geçici loopback SSRF canary başlatılamadı.") from exc

    encoded = urlencode({parameter: canary.reference})
    method = str(limits["method"])
    body = encoded.encode("ascii") if method == "POST" else None
    if body is not None and len(body) > MAX_SSRF_REQUEST_BODY_BYTES:
        canary.close_resource()
        raise RuntimeProofError("SSRF POST kanıt gövdesi güvenli sınırı aşıyor.")
    request_target = path if body is not None else path + "?" + encoded
    target_request_count = 0
    redirect_count = 0
    redirect_followed = False
    status = 0
    locations: list[str] = []
    deadline = time.monotonic() + int(limits["total_ms"]) / 1000
    canary.start()
    error: Exception | None = None
    try:
        status, locations = _ssrf_request(port, method, request_target, body, deadline - time.monotonic())
        target_request_count = 1
        if int(limits["redirects"]) == 1 and status in {301, 302, 303, 307, 308} and len(locations) == 1:
            redirect_target = _same_origin_ssrf_redirect(locations[0], port, parameter, canary.reference)
            if redirect_target is not None:
                redirect_followed = True
                redirect_count = 1
                status, _second_locations = _ssrf_request(
                    port, "GET", redirect_target, None, deadline - time.monotonic(),
                )
                target_request_count = 2
    except Exception as exc:
        error = exc
    finally:
        remaining_ms = max(0, int((deadline - time.monotonic()) * 1000))
        worker_cleaned = canary.finish(0 if error is not None else min(int(limits["wait_ms"]), remaining_ms))
    if error is not None:
        raise error
    if not worker_cleaned:
        raise RuntimeProofUnavailable("Loopback SSRF canary çalışanı süre sınırında temizlenemedi.")

    callback_observed = canary.observed.is_set()
    callback_request_count = 1 if canary.counts["requests"] else 0
    profile_conditions_met = callback_observed and (
        profile_id != "ssrf_callback_redirect" or redirect_count == 1
    )
    evidence = {
        "format": SSRF_FORMAT,
        "finding_kind": "ssrf",
        "profile_id": profile_id,
        "verdict": "confirmed" if profile_conditions_met else "not_reproduced",
        "http_status": status,
        "request_method": method,
        "callback_observed": callback_observed,
        "trigger_request_count": 1,
        "target_request_count": target_request_count,
        "callback_request_count": callback_request_count,
        "redirect_count": redirect_count,
        "redirect_followed": redirect_followed,
        "response_body_read": False,
        "request_body_bytes": len(body or b""),
        "correlation_kind": str(limits["correlation"]),
        "callback_wait_ms": int(limits["wait_ms"]),
        "canary_loopback_only": True,
        "canary_worker_cleaned": worker_cleaned,
    }
    digest = hashlib.sha256(json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    proof = {
        **evidence,
        "audit_id": str(audit_id),
        "finding_index": int(finding_index),
        "finding_reference": (
            str(finding.get("reference") or finding.get("cwe") or finding.get("cwe_id") or "")
            or _finding_cwe(finding)
        )[:80],
        "evidence_sha256": digest,
    }
    return store.add_project_ssrf_runtime_proof(str(audit_id), int(finding_index), proof)


def verify_reflected_html(store, audit_id: object, finding_index: object, *, target: object, path: object,
                          parameter: object, confirm_local: object) -> dict[str, Any]:
    """Zararsız özel HTML öğesinin ham yansımasını ölçer; betik veya olay işleyicisi çalıştırmaz."""
    if confirm_local is not True:
        raise RuntimeProofError("Yerel çalışma zamanı kanıtı için confirm_local tam olarak true olmalı.")
    finding = _static_html_finding(store, audit_id, finding_index)
    _value, port = _target(target)
    if not isinstance(path, str) or not _PATH.fullmatch(path) or "//" in path or "/../" in path + "/" \
            or "/./" in path + "/":
        raise RuntimeProofError("Kanıt yolu tek, göreli olmayan güvenli HTTP yolu olmalı.")
    if not isinstance(parameter, str) or not _PARAMETER.fullmatch(parameter):
        raise RuntimeProofError("Geçersiz yansıma parametresi.")

    token = secrets.token_hex(16)
    marker = f'<sniper-proof data-token="{token}">'
    request_target = path + "?" + urlencode({parameter: marker})
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        connection.request("GET", request_target, headers={
            "Host": f"127.0.0.1:{port}",
            "User-Agent": "Sniper-Runtime-Proof/1",
            "Accept": "text/html",
            "Connection": "close",
        })
        response = connection.getresponse()
        status = int(response.status)
        content_type = str(response.getheader("Content-Type", "")).split(";", 1)[0].strip().lower()
        body = response.read(MAX_RESPONSE_BYTES + 1)
        response.close()
        if len(body) > MAX_RESPONSE_BYTES:
            raise RuntimeProofUnavailable("Yerel hedef yanıtı güvenli kanıt sınırını aştı.")
    except RuntimeProofUnavailable:
        raise
    except (OSError, http.client.HTTPException) as exc:
        raise RuntimeProofUnavailable("Kayıtlı yerel hedef geçerli HTTP yanıtı vermedi.") from exc
    finally:
        connection.close()

    content_type_html = content_type in {"text/html", "application/xhtml+xml"}
    matched = content_type_html and marker.encode("utf-8") in body
    evidence = {
        "format": REFLECTION_FORMAT,
        "finding_kind": "html",
        "verdict": "confirmed" if matched else "not_reproduced",
        "http_status": status,
        "marker_reflected": matched,
        "content_type_html": content_type_html,
        "request_count": 1,
        "script_executed": False,
        "probe_sha256": hashlib.sha256(marker.encode()).hexdigest(),
    }
    digest = hashlib.sha256(json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    proof = {
        **{key: value for key, value in evidence.items() if key != "probe_sha256"},
        "audit_id": str(audit_id), "finding_index": int(finding_index),
        "finding_reference": (str(finding.get("reference") or finding.get("cwe") or finding.get("cwe_id") or "") or _finding_cwe(finding))[:80], "evidence_sha256": digest,
    }
    return store.add_project_reflection_runtime_proof(str(audit_id), int(finding_index), proof)


def verify_cors_credentials(store, audit_id: object, finding_index: object, *, target: object, path: object,
                            confirm_local: object) -> dict[str, Any]:
    """Rastgele bir ``.invalid`` Origin değerinin kimlik bilgileriyle kabul edilip edilmediğini ölçer."""
    if confirm_local is not True:
        raise RuntimeProofError("Yerel çalışma zamanı kanıtı için confirm_local tam olarak true olmalı.")
    finding = _static_cors_finding(store, audit_id, finding_index)
    _value, port = _target(target)
    if not isinstance(path, str) or not _PATH.fullmatch(path) or "//" in path or "/../" in path + "/" \
            or "/./" in path + "/":
        raise RuntimeProofError("Kanıt yolu tek, göreli olmayan güvenli HTTP yolu olmalı.")

    origin = f"https://{secrets.token_hex(16)}.runtime-proof.invalid"
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        connection.request("GET", path, headers={
            "Host": f"127.0.0.1:{port}",
            "User-Agent": "Sniper-Runtime-Proof/1",
            "Origin": origin,
            "Accept": "*/*",
            "Connection": "close",
        })
        response = connection.getresponse()
        status = int(response.status)
        allowed_origin = str(response.getheader("Access-Control-Allow-Origin", "")).strip()
        allowed_credentials = str(response.getheader("Access-Control-Allow-Credentials", "")).strip().lower()
        response.close()  # gövde bilinçli olarak okunmaz
    except (OSError, http.client.HTTPException) as exc:
        raise RuntimeProofUnavailable("Kayıtlı yerel hedef geçerli HTTP yanıtı vermedi.") from exc
    finally:
        connection.close()

    origin_reflected = allowed_origin == origin
    credentials_allowed = allowed_credentials == "true"
    evidence = {
        "format": CORS_FORMAT,
        "finding_kind": "cors",
        "verdict": "confirmed" if origin_reflected and credentials_allowed else "not_reproduced",
        "http_status": status,
        "origin_reflected": origin_reflected,
        "credentials_allowed": credentials_allowed,
        "request_count": 1,
        "body_read": False,
        "probe_sha256": hashlib.sha256(origin.encode()).hexdigest(),
    }
    digest = hashlib.sha256(json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    proof = {
        **{key: value for key, value in evidence.items() if key != "probe_sha256"},
        "audit_id": str(audit_id), "finding_index": int(finding_index),
        "finding_reference": (str(finding.get("reference") or finding.get("cwe") or finding.get("cwe_id") or "") or _finding_cwe(finding))[:80], "evidence_sha256": digest,
    }
    return store.add_project_cors_runtime_proof(str(audit_id), int(finding_index), proof)


def verify_clickjacking_headers(store, audit_id: object, finding_index: object, *, target: object, path: object,
                                confirm_local: object) -> dict[str, Any]:
    """Tek loopback GET ile etkili XFO/frame-ancestors yokluğunu ölçer; gövdeyi okumaz."""
    if confirm_local is not True:
        raise RuntimeProofError("Yerel çalışma zamanı kanıtı için confirm_local tam olarak true olmalı.")
    finding = _static_clickjacking_finding(store, audit_id, finding_index)
    _value, port = _target(target)
    if not isinstance(path, str) or not _PATH.fullmatch(path) or "//" in path or "/../" in path + "/" \
            or "/./" in path + "/":
        raise RuntimeProofError("Kanıt yolu tek, göreli olmayan güvenli HTTP yolu olmalı.")

    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        connection.request("GET", path, headers={
            "Host": f"127.0.0.1:{port}",
            "User-Agent": "Sniper-Runtime-Proof/1",
            "Accept": "text/html,*/*;q=0.1",
            "Connection": "close",
        })
        response = connection.getresponse()
        status = int(response.status)
        xfo = str(response.getheader("X-Frame-Options", ""))
        csp_policies = [str(value) for value in response.headers.get_all("Content-Security-Policy", [])]
        content_type = str(response.getheader("Content-Type", "")).split(";", 1)[0].strip().lower()
        content_lengths = [str(value) for value in response.headers.get_all("Content-Length", [])]
        response.close()  # gövde bilinçli olarak okunmaz
    except (OSError, http.client.HTTPException) as exc:
        raise RuntimeProofUnavailable("Kayıtlı yerel hedef geçerli HTTP yanıtı vermedi.") from exc
    finally:
        connection.close()

    xfo_values = {part.strip().upper() for part in xfo.split(",") if part.strip()}
    xfo_effective = bool(xfo_values & {"DENY", "SAMEORIGIN"})
    frame_ancestors_present = False
    frame_ancestors_effective = False
    for policy in csp_policies:
        present, restrictive = _frame_ancestors_policy(policy)
        frame_ancestors_present = frame_ancestors_present or present
        frame_ancestors_effective = frame_ancestors_effective or restrictive
    effective = xfo_effective or frame_ancestors_effective
    content_type_html = content_type in {"text/html", "application/xhtml+xml"}
    body_capable = _response_body_capable(status, content_lengths)
    page_response = 200 <= status <= 299 and content_type_html and body_capable
    evidence = {
        "format": CLICKJACKING_FORMAT,
        "finding_kind": "clickjacking",
        "verdict": "confirmed" if page_response and not effective else "not_reproduced",
        "http_status": status,
        "x_frame_options_effective": xfo_effective,
        "frame_ancestors_present": frame_ancestors_present,
        "effective_protection": effective,
        "content_type_html": content_type_html,
        "body_capable": body_capable,
        "request_count": 1,
        "body_read": False,
    }
    digest = hashlib.sha256(json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    proof = {
        **evidence, "audit_id": str(audit_id), "finding_index": int(finding_index),
        "finding_reference": (str(finding.get("reference") or finding.get("cwe") or finding.get("cwe_id") or "") or _finding_cwe(finding))[:80], "evidence_sha256": digest,
    }
    return store.add_project_clickjacking_runtime_proof(str(audit_id), int(finding_index), proof)

LOOPBACK_CANARY_PROOF_FORMAT = "sniper-loopback-redirect-dcr-canary-proof/1"


def _redact_token_value(raw: str) -> str:
    digest = hashlib.sha256(str(raw or "").encode("utf-8", errors="ignore")).hexdigest()[:16]
    return f"[REDACTED_TEST_TOKEN_SHA256:{digest}]"


def run_loopback_redirect_and_dcr_canary_proof(
    target_handler_fn: Any,
    *,
    scenario: str = "redirect_auth_leak",
) -> dict[str, Any]:
    """Faz 2 R7: Yalnızca 127.0.0.1 loopback üzerinde iki geçici HTTP sunucusu (Redirector A ->
    Internal Canary B veya OAuth DCR /.well-known/openid-configuration canary) başlatarak
    cross-origin 302/307 Authorization sızıntısını, POST gövdesi korunumunu ve OAuth DCR SSRF
    davranışını deterministik olarak kanıtlar."""
    if not callable(target_handler_fn):
        raise RuntimeProofError("target_handler_fn çağrılabilir bir nesne olmalıdır.")
    if scenario not in {"redirect_auth_leak", "oauth_dcr_metadata_ssrf", "sni_redirect_mismatch"}:
        raise RuntimeProofError(f"Desteklenmeyen loopback canary senaryosu: {scenario}")

    probe_token = secrets.token_hex(16)
    redacted_probe = _redact_token_value(probe_token)
    b_requests: list[dict[str, Any]] = []
    a_requests: list[dict[str, Any]] = []

    class CanaryBHandler(BaseHTTPRequestHandler):
        def _record_and_reply(self) -> None:
            length = int(self.headers.get("Content-Length", "0") or 0)
            body = self.rfile.read(min(length, 65536)) if length > 0 else b""
            auth_raw = str(self.headers.get("Authorization") or "")
            b_requests.append({
                "method": self.command,
                "path": self.path,
                "host": str(self.headers.get("Host") or ""),
                "has_auth": bool(auth_raw.strip()),
                "redacted_auth": _redact_token_value(auth_raw) if auth_raw.strip() else "",
                "body_len": len(body),
            })
            payload = json.dumps({
                "issuer": f"http://127.0.0.1:{self.server.server_address[1]}",
                "registration_endpoint": f"http://127.0.0.1:{self.server.server_address[1]}/oauth/register",
                "canary_status": "reached",
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:  # noqa: N802
            self._record_and_reply()

        def do_POST(self) -> None:  # noqa: N802
            self._record_and_reply()

        def do_PUT(self) -> None:  # noqa: N802
            self._record_and_reply()

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            pass

    server_b = HTTPServer(("127.0.0.1", 0), CanaryBHandler)
    port_b = int(server_b.server_address[1])
    server_b_url = (
        f"http://127.0.0.1:{port_b}/.well-known/openid-configuration"
        if scenario == "oauth_dcr_metadata_ssrf"
        else f"http://127.0.0.1:{port_b}/internal-canary"
    )

    class RedirectorAHandler(BaseHTTPRequestHandler):
        def _redirect_to_b(self, status_code: int) -> None:
            length = int(self.headers.get("Content-Length", "0") or 0)
            body = self.rfile.read(min(length, 65536)) if length > 0 else b""
            auth_raw = str(self.headers.get("Authorization") or "")
            a_requests.append({
                "method": self.command,
                "path": self.path,
                "has_auth": bool(auth_raw.strip()),
                "redacted_auth": _redact_token_value(auth_raw) if auth_raw.strip() else "",
                "body_len": len(body),
            })
            self.send_response(status_code)
            self.send_header("Location", server_b_url)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()

        def do_GET(self) -> None:  # noqa: N802
            self._redirect_to_b(302)

        def do_POST(self) -> None:  # noqa: N802
            self._redirect_to_b(307)

        def do_PUT(self) -> None:  # noqa: N802
            self._redirect_to_b(307)

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            pass

    server_a = HTTPServer(("127.0.0.1", 0), RedirectorAHandler)
    port_a = int(server_a.server_address[1])
    server_a_url = f"http://127.0.0.1:{port_a}/redirect-entry"

    thread_b = threading.Thread(
        target=server_b.serve_forever,
        kwargs={"poll_interval": 0.02},
        daemon=True,
        name="sniper-canary-b",
    )
    thread_a = threading.Thread(
        target=server_a.serve_forever,
        kwargs={"poll_interval": 0.02},
        daemon=True,
        name="sniper-redirector-a",
    )
    thread_b.start()
    thread_a.start()

    handler_blocked = False
    handler_result: Any = None
    entry_url = server_b_url if scenario == "oauth_dcr_metadata_ssrf" else server_a_url
    try:
        try:
            handler_result = target_handler_fn(entry_url)
        except Exception:
            handler_blocked = True
    finally:
        server_a.shutdown()
        server_a.server_close()
        server_b.shutdown()
        server_b.server_close()
        thread_a.join(timeout=1.0)
        thread_b.join(timeout=1.0)

    canary_reached = len(b_requests) > 0
    auth_leaked = any(bool(r.get("has_auth")) for r in b_requests)
    post_body_preserved = any(r.get("method") == "POST" and int(r.get("body_len", 0)) > 0 for r in b_requests)
    redacted_tokens: list[str] = [
        str(r["redacted_auth"]) for r in (*a_requests, *b_requests) if r.get("redacted_auth")
    ]
    if isinstance(handler_result, dict):
        if handler_result.get("canary_reached") or handler_result.get("followed_redirect"):
            canary_reached = True
        if handler_result.get("auth_leaked") or handler_result.get("leaked_authorization"):
            auth_leaked = True
        if handler_result.get("post_body_preserved"):
            post_body_preserved = True
        if handler_result.get("blocked"):
            handler_blocked = True
        raw_tok = str(handler_result.get("authorization") or handler_result.get("token") or "").strip()
        if raw_tok:
            redacted_tokens.append(_redact_token_value(raw_tok))
    if not redacted_tokens:
        redacted_tokens.append(redacted_probe)

    is_vulnerable = bool(canary_reached or auth_leaked or post_body_preserved)
    status = "RED" if is_vulnerable else "GREEN"
    verdict = "confirmed" if is_vulnerable else "not_reproduced"

    evidence = {
        "format": LOOPBACK_CANARY_PROOF_FORMAT,
        "scenario": scenario,
        "loopback_only": True,
        "server_a_host": "127.0.0.1",
        "server_b_host": "127.0.0.1",
        "redirector_requests": len(a_requests),
        "canary_requests": len(b_requests),
        "canary_reached": canary_reached,
        "auth_leaked": auth_leaked,
        "post_body_preserved": post_body_preserved,
        "blocked_by_guard": bool(handler_blocked or not canary_reached),
        "status": status,
        "verdict": verdict,
        "redacted_tokens": redacted_tokens,
    }
    digest = hashlib.sha256(json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {
        **evidence,
        "server_a_url": server_a_url,
        "server_b_url": server_b_url,
        "evidence_sha256": digest,
    }


def run_extended_loopback_canary_profile(
    target_handler_fn: Any,
    *,
    scenario: str = "redirect_auth_leak",
) -> dict[str, Any]:
    """Faz 2 R7: Extended loopback canary profili sarmalayıcısı."""
    return run_loopback_redirect_and_dcr_canary_proof(target_handler_fn, scenario=scenario)

