"""Statik web bulgularını tek, kayıtlı loopback isteğiyle güvenle yeniden üretme.

Profil yalnız ``http://127.0.0.1:<ayrıcalıksız-port>`` hedeflerini kabul eder, yönlendirmeyi izlemez, yanıt gövdesini
okumaz ve sabit ``.invalid`` kanıt adresine hiçbir bağlantı kurmaz. Sonuç bulguyu otomatik kapatmaz veya onaylamaz;
uzman triyajı için yalnız toplu çalışma zamanı kanıtı ekler.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import re
import secrets
from typing import Any
from urllib.parse import urlencode, urlsplit

import sandbox_targets
import taint_autofix

FORMAT = "sniper-open-redirect-runtime-proof/1"
REFLECTION_FORMAT = "sniper-reflected-html-runtime-proof/1"
CORS_FORMAT = "sniper-cors-runtime-proof/1"
CLICKJACKING_FORMAT = "sniper-clickjacking-runtime-proof/1"
MAX_RESPONSE_BYTES = 262_144
_PATH = re.compile(r"/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,500}\Z")
_PARAMETER = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}\Z")
_CSP_SCHEME_SOURCE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:\Z")
_CSP_HOST_SOURCE = re.compile(
    r"(?:(?:[A-Za-z][A-Za-z0-9+.-]*):\/\/)?"
    r"(?:\*\.)?(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
    r"(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*"
    r"(?::(?:\*|[0-9]{1,5}))?(?:/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*)?\Z"
)


class RuntimeProofError(ValueError):
    """İstek statik bulgu veya güvenli loopback sözleşmesine uymuyor."""


class RuntimeProofUnavailable(RuntimeProofError):
    """Kayıtlı yerel fikstüre bağlanılamadı ya da geçerli HTTP yanıtı alınamadı."""


def _valid_frame_ancestor_source(value: str) -> bool:
    """Recognize a conservative frame-ancestors source subset without repairing malformed values."""
    if value in {"'self'", "'none'", "*"} or _CSP_SCHEME_SOURCE.fullmatch(value):
        return True
    match = _CSP_HOST_SOURCE.fullmatch(value)
    if not match:
        return False
    port = re.search(r":([0-9]{1,5})(?:/|\Z)", value)
    return port is None or 1 <= int(port.group(1)) <= 65535


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
    reference = str(finding.get("reference") or "").strip().upper() if isinstance(finding, dict) else ""
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
    reference = str(finding.get("reference") or "").strip().upper() if isinstance(finding, dict) else ""
    if not isinstance(finding, dict) or reference != "CWE-1021":
        raise RuntimeProofError("Bu profil yalnız statik CWE-1021 clickjacking bulgularını doğrular.")
    return finding


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
        "finding_reference": str(finding.get("reference") or "")[:80],
        "evidence_sha256": digest,
    }
    return store.add_project_runtime_proof(str(audit_id), int(finding_index), proof)


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
        "finding_reference": str(finding.get("reference") or "")[:80], "evidence_sha256": digest,
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
        "finding_reference": str(finding.get("reference") or "")[:80], "evidence_sha256": digest,
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
        "finding_reference": str(finding.get("reference") or "")[:80], "evidence_sha256": digest,
    }
    return store.add_project_clickjacking_runtime_proof(str(audit_id), int(finding_index), proof)
