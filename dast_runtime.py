"""Statik bulgulara bağlı, sabit profilli ve sınırlı loopback DAST çekirdeği."""
from __future__ import annotations

from typing import Any

import runtime_proof


class DastRuntimeError(ValueError):
    """Profil, bulgu bağı veya girdi güvenli DAST sözleşmesine uymuyor."""


class DastRuntimeUnavailable(DastRuntimeError):
    """Kayıtlı yerel hedef geçerli HTTP yanıtı vermedi."""


_PROFILES = (
    {"id": "open_redirect", "label": "Açık yönlendirme", "finding_reference": "CWE-601",
     "request_method": "GET", "max_requests": 1},
    {"id": "reflected_html", "label": "Yansıyan HTML", "finding_reference": "CWE-79",
     "request_method": "GET", "max_requests": 1},
    {"id": "cors_credentials", "label": "Kimlik bilgili CORS yansıması", "finding_reference": "CWE-942",
     "request_method": "GET", "max_requests": 1},
    {"id": "clickjacking_headers", "label": "Clickjacking başlıkları", "finding_reference": "CWE-1021",
     "request_method": "GET", "max_requests": 1},
    {"id": "ssrf_callback", "label": "SSRF loopback callback", "finding_reference": "CWE-918",
     "request_method": "GET", "max_requests": 1, "max_initial_triggers": 1, "max_callback_requests": 1,
     "max_redirects": 0, "timeout_seconds": 4, "max_response_body_bytes": 0,
     "correlation_kind": "http_callback"},
    {"id": "ssrf_callback_post", "label": "SSRF loopback POST callback", "finding_reference": "CWE-918",
     "request_method": "POST", "max_requests": 1, "max_initial_triggers": 1, "max_callback_requests": 1,
     "max_redirects": 0, "timeout_seconds": 4, "max_request_body_bytes": 1024,
     "max_response_body_bytes": 0, "correlation_kind": "http_callback"},
    {"id": "ssrf_callback_redirect", "label": "SSRF same-origin redirect callback",
     "finding_reference": "CWE-918", "request_method": "GET", "max_requests": 2,
     "max_initial_triggers": 1, "max_callback_requests": 1, "max_redirects": 1,
     "timeout_seconds": 5, "max_response_body_bytes": 0, "correlation_kind": "http_callback"},
    {"id": "ssrf_callback_delayed", "label": "SSRF delayed loopback callback",
     "finding_reference": "CWE-918", "request_method": "GET", "max_requests": 1,
     "max_initial_triggers": 1, "max_callback_requests": 1, "max_redirects": 0,
     "timeout_seconds": 5, "max_response_body_bytes": 0, "correlation_kind": "http_callback"},
    {"id": "ssrf_callback_dns", "label": "SSRF local DNS/OOB correlation",
     "finding_reference": "CWE-918", "request_method": "GET", "max_requests": 1,
     "max_initial_triggers": 1, "max_callback_requests": 1, "max_redirects": 0,
     "timeout_seconds": 4, "max_response_body_bytes": 0, "correlation_kind": "local_dns_oob"},
)


def catalog() -> dict[str, Any]:
    return {
        "format": "sniper-dast-runtime-catalog/1",
        "target_policy": "registered_noncritical_loopback_only",
        "profiles": [dict(profile) for profile in _PROFILES],
    }


def run(store, audit_id: object, finding_index: object, *, profile_id: object, target: object,
        path: object, parameter: object, confirm_local: object) -> dict[str, Any]:
    if not isinstance(profile_id, str) or profile_id not in {row["id"] for row in _PROFILES}:
        raise DastRuntimeError("Bilinmeyen, dinamik veya geçersiz DAST profili çalıştırılmadı (not_run).")
    if not isinstance(parameter, str):
        raise DastRuntimeError("DAST parametresi metin olmalı.")
    try:
        if profile_id == "open_redirect":
            return runtime_proof.verify_open_redirect(
                store, audit_id, finding_index, target=target, path=path, parameter=parameter,
                confirm_local=confirm_local,
            )
        if profile_id == "reflected_html":
            return runtime_proof.verify_reflected_html(
                store, audit_id, finding_index, target=target, path=path, parameter=parameter,
                confirm_local=confirm_local,
            )
        if profile_id in runtime_proof.SSRF_PROFILE_LIMITS:
            return runtime_proof.verify_ssrf_callback(
                store, audit_id, finding_index, target=target, path=path, parameter=parameter,
                confirm_local=confirm_local, profile_id=profile_id,
            )
        if parameter != "":
            raise DastRuntimeError("Başlık profilleri parameter alanını boş ister.")
        if profile_id == "cors_credentials":
            return runtime_proof.verify_cors_credentials(
                store, audit_id, finding_index, target=target, path=path, confirm_local=confirm_local,
            )
        return runtime_proof.verify_clickjacking_headers(
            store, audit_id, finding_index, target=target, path=path, confirm_local=confirm_local,
        )
    except runtime_proof.RuntimeProofUnavailable as exc:
        raise DastRuntimeUnavailable(str(exc)) from exc
    except runtime_proof.RuntimeProofError as exc:
        raise DastRuntimeError(str(exc)) from exc

def run_extended_loopback_canary_profile(
    target_handler_fn: Any,
    *,
    scenario: str = "redirect_auth_leak",
) -> dict[str, Any]:
    """Faz 2 R7: _PROFILES sabit listesini değiştirmeden iki sunuculu loopback redirect/DCR
    canary çalışma zamanı kanıtını çalıştırır."""
    try:
        return runtime_proof.run_loopback_redirect_and_dcr_canary_proof(
            target_handler_fn,
            scenario=scenario,
        )
    except runtime_proof.RuntimeProofUnavailable as exc:
        raise DastRuntimeUnavailable(str(exc)) from exc
    except runtime_proof.RuntimeProofError as exc:
        raise DastRuntimeError(str(exc)) from exc

