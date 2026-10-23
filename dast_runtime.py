"""Statik bulgulara bağlı, sabit profilli ve tek istekli loopback DAST çekirdeği."""
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
        raise DastRuntimeError("Bilinmeyen veya geçersiz DAST profili.")
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
