"""Sniper Autorize Matrix Tester (Burp Autorize eklentisi karşılığı).

Aynı API uç noktasını 3 farklı oturum bağlamında (Sahip / Kullanıcı A, Farklı Kiracı / Kullanıcı B,
Anonim / Oturumsuz) ve gizli alan enjeksiyonuyla (Mass Assignment / BOPLA) değerlendirerek
IDOR (CWE-639), Kimlik Doğrulama Eksikliği (CWE-306) ve Toplu Alan Atama (CWE-915)
açıklarını otomatik tespit eder.
"""
from __future__ import annotations

import copy
import difflib
import json
from typing import Any


FORMAT = "sniper-autorize-matrix-report/1"


def _body_text(resp: dict[str, Any]) -> str:
    body = resp.get("body", "")
    if isinstance(body, (dict, list)):
        return json.dumps(body, sort_keys=True, ensure_ascii=False)
    return str(body or "")


def _is_error_stub(resp: dict[str, Any]) -> bool:
    body = resp.get("body")
    if isinstance(body, dict):
        keys = {str(k).lower() for k in body.keys()}
        if keys <= {"error", "message", "detail", "status", "code"} and any(
            k in keys for k in ("error", "message", "detail")
        ):
            msg = " ".join(str(v).lower() for v in body.values())
            if any(w in msg for w in ("denied", "forbidden", "unauthorized", "not found", "yetkisiz", "yasak", "bulunamadı")):
                return True
    return False


def evaluate_autorize_access_matrix(probes: list[dict[str, Any]]) -> dict[str, Any]:
    """Çoklu oturum (Kullanıcı A, Kullanıcı B, Anonim) ve Mass Assignment yanıt matrisini denetler."""
    matrix_rows: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []

    for idx, probe in enumerate(probes or []):
        if not isinstance(probe, dict):
            continue
        endpoint = str(probe.get("endpoint") or f"GET /api/resource/{idx + 1}")
        owner_resp = probe.get("owner_response") if isinstance(probe.get("owner_response"), dict) else {"status": 200, "body": {}}
        other_resp = probe.get("other_user_response") if isinstance(probe.get("other_user_response"), dict) else None
        unauth_resp = probe.get("unauthenticated_response") if isinstance(probe.get("unauthenticated_response"), dict) else None
        mass_resp = probe.get("mass_assignment_response") if isinstance(probe.get("mass_assignment_response"), dict) else None

        owner_status = int(owner_resp.get("status_code", owner_resp.get("status", 200)) or 200)
        owner_text = _body_text(owner_resp)

        idor_status = "enforced"
        unauth_status = "enforced"
        mass_status = "enforced"

        # 1. Cross-User / Cross-Tenant IDOR (BOLA) Kontrolü
        if other_resp is not None and 200 <= owner_status < 300:
            other_code = int(other_resp.get("status_code", other_resp.get("status", 403)) or 403)
            other_text = _body_text(other_resp)
            sim = difflib.SequenceMatcher(None, owner_text[:8192], other_text[:8192]).ratio() if owner_text else 1.0
            if 200 <= other_code < 300 and not _is_error_stub(other_resp) and (sim >= 0.55 or len(other_text) > 16):
                idor_status = " bypassed_idor"
                idor_status = idor_status.strip()
                findings.append({
                    "control_id": "SNIPER-AUTORIZE-IDOR-01",
                    "cwe": "CWE-639",
                    "reference": "CWE-639",
                    "severity": "critical",
                    "category": "authz",
                    "endpoint": endpoint,
                    "title": f"Çapraz kullanıcı/kiracı yetki atlaması (IDOR / BOLA): {endpoint}",
                    "evidence": (
                        f"Sahip oturumu status={owner_status} dönerken, farklı kullanıcı/kiracı oturumu "
                        f"status={other_code} ve benzerlik={sim:.2f} ile kaynağa erişti."
                    ),
                    "recommendation": "Nesne sorgularında oturumdaki kullanıcı/kiracı kimliğini (user_id / tenant_id) zorunlu filtre olarak uygulayın.",
                })

        # 2. Oturumsuz (Unauthenticated) Erişim Kontrolü
        if unauth_resp is not None and 200 <= owner_status < 300:
            unauth_code = int(unauth_resp.get("status_code", unauth_resp.get("status", 401)) or 401)
            unauth_text = _body_text(unauth_resp)
            sim_u = difflib.SequenceMatcher(None, owner_text[:8192], unauth_text[:8192]).ratio() if owner_text else 1.0
            if 200 <= unauth_code < 300 and not _is_error_stub(unauth_resp) and (sim_u >= 0.55 or len(unauth_text) > 16):
                unauth_status = "bypassed_unauthenticated"
                findings.append({
                    "control_id": "SNIPER-AUTORIZE-UNAUTH-02",
                    "cwe": "CWE-306",
                    "reference": "CWE-306",
                    "severity": "critical",
                    "category": "authz",
                    "endpoint": endpoint,
                    "title": f"Korunan uç noktaya oturumsuz (Unauthenticated) erişim: {endpoint}",
                    "evidence": f"Kimlik doğrulama bilgisi kaldırıldığında uç nokta status={unauth_code} (benzerlik={sim_u:.2f}) döndürdü.",
                    "recommendation": "Uç noktada oturum/belirteç doğrulamasını (authentication middleware) zorunlu kılın.",
                })

        # 3. Gizli Yetki Alanı Enjeksiyonu (Mass Assignment / BOPLA)
        if mass_resp is not None:
            mass_code = int(mass_resp.get("status_code", mass_resp.get("status", 400)) or 400)
            injected = mass_resp.get("injected_fields") if isinstance(mass_resp.get("injected_fields"), dict) else {}
            mass_body = mass_resp.get("body") if isinstance(mass_resp.get("body"), dict) else {}
            accepted_fields = [
                k for k, v in injected.items()
                if k in mass_body and mass_body.get(k) == v
            ]
            if 200 <= mass_code < 300 and accepted_fields:
                mass_status = "bypassed_mass_assignment"
                findings.append({
                    "control_id": "SNIPER-AUTORIZE-MASS-03",
                    "cwe": "CWE-915",
                    "reference": "CWE-915",
                    "severity": "high",
                    "category": "authz",
                    "endpoint": endpoint,
                    "title": f"Toplu alan atama (Mass Assignment / BOPLA) ile yetki yükseltme: {endpoint}",
                    "evidence": f"Enjekte edilen ayrıcalıklı alanlar {accepted_fields!r} sunucu tarafından kabul edildi (status={mass_code}).",
                    "recommendation": "Girdi şemasında yalnızca izin verilen alanları (DTO / strong parameters) kabul edin; rol ve yetki alanlarını reddedin.",
                })

        matrix_rows.append({
            "endpoint": endpoint,
            "owner_status": owner_status,
            "cross_user_verdict": idor_status,
            "unauthenticated_verdict": unauth_status,
            "mass_assignment_verdict": mass_status,
        })

    return {
        "format": FORMAT,
        "probe_count": len(matrix_rows),
        "vulnerable_count": len(findings),
        "finding_count": len(findings),
        "matrix": matrix_rows,
        "findings": findings,
    }


def run_loopback_autorize_probe(
    endpoint_spec: dict[str, Any],
    *,
    target_handler_fn: Any,
) -> dict[str, Any]:
    """Verilen uç nokta şablonunu Sahip, Farklı Kullanıcı, Anonim ve Mass Assignment bağlamlarında çalıştırıp denetler."""
    endpoint = str(endpoint_spec.get("endpoint") or "GET /api/orders/1")
    base_req = copy.deepcopy(endpoint_spec.get("request") if isinstance(endpoint_spec.get("request"), dict) else {})
    owner_ctx = endpoint_spec.get("owner_headers") or {"X-User-Id": "user_a", "X-Tenant-Id": "tenant_a"}
    other_ctx = endpoint_spec.get("other_user_headers") or {"X-User-Id": "user_b", "X-Tenant-Id": "tenant_b"}
    injected_fields = endpoint_spec.get("injected_fields") or {"role": "admin", "is_admin": True}

    req_owner = copy.deepcopy(base_req)
    req_owner["headers"] = {**(req_owner.get("headers") or {}), **owner_ctx}
    owner_resp = target_handler_fn(req_owner)

    req_other = copy.deepcopy(base_req)
    req_other["headers"] = {**(req_other.get("headers") or {}), **other_ctx}
    other_resp = target_handler_fn(req_other)

    req_unauth = copy.deepcopy(base_req)
    req_unauth["headers"] = {}
    unauth_resp = target_handler_fn(req_unauth)

    req_mass = copy.deepcopy(req_owner)
    body_mass = dict(req_mass.get("json_body") or {})
    body_mass.update(injected_fields)
    req_mass["json_body"] = body_mass
    mass_raw_resp = target_handler_fn(req_mass)
    mass_resp = {
        **dict(mass_raw_resp or {}),
        "injected_fields": injected_fields,
    }

    return evaluate_autorize_access_matrix([{
        "endpoint": endpoint,
        "owner_response": owner_resp,
        "other_user_response": other_resp,
        "unauthenticated_response": unauth_resp,
        "mass_assignment_response": mass_resp,
    }])
