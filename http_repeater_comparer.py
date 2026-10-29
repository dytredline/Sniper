"""Sniper HTTP Repeater & Comparer (Burp Repeater + Comparer karşılığı).

Yerel loopback (127.0.0.1) veya deterministik işleyici üzerinde bir temel (baseline) HTTP
isteğinin parametre, başlık, çerez veya JSON gövdesini değiştirerek yeniden gönderir ve
Temel Yanıt ile Değiştirilmiş Yanıt arasındaki yapısal farkları (durum kodu, uzunluk,
başlıklar, JSON alanları ve yetki/fiyat anomalileri) yan yana çıkarır.
"""
from __future__ import annotations

import copy
import difflib
import hashlib
import json
import urllib.parse
import urllib.request
from typing import Any


FORMAT = "sniper-http-repeater-comparer/1"
MAX_BODY_BYTES = 512 * 1024
_PRIVILEGE_KEYS = frozenset({
    "role", "is_admin", "admin", "permissions", "org_id", "organization_id",
    "tenant_id", "price", "amount", "discount", "balance", "verified", "is_verified",
})


def _redact_sensitive_value(val: str) -> str:
    text = str(val or "")
    if any(text.startswith(prefix) for prefix in ("Bearer ", "glpat-", "ghp_", "eyJ")):
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]
        return f"[REDACTED_TOKEN_SHA256:{digest}]"
    return text


def _safe_json_loads(raw: Any) -> dict[str, Any] | None:
    if isinstance(raw, dict):
        return dict(raw)
    if not isinstance(raw, str):
        return None
    stripped = raw.strip()
    if not (stripped.startswith("{") and stripped.endswith("}")):
        return None
    try:
        parsed = json.loads(stripped)
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        return None


def _flatten_json(obj: Any, prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, dict):
                out.update(_flatten_json(v, key))
            else:
                out[key] = v
    return out


def compare_http_responses(
    baseline: dict[str, Any],
    mutated: dict[str, Any],
    *,
    applied_mutation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """İki HTTP yanıtını (baseline vs mutated) Burp Comparer tarzında karşılaştırır ve güvenlik anomalilerini çıkarır."""
    base_status = int(baseline.get("status_code", baseline.get("status", 200)) or 200)
    mut_status = int(mutated.get("status_code", mutated.get("status", 200)) or 200)

    base_body_raw = baseline.get("body", "")
    mut_body_raw = mutated.get("body", "")
    base_body_str = json.dumps(base_body_raw, sort_keys=True, ensure_ascii=False) if isinstance(base_body_raw, (dict, list)) else str(base_body_raw or "")
    mut_body_str = json.dumps(mut_body_raw, sort_keys=True, ensure_ascii=False) if isinstance(mut_body_raw, (dict, list)) else str(mut_body_raw or "")

    base_bytes = base_body_str.encode("utf-8", errors="replace")[:MAX_BODY_BYTES]
    mut_bytes = mut_body_str.encode("utf-8", errors="replace")[:MAX_BODY_BYTES]

    similarity = round(
        difflib.SequenceMatcher(None, base_body_str[:16384], mut_body_str[:16384]).ratio(),
        4,
    )

    base_headers = {str(k).lower(): _redact_sensitive_value(str(v)) for k, v in (baseline.get("headers") or {}).items()}
    mut_headers = {str(k).lower(): _redact_sensitive_value(str(v)) for k, v in (mutated.get("headers") or {}).items()}
    header_diffs: list[dict[str, Any]] = []
    for hk in sorted(set(base_headers) | set(mut_headers)):
        if base_headers.get(hk) != mut_headers.get(hk):
            header_diffs.append({
                "header": hk,
                "baseline": base_headers.get(hk),
                "mutated": mut_headers.get(hk),
            })

    base_json = _safe_json_loads(base_body_raw)
    mut_json = _safe_json_loads(mut_body_raw)
    json_diffs: list[dict[str, Any]] = []
    if base_json is not None and mut_json is not None:
        flat_b = _flatten_json(base_json)
        flat_m = _flatten_json(mut_json)
        for jk in sorted(set(flat_b) | set(flat_m)):
            if flat_b.get(jk) != flat_m.get(jk):
                json_diffs.append({
                    "field": jk,
                    "baseline": flat_b.get(jk),
                    "mutated": flat_m.get(jk),
                })

    anomalies: list[dict[str, Any]] = []
    # 1. Başarısız/yasaklı (401/403/404) durumdan 2xx durumuna geçiş (Auth / Guard Bypass)
    if base_status in {401, 403, 404} and 200 <= mut_status < 300:
        anomalies.append({
            "control_id": "SNIPER-REPEATER-BYPASS-01",
            "cwe": "CWE-285",
            "severity": "critical",
            "title": "Paket mutasyonu ile erişim kontrolü / durum kodu atlaması (401/403 -> 2xx)",
            "evidence": f"baseline_status={base_status} iken mutated_status={mut_status} döndü.",
            "recommendation": "Yöntem, başlık veya parametre değişimlerinde yetkilendirme kontrolünü tüm dallarda zorunlu kılın.",
        })

    # 2. Fiyat / miktar / rol / kiracı alanı manipülasyonunun 2xx ile kabul edilmesi
    if 200 <= mut_status < 300 and json_diffs:
        for diff in json_diffs:
            leaf = diff["field"].rsplit(".", 1)[-1].lower()
            is_price_field = leaf in _PRIVILEGE_KEYS or any(tok in leaf for tok in ("price", "amount", "total", "cost"))
            is_role_field = leaf in _PRIVILEGE_KEYS or any(tok in leaf for tok in ("role", "admin", "verified", "permission", "tenant", "org"))
            if is_price_field or is_role_field:
                mut_val = diff["mutated"]
                if any(tok in leaf for tok in ("price", "amount", "total", "cost")) and isinstance(mut_val, (int, float)) and mut_val <= 0:
                    anomalies.append({
                        "control_id": "SNIPER-REPEATER-LOGIC-02",
                        "cwe": "CWE-840",
                        "severity": "critical",
                        "title": "Paket mutasyonu ile negatif veya sıfır fiyat/tutar kabul edildi (Business Logic Bypass)",
                        "evidence": f"Alan '{diff['field']}' değeri {diff['baseline']!r} -> {mut_val!r} olarak 2xx yanıtında kabul edildi.",
                        "recommendation": "Fiyat ve tutar bilgilerini istemci paketinden okumayın; sunucu tarafında katalogdan hesaplayın.",
                    })
                elif any(tok in leaf for tok in ("role", "admin", "verified")) and mut_val in {"admin", "superadmin", True, 1}:
                    anomalies.append({
                        "control_id": "SNIPER-REPEATER-MASS-03",
                        "cwe": "CWE-915",
                        "severity": "high",
                        "title": "Paket mutasyonu ile yetki/rol alanı (Mass Assignment) yükseltildi",
                        "evidence": f"Alan '{diff['field']}' değeri {diff['baseline']!r} -> {mut_val!r} olarak güncellendi.",
                        "recommendation": "İstemciden gelen JSON gövdesinde rol ve doğrulama alanlarını açık izin listesiyle (allowlist) filtreleyin.",
                    })

    return {
        "format": FORMAT,
        "status_changed": base_status != mut_status,
        "baseline_status": base_status,
        "mutated_status": mut_status,
        "baseline_length": len(base_bytes),
        "mutated_length": len(mut_bytes),
        "length_delta": len(mut_bytes) - len(base_bytes),
        "baseline_sha256": hashlib.sha256(base_bytes).hexdigest(),
        "mutated_sha256": hashlib.sha256(mut_bytes).hexdigest(),
        "similarity_ratio": similarity,
        "header_diffs": header_diffs,
        "json_diffs": json_diffs,
        "applied_mutation": applied_mutation or {},
        "finding_count": len(anomalies),
        "findings": anomalies,
    }


def apply_request_mutation(base_request: dict[str, Any], mutation: dict[str, Any]) -> dict[str, Any]:
    """Temel HTTP istek şablonuna başlık, sorgu parametresi, çerez veya JSON gövde mutasyonu uygular."""
    req = copy.deepcopy(base_request)
    if "method" in mutation and mutation["method"]:
        req["method"] = str(mutation["method"]).upper()
    if "path" in mutation and mutation["path"]:
        req["path"] = str(mutation["path"])

    headers = dict(req.get("headers") or {})
    for hk, hv in (mutation.get("headers") or {}).items():
        if hv is None:
            headers.pop(hk, None)
        else:
            headers[str(hk)] = str(hv)
    req["headers"] = headers

    query = dict(req.get("query_params") or {})
    for qk, qv in (mutation.get("query_params") or {}).items():
        if qv is None:
            query.pop(qk, None)
        else:
            query[str(qk)] = qv
    req["query_params"] = query

    if "json_body_overrides" in mutation and isinstance(mutation["json_body_overrides"], dict):
        body = copy.deepcopy(req.get("json_body") if isinstance(req.get("json_body"), dict) else {})
        for bk, bv in mutation["json_body_overrides"].items():
            if bv is None:
                body.pop(bk, None)
            else:
                body[str(bk)] = bv
        req["json_body"] = body

    return req


def _send_loopback_http(req: dict[str, Any], *, timeout_sec: float = 5.0) -> dict[str, Any]:
    url = str(req.get("url") or "http://127.0.0.1/")
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("Canlı Repeater isteği yalnızca yerel loopback (127.0.0.1 / localhost) hedeflerine gönderilebilir.")
    query_dict = req.get("query_params") or {}
    if query_dict:
        q_str = urllib.parse.urlencode(query_dict, doseq=True)
        url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, q_str, ""))
    method = str(req.get("method") or "GET").upper()
    headers = {str(k): str(v) for k, v in (req.get("headers") or {}).items()}
    data_bytes = None
    if "json_body" in req and req["json_body"] is not None:
        data_bytes = json.dumps(req["json_body"]).encode("utf-8")
        headers.setdefault("Content-Type", "application/json")
    request_obj = urllib.request.Request(url, data=data_bytes, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request_obj, timeout=max(0.5, min(float(timeout_sec), 10.0))) as resp:
            raw_body = resp.read(MAX_BODY_BYTES).decode("utf-8", errors="replace")
            return {
                "status_code": resp.status,
                "headers": dict(resp.headers.items()),
                "body": _safe_json_loads(raw_body) or raw_body,
            }
    except urllib.error.HTTPError as exc:
        raw_body = exc.read(MAX_BODY_BYTES).decode("utf-8", errors="replace") if exc.fp else ""
        return {
            "status_code": exc.code,
            "headers": dict(exc.headers.items()) if exc.headers else {},
            "body": _safe_json_loads(raw_body) or raw_body,
        }


def execute_loopback_repeater_mutation(
    base_request: dict[str, Any],
    mutation: dict[str, Any],
    *,
    target_handler_fn: Any | None = None,
    timeout_sec: float = 5.0,
) -> dict[str, Any]:
    """Temel isteği ve mutasyonlu isteği çalıştırıp yanıt farklarını (Repeater + Comparer) döndürür."""
    mutated_request = apply_request_mutation(base_request, mutation)
    if callable(target_handler_fn):
        baseline_resp = target_handler_fn(copy.deepcopy(base_request))
        mutated_resp = target_handler_fn(copy.deepcopy(mutated_request))
    else:
        baseline_resp = _send_loopback_http(base_request, timeout_sec=timeout_sec)
        mutated_resp = _send_loopback_http(mutated_request, timeout_sec=timeout_sec)
    return compare_http_responses(
        baseline_resp,
        mutated_resp,
        applied_mutation=mutation,
    )
