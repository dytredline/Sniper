"""Sniper HTTP Request Smuggling & Web Cache Poisoning Prober
(Burp HTTP Request Smuggler + Web Cache Poisoning eklentileri karşılığı).

1. CL.TE, TE.CL, TE.TE (gizlenmiş Transfer-Encoding) ve H2.CL / H2.TE (HTTP/2 downgrade)
   diferansiyel zamanlama ve kuyruk (pipelined request) zehirlenme kanıtlarını değerlendirir.
2. Unkeyed Header (X-Forwarded-Host, X-Forwarded-Scheme, X-Original-Host) üzerinden
   Web Önbellek Zehirlenmesi (Web Cache Poisoning) kanarya testini çalıştırır.
"""
from __future__ import annotations

import copy
from typing import Any, Callable


FORMAT_SMUGGLING = "sniper-http-smuggling-differential-proof/1"
FORMAT_CACHE_POISON = "sniper-web-cache-poisoning-proof/1"


def evaluate_smuggling_differential_probes(probes: list[dict[str, Any]]) -> dict[str, Any]:
    """Diferansiyel CL.TE / TE.CL / H2.CL zamanlama ve ardışık istek (desync) kanıtlarını değerlendirir."""
    findings: list[dict[str, Any]] = []
    evaluated: list[dict[str, Any]] = []

    for probe in (probes or []):
        if not isinstance(probe, dict):
            continue
        variant = str(probe.get("variant") or "CL.TE").upper()
        normal_ms = float(probe.get("baseline_elapsed_ms", 20.0) or 20.0)
        ambiguous_ms = float(probe.get("ambiguous_elapsed_ms", 20.0) or 20.0)
        victim_status = int(probe.get("followup_victim_status", 200) or 200)
        baseline_status = int(probe.get("baseline_status", 200) or 200)
        poisoned_prefix_reflected = bool(probe.get("poisoned_prefix_reflected", False))

        timing_desync = (ambiguous_ms - normal_ms) >= 1500.0 and baseline_status == 200
        queue_desync = poisoned_prefix_reflected or (baseline_status == 200 and victim_status in {400, 404, 405})
        vulnerable = timing_desync or queue_desync

        if vulnerable:
            findings.append({
                "control_id": "SNIPER-SMUGGLE-DESYNC-01",
                "cwe": "CWE-444",
                "reference": "CWE-444",
                "severity": "critical",
                "category": "web_hardening",
                "variant": variant,
                "title": f"HTTP İstek Kaçakçılığı (Request Smuggling — {variant}) desenkronizasyon kanıtı doğrulandı",
                "evidence": (
                    f"variant={variant}: baseline_ms={normal_ms}, ambiguous_ms={ambiguous_ms}, "
                    f"followup_victim_status={victim_status}, poisoned_prefix_reflected={poisoned_prefix_reflected}"
                ),
                "recommendation": (
                    "Ön uç (CDN/Vekil) ve arka uç sunucularında hem Content-Length hem Transfer-Encoding içeren "
                    "istekleri RFC 9112 uyarınca 400 Bad Request ile reddedin ve uçtan uca HTTP/2 kullanın."
                ),
            })

        evaluated.append({
            "variant": variant,
            "timing_desync": timing_desync,
            "queue_desync": queue_desync,
            "vulnerable": vulnerable,
        })

    return {
        "format": FORMAT_SMUGGLING,
        "probe_count": len(evaluated),
        "vulnerable_count": len(findings),
        "probes": evaluated,
        "finding_count": len(findings),
        "findings": findings,
    }


def run_loopback_cache_poisoning_probe(
    base_request: dict[str, Any],
    *,
    target_handler_fn: Callable[[dict[str, Any]], dict[str, Any]],
    unkeyed_headers: dict[str, str] | None = None,
    cache_buster: str = "cb_sniper_991",
) -> dict[str, Any]:
    """Unkeyed başlıklarla gönderilen zehirleme isteğinin ardından temiz kurban isteğinde önbellekten yansıyıp yansımadığını kanıtlar."""
    injected_hdrs = unkeyed_headers or {
        "X-Forwarded-Host": "canary-poison.internal",
        "X-Forwarded-Scheme": "http",
    }
    canaries = [str(v) for v in injected_hdrs.values() if str(v)]

    # 1. Zehirleyici (Attacker) İstek: cache_buster + unkeyed headers
    poison_req = copy.deepcopy(base_request)
    qp = dict(poison_req.get("query_params") or {})
    qp["_cb"] = cache_buster
    poison_req["query_params"] = qp
    hdrs = dict(poison_req.get("headers") or {})
    hdrs.update(injected_hdrs)
    poison_req["headers"] = hdrs
    poison_resp = target_handler_fn(poison_req)

    # 2. Temiz Kurban (Victim) İstek: aynı cache_buster, unkeyed header YOK
    victim_req = copy.deepcopy(base_request)
    v_qp = dict(victim_req.get("query_params") or {})
    v_qp["_cb"] = cache_buster
    victim_req["query_params"] = v_qp
    victim_req["headers"] = dict(base_request.get("headers") or {})
    victim_resp = target_handler_fn(victim_req)

    victim_body = str(victim_resp.get("body") or "")
    victim_headers_str = " ".join(f"{k}: {v}" for k, v in (victim_resp.get("headers") or {}).items())
    reflected_canaries = [c for c in canaries if c in victim_body or c in victim_headers_str]
    poisoned = len(reflected_canaries) > 0

    findings: list[dict[str, Any]] = []
    if poisoned:
        findings.append({
            "control_id": "SNIPER-CACHE-POISON-01",
            "cwe": "CWE-444",
            "reference": "CWE-444",
            "severity": "high",
            "category": "web_hardening",
            "title": "Web Önbellek Zehirlenmesi (Web Cache Poisoning): Anahtar dışı (Unkeyed) başlık temiz kurban yanıtında önbellekten döndü",
            "evidence": (
                f"Zehirleyici istekte gönderilen {injected_hdrs!r} değerleri, başlık içermeyen "
                f"kurban isteğinde ({cache_buster}) önbellekten yansıdı: {reflected_canaries!r}"
            ),
            "recommendation": "Yanıt üretiminde kullanılan X-Forwarded-Host / X-Forwarded-Scheme gibi başlıkları önbellek anahtarına (Vary / Cache Key) dahil edin veya tamamen yoksayın.",
        })

    return {
        "format": FORMAT_CACHE_POISON,
        "cache_buster": cache_buster,
        "poison_status": int(poison_resp.get("status_code", poison_resp.get("status", 200)) or 200),
        "victim_status": int(victim_resp.get("status_code", victim_resp.get("status", 200)) or 200),
        "cache_poisoned": poisoned,
        "reflected_canaries": reflected_canaries,
        "finding_count": len(findings),
        "findings": findings,
    }
