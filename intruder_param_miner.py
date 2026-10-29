"""Sniper Intruder & Param Miner (Burp Intruder 4 Saldırı Modu + Param Miner karşılığı).

1. Burp Intruder'ın 4 çoklu yük (payload position §...§) modunu destekler:
   - sniper: Tek yük kümesini her konumda sırayla dener (diğer konumlar varsayılan değerinde kalır).
   - battering_ram: Tek yük kümesini aynı anda tüm konumlara yerleştirir.
   - pitchfork: Çoklu yük kümelerini paralel indeksle (zip) eşleştirir.
   - cluster_bomb: Çoklu yük kümelerinin kartezyen çarpımını (product) üretir.
2. Grep-Match, Grep-Extract ve Zaman Gecikmesi (Time-Based Blind Injection) anomalilerini yakalar.
3. Param Miner: Gizli sorgu/gövde parametrelerini ve ters vekil başlıklarını (X-Original-URL,
   X-Forwarded-Host vb.) kanarya değerleriyle tarayarak gizli yüzeyleri keşfeder.
"""
from __future__ import annotations

import copy
import difflib
import itertools
import re
from typing import Any, Callable


FORMAT_INTRUDER = "sniper-intruder-campaign/1"
FORMAT_PARAM_MINER = "sniper-param-miner-report/1"

_POSITION_RE = re.compile(r"§([^§]*)§")
DEFAULT_HIDDEN_PARAMS = (
    "debug", "admin", "internal", "test", "env", "format", "callback", "redirect", "role", "version",
)
DEFAULT_HIDDEN_HEADERS = (
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Forwarded-Host",
    "X-Forwarded-For",
    "X-Custom-IP-Authorization",
    "X-Forwarded-Scheme",
)


def generate_intruder_payload_positions(
    template_str: str,
    payload_sets: list[list[str]],
    *,
    attack_type: str = "sniper",
    max_requests: int = 256,
) -> dict[str, Any]:
    """Şablondaki §...§ işaretçilerine göre 4 Intruder modundan birinde istek dizgelerini üretir."""
    mode = str(attack_type or "sniper").strip().lower()
    if mode not in {"sniper", "battering_ram", "pitchfork", "cluster_bomb"}:
        raise ValueError(f"Desteklenmeyen Intruder saldırı modu: {mode}")

    matches = list(_POSITION_RE.finditer(template_str))
    defaults = [m.group(1) for m in matches]
    pos_count = len(matches)
    cap = max(1, min(int(max_requests or 256), 1024))

    def _render(values: list[str]) -> str:
        out: list[str] = []
        last = 0
        for idx, m in enumerate(matches):
            out.append(template_str[last:m.start()])
            out.append(str(values[idx]))
            last = m.end()
        out.append(template_str[last:])
        return "".join(out)

    rendered_requests: list[dict[str, Any]] = []
    if pos_count == 0 or not payload_sets:
        return {
            "attack_type": mode,
            "position_count": pos_count,
            "request_count": 0,
            "requests": [],
        }

    first_set = [str(x) for x in (payload_sets[0] or [])]

    if mode == "sniper":
        for pos_idx in range(pos_count):
            for payload in first_set:
                if len(rendered_requests) >= cap:
                    break
                vals = list(defaults)
                vals[pos_idx] = payload
                rendered_requests.append({
                    "position_index": pos_idx,
                    "payloads": [payload],
                    "rendered": _render(vals),
                })
    elif mode == "battering_ram":
        for payload in first_set:
            if len(rendered_requests) >= cap:
                break
            vals = [payload] * pos_count
            rendered_requests.append({
                "position_index": -1,
                "payloads": vals,
                "rendered": _render(vals),
            })
    elif mode == "pitchfork":
        active_sets = [[str(x) for x in ( payload_sets[i] if i < len(payload_sets) else [])] for i in range(pos_count)]
        for combo in zip(*active_sets):
            if len(rendered_requests) >= cap:
                break
            vals = list(combo)
            rendered_requests.append({
                "position_index": -1,
                "payloads": vals,
                "rendered": _render(vals),
            })
    elif mode == "cluster_bomb":
        active_sets = [[str(x) for x in (payload_sets[i] if i < len(payload_sets) else [])] for i in range(pos_count)]
        for combo in itertools.product(*active_sets):
            if len(rendered_requests) >= cap:
                break
            vals = list(combo)
            rendered_requests.append({
                "position_index": -1,
                "payloads": vals,
                "rendered": _render(vals),
            })

    return {
        "attack_type": mode,
        "position_count": pos_count,
        "request_count": len(rendered_requests),
        "requests": rendered_requests,
    }


def execute_intruder_campaign(
    template_str: str,
    payload_sets: list[list[str]],
    *,
    target_handler_fn: Callable[[str], dict[str, Any]],
    attack_type: str = "sniper",
    grep_match_patterns: list[str] | None = None,
    grep_extract_regex: str | None = None,
    time_anomaly_threshold_ms: float = 500.0,
    max_requests: int = 256,
) -> dict[str, Any]:
    """Intruder kampanyasını çalıştırıp Grep-Match, Grep-Extract ve Time-Based Blind anomalilerini raporlar."""
    plan = generate_intruder_payload_positions(
        template_str,
        payload_sets,
        attack_type=attack_type,
        max_requests=max_requests,
    )
    baseline_rendered = _POSITION_RE.sub(r"\1", template_str)
    base_resp = target_handler_fn(baseline_rendered)
    base_body = str(base_resp.get("body") or "")
    base_ms = float(base_resp.get("elapsed_ms", 1.0) or 1.0)

    extract_rx = re.compile(grep_extract_regex) if grep_extract_regex else None
    results: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []

    for item in plan["requests"]:
        resp = target_handler_fn(item["rendered"])
        status_code = int(resp.get("status_code", resp.get("status", 200)) or 200)
        body = str(resp.get("body") or "")
        elapsed_ms = float(resp.get("elapsed_ms", 1.0) or 1.0)

        matched_greps: list[str] = []
        for pat in (grep_match_patterns or []):
            if pat and pat in body and pat not in base_body:
                matched_greps.append(pat)

        extracted_val = None
        if extract_rx is not None:
            m = extract_rx.search(body)
            if m:
                extracted_val = m.group(1) if m.groups() else m.group(0)

        time_delta_ms = round(elapsed_ms - base_ms, 2)
        if matched_greps:
            findings.append({
                "control_id": "SNIPER-INTRUDER-GREP-01",
                "cwe": "CWE-89",
                "reference": "CWE-89",
                "severity": "critical",
                "category": "command_data",
                "title": f"Intruder ({attack_type}) yükünde Grep-Match imzası yakalandı",
                "evidence": f"payloads={item['payloads']!r} -> eşleşen kalıplar={matched_greps!r}, status={status_code}",
                "recommendation": "Girdi parametrelerini parametreli sorgu ve sıkı izin listesiyle doğrulayın.",
            })

        if time_delta_ms >= float(time_anomaly_threshold_ms):
            findings.append({
                "control_id": "SNIPER-INTRUDER-TIMING-02",
                "cwe": "CWE-89",
                "reference": "CWE-89",
                "severity": "high",
                "category": "command_data",
                "title": f"Intruder ({attack_type}) yükünde zaman gecikmesi (Time-Based Blind) anomalisi tespit edildi",
                "evidence": f"payloads={item['payloads']!r} -> gecikme farkı +{time_delta_ms} ms (eşik={time_anomaly_threshold_ms} ms)",
                "recommendation": "Zaman tabanlı kör enjeksiyonlara karşı kabuk/veritabanı çağrılarında kullanıcı girdisi birleştirmeyin.",
            })

        results.append({
            "payloads": item["payloads"],
            "status_code": status_code,
            "length": len(body),
            "length_delta": len(body) - len(base_body),
            "elapsed_ms": elapsed_ms,
            "grep_matches": matched_greps,
            "grep_extracted": extracted_val,
        })

    return {
        "format": FORMAT_INTRUDER,
        "attack_type": plan["attack_type"],
        "position_count": plan["position_count"],
        "request_count": len(results),
        "results": results,
        "finding_count": len(findings),
        "findings": findings,
    }


def mine_unlinked_parameters_and_headers(
    baseline_req: dict[str, Any],
    *,
    target_handler_fn: Callable[[dict[str, Any]], dict[str, Any]],
    candidate_params: list[str] | None = None,
    candidate_headers: list[str] | None = None,
) -> dict[str, Any]:
    """Burp Param Miner karşılığı: gizli sorgu/gövde parametrelerini ve ters vekil başlıklarını keşfeder."""
    base_resp = target_handler_fn(copy.deepcopy(baseline_req))
    base_status = int(base_resp.get("status_code", base_resp.get("status", 200)) or 200)
    base_body = str(base_resp.get("body") or "")

    discovered_params: list[dict[str, Any]] = []
    discovered_headers: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []

    for param in (candidate_params or list(DEFAULT_HIDDEN_PARAMS)):
        canary = f"sniper_pm_{param}_1"
        probe_req = copy.deepcopy(baseline_req)
        qp = dict(probe_req.get("query_params") or {})
        qp[param] = "true" if param in {"debug", "admin", "internal", "test"} else canary
        probe_req["query_params"] = qp
        resp = target_handler_fn(probe_req)
        code = int(resp.get("status_code", resp.get("status", 200)) or 200)
        body = str(resp.get("body") or "")
        sim = difflib.SequenceMatcher(None, base_body[:4096], body[:4096]).ratio()
        if code != base_status or canary in body or sim < 0.85:
            discovered_params.append({"parameter": param, "baseline_status": base_status, "probe_status": code, "similarity": round(sim, 4)})
            findings.append({
                "control_id": "SNIPER-PARAM-MINER-01",
                "cwe": "CWE-472",
                "reference": "CWE-472",
                "severity": "high" if (base_status in {401, 403} and 200 <= code < 300) else "medium",
                "category": "authz",
                "title": f"Gizli/bağlantısız uygulama parametresi davranış değişikliği üretti: {param}",
                "evidence": f"Parametre '{param}' eklendiğinde yanıt status={base_status}->{code}, benzerlik={sim:.2f} oldu.",
                "recommendation": "Üretim ortamında debug/admin/test gibi gizli sorgu parametrelerini devre dışı bırakın.",
            })

    for hdr in (candidate_headers or list(DEFAULT_HIDDEN_HEADERS)):
        canary_val = "/admin" if "URL" in hdr else "127.0.0.1"
        probe_req = copy.deepcopy(baseline_req)
        headers = dict(probe_req.get("headers") or {})
        headers[hdr] = canary_val
        probe_req["headers"] = headers
        resp = target_handler_fn(probe_req)
        code = int(resp.get("status_code", resp.get("status", 200)) or 200)
        body = str(resp.get("body") or "")
        sim = difflib.SequenceMatcher(None, base_body[:4096], body[:4096]).ratio()
        if code != base_status or sim < 0.85:
            discovered_headers.append({"header": hdr, "baseline_status": base_status, "probe_status": code, "similarity": round(sim, 4)})
            findings.append({
                "control_id": "SNIPER-PARAM-MINER-02",
                "cwe": "CWE-285",
                "reference": "CWE-285",
                "severity": "critical" if (base_status in {401, 403} and 200 <= code < 300) else "high",
                "category": "authz",
                "title": f"Gizli vekil/yönlendirme başlığı erişim davranışını değiştirdi: {hdr}",
                "evidence": f"Başlık '{hdr}: {canary_val}' gönderildiğinde yanıt status={base_status}->{code}, benzerlik={sim:.2f} oldu.",
                "recommendation": "Dış istemcilerden gelen X-Original-URL, X-Rewrite-URL ve X-Forwarded-Host başlıklarını kenar vekilde temizleyin.",
            })

    return {
        "format": FORMAT_PARAM_MINER,
        "discovered_parameters": discovered_params,
        "discovered_headers": discovered_headers,
        "finding_count": len(findings),
        "findings": findings,
    }
