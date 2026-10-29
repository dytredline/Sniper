"""Sniper Traffic Decoder & HAR/HTTP Inspector (Burp Decoder + Proxy Inspector karşılığı).

Çok katmanlı kodlanmış (URL, Base64/Base64URL, Hex, HTML entity, JWT) verileri özyinelemeli
olarak çözer; içindeki güvensiz JWT başlıklarını (alg:none, jku, x5u), serileştirilmiş
nesne imzalarını (Java rO0AB, Python pickle, PHP serialize), iç ağ SSRF hedeflerini ve
gizli yetki parametrelerini tespit ederek Repeater ve Autorize şablonları üretir.
"""
from __future__ import annotations

import base64
import binascii
import html
import json
import re
import urllib.parse
from typing import Any


FORMAT_DECODER = "sniper-traffic-decoder/1"
FORMAT_INSPECTOR = "sniper-traffic-inspector/1"

_HEX_STR_RE = re.compile(r"^(?:[0-9a-fA-F]{2}){8,}$")
_B64_STR_RE = re.compile(r"^[A-Za-z0-9+/_-]{12,}={0,2}$")
_INTERNAL_HOST_RE = re.compile(
    r"(?i)\b(?:127\.0\.0\.1|localhost|169\.254\.169\.254|metadata\.google\.internal|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"
)


def _try_decode_jwt(value: str) -> dict[str, Any] | None:
    cleaned = value.strip()
    if cleaned.lower().startswith("bearer "):
        cleaned = cleaned[7:].strip()
    parts = cleaned.split(".")
    if len(parts) not in (2, 3) or not parts[0].startswith("eyJ"):
        return None
    try:
        hdr_pad = parts[0] + "=" * ((4 - len(parts[0]) % 4) % 4)
        pay_pad = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
        header = json.loads(base64.urlsafe_b64decode(hdr_pad).decode("utf-8"))
        payload = json.loads(base64.urlsafe_b64decode(pay_pad).decode("utf-8"))
        if isinstance(header, dict) and isinstance(payload, dict):
            return {"header": header, "payload": payload, "has_signature": len(parts) == 3 and bool(parts[2])}
    except Exception:
        return None
    return None


def recursive_decode_and_inspect(raw_value: str, *, max_depth: int = 4) -> dict[str, Any]:
    """Girdi değerini çok katmanlı olarak çözer ve güvenlik sinyallerini çıkarır."""
    current = str(raw_value or "").strip()
    steps: list[dict[str, str]] = []
    signals: list[str] = []
    findings: list[dict[str, Any]] = []

    if current.startswith("rO0AB"):
        signals.append("java_serialized_object_base64")
        findings.append({
            "control_id": "SNIPER-DECODER-DESER-01",
            "cwe": "CWE-502",
            "reference": "CWE-502",
            "severity": "critical",
            "category": "command_data",
            "title": "HTTP trafiğinde Base64 kodlu Java ObjectInputStream serileştirme imzası (rO0AB) tespit edildi",
            "evidence": "Parametre veya çerez değeri Java serileştirme başlığı 'rO0AB' (0xACED0005) ile başlıyor.",
            "recommendation": "İstemciden gelen verilerde Java ObjectInputStream serileştirme çözümünü kaldırın; JSON şeması kullanın.",
        })

    for _depth in range(max(1, min(int(max_depth), 8))):
        jwt_info = _try_decode_jwt(current)
        if jwt_info is not None:
            steps.append({"encoding": "jwt", "output": json.dumps(jwt_info, ensure_ascii=False, sort_keys=True)})
            alg = str(jwt_info["header"].get("alg") or "").lower()
            if alg == "none" or not jwt_info["has_signature"]:
                signals.append("jwt_alg_none_or_unsigned")
                findings.append({
                    "control_id": "SNIPER-DECODER-JWT-01",
                    "cwe": "CWE-347",
                    "reference": "CWE-347",
                    "severity": "critical",
                    "category": "crypto",
                    "title": "HTTP trafiğinde imzasız veya 'alg: none' JWT belirteci tespit edildi",
                    "evidence": f"JWT header={jwt_info['header']!r}, has_signature={jwt_info['has_signature']}",
                    "recommendation": "JWT doğrulayıcısında 'none' algoritmasını reddedin ve sabit algoritma izin listesi zorunlu kılın.",
                })
            if any(k in jwt_info["header"] for k in ("jku", "x5u")):
                signals.append("jwt_external_key_url_header")
                findings.append({
                    "control_id": "SNIPER-DECODER-JWT-02",
                    "cwe": "CWE-347",
                    "reference": "CWE-347",
                    "severity": "high",
                    "category": "crypto",
                    "title": "JWT başlığında harici anahtar URL'si (jku/x5u) tespit edildi",
                    "evidence": f"JWT header={jwt_info['header']!r}",
                    "recommendation": "JWT başlığındaki dinamik jku/x5u adreslerine istek göndermeyin; sabit yerel JWKS kullanın.",
                })
            current = json.dumps(jwt_info, ensure_ascii=False, sort_keys=True)
            break

        if "%" in current:
            unquoted = urllib.parse.unquote(current)
            if unquoted != current:
                steps.append({"encoding": "url", "output": unquoted})
                current = unquoted
                continue

        if "&" in current and ";" in current:
            unescaped = html.unescape(current)
            if unescaped != current:
                steps.append({"encoding": "html_entity", "output": unescaped})
                current = unescaped
                continue

        if _HEX_STR_RE.fullmatch(current):
            try:
                raw_hex = binascii.unhexlify(current)
                decoded_hex = raw_hex.decode("utf-8")
                if all(ch.isprintable() or ch in "\r\n\t" for ch in decoded_hex):
                    steps.append({"encoding": "hex", "output": decoded_hex})
                    current = decoded_hex
                    continue
            except Exception:
                pass

        if _B64_STR_RE.fullmatch(current):
            try:
                padded = current + "=" * ((4 - len(current) % 4) % 4)
                raw_b64 = base64.urlsafe_b64decode(padded)
                decoded_b64 = raw_b64.decode("utf-8")
                if decoded_b64 and all(ch.isprintable() or ch in "\r\n\t" for ch in decoded_b64):
                    steps.append({"encoding": "base64", "output": decoded_b64})
                    current = decoded_b64
                    continue
            except Exception:
                pass

        break

    if _INTERNAL_HOST_RE.search(current):
        signals.append("internal_network_or_imds_target")
        findings.append({
            "control_id": "SNIPER-DECODER-SSRF-03",
            "cwe": "CWE-918",
            "reference": "CWE-918",
            "severity": "high",
            "category": "ssrf",
            "title": "Çözümlenen trafik parametresinde iç ağ veya bulut metadata (IMDS) adresi tespit edildi",
            "evidence": f"Çözümlenen değer içinde iç adres görüldü: {current[:160]}",
            "recommendation": "Girdi parametrelerindeki URL hedeflerini SSRF izin listesi ve özel IP filtresinden geçirin.",
        })

    if re.search(r'\bO:\d+:"[A-Za-z0-9_]+"', current):
        signals.append("php_serialized_object")
        findings.append({
            "control_id": "SNIPER-DECODER-DESER-02",
            "cwe": "CWE-502",
            "reference": "CWE-502",
            "severity": "critical",
            "category": "command_data",
            "title": "Çözümlenen trafik parametresinde PHP serileştirilmiş nesne (unserialize) tespit edildi",
            "evidence": f"Çözümlenen değer: {current[:160]}",
            "recommendation": "PHP unserialize() yerine json_decode() kullanın.",
        })

    return {
        "format": FORMAT_DECODER,
        "steps": steps,
        "step_count": len(steps),
        "final_decoded": current,
        "detected_signals": sorted(set(signals)),
        "signals": sorted(set(signals)),
        "finding_count": len(findings),
        "findings": findings,
    }


def inspect_har_or_http_exchange(exchange: dict[str, Any]) -> dict[str, Any]:
    """Yakalanan bir HTTP/HAR isteğini inceleyip kodlanmış alanları çözer ve Repeater/Autorize şablonu üretir."""
    req = exchange.get("request") if isinstance(exchange.get("request"), dict) else exchange
    method = str(req.get("method") or "GET").upper()
    url = str(req.get("url") or "http://127.0.0.1/api/item/1")
    headers = dict(req.get("headers") or {})
    query_params = dict(req.get("query_params") or {})
    json_body = req.get("json_body") if isinstance(req.get("json_body"), dict) else {}

    parsed_url = urllib.parse.urlsplit(url)
    if parsed_url.query and not query_params:
        for k, v in urllib.parse.parse_qsl(parsed_url.query, keep_blank_values=True):
            query_params[k] = v

    decoded_fields: list[dict[str, Any]] = []
    all_findings: list[dict[str, Any]] = []

    for location, mapping in (("query", query_params), ("header", headers), ("body", json_body)):
        if not isinstance(mapping, dict):
            continue
        for k, v in mapping.items():
            if not isinstance(v, str) or len(v) < 6:
                continue
            dec = recursive_decode_and_inspect(v)
            if dec["step_count"] > 0 or dec["finding_count"] > 0:
                decoded_fields.append({
                    "location": location,
                    "parameter": str(k),
                    "steps": dec["steps"],
                    "final_decoded": dec["final_decoded"],
                    "signals": dec["detected_signals"],
                })
                all_findings.extend(dec["findings"])

    repeater_template = {
        "base_request": {
            "method": method,
            "url": urllib.parse.urlunsplit((parsed_url.scheme or "http", parsed_url.netloc or "127.0.0.1", parsed_url.path or "/", "", "")),
            "headers": headers,
            "query_params": query_params,
            "json_body": json_body,
        },
        "suggested_mutations": [
            {"label": "Yetki/Rol Yükseltme (Mass Assignment)", "json_body_overrides": {"role": "admin", "is_admin": True}},
            {"label": "Negatif Tutar/Miktar İş Mantığı Testi", "json_body_overrides": {"price": -1, "amount": 0}},
        ],
    }

    autorize_template = {
        "endpoint": f"{method} {parsed_url.path or '/'}",
        "request": repeater_template["base_request"],
        "injected_fields": {"role": "admin", "is_admin": True},
    }

    return {
        "format": FORMAT_INSPECTOR,
        "method": method,
        "url": url,
        "decoded_field_count": len(decoded_fields),
        "decoded_fields": decoded_fields,
        "repeater_template": repeater_template,
        "autorize_template": autorize_template,
        "finding_count": len(all_findings),
        "findings": all_findings,
    }
