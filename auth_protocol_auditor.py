from __future__ import annotations

import base64
import json
import re
from typing import Any
from urllib.parse import parse_qs, urlsplit

from scanner import calculate_score, utc_now
from finding_limits import INLINE_FINDING_LIMIT, PROJECT_FINDING_LIMIT, cap_findings, summarize_finding_groups


MAX_AUTH_ARTIFACT_BYTES = 256_000
SENSITIVE_CLAIM_KEYS = {
    "password", "passwd", "secret", "private_key", "ssn", "cvv", "pin", "api_key", "client_secret",
}


def _b64url_decode_json(segment: str) -> dict[str, Any]:
    padded = segment.strip() + "=" * ((4 - len(segment.strip()) % 4) % 4)
    raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    parsed = json.loads(raw.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("JWT segmenti JSON nesnesi değil.")
    return parsed


def _finding(
    severity: str,
    category: str,
    title: str,
    description: str,
    evidence: str,
    recommendation: str,
    cwe: str,
    control_id: str,
) -> dict[str, Any]:
    return {
        "severity": severity,
        "category": category,
        "title": title,
        "description": description,
        "evidence": evidence,
        "recommendation": recommendation,
        "reference": cwe,
        "cwe": cwe,
        "control_id": control_id,
    }


def audit_auth_artifact(
    raw_content: str,
    *,
    artifact_type: str = "auto",
) -> dict[str, Any]:
    if not isinstance(raw_content, str) or not raw_content.strip():
        raise ValueError("Analiz için geçerli bir kimlik doğrulama artefaktı (JWT, OAuth URL veya SAML XML) girin.")
    if len(raw_content.encode("utf-8", errors="ignore")) > MAX_AUTH_ARTIFACT_BYTES:
        raise ValueError("Artefakt boyutu izin verilen sınırı (256 KB) aşıyor.")

    cleaned = raw_content.strip()
    if cleaned.lower().startswith("bearer "):
        cleaned = cleaned[7:].strip()

    requested = (artifact_type or "auto").strip().casefold()
    if requested in {"jwt", "token"}:
        detected_type = "jwt"
    elif requested in {"oauth", "oauth_url", "oidc"}:
        detected_type = "oauth_url"
    elif requested in {"saml", "saml_xml", "xml"}:
        detected_type = "saml_xml"
    else:
        parts = cleaned.split(".")
        if len(parts) in {2, 3} and parts[0].startswith("eyJ"):
            detected_type = "jwt"
        elif re.search(r"(?i)<\s*(?:saml2?:|Assertion\b|EntityDescriptor\b|Response\b|!DOCTYPE\b)", cleaned):
            detected_type = "saml_xml"
        elif re.search(r"(?i)(?:response_type=|client_id=|redirect_uri=|code_challenge=)", cleaned) or (
            cleaned.startswith("{") and "redirect_uri" in cleaned.casefold()
        ):
            detected_type = "oauth_url"
        else:
            raise ValueError("Artefakt türü otomatik algılanamadı; JWT, OAuth2/OIDC URL veya SAML XML bekleniyor.")

    findings: list[dict[str, Any]] = []
    parsed_metadata: dict[str, Any] = {}

    if detected_type == "jwt":
        parts = cleaned.split(".")
        if len(parts) not in {2, 3}:
            raise ValueError("Geçersiz JWT formatı; 2 veya 3 nokta ayrılmış bölüm bekleniyor.")
        header = _b64url_decode_json(parts[0])
        payload = _b64url_decode_json(parts[1])
        signature = parts[2].strip() if len(parts) == 3 else ""

        alg = header.get("alg")
        if not alg or str(alg).strip().casefold() == "none" or not signature:
            findings.append(
                _finding(
                    "critical",
                    "crypto",
                    "JWT imzasız (alg: none) veya imza bölümü boş",
                    "JWT başlığında alg: none kullanılmış veya imza bölümü boş bırakılmış; belirteç bütünlüğü doğrulanamaz.",
                    f"alg={alg!r}, signature_present={bool(signature)}",
                    "alg: none kabulünü kapatın ve RS256/ES256/EdDSA gibi güçlü imza algoritmalarını zorunlu kılın.",
                    "CWE-347",
                    "SNIPER-CRYP-06",
                )
            )

        if any(k in header for k in ("jku", "x5u", "jwk")):
            findings.append(
                _finding(
                    "high",
                    "crypto",
                    "JWT başlığında harici anahtar referansı (jku/x5u/jwk) enjeksiyon riski",
                    "JWT başlığı doğrulama anahtarını harici URL (jku/x5u) veya gömülü jwk üzerinden dinamik belirtiyor.",
                    f"headers={[k for k in ('jku', 'x5u', 'jwk') if k in header]}",
                    "Doğrulama anahtarlarını yalnızca sunucu tarafındaki sabit güvenilir JWKS kaynağından seçin; gömülü jwk/jku başlıklarına güvenmeyin.",
                    "CWE-918",
                    "SNIPER-CRYP-06",
                )
            )

        kid = header.get("kid")
        if isinstance(kid, str) and re.search(r'(?:\.\.|/|\\|[\'";]|--)', kid):
            findings.append(
                _finding(
                    "critical",
                    "command_data",
                    "JWT kid başlığında dizin geçişi veya SQL enjeksiyonu deseni",
                    "JWT kid (Key ID) alanında dosya yolu geçişi (../) veya SQL/komut enjeksiyonu karakterleri saptandı.",
                    "kid alanında tehlikeli karakter dizisi bulundu",
                    "kid değerini yalnızca sabit alfanümerik anahtar tanımlayıcı allowlist'i ile eşleştirin.",
                    "CWE-22",
                    "SNIPER-INPV-05",
                )
            )

        exp = payload.get("exp")
        iat = payload.get("iat")
        if not isinstance(exp, (int, float)) or (
            isinstance(iat, (int, float)) and (exp - iat) > 86400 * 30
        ):
            findings.append(
                _finding(
                    "medium",
                    "session",
                    "JWT belirtecinde süre sonu (exp) eksik veya aşırı uzun",
                    "JWT yükünde exp (süre sonu) alanı bulunmuyor veya belirteç ömrü 30 günü aşıyor.",
                    f"exp_present={isinstance(exp, (int, float))}",
                    "Erişim belirteçlerinde (access token) kısa süreli exp (ör. 5–15 dakika) zorunlu kılın.",
                    "CWE-613",
                    "SNIPER-SESS-03",
                )
            )

        exposed_keys = sorted(
            k for k in payload.keys()
            if any(sens in k.casefold() for sens in SENSITIVE_CLAIM_KEYS)
        )
        if exposed_keys:
            findings.append(
                _finding(
                    "high",
                    "secrets",
                    "Şifrelenmemiş JWT yükünde (payload) hassas veri maruziyeti",
                    "Base64url ile kodlanmış (şifrelenmemiş JWS) JWT yükünde parola, sır veya özel anahtar alanı bulundu.",
                    f"sensitive_claims={exposed_keys}",
                    "JWT yükünde hassas veri taşımayın; gizlilik gerekiyorsa JWE (şifrelenmiş JWT) veya sunucu tarafı oturum kullanın.",
                    "CWE-312",
                    "SNIPER-DATA-09",
                )
            )

        redacted_payload = {
            k: ("[REDACTED]" if k in exposed_keys else v)
            for k, v in payload.items()
        }
        parsed_metadata = {
            "header": header,
            "claims": redacted_payload,
            "signature_present": bool(signature),
        }

    elif detected_type == "oauth_url":
        params: dict[str, list[str]] = {}
        if cleaned.startswith("{"):
            try:
                cfg = json.loads(cleaned)
            except json.JSONDecodeError as exc:
                raise ValueError("Geçersiz OAuth JSON yapılandırması.") from exc
            if isinstance(cfg, dict):
                for k, v in cfg.items():
                    params[str(k)] = [str(v)]
        else:
            split = urlsplit(cleaned)
            for k, vals in parse_qs(split.query, keep_blank_values=True).items():
                params.setdefault(k, []).extend(vals)
            for k, vals in parse_qs(split.fragment, keep_blank_values=True).items():
                params.setdefault(k, []).extend(vals)
            if not params and "=" in cleaned:
                for k, vals in parse_qs(cleaned, keep_blank_values=True).items():
                    params.setdefault(k, []).extend(vals)

        response_types = " ".join(params.get("response_type", [])).casefold().split()
        if any(rt in {"token", "id_token"} for rt in response_types):
            findings.append(
                _finding(
                    "high",
                    "authentication",
                    "OAuth 2.0 Implicit Flow (response_type=token) kullanımı",
                    "Yetkilendirme isteğinde kullanımdan kaldırılmış Implicit Flow (response_type=token / id_token) kullanılıyor; belirteçler URL fragment ve tarayıcı geçmişinde açığa çıkabilir.",
                    f"response_type={' '.join(response_types)}",
                    "Authorization Code Flow + PKCE (response_type=code ve code_challenge_method=S256) kullanın.",
                    "CWE-522",
                    "SNIPER-AUTH-11",
                )
            )

        state_vals = [v.strip() for v in params.get("state", []) if v.strip()]
        if not state_vals:
            findings.append(
                _finding(
                    "medium",
                    "authentication",
                    "OAuth 2.0 yetkilendirme isteğinde CSRF koruması (state) eksik",
                    "Yetkilendirme URL'sinde oturuma bağlı tahmin edilemez state parametresi bulunmuyor.",
                    "state parametresi eksik",
                    "Her yetkilendirme isteğinde kriptografik rastgele state/nonce değeri üretin ve geri dönüşte doğrulayın.",
                    "CWE-352",
                    "SNIPER-AUTH-11",
                )
            )

        challenge_vals = [v.strip() for v in params.get("code_challenge", []) if v.strip()]
        method_vals = [v.strip().upper() for v in params.get("code_challenge_method", []) if v.strip()]
        if not challenge_vals or "PLAIN" in method_vals or (challenge_vals and "S256" not in method_vals):
            findings.append(
                _finding(
                    "medium",
                    "authentication",
                    "OAuth 2.0 akışında PKCE (S256) doğrulaması eksik veya zayıf",
                    "Yetkilendirme isteğinde code_challenge (PKCE) bulunmuyor veya zayıf plain yöntemi kullanılıyor.",
                    f"code_challenge_present={bool(challenge_vals)}, method={method_vals or ['missing']}",
                    "Tüm istemcilerde PKCE (code_challenge ve code_challenge_method=S256) zorunlu kılın.",
                    "CWE-345",
                    "SNIPER-AUTH-11",
                )
            )

        redirect_uris = [v.strip() for v in params.get("redirect_uri", []) if v.strip()]
        for uri in redirect_uris:
            if "*" in uri or (
                uri.casefold().startswith("http://")
                and not re.match(r"(?i)^http://(?:localhost|127\.0\.0\.1)(?:[:/]|$)", uri)
            ):
                findings.append(
                    _finding(
                        "high",
                        "authentication",
                        "OAuth 2.0 redirect_uri şifrelenmemiş (HTTP) veya joker karakter içeriyor",
                        "redirect_uri parametresinde şifresiz http:// şeması veya açık yönlendirmeye yol açabilecek joker (*) karakteri saptandı.",
                        f"redirect_uri={uri}",
                        "redirect_uri için yalnızca tam eşleşen HTTPS adreslerine izin verin; joker karakter kullanmayın.",
                        "CWE-601",
                        "SNIPER-AUTH-11",
                    )
                )
                break

        parsed_metadata = {
            "response_type": response_types,
            "has_state": bool(state_vals),
            "has_pkce_s256": bool(challenge_vals and "S256" in method_vals),
            "redirect_uris": redirect_uris,
        }

    elif detected_type == "saml_xml":
        if re.search(r"(?i)<!(?:DOCTYPE|ENTITY)\b", cleaned):
            findings.append(
                _finding(
                    "critical",
                    "data_query",
                    "SAML XML belgesinde DTD / XXE tanımı bulundu",
                    "SAML XML içeriğinde DOCTYPE veya ENTITY bildirimi yer alıyor; XML dış varlık (XXE) veya imza sarma (XSW) saldırılarına yol açabilir.",
                    "<!DOCTYPE / <!ENTITY bildirimi mevcut",
                    "SAML XML ayrıştırıcısında DTD ve dış varlık işlemeyi tamamen yasaklayın.",
                    "CWE-611",
                    "SNIPER-INPV-06",
                )
            )

        has_signature = bool(re.search(r"<\s*(?:[A-Za-z0-9_]+:)?Signature\b", cleaned))
        if not has_signature:
            findings.append(
                _finding(
                    "critical",
                    "authentication",
                    "SAML yanıtında dijital imza (Signature) eksik",
                    "SAML Response veya Assertion içinde XML dijital imzası (<ds:Signature>) bulunamadı.",
                    "Signature elemanı görülmedi",
                    "Hem SAML Response hem de Assertion üzerinde XML-DSig imza doğrulamasını zorunlu kılın.",
                    "CWE-347",
                    "SNIPER-AUTH-11",
                )
            )

        if re.search(r"(?i)(?:rsa-sha1|xmlenc#sha1|xmldsig#sha1|dsa-sha1)", cleaned):
            findings.append(
                _finding(
                    "medium",
                    "crypto",
                    "SAML imzasında zayıf özet/imza algoritması (SHA-1) kullanılıyor",
                    "SAML dijital imzasında çakışma saldırılarına açık SHA-1 (rsa-sha1 / xmldsig#sha1) algoritması kullanılıyor.",
                    "rsa-sha1 / xmldsig#sha1 referansı bulundu",
                    "SAML imza ve özet algoritmalarında SHA-256 (rsa-sha256 / xmlenc#sha256) zorunlu kılın.",
                    "CWE-327",
                    "SNIPER-CRYP-03",
                )
            )

        has_audience = bool(re.search(r"<\s*(?:[A-Za-z0-9_]+:)?AudienceRestriction\b", cleaned))
        has_recipient = bool(re.search(r'\bRecipient\s*=\s*["\'][^"\']+["\']', cleaned))
        if not has_audience or not has_recipient:
            findings.append(
                _finding(
                    "high",
                    "authentication",
                    "SAML Assertion içinde AudienceRestriction veya Recipient kısıtlaması eksik",
                    "SAML Assertion başka bir servis sağlayıcıya (SP) yeniden oynatılmayı önleyen AudienceRestriction veya Recipient doğrulama alanlarını içermiyor.",
                    f"AudienceRestriction={has_audience}, Recipient={has_recipient}",
                    "SAML Assertion doğrulamasında AudienceRestriction, Recipient ve NotOnOrAfter zaman pencerelerini zorunlu olarak kontrol edin.",
                    "CWE-287",
                    "SNIPER-AUTH-11",
                )
            )

        parsed_metadata = {
            "has_signature": has_signature,
            "has_audience_restriction": has_audience,
            "has_recipient": has_recipient,
        }

    score, grade, counts = calculate_score(findings)
    return {
        "format": "sniper-auth-protocol-audit-v1",
        "created_at": utc_now(),
        "artifact_type": detected_type,
        "score": score,
        "grade": grade,
        "finding_count": len(findings),
        "findings_truncated": len(findings) > INLINE_FINDING_LIMIT,
        "finding_groups": summarize_finding_groups(findings),
        "finding_counts": counts,
        "findings": cap_findings(findings, INLINE_FINDING_LIMIT)[0],
        "parsed_metadata": parsed_metadata,
        "controls_evaluated": [
            "SNIPER-AUTH-11",
            "SNIPER-CRYP-03",
            "SNIPER-CRYP-06",
            "SNIPER-DATA-09",
            "SNIPER-INPV-05",
            "SNIPER-INPV-06",
            "SNIPER-SESS-03",
        ],
    }
