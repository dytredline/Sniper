"""Faz 1.3 — HTTP Yönlendirme, Güvenli Sarmalayıcı ve TLS Semantik Denetleyicisi.

Üç temel semantik güvenlik zafiyetini tespit eder:
- SNIPER-HTTP-WRAP-01: Güvenli HTTP sarmalayıcısı (Gitlab::HTTP / WithSSRFFilter)
  yerine ham HTTP istemcisi (OAuth2::Client.new, Faraday.new, Net::HTTP.start,
  http.DefaultTransport.Clone) kullanımı.
- SNIPER-HTTP-REDIR-02: HTTP yönlendirmesinde (302/307/308) çapraz köken
  Authorization başlığı veya OAuth/Faraday :follow_redirects sızıntısı.
- SNIPER-TLS-DEAD-03: TLS yapılandırmasında RootCAs / x509.UnknownAuthorityError
  ile InsecureSkipVerify: true çelişkisi (ölü sertifika doğrulaması).
"""

from __future__ import annotations

import re
from typing import Any

FORMAT_VERSION = "sniper-http-tls-semantics-audit/1"

_RAW_HTTP_CLIENT_RE = re.compile(
    r"(OAuth2::Client\.new|Faraday\.new|Net::HTTP\.start|http\.DefaultTransport\.\(\*http\.Transport\)\.Clone\(\))"
)
_SAFE_WRAPPER_GUARD_RE = re.compile(
    r"(WithSSRFFilter|ssrf_filter|SafeDialContext|Gitlab::HTTP\.perform_request|Gitlab::HTTP\.get|Gitlab::HTTP\.post|Gitlab::HTTP_V2|UrlBlocker\.validate!)"
)

_GO_ROUNDTRIP_AUTH_RE = re.compile(
    r"func\s*\([^)]*\)\s*RoundTrip\s*\([^)]*\)[^{]*\{[\s\S]*?Header\.(?:Set|Add)\(\s*[\"']Authorization[\"']",
    re.MULTILINE,
)
_ORIGIN_CHECK_RE = re.compile(
    r"(CheckRedirect|sameOrigin|sameHost|req\.URL\.Host\s*!=|initialHost|expectedHost|Header\.Del\(\s*[\"']Authorization[\"'])"
)
_RUBY_FOLLOW_REDIRECTS_RE = re.compile(
    r"(:follow_redirects\b|follow_redirects\s*:\s*true)"
)
_RUBY_SENSITIVE_OAUTH_RE = re.compile(
    r"(OAuth2::Client|token_url|authorize_url|register|Authorization|Bearer)",
    re.IGNORECASE,
)

_INSECURE_TLS_RE = re.compile(
    r"(InsecureSkipVerify\s*:\s*true|check_hostname\s*=\s*False|verify_mode\s*=\s*ssl\.CERT_NONE)"
)
_DEAD_CA_LOGIC_RE = re.compile(
    r"(RootCAs\b|x509\.UnknownAuthorityError\b|x509\.CertificateInvalidError\b|load_verify_locations\b)"
)

_DNS_PRECHECK_RE = re.compile(
    r"\b(validateHostNotPrivate|dns(?:\.promises)?\.lookup|dnsPromises\.lookup|resolve4|resolve6)\s*\("
)
_FETCH_CALL_RE = re.compile(r"\bfetch\s*\(")
_DNS_PINNING_GUARD_RE = re.compile(
    r"(\bdispatcher\b|\bagent\b|\bpinnedIp\b|\bpinnedAddress\b|createPinnedDispatcher|ssrfSafeDispatcher|connect\s*:\s*\{[^}]*\blookup\b|\blookup\s*:\s*(?:async\s*)?\()"
)

_AUTH_SESSION_ENDPOINT_RE = re.compile(
    r"(getAuthSession|/v1/sessions(?:/:[A-Za-z0-9_]+)?)\b"
)
_UNSAFE_RESOLVE_CLIENT_RE = re.compile(
    r"\b(?:resolveClient|fetchClientMetadata)\s*\(\s*(?:[A-Za-z0-9_.]*\.clientId|clientId)\s*\)"
)
_REFETCH_SAFE_GUARD_RE = re.compile(
    r"(resolveClient\s*\([^)]*redirectUri|validateRedirectUri\s*\(|assertRedirectUri\s*\(|allowExternalFetch\s*:\s*false|cachedOnly\s*:\s*true|session\.clientMetadata)"
)


def _line_number(content: str, offset: int) -> int:
    return content.count("\n", 0, max(0, offset)) + 1


def audit_http_redirect_and_tls_semantics(
    raw_content: str,
    *,
    filename: str = "client.go",
    repo_has_safe_http_wrapper: bool = True,
) -> dict[str, Any]:
    """HTTP sarmalayıcı baypası, yönlendirme kimlik bilgisi sızıntısı ve ölü TLS doğrulamasını denetler."""
    content = str(raw_content or "")
    findings: list[dict[str, Any]] = []

    has_safe_wrapper_ref = bool(
        repo_has_safe_http_wrapper
        or "Gitlab::HTTP" in content
        or "WithSSRFFilter" in content
    )

    # (a) SNIPER-HTTP-WRAP-01
    if has_safe_wrapper_ref and not _SAFE_WRAPPER_GUARD_RE.search(content):
        for m in _RAW_HTTP_CLIENT_RE.finditer(content):
            line_no = _line_number(content, m.start())
            findings.append(
                {
                    "rule_id": "SNIPER-HTTP-WRAP-01",
                    "cwe": "CWE-918",
                    "reference": "CWE-918",
                    "severity": "high",
                    "category": "ssrf",
                    "title": "Güvenli HTTP sarmalayıcısı (Gitlab::HTTP / WithSSRFFilter) yerine ham HTTP istemcisi kullanımı",
                    "description": (
                        f"`{filename}` içinde güvenli SSRF sarmalayıcısı (`Gitlab::HTTP` / `WithSSRFFilter`) "
                        f"yerine ham `{m.group(1)}` istemcisi kullanılıyor; iç ağ / metadata adreslerine "
                        "SSRF koruması devre dışı kalabilir."
                    ),
                    "remediation": (
                        "Dış HTTP çağrılarını `Gitlab::HTTP` veya `WithSSRFFilter` / `UrlBlocker.validate!` "
                        "kullanan güvenli sarmalayıcı üzerinden gerçekleştirin."
                    ),
                    "filename": filename,
                    "line": line_no,
                    "evidence": m.group(0).strip(),
                }
            )

    # (b) SNIPER-HTTP-REDIR-02
    rt_match = _GO_ROUNDTRIP_AUTH_RE.search(content)
    if rt_match and not _ORIGIN_CHECK_RE.search(content):
        line_no = _line_number(content, rt_match.start())
        findings.append(
            {
                "rule_id": "SNIPER-HTTP-REDIR-02",
                "cwe": "CWE-522",
                "reference": "CWE-522",
                "severity": "high",
                "category": "authz",
                "title": "HTTP yönlendirmesinde (302/307/308) çapraz köken Authorization başlığı veya POST gövdesi sızıntısı",
                "description": (
                    "`RoundTrip` metodu her istekte `Authorization` başlığını koşulsuz olarak ayarlıyor; "
                    "302/307/308 çapraz köken yönlendirmelerinde Bearer token üçüncü taraf sunucuya sızabilir."
                ),
                "remediation": (
                    "`RoundTrip` veya `CheckRedirect` içinde `req.URL.Host` değerini başlangıç hedef "
                    "kökeniyle karşılaştırın ve farklı kökene yönlendirmede `Authorization` başlığını silin."
                ),
                "filename": filename,
                "line": line_no,
                "evidence": rt_match.group(0).splitlines()[0].strip(),
            }
        )

    redir_match = _RUBY_FOLLOW_REDIRECTS_RE.search(content)
    if redir_match and _RUBY_SENSITIVE_OAUTH_RE.search(content):
        if "ssrf_filter" not in content and "disable_redirects" not in content:
            line_no = _line_number(content, redir_match.start())
            findings.append(
                {
                    "rule_id": "SNIPER-HTTP-REDIR-02",
                    "cwe": "CWE-522",
                    "reference": "CWE-522",
                    "severity": "high",
                    "category": "authz",
                    "title": "HTTP yönlendirmesinde (302/307/308) çapraz köken Authorization başlığı veya POST gövdesi sızıntısı",
                    "description": (
                        "OAuth / kimlik doğrulama veya kayıt istemcisinde `:follow_redirects` etkinleştirilmiş; "
                        "307/308 yönlendirmeleri kimlik bilgilerini veya POST gövdesini iç/harici hedeflere taşıyabilir."
                    ),
                    "remediation": (
                        "OAuth token/kayıt uç noktalarında otomatik yönlendirmeyi kapatın (`follow_redirects: false`) "
                        "veya çapraz köken yönlendirmelerde kimlik başlıklarını temizleyin."
                    ),
                    "filename": filename,
                    "line": line_no,
                    "evidence": redir_match.group(0).strip(),
                }
            )

    # (c) SNIPER-TLS-DEAD-03
    insecure_match = _INSECURE_TLS_RE.search(content)
    dead_ca_match = _DEAD_CA_LOGIC_RE.search(content)
    if insecure_match and dead_ca_match:
        line_no = _line_number(content, insecure_match.start())
        findings.append(
            {
                "rule_id": "SNIPER-TLS-DEAD-03",
                "cwe": "CWE-295",
                "reference": "CWE-295",
                "severity": "high",
                "category": "crypto",
                "title": "TLS yapılandırmasında RootCAs / UnknownAuthorityError ile InsecureSkipVerify: true çelişkisi (Ölü Sertifika Doğrulaması)",
                "description": (
                    f"Dosya içinde `{dead_ca_match.group(1)}` ile özel kök sertifika / otorite kontrolü "
                    f"tanımlanmasına rağmen `{insecure_match.group(1)}` etkin bırakılmış; standart TLS "
                    "zincir doğrulaması tamamen devre dışı kalarak CA kontrolünü ölü koda dönüştürüyor."
                ),
                "remediation": (
                    "`InsecureSkipVerify: false` (veya varsayılan doğrulama) kullanın ve özel CA havuzunu "
                    "`RootCAs` üzerinden doğrulayın."
                ),
                "filename": filename,
                "line": line_no,
                "evidence": insecure_match.group(0).strip(),
            }
        )

    # (d) SNIPER-HTTP-DNSREBIND-04
    dns_precheck_match = _DNS_PRECHECK_RE.search(content)
    if dns_precheck_match:
        fetch_after_match = _FETCH_CALL_RE.search(content, dns_precheck_match.end())
        if fetch_after_match and not _DNS_PINNING_GUARD_RE.search(content):
            line_no = _line_number(content, fetch_after_match.start())
            findings.append(
                {
                    "rule_id": "SNIPER-HTTP-DNSREBIND-04",
                    "cwe": "CWE-367",
                    "reference": "CWE-367",
                    "severity": "high",
                    "category": "ssrf",
                    "title": "DNS doğrulaması (validateHostNotPrivate / lookup) ile IP pinlemesiz fetch çağrısı arasında DNS Rebinding TOCTOU penceresi",
                    "description": (
                        f"`{filename}` içinde `{dns_precheck_match.group(1)}` ile ön DNS çözümlemesi yapıldıktan "
                        "sonra `fetch(` çağrısına çözümlenen IP adresini sabitleyen özel bir `dispatcher` / "
                        "`agent` / `lookup` geri çağrısı geçirilmiyor; ikinci DNS sorgusunda özel IP'ye "
                        "rebinding (TOCTOU) yapılabilir."
                    ),
                    "remediation": (
                        "`validateHostNotPrivate` / `dns.lookup` tarafından doğrulanan IP adresini özel "
                        "`dispatcher` / `agent` (`connect: { lookup }`) üzerinden `fetch` çağrısına sabitleyin."
                    ),
                    "filename": filename,
                    "line": line_no,
                    "evidence": dns_precheck_match.group(0).strip(),
                }
            )

    # (e) SNIPER-HTTP-REFETCH-05
    session_ep_match = _AUTH_SESSION_ENDPOINT_RE.search(content)
    unsafe_resolve_match = _UNSAFE_RESOLVE_CLIENT_RE.search(content)
    if session_ep_match and unsafe_resolve_match and not _REFETCH_SAFE_GUARD_RE.search(content):
        line_no = _line_number(content, unsafe_resolve_match.start())
        findings.append(
            {
                "rule_id": "SNIPER-HTTP-REFETCH-05",
                "cwe": "CWE-367",
                "reference": "CWE-367",
                "severity": "high",
                "category": "authz",
                "title": "Kimlik doğrulamasız oturum uç noktasında (getAuthSession / /v1/sessions) redirectUri doğrulamasız tekrarlı metadata refetch ve TOCTOU",
                "description": (
                    f"`{filename}` içinde kimlik doğrulamasız oturum uç noktasında (`{session_ep_match.group(1)}`) "
                    f"`{unsafe_resolve_match.group(0)}` çağrısı `redirectUri` doğrulaması olmadan veya "
                    "harici istemci metadata bilgisini yeniden çekerek çalıştırılıyor; oturum başlatma ile "
                    "okuma arasında TOCTOU / SSRF riski oluşur."
                ),
                "remediation": (
                    "`resolveClient(session.clientId, session.redirectUri)` ile kayıtlı `redirectUri` "
                    "doğrulamasını zorunlu kılın veya oturum nesnesindeki önbelleklenmiş istemci anlık "
                    "görüntüsünü kullanın."
                ),
                "filename": filename,
                "line": line_no,
                "evidence": unsafe_resolve_match.group(0).strip(),
            }
        )

    return {
        "format": FORMAT_VERSION,
        "filename": filename,
        "finding_count": len(findings),
        "findings": findings,
    }
