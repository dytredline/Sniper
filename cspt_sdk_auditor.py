"""Wave 4 — CSPT (Client-Side Path Traversal) ve Yetkili SDK URL Şablonu Denetleyicisi.

İki yüksek etkili SDK/istemci URL oluşturma zafiyetini tespit eder:
- SNIPER-CSPT-SDK-01: Yetkili SDK/İstemci API çağrısında encode edilmemiş kaynak
  kimliği üzerinden İstemci Tarafı Yol Geçişi (CSPT).
- SNIPER-URL-TMPL-02: Yetkili giden istekte doğrulanmamış alt-alan adı (region)
  veya Host başlığı şablonu üzerinden SSRF ve kimlik bilgisi sızıntısı.
"""

from __future__ import annotations

import re
from typing import Any

FORMAT_VERSION = "sniper-cspt-sdk-url-template-audit/1"

_SDK_REQUEST_CALL_RE = re.compile(
    r"\b(makeRequest|getRequest|putRequest|postRequest|deleteRequest|fetch|axios(?:\.(?:get|post|put|delete|patch|request))?)\s*(?:<[^>]*>)?\s*\("
)

_CSPT_RAW_PATH_TEMPLATE_RE = re.compile(
    r"(?:playlists|albums|artists|users|tracks|shows|episodes|me)/\$\{\s*(?:playlist_id|album_id|artist_id|id|user_id|[A-Za-z0-9_]*[Ii]d)\s*\}"
)

_CSPT_SAFE_PATH_GUARD_RE = re.compile(
    r"(encodeURIComponent\s*\(|url\.PathEscape\s*\(|isSafeBackendPathSegment\s*\(|urllib\.parse\.quote\s*\()"
)

_URL_AUTHORITY_TEMPLATE_RE = re.compile(
    r"https?://(?:[A-Za-z0-9_.-]*\$\{\s*(?:region|resolved|resolvedRegion|host|firewallHost|targetHost|subdomain|tenant)[A-Za-z0-9_.]*\s*\}[A-Za-z0-9_.-]*)"
)

_URL_AUTHORITY_SAFE_GUARD_RE = re.compile(
    r"(/\^\[a-z0-9-\]\+\$/i|/\^\[a-zA-Z0-9-\]\+\$/|ALLOWED_REGIONS|VALID_REGIONS|ALLOWED_HOSTS|VALID_HOSTS|isValidRegion|isValidHost|validateHostAllowlist)"
)


def _line_number(content: str, offset: int) -> int:
    return content.count("\n", 0, max(0, offset)) + 1


def audit_cspt_and_authenticated_url_templates(
    raw_content: str,
    *,
    filename: str = "PlaylistsEndpoints.ts",
) -> dict[str, Any]:
    """SDK/İstemci çağrılarında CSPT yol şablonu ve doğrulanmamış otorite/alt-alan adı şablonlarını denetler."""
    content = str(raw_content or "")
    findings: list[dict[str, Any]] = []

    # (a) SNIPER-CSPT-SDK-01
    sdk_call_match = _SDK_REQUEST_CALL_RE.search(content)
    cspt_path_match = _CSPT_RAW_PATH_TEMPLATE_RE.search(content)
    if sdk_call_match and cspt_path_match and not _CSPT_SAFE_PATH_GUARD_RE.search(content):
        line_no = _line_number(content, cspt_path_match.start())
        findings.append(
            {
                "rule_id": "SNIPER-CSPT-SDK-01",
                "cwe": "CWE-22",
                "reference": "CWE-22",
                "severity": "high",
                "category": "command_data",
                "title": "Yetkili SDK/İstemci API çağrısında encode edilmemiş kaynak kimliği üzerinden İstemci Tarafı Yol Geçişi (CSPT)",
                "description": (
                    f"`{filename}` içinde yetkili SDK metodu (`{sdk_call_match.group(1)}`) çok segmentli API "
                    f"yol şablonuna (`{cspt_path_match.group(0)}`) kaynak kimliğini `encodeURIComponent` / "
                    "`url.PathEscape` / `isSafeBackendPathSegment` olmadan doğrudan yerleştiriyor; `../` dizileri "
                    "yetkili çağrıyı farklı bir API uç noktasına yönlendirebilir (CSPT)."
                ),
                "remediation": (
                    "Yol şablonuna yerleştirilen tüm kaynak kimliklerini `encodeURIComponent(id)`, "
                    "`url.PathEscape(id)` veya `isSafeBackendPathSegment(id)` ile doğrulayın/kodlayın."
                ),
                "filename": filename,
                "line": line_no,
                "evidence": cspt_path_match.group(0).strip(),
            }
        )

    # (b) SNIPER-URL-TMPL-02
    url_tmpl_match = _URL_AUTHORITY_TEMPLATE_RE.search(content)
    if url_tmpl_match and not _URL_AUTHORITY_SAFE_GUARD_RE.search(content):
        line_no = _line_number(content, url_tmpl_match.start())
        findings.append(
            {
                "rule_id": "SNIPER-URL-TMPL-02",
                "cwe": "CWE-918",
                "reference": "CWE-918",
                "severity": "high",
                "category": "ssrf",
                "title": "Yetkili giden istekte doğrulanmamış alt-alan adı (region) veya Host başlığı şablonu üzerinden SSRF ve kimlik bilgisi sızıntısı",
                "description": (
                    f"`{filename}` içinde giden `https://` URL otorite/host şablonuna (`{url_tmpl_match.group(0)}`) "
                    "doğrulanmamış `region` veya `host` / `firewallHost` değişkeni doğrudan yerleştiriliyor; "
                    "saldırgan kontrolündeki alt-alan adı veya host değeri yetkili başlıkların harici bir "
                    "hedefe sızmasına (SSRF / kimlik bilgisi sızıntısı) yol açabilir."
                ),
                "remediation": (
                    "URL otorite/alt-alan adı bileşenine yerleştirilen değişkenleri sıkı `/^[a-z0-9-]+$/i` "
                    "düzenli ifadesi veya sabit izinli liste (allowlist) ile doğrulayın."
                ),
                "filename": filename,
                "line": line_no,
                "evidence": url_tmpl_match.group(0).strip(),
            }
        )

    return {
        "format": FORMAT_VERSION,
        "filename": filename,
        "finding_count": len(findings),
        "findings": findings,
    }
