"""Faz 1.2 — Diller Arası Monorepo Köprü Denetleyicisi (Cross-Language Monorepo Bridge Auditor).

Backend dilleri (.rb, .py, .java, .ts, .js) tarafından üretilen iç vekil başlıklarını
(ör. X-Gitlab-Mcp-Server-*, X-Accel-Redirect, X-Sendfile, WorkhorseRewriter veya
kullanıcı/DB kaynaklı X-* başlıkları) ve bunları tüketen Go/Rust/C++ sidecar/proxy
bileşenlerini (.go, .rs, .cc, .cpp) eşleştirerek uçtan uca veri akışı kurar.
- SNIPER-XLANG-BRIDGE-01: Diller arası iç başlık köprüsünde SSRF filtresi eksikliği
  veya redirect üzerinde Bearer token sızıntısı.
"""

from __future__ import annotations

import os
import re
from typing import Any

FORMAT_VERSION = "sniper-cross-language-bridge-audit/1"

_BACKEND_EXTS = frozenset({".rb", ".py", ".java", ".ts", ".js"})
_SIDECAR_EXTS = frozenset({".go", ".rs", ".cc", ".cpp"})

_HEADER_TOKEN_RE = re.compile(
    r"['\"](X-Gitlab-Mcp-Server-[A-Za-z0-9_-]*|X-Accel-Redirect|X-Sendfile|X-[A-Za-z0-9]+-[A-Za-z0-9_-]+)['\"]",
    re.IGNORECASE,
)
_WORKHORSE_RE = re.compile(r"\bWorkhorseRewriter\b|\bsend_git_http\b|\bworkhorse_set_header\b")

_SIDECAR_CONSUMER_RE = re.compile(
    r"(Header\.Get|Header\.Values|r\.Header|req\.Header|headers\.get|http\.NewRequest|http\.NewRequestWithContext|RoundTrip)"
)
_OUTBOUND_SINK_RE = re.compile(
    r"(http\.NewRequest|http\.NewRequestWithContext|http\.DefaultTransport|http\.Client|RoundTrip|reqwest::Client|hyper::Client)"
)
_SSRF_GUARD_RE = re.compile(
    r"(WithSSRFFilter|ssrf_filter|SafeDialContext|NewSafeTransport|AllowLocalRequests)"
)
_AUTH_SET_IN_ROUNDTRIP_RE = re.compile(
    r"func\s*\([^)]*\)\s*RoundTrip\s*\([^)]*\)[^{]*\{[\s\S]*?Header\.(?:Set|Add)\(\s*[\"']Authorization[\"']",
    re.MULTILINE,
)
_REDIRECT_ORIGIN_GUARD_RE = re.compile(
    r"(CheckRedirect|sameOrigin|sameHost|req\.URL\.Host\s*!=|initialHost|stripAuthorization|Header\.Del\(\s*[\"']Authorization[\"'])"
)


def _line_number(content: str, offset: int) -> int:
    return content.count("\n", 0, max(0, offset)) + 1


def _normalize_header_key(hdr: str) -> str:
    low = hdr.strip().lower()
    if low.startswith("x-gitlab-mcp-server-"):
        return "x-gitlab-mcp-server-*"
    return low


def audit_cross_language_monorepo_bridges(files_map: dict[str, str]) -> dict[str, Any]:
    """Backend ve Go/Rust sidecar dosyaları arasındaki iç başlık köprülerini denetler."""
    producers: list[dict[str, Any]] = []
    consumers: list[dict[str, Any]] = []

    for filepath, raw in (files_map or {}).items():
        content = str(raw or "")
        _, ext = os.path.splitext(filepath.lower())

        if ext in _BACKEND_EXTS:
            matched_headers: list[tuple[str, str, int]] = []
            for m in _HEADER_TOKEN_RE.finditer(content):
                raw_hdr = m.group(1)
                norm = _normalize_header_key(raw_hdr)
                matched_headers.append((raw_hdr, norm, _line_number(content, m.start())))
            if _WORKHORSE_RE.search(content) and not matched_headers:
                wm = _WORKHORSE_RE.search(content)
                matched_headers.append(
                    ("WorkhorseRewriter", "workhorserewriter", _line_number(content, wm.start() if wm else 0))
                )
            for raw_hdr, norm, line_no in matched_headers:
                producers.append(
                    {
                        "file": filepath,
                        "header": raw_hdr,
                        "normalized_header": norm,
                        "line": line_no,
                    }
                )

        elif ext in _SIDECAR_EXTS:
            if not _SIDECAR_CONSUMER_RE.search(content):
                continue
            matched_headers_sidecar: list[tuple[str, str, int]] = []
            for m in _HEADER_TOKEN_RE.finditer(content):
                raw_hdr = m.group(1)
                norm = _normalize_header_key(raw_hdr)
                matched_headers_sidecar.append((raw_hdr, norm, _line_number(content, m.start())))
            if os.path.basename(filepath.lower()) == "mcp.go" and not matched_headers_sidecar:
                cm = _SIDECAR_CONSUMER_RE.search(content)
                matched_headers_sidecar.append(
                    ("X-Gitlab-Mcp-Server-*", "x-gitlab-mcp-server-*", _line_number(content, cm.start() if cm else 0))
                )
            for raw_hdr, norm, line_no in matched_headers_sidecar:
                consumers.append(
                    {
                        "file": filepath,
                        "header": raw_hdr,
                        "normalized_header": norm,
                        "line": line_no,
                        "content": content,
                    }
                )

    edges: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    seen_Consumer_findings: set[tuple[str, str]] = set()

    for prod in producers:
        for cons in consumers:
            same_bridge = (
                prod["normalized_header"] == cons["normalized_header"]
                or (
                    prod["normalized_header"].startswith("x-gitlab-mcp-server")
                    and cons["normalized_header"].startswith("x-gitlab-mcp-server")
                )
            )
            if not same_bridge:
                continue

            c_content = cons["content"]
            has_outbound = bool(_OUTBOUND_SINK_RE.search(c_content))
            has_ssrf_guard = bool(_SSRF_GUARD_RE.search(c_content))
            has_unsafe_roundtrip_auth = bool(
                _AUTH_SET_IN_ROUNDTRIP_RE.search(c_content)
                and not _REDIRECT_ORIGIN_GUARD_RE.search(c_content)
            )

            edge = {
                "producer_file": prod["file"],
                "producer_line": prod["line"],
                "consumer_file": cons["file"],
                "consumer_line": cons["line"],
                "bridge_header": prod["header"],
                "has_outbound_sink": has_outbound,
                "has_ssrf_guard": has_ssrf_guard,
                "has_unsafe_roundtrip_auth": has_unsafe_roundtrip_auth,
            }
            edges.append(edge)

            if has_outbound and (not has_ssrf_guard or has_unsafe_roundtrip_auth):
                dedup_key = (cons["file"], cons["normalized_header"])
                if dedup_key in seen_Consumer_findings:
                    continue
                seen_Consumer_findings.add(dedup_key)

                reasons: list[str] = []
                if not has_ssrf_guard:
                    reasons.append("SSRF filtresi (`WithSSRFFilter` / `ssrf_filter`) eksik")
                if has_unsafe_roundtrip_auth:
                    reasons.append(
                        "`RoundTrip` içinde köken doğrulaması olmadan `Authorization` başlığı ekleniyor (302/307 redirect sızıntısı)"
                    )

                findings.append(
                    {
                        "rule_id": "SNIPER-XLANG-BRIDGE-01",
                        "cwe": "CWE-918",
                        "reference": "CWE-918",
                        "severity": "critical",
                        "category": "ssrf",
                        "title": "Diller arası (Backend -> Go/Rust Sidecar) iç başlık köprüsünde SSRF filtresi eksikliği veya redirect üzerinde Bearer token sızıntısı",
                        "description": (
                            f"`{prod['file']}` tarafından üretilen `{prod['header']}` iç başlığı "
                            f"`{cons['file']}` bileşeninde dış HTTP isteğine dönüştürülüyor ancak "
                            f"{' ve '.join(reasons)}."
                        ),
                        "remediation": (
                            "Sidecar/proxy HTTP istemcisinde `WithSSRFFilter` (veya iç IP engelleme) zorunlu kılın "
                            "ve yönlendirmelerde (`CheckRedirect` / `RoundTrip`) hedef köken değiştiğinde "
                            "`Authorization` başlığını temizleyin."
                        ),
                        "filename": cons["file"],
                        "line": cons["line"],
                        "producer_filename": prod["file"],
                        "producer_line": prod["line"],
                        "bridge_header": prod["header"],
                        "evidence": f"{prod['file']}:{prod['line']} -> {cons['file']}:{cons['line']} ({prod['header']})",
                    }
                )

    return {
        "format": FORMAT_VERSION,
        "bridge_edges": edges,
        "finding_count": len(findings),
        "findings": findings,
    }
