"""Faz 1.4 — Sembolik Link TOCTOU ve Arşiv Çıkarma Semantik Denetleyicisi.

Java NIO ve Go dosya sistemi işlemlerinde NOFOLLOW_LINKS / Lstat kontrol-kullanım
(TOCTOU) asimetrisini tespit eder; Python >= 3.12 standart kütüphane güvenli
arşiv çıkarma (zipfile.extractall ve tarfile filter='data') çağrılarında ise
yanlış pozitifleri bastırır:
- SNIPER-FS-SYMLINK-01: Dosya sistemi işleminde NOFOLLOW_LINKS kontrol-kullanım
  (TOCTOU) asimetrisi veya sembolik link takibi.
"""

from __future__ import annotations

import re
from typing import Any

FORMAT_VERSION = "sniper-symlink-archive-semantics/1"

_JAVA_NOFOLLOW_CHECK_RE = re.compile(
    r"Files\.(?:notExists|exists|isRegularFile|isDirectory)\s{0,32}\([^)]{0,2048}NOFOLLOW_LINKS[^)]{0,2048}\)"
)
_JAVA_FOLLOW_SINK_RE = re.compile(
    r"Files\.(?:copy|move|newInputStream|newOutputStream|readAllBytes|readString|write)\s{0,32}\((?![^;]{0,2048}NOFOLLOW_LINKS)[^;]{1,2048}"
)

_GO_LSTAT_RE = re.compile(r"\bos\.Lstat\s*\(")
_GO_UNSAFE_OPEN_RE = re.compile(r"\bos\.(?:Open|ReadFile|Create|WriteFile)\s*\(")
_GO_NOFOLLOW_GUARD_RE = re.compile(r"(O_NOFOLLOW|EvalSymlinks|os\.SameFile)")

_PY_ZIP_EXTRACTALL_RE = re.compile(
    r"(?:zipfile\.ZipFile\([^)]{0,2048}\)[\s\S]{0,120}?|\.|\bzf\.)extractall\s{0,32}\("
)
_PY_TAR_SAFE_FILTER_RE = re.compile(
    r"extractall\s{0,32}\([^)]{0,2048}filter\s{0,32}=\s{0,32}['\"]data['\"][^)]{0,2048}\)"
)
_PY_CUSTOM_JOIN_EXTRACT_RE = re.compile(
    r"os\.path\.join\s{0,32}\([^,]{1,2048},\s{0,32}[A-Za-z0-9_]++\.(?:filename|name)\s{0,32}\)"
)
_PY_PATH_GUARD_RE = re.compile(
    r"(os\.path\.commonpath|os\.path\.realpath|is_relative_to|\.resolve\(\))"
)


def _line_number(content: str, offset: int) -> int:
    return content.count("\n", 0, max(0, offset)) + 1


def audit_symlink_toctou_and_archive_semantics(
    raw_content: str,
    *,
    filename: str = "FolderOutputSink.java",
    python_version: tuple[int, int] = (3, 12),
) -> dict[str, Any]:
    """Java/Go symlink TOCTOU asimetrilerini ve Python arşiv çıkarma semantiğini denetler."""
    content = str(raw_content or "")
    findings: list[dict[str, Any]] = []
    suppressed_count = 0

    # 1) Java NIO NOFOLLOW_LINKS kontrol -> takip eden Files.copy/move/readAllBytes asimetrisi
    check_match = _JAVA_NOFOLLOW_CHECK_RE.search(content)
    if check_match:
        tail = content[check_match.end() :]
        sink_match = _JAVA_FOLLOW_SINK_RE.search(tail)
        if sink_match and "isSymbolicLink" not in tail[: sink_match.start()]:
            sink_offset = check_match.end() + sink_match.start()
            line_no = _line_number(content, sink_offset)
            findings.append(
                {
                    "rule_id": "SNIPER-FS-SYMLINK-01",
                    "cwe": "CWE-59",
                    "reference": "CWE-59",
                    "severity": "high",
                    "category": "command_data",
                    "title": "Dosya sistemi işleminde NOFOLLOW_LINKS kontrol-kullanım (TOCTOU) asimetrisi veya sembolik link takibi",
                    "description": (
                        f"`{check_match.group(0).strip()}` ile `NOFOLLOW_LINKS` kullanılarak varlık kontrolü "
                        f"yapılmış ancak izleyen `{sink_match.group(0).strip()}` çağrısında `NOFOLLOW_LINKS` "
                        "geçirilmemiş; kırık sembolik link veya yarış durumu (TOCTOU) hedef dosya üzerine "
                        "yazılmasına/okunmasına yol açabilir."
                    ),
                    "remediation": (
                        "Dosya taşıma/kopyalama/okuma işleminde de `LinkOption.NOFOLLOW_LINKS` kullanın "
                        "ve işlem öncesinde `Files.isSymbolicLink` kontrolü ile sembolik linkleri reddedin."
                    ),
                    "filename": filename,
                    "line": line_no,
                    "evidence": sink_match.group(0).strip(),
                }
            )

    # 2) Go os.Lstat -> os.Open / os.ReadFile / os.Create / os.WriteFile (O_NOFOLLOW olmadan)
    lstat_match = _GO_LSTAT_RE.search(content)
    if lstat_match and not _GO_NOFOLLOW_GUARD_RE.search(content):
        tail = content[lstat_match.end() :]
        open_match = _GO_UNSAFE_OPEN_RE.search(tail)
        if open_match:
            open_offset = lstat_match.end() + open_match.start()
            line_no = _line_number(content, open_offset)
            findings.append(
                {
                    "rule_id": "SNIPER-FS-SYMLINK-01",
                    "cwe": "CWE-59",
                    "reference": "CWE-59",
                    "severity": "high",
                    "category": "command_data",
                    "title": "Dosya sistemi işleminde NOFOLLOW_LINKS kontrol-kullanım (TOCTOU) asimetrisi veya sembolik link takibi",
                    "description": (
                        f"`os.Lstat` kontrolünden sonra `{open_match.group(0).strip()}` sembolik linkleri "
                        "takip ederek açılıyor (`syscall.O_NOFOLLOW` eksik); kontrol ile kullanım arasında "
                        "TOCTOU sembolik link saldırısına açıktır."
                    ),
                    "remediation": (
                        "Dosyayı `os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)` veya `os.Root` ile açın."
                    ),
                    "filename": filename,
                    "line": line_no,
                    "evidence": open_match.group(0).strip(),
                }
            )

    # 3) Python >= 3.12 stdlib güvenli arşiv çıkarma bastırması vs özel (custom) güvensiz çıkarma
    if python_version >= (3, 12):
        if "zipfile" in content and _PY_ZIP_EXTRACTALL_RE.search(content):
            suppressed_count += len(_PY_ZIP_EXTRACTALL_RE.findall(content))
        if "tarfile" in content and _PY_TAR_SAFE_FILTER_RE.search(content):
            suppressed_count += len(_PY_TAR_SAFE_FILTER_RE.findall(content))

    custom_join_match = _PY_CUSTOM_JOIN_EXTRACT_RE.search(content)
    if (
        custom_join_match
        and re.search(r"\bopen\s{0,32}\([^)]{0,2048}['\"]w[b+]?['\"]", content)
        and not _PY_PATH_GUARD_RE.search(content)
    ):
        line_no = _line_number(content, custom_join_match.start())
        findings.append(
            {
                "rule_id": "SNIPER-FS-SYMLINK-01",
                "cwe": "CWE-59",
                "reference": "CWE-59",
                "severity": "high",
                "category": "command_data",
                "title": "Dosya sistemi işleminde NOFOLLOW_LINKS kontrol-kullanım (TOCTOU) asimetrisi veya sembolik link takibi",
                "description": (
                    f"Arşiv üyesi `{custom_join_match.group(0).strip()}` ile birleştirilip `commonpath` / "
                    "`realpath` doğrulaması yapılmadan doğrudan yazılmak üzere açılıyor (Zip-Slip / Symlink riski)."
                ),
                "remediation": (
                    "`os.path.realpath` ve `os.path.commonpath` ile hedef yolun çıkarma dizini içinde "
                    "kaldığını doğrulayın veya Python 3.12+ güvenli `extractall(filter='data')` kullanın."
                ),
                "filename": filename,
                "line": line_no,
                "evidence": custom_join_match.group(0).strip(),
            }
        )

    return {
        "format": FORMAT_VERSION,
        "filename": filename,
        "suppressed_stdlib_safe_extractions": suppressed_count,
        "finding_count": len(findings),
        "findings": findings,
    }
