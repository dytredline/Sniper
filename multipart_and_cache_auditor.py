"""Wave 5 — Çok Parçalı Yükleme (uploadId) Koşulsuz Silme ve P2P Durum Önbelleği Zehirlenmesi Denetleyicisi.

İki yüksek etkili gerçek dünya zafiyet sınıfını tespit eder:
- SNIPER-UPLOAD-DEL-01: Çok parçalı yükleme (uploadId) işleyicisinde doğrulanmamış
  ikincil parametre ile yol geçişi ve koşulsuz dizin silme (CUA Daytona GHSA-3x8g-6h2v-8qx9 sınıfı).
- SNIPER-P2P-CACHE-02: P2P/Konsensüs mesaj işleyicisinde kriptografik kanıt
  doğrulanmadan önce paylaşılan durum önbelleğinin güncellenmesi (Cache Poisoning DoS).
"""

from __future__ import annotations

import re
from typing import Any

FORMAT_VERSION = "sniper-multipart-and-cache-audit/1"

_UPLOAD_PARAM_RE = re.compile(r"\b(?:uploadId|upload_id)\b")

_UNSAFE_UPLOAD_JOIN_RE = re.compile(
    r"(?:"
    r"\.join\s*\(\s*\"uploads\"\s*\)\s*\.join\s*\(\s*&?\s*(?:id|upload_id|uploadId)\b"
    r"|os\.path\.join\s*\([^)]*,\s*upload_id\s*\)"
    r"|Path\s*\([^)]*\)\s*(?:/\s*[\"']uploads[\"']\s*)?/\s*upload_id\b"
    r"|path\.join\s*\([^)]*,\s*uploadId\s*\)"
    r")"
)

_SAFE_UPLOAD_ID_GUARD_RE = re.compile(
    r"(?:"
    r"\bfn\s+upload_dir\s*\("
    r"|\bself\.upload_dir\s*\("
    r"|\bupload_dir\s*\(\s*&?\s*(?:self\s*,\s*)?&?\s*(?:id|upload_id|uploadId)\b"
    r"|\bvalidate_upload_id\s*\("
    r"|\bis_valid_upload_id\s*\("
    r"|\bis_ascii_alphanumeric\s*\("
    r"|re\.fullmatch\s*\(\s*r?[\"']\^?\[a-zA-Z0-9_-]+\+\$?[\"']\s*,\s*(?:upload_id|uploadId)\s*\)"
    r")"
)

_UNCONDITIONAL_DELETE_SINK_RE = re.compile(
    r"\b(?:tokio::fs::remove_dir_all|std::fs::remove_dir_all|fs::remove_dir_all|remove_dir_all|shutil\.rmtree|fs\.rmSync|fs\.rmdirSync)\s*\("
)

_SAFE_DELETE_GUARD_RE = re.compile(
    r"(?:"
    r"\bif\s+removed\.is_some\s*\(\s*\)"
    r"|\bif\s+let\s+Some\s*\([^)]*\)\s*=\s*(?:removed|[A-Za-z0-9_.]*remove\s*\()"
    r"|\bif\s+(?:upload_id|uploadId)\s+in\s+[A-Za-z0-9_.]+"
    r"|\bif\s*\(\s*[A-Za-z0-9_.]+\.(?:delete|has)\s*\(\s*(?:uploadId|upload_id)\s*\)\s*\)"
    r")"
)

_P2P_HANDLER_RE = re.compile(
    r"\b(?:"
    r"async\s+def\s+(?:new_peak|handle_peak|on_unverified_block|handle_new_peak)"
    r"|def\s+(?:new_peak|handle_peak|on_unverified_block|handle_new_peak)"
    r"|(?:pub\s+)?(?:async\s+)?fn\s+(?:handle_new_peak|new_peak|on_unverified_block|handle_peak)"
    r")\b"
)

_CACHE_MUTATION_RE = re.compile(
    r"(?:"
    r"\b(?:self\.)?(?:peak_cache|sub_epoch_cache|unverified_peaks|state_cache)\s*\[[^\]]+\]\s*="
    r"|\b(?:self\.)?(?:peak_cache|sub_epoch_cache|unverified_peaks|state_cache)\.(?:put|insert|update)\s*\("
    r")"
)

_PROOF_VALIDATION_RE = re.compile(
    r"\b(?:verify_proof|validate_weight|verify_signature|check_sub_epoch_hash|validate_sub_epoch_segments|verify_header_block)\s*\("
)

_CACHE_PRESERVE_GUARD_RE = re.compile(
    r"(?:"
    r"\bif\s+[A-Za-z0-9_.]+\s+not\s+in\s+(?:self\.)?(?:peak_cache|sub_epoch_cache|unverified_peaks|state_cache)\b"
    r"|\.(?:entry\s*\([^)]*\)\.or_insert|setdefault)\s*\("
    r"|\bif\s+!\s*(?:self\.)?(?:peak_cache|sub_epoch_cache|unverified_peaks|state_cache)\.contains_key\s*\("
    r")"
)


def _line_number(content: str, offset: int) -> int:
    return content.count("\n", 0, max(0, offset)) + 1


def audit_multipart_upload_and_state_cache(
    raw_content: str,
    *,
    filename: str = "objectstore.rs",
) -> dict[str, Any]:
    """Çok parçalı yükleme (uploadId) yol geçişi/koşulsuz silme ve P2P durum önbelleği zehirlenmesi kalıplarını denetler."""
    content = str(raw_content or "")
    findings: list[dict[str, Any]] = []

    # (a) SNIPER-UPLOAD-DEL-01
    if _UPLOAD_PARAM_RE.search(content):
        join_match = _UNSAFE_UPLOAD_JOIN_RE.search(content)
        delete_match = _UNCONDITIONAL_DELETE_SINK_RE.search(content)
        has_upload_id_guard = bool(_SAFE_UPLOAD_ID_GUARD_RE.search(content))
        has_delete_guard = bool(_SAFE_DELETE_GUARD_RE.search(content))

        unsafe_join = bool(join_match and not has_upload_id_guard)
        unsafe_delete = bool(delete_match and not has_delete_guard)

        if unsafe_join or unsafe_delete:
            anchor = delete_match if (unsafe_delete and delete_match is not None) else join_match
            line_no = _line_number(content, anchor.start() if anchor is not None else 0)
            evidence_text = anchor.group(0).strip() if anchor is not None else "uploadId"
            remediation_text = (
                "`uploadId` / `upload_id` parametresini adanmış `upload_dir` / alfasayısal doğrulayıcıdan "
                "geçirin (`Component::ParentDir` / `..` reddi) ve özyinelemeli dizin silme (`remove_dir_all` / "
                "`shutil.rmtree`) işlemini yalnızca oturum haritasında geçerli kayıt bulunduğunda "
                "(`if removed.is_some()` / `if upload_id in uploads`) çalıştırın."
            )
            findings.append(
                {
                    "control_id": "SNIPER-UPLOAD-DEL-01",
                    "rule_id": "SNIPER-UPLOAD-DEL-01",
                    "cwe": "CWE-22",
                    "reference": "CWE-22",
                    "severity": "high",
                    "category": "command_data",
                    "title": "Çok parçalı yükleme (uploadId) işleyicisinde doğrulanmamış ikincil parametre ile yol geçişi ve koşulsuz dizin silme",
                    "description": (
                        f"`{filename}` içinde çok parçalı yükleme (`uploadId` / `upload_id`) işleyicisinde "
                        "ikincil parametre adanmış `upload_dir` doğrulayıcısından geçirilmeden dosya sistemi "
                        "yoluna ekleniyor ve/veya `DELETE`/iptal dalında `if removed.is_some()` / "
                        "`if upload_id in uploads` kontrolü yapılmadan koşulsuz özyinelemeli dizin silme "
                        "çağrılıyor."
                    ),
                    "remediation": remediation_text,
                    "recommendation": remediation_text,
                    "filename": filename,
                    "line": line_no,
                    "evidence": evidence_text,
                }
            )

    # (b) SNIPER-P2P-CACHE-02
    handler_match = _P2P_HANDLER_RE.search(content)
    if handler_match:
        tail = content[handler_match.start() :]
        cache_match = _CACHE_MUTATION_RE.search(tail)
        if cache_match:
            proof_match = _PROOF_VALIDATION_RE.search(tail)
            preserve_match = _CACHE_PRESERVE_GUARD_RE.search(tail)
            proof_before_cache = bool(proof_match is not None and proof_match.start() < cache_match.start())
            preserves_existing = bool(preserve_match is not None and preserve_match.start() < cache_match.end())
            if not (proof_before_cache and preserves_existing):
                abs_offset = handler_match.start() + cache_match.start()
                line_no = _line_number(content, abs_offset)
                remediation_text = (
                    "Paylaşılan P2P/konsensüs önbelleğini (`peak_cache`, `sub_epoch_cache`, `state_cache`) "
                    "güncellemeden önce kriptografik kanıt, ağırlık ve imza doğrulamasını (`verify_proof`, "
                    "`validate_weight`, `verify_signature`) tamamlayın ve mevcut doğrulanmış önbellek "
                    "girdilerinin (`if key not in peak_cache`) üzerine yazılmasını engelleyin."
                )
                findings.append(
                    {
                        "control_id": "SNIPER-P2P-CACHE-02",
                        "rule_id": "SNIPER-P2P-CACHE-02",
                        "cwe": "CWE-400",
                        "reference": "CWE-400",
                        "severity": "high",
                        "category": "dos",
                        "title": "P2P/Konsensüs mesaj işleyicisinde kriptografik kanıt doğrulanmadan önce paylaşılan durum önbelleğinin güncellenmesi (Cache Poisoning DoS)",
                        "description": (
                            f"`{filename}` içinde P2P/konsensüs mesaj işleyicisi (`{handler_match.group(0).strip()}`), "
                            "kriptografik kanıt/imza/ağırlık doğrulaması tamamlanmadan veya mevcut tam girdi "
                            "korunmadan paylaşılan durum önbelleğini (`peak_cache` / `sub_epoch_cache` / `state_cache`) "
                            "güncelliyor; doğrulanmamış mesajlarla önbellek zehirlenmesi (Cache Poisoning DoS) "
                            "oluşabilir."
                        ),
                        "remediation": remediation_text,
                        "recommendation": remediation_text,
                        "filename": filename,
                        "line": line_no,
                        "evidence": cache_match.group(0).strip(),
                    }
                )

    return {
        "format": FORMAT_VERSION,
        "filename": filename,
        "finding_count": len(findings),
        "findings": findings,
    }
