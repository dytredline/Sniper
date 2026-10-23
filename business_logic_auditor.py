from __future__ import annotations

import os
from pathlib import Path
import re
from typing import Any

from project_analyzer import SKIP_DIRS, validate_project_path
from safe_file_read import read_text_bounded
from scanner import _finding, calculate_score as _scanner_calculate_score
from finding_limits import INLINE_FINDING_LIMIT, PROJECT_FINDING_LIMIT, cap_findings, summarize_finding_groups, project_scan_scope


MAX_INLINE_BYTES = 512_000
MAX_PROJECT_FILES = 1_500

BUSINESS_LOGIC_CONTROLS_EVALUATED: list[str] = [
    "SNIPER-BUSL-01",
    "SNIPER-BUSL-02",
    "SNIPER-BUSL-03",
    "SNIPER-AUTHZ-02",
]

BUSINESS_LOGIC_EXTENSIONS: set[str] = {
    ".py",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".jsx",
    ".go",
    ".java",
    ".kt",
    ".php",
    ".rb",
}


def calculate_score(findings: list[dict[str, Any]]) -> tuple[int, str]:
    score, grade, _counts = _scanner_calculate_score(findings)
    return score, grade


def _line_number_for_offset(content: str, offset: int) -> int:
    return content.count("\n", 0, max(0, offset)) + 1


def _make_busl_finding(
    *,
    severity: str,
    category: str,
    title: str,
    description: str,
    evidence: str,
    recommendation: str,
    cwe: str,
    control_id: str,
    filename: str,
    line: int,
) -> dict[str, Any]:
    clean_ev = evidence.strip()[:320]
    reference = f"OWASP API Security Top 10 / ASVS V4 & V11 · {cwe}"
    item = _finding(
        severity,
        category,
        title,
        description,
        f"{filename}:{line} · {clean_ev}",
        recommendation,
        reference,
        cookie_identity=(filename, str(line), control_id, cwe),
    )
    item["cwe"] = cwe
    item["control_id"] = control_id
    item["file"] = filename
    item["line"] = line
    return item


def _extract_enclosing_window(content: str, match_offset: int, before: int = 350, after: int = 750) -> str:
    start = max(0, match_offset - before)
    end = min(len(content), match_offset + after)
    return content[start:end]


def audit_business_logic_inline(
    raw_content: str,
    *,
    filename: str = "payment.py",
) -> dict[str, Any]:
    if not isinstance(raw_content, str) or not raw_content.strip():
        raise ValueError("Denetlenecek iş mantığı (business logic) kaynak içeriği boş olamaz.")
    encoded = raw_content.encode("utf-8", errors="replace")
    if len(encoded) > MAX_INLINE_BYTES:
        raise ValueError(f"İçerik boyutu güvenli sınırı ({MAX_INLINE_BYTES} bayt) aşıyor.")
    if not isinstance(filename, str) or not filename.strip():
        filename = "payment.py"
    clean_filename = filename.strip()
    lines = raw_content.splitlines()

    findings: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str, int]] = set()

    def _add(finding: dict[str, Any]) -> None:
        key = (finding["control_id"], finding["cwe"], int(finding["line"]))
        if key not in seen_keys:
            seen_keys.add(key)
            findings.append(finding)

    # 1. Race Condition / TOCTOU / Double Spending (high, CWE-362, SNIPER-BUSL-01)
    toctou_mutation_re = re.compile(
        r"(?im)^[^\n#]*(?:\b(?:balance|wallet\.balance|user\.balance|account\.balance|credit|credits|stock|inventory)\s*(?:-=|=\s*[^\n;]*-\s*\b(?:amount|qty|quantity|price|cost)\b)"
        r"|\b(?:coupon|voucher|promo_code|gift_card)\.(?:used|is_used|redeemed|is_redeemed)\s*=\s*(?:True|true|1)\b)"
    )
    concurrency_guard_re = re.compile(
        r"\b(?:select_for_update|with_for_update|FOR\s+UPDATE|transaction\.atomic|"
        r"F\s*\(|idempotency_key|Idempotency-Key|mutex|RLock|Lock\s*\(|atomic\b|SERIALIZABLE)\b",
        re.IGNORECASE,
    )
    for match in toctou_mutation_re.finditer(raw_content):
        window = _extract_enclosing_window(raw_content, match.start(), before=450, after=450)
        if not concurrency_guard_re.search(window):
            line_no = _line_number_for_offset(raw_content, match.start())
            snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else match.group(0)
            _add(
                _make_busl_finding(
                    severity="high",
                    category="business_logic",
                    title="Atomik kilit olmadan bakiye/kupon/stok düşümü: Race Condition / Double Spending riski",
                    description=(
                        "Bakiye, cüzdan, kupon veya stok durumu satır düzeyinde veritabanı kilidi "
                        "(SELECT ... FOR UPDATE / select_for_update), atomik ifade (F()) veya "
                        "idempotency anahtarı olmadan güncelleniyor (TOCTOU)."
                    ),
                    evidence=snippet,
                    recommendation=(
                        "Finansal bakiye ve kupon/stok işlemlerini transaction.atomic() içinde "
                        "select_for_update() veya atomik veritabanı güncellemeleri ve Idempotency-Key ile koruyun."
                    ),
                    cwe="CWE-362",
                    control_id="SNIPER-BUSL-01",
                    filename=clean_filename,
                    line=line_no,
                )
            )

    # 2. Financial Float Precision & Negative Amount Bypass (high, CWE-682, SNIPER-BUSL-02)
    float_money_re = re.compile(
        r"(?im)^[^\n#]*(?:\b(?:float|parseFloat)\s*\([^)\n]*\b(?:amount|price|balance|total|discount|fee|payout|cost)\b"
        r"|\b(?:amount|price|balance|total|discount|fee|payout)\s*[:=]\s*(?:float|parseFloat)\s*\()"
    )
    for match in float_money_re.finditer(raw_content):
        line_no = _line_number_for_offset(raw_content, match.start())
        snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else match.group(0)
        _add(
            _make_busl_finding(
                severity="high",
                category="business_logic",
                title="Finansal hesaplamada kayan noktalı (float) veri tipi kullanımı",
                description=(
                    "Tutar, fiyat, bakiye veya komisyon hesaplamasında IEEE 754 float/parseFloat "
                    "kullanılıyor; yuvarlama hataları ve kuruş sapmaları oluşabilir."
                ),
                evidence=snippet,
                recommendation=(
                    "Tüm parasal hesaplamalarda Decimal (sabit noktalı aritmetik) veya en küçük para "
                    "birimi cinsinden (kuruş/cent) tam sayı (integer) kullanın."
                ),
                cwe="CWE-682",
                control_id="SNIPER-BUSL-02",
                filename=clean_filename,
                line=line_no,
            )
        )

    fin_func_re = re.compile(
        r"(?im)^[ \t]*(?:async\s+)?(?:def|function)\s+(?:transfer|withdraw|deposit|refund|checkout|create_order|process_payment)\s*\(([^)]*)\)"
    )
    positive_check_re = re.compile(
        r"(?:\b(?:amount|quantity|qty)\s*(?:<=|<)\s*0\b|\b(?:amount|quantity|qty)\s*>\s*0\b"
        r"|\b(?:gt|ge|min)\s*=\s*(?:0|1)\b|\bPositiveInt\b|\b PositiveDecimal\b)",
        re.IGNORECASE,
    )
    for match in fin_func_re.finditer(raw_content):
        params = match.group(1)
        if re.search(r"\b(?:amount|quantity|qty)\b", params):
            window = _extract_enclosing_window(raw_content, match.start(), before=100, after=800)
            if not positive_check_re.search(window):
                line_no = _line_number_for_offset(raw_content, match.start())
                snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else match.group(0)
                _add(
                    _make_busl_finding(
                        severity="high",
                        category="business_logic",
                        title="Finansal işlemde negatif veya sıfır tutar/miktar kontrolü eksik",
                        description=(
                            "Transfer, ödeme veya sipariş fonksiyonu amount/quantity parametresini "
                            "pozitif sınır kontrolü (amount <= 0) yapmadan işliyor; negatif değerlerle "
                            "ters yönlü bakiye artırımı yapılabilir."
                        ),
                        evidence=snippet,
                        recommendation=(
                            "İşlem başında tutar ve miktarın kesinlikle sıfırdan büyük olduğunu "
                            "(amount <= 0 ise hata döndürerek) doğrulayın."
                        ),
                        cwe="CWE-682",
                        control_id="SNIPER-BUSL-02",
                        filename=clean_filename,
                        line=line_no,
                    )
                )

    # 3. Broken Function Level Authorization — BFLA (high, CWE-285, SNIPER-AUTHZ-02)
    bfla_func_re = re.compile(
        r"(?im)^[ \t]*(?:async\s+)?(?:def|function)\s+"
        r"(admin_[A-Za-z0-9_]*|delete_user[A-Za-z0-9_]*|refund[A-Za-z0-9_]*|approve_loan[A-Za-z0-9_]*|"
        r"grant_role[A-Za-z0-9_]*|set_role[A-Za-z0-9_]*|export_all_users[A-Za-z0-9_]*)\s*\("
    )
    authz_guard_re = re.compile(
        r"(?:\bis_admin\b|\bis_superuser\b|\bis_staff\b|\brequire_role\b|\bhas_permission\b|"
        r"\bhas_role\b|@admin_required\b|@permission_required\b|\brole\s*==|\brole\s+in\b|"
        r"\bcheck_permission\b|\bauthorize_admin\b|\bPreAuthorize\b|\bRolesAllowed\b)",
        re.IGNORECASE,
    )
    for match in bfla_func_re.finditer(raw_content):
        window = _extract_enclosing_window(raw_content, match.start(), before=250, after=650)
        if not authz_guard_re.search(window):
            line_no = _line_number_for_offset(raw_content, match.start())
            snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else match.group(0)
            _add(
                _make_busl_finding(
                    severity="high",
                    category="authorization",
                    title=f"Yönetimsel/finansal işlevde yetki kontrolü eksik (BFLA: {match.group(1)})",
                    description=(
                        f"Ayrıcalıklı '{match.group(1)}' işlevi açık bir rol veya yetki doğrulaması "
                        "(is_admin, require_role, has_permission vb.) olmadan tanımlanmış."
                    ),
                    evidence=snippet,
                    recommendation=(
                        "Tüm yönetimsel ve kritik finansal uç noktalarda sunucu taraflı işlev düzeyi "
                        "yetkilendirme (RBAC/ABAC) kontrolünü zorunlu kılın."
                    ),
                    cwe="CWE-285",
                    control_id="SNIPER-AUTHZ-02",
                    filename=clean_filename,
                    line=line_no,
                )
            )

    # 4. Workflow / State Machine Step Bypass (medium, CWE-841, SNIPER-BUSL-03)
    state_bypass_re = re.compile(
        r"(?im)^[^\n#]*(?:\b(?:[A-Za-z0-9_]+\.)?(?:status|payment_status|order_status|kyc_status)\s*=\s*[\"'](?:paid|completed|approved|settled)[\"']"
        r"|\b(?:[A-Za-z0-9_]+\.)?is_verified\s*=\s*True\b)"
    )
    state_guard_re = re.compile(
        r"(?:\bif\s+[^\n:]*\b(?:status|state)\s*(?:==|!=|in\b)|"
        r"\b(?:transition_to|can_transition|validate_transition|verify_signature|"
        r"construct_event|hmac\.compare_digest|webhook_secret)\b)",
        re.IGNORECASE,
    )
    for match in state_bypass_re.finditer(raw_content):
        window = _extract_enclosing_window(raw_content, match.start(), before=450, after=300)
        if not state_guard_re.search(window):
            line_no = _line_number_for_offset(raw_content, match.start())
            snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else match.group(0)
            _add(
                _make_busl_finding(
                    severity="medium",
                    category="business_logic",
                    title="Durum makinesi (State Machine) geçiş doğrulaması olmadan doğrudan durum ataması",
                    description=(
                        "Sipariş, ödeme veya KYC durumu (paid / completed / approved / is_verified=True) "
                        "önceki durum kontrolü veya kriptografik ödeme imzası doğrulanmadan doğrudan atanıyor."
                    ),
                    evidence=snippet,
                    recommendation=(
                        "Durum geçişlerini merkezi bir sonlu durum makinesi (FSM) ile zorunlu kılın ve "
                        "ödeme/onay geçişlerinde webhook imza doğrulaması uygulayın."
                    ),
                    cwe="CWE-841",
                    control_id="SNIPER-BUSL-03",
                    filename=clean_filename,
                    line=line_no,
                )
            )

    score, grade = calculate_score(findings)
    return {
        "format": "sniper-business-logic-inline-audit-v1",
        "filename": clean_filename,
        "score": score,
        "grade": grade,
        "finding_count": len(findings),
        "findings_truncated": len(findings) > INLINE_FINDING_LIMIT,
        "finding_groups": summarize_finding_groups(findings),
        "findings": cap_findings(findings, INLINE_FINDING_LIMIT)[0],
        "controls_evaluated": list(BUSINESS_LOGIC_CONTROLS_EVALUATED),
    }


@project_scan_scope
def audit_business_logic_project(
    project_path: str,
    *,
    allowed_roots: tuple[Path, ...] | None = None,
) -> dict[str, Any]:
    root = validate_project_path(project_path, allowed_roots=allowed_roots)
    findings: list[dict[str, Any]] = []
    scanned_files = 0

    for current, directories, files in os.walk(root, followlinks=False):
        directories[:] = sorted(
            name
            for name in directories
            if name.casefold() not in SKIP_DIRS and not (Path(current) / name).is_symlink()
        )
        for name in sorted(files):
            if scanned_files >= MAX_PROJECT_FILES:
                break
            file_path = Path(current) / name
            if file_path.is_symlink():
                continue
            ext = file_path.suffix.lower()
            if ext not in BUSINESS_LOGIC_EXTENSIONS:
                continue
            content = read_text_bounded(file_path, MAX_INLINE_BYTES)
            if content is None:
                continue
            if not content.strip():
                continue
            rel_name = str(file_path.relative_to(root))
            scanned_files += 1
            file_report = audit_business_logic_inline(content, filename=rel_name)
            findings.extend(file_report["findings"])

    score, grade = calculate_score(findings)
    return {
        "format": "sniper-business-logic-audit-v1",
        "project": root.name,
        "project_path": str(root),
        "scanned_files": scanned_files,
        "score": score,
        "grade": grade,
        "finding_count": len(findings),
        "findings_truncated": len(findings) > PROJECT_FINDING_LIMIT,
        "finding_groups": summarize_finding_groups(findings),
        "findings": cap_findings(findings, PROJECT_FINDING_LIMIT)[0],
        "controls_evaluated": list(BUSINESS_LOGIC_CONTROLS_EVALUATED),
    }
