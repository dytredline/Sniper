from __future__ import annotations

from pathlib import Path
import re
from typing import Any

from project_analyzer import SKIP_DIRS, validate_project_path
from project_tree import ProjectTree
from scanner import _finding, calculate_score as _scanner_calculate_score
from finding_limits import INLINE_FINDING_LIMIT, PROJECT_FINDING_LIMIT, cap_findings, summarize_finding_groups, project_scan_scope


MAX_INLINE_BYTES = 512_000
MAX_PROJECT_FILES = 1_500

BUSINESS_LOGIC_CONTROLS_EVALUATED: list[str] = [
    "SNIPER-BUSL-01",
    "SNIPER-BUSL-02",
    "SNIPER-BUSL-03",
    "SNIPER-AUTHZ-02",
    "SNIPER-AUTHZ-03",
    "SNIPER-AUTHZ-BOLA-04",
    "SNIPER-FIN-TOCTOU-05",
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


_BALANCE_TARGET_RE = re.compile(
    r"\b(?:balance|wallet\.balance|user\.balance|account\.balance|credit|credits|stock|inventory)\b",
    re.IGNORECASE,
)
_COUPON_TARGET_RE = re.compile(
    r"\b(?:coupon|voucher|promo_code|gift_card)\.(?:used|is_used|redeemed|is_redeemed)\b",
    re.IGNORECASE,
)
_STATE_GUARD_CALL_RE = re.compile(
    r"\b(?:transition_to|can_transition|validate_transition|verify_signature|construct_event|"
    r"hmac\.compare_digest|webhook_secret)\b",
    re.IGNORECASE,
)


def _skip_space(text: str, pos: int) -> int:
    while pos < len(text) and text[pos].isspace():
        pos += 1
    return pos


def _has_toctou_mutation(line: str) -> bool:
    for found in _BALANCE_TARGET_RE.finditer(line):
        pos = _skip_space(line, found.end())
        if line.startswith("-=", pos):
            return True
        if pos < len(line) and line[pos] == "=":
            tail = line[pos + 1:].split(";", 1)[0]
            dash = tail.find("-")
            while dash >= 0:
                value = _skip_space(tail, dash + 1)
                end = value
                while end < len(tail) and (tail[end].isalnum() or tail[end] == "_"):
                    end += 1
                if tail[value:end].casefold() in {"amount", "qty", "quantity", "price", "cost"}:
                    return True
                dash = tail.find("-", dash + 1)
    for found in _COUPON_TARGET_RE.finditer(line):
        pos = _skip_space(line, found.end())
        if pos >= len(line) or line[pos] != "=":
            continue
        pos = _skip_space(line, pos + 1)
        end = pos
        while end < len(line) and (line[end].isalnum() or line[end] == "_"):
            end += 1
        if line[pos:end].casefold() in {"true", "1"}:
            return True
    return False


def _has_state_guard(text: str) -> bool:
    if _STATE_GUARD_CALL_RE.search(text):
        return True
    for line in text.splitlines():
        head = line.split(":", 1)[0]
        folded = head.casefold()
        condition = re.search(r"\bif\b", folded)
        if condition is None:
            continue
        condition_tail = folded[condition.end():]
        for state in re.finditer(r"\b(?:status|state)\b", condition_tail):
            operator = _skip_space(condition_tail, state.end())
            if condition_tail.startswith(("==", "!="), operator):
                return True
            if condition_tail.startswith("in", operator):
                word_end = operator + len("in")
                if word_end == len(condition_tail) or not (
                    condition_tail[word_end].isalnum() or condition_tail[word_end] == "_"
                ):
                    return True
    return False


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
    concurrency_guard_re = re.compile(
        r"\b(?:select_for_update|with_for_update|FOR\s+UPDATE|transaction\.atomic|"
        r"F\s*\(|idempotency_key|Idempotency-Key|mutex|RLock|Lock\s*\(|atomic\b|SERIALIZABLE)\b",
        re.IGNORECASE,
    )
    offset = 0
    for line_no, raw_line in enumerate(raw_content.splitlines(keepends=True), 1):
        code = raw_line.split("#", 1)[0]
        if not _has_toctou_mutation(code):
            offset += len(raw_line)
            continue
        window = _extract_enclosing_window(raw_content, offset, before=450, after=450)
        if not concurrency_guard_re.search(window):
            snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else code
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
        offset += len(raw_line)

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
    for match in state_bypass_re.finditer(raw_content):
        window = _extract_enclosing_window(raw_content, match.start(), before=450, after=300)
        if not _has_state_guard(window):
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

    # 5. Mass Assignment / BOPLA (high, CWE-915, SNIPER-AUTHZ-03)
    mass_assign_re = re.compile(
        r"(?im)^[^\n#]*(?:\b(?:create|update|update_or_create|bulk_create|findByIdAndUpdate|updateOne|updateMany|assign)\s*\([^)\n]*\*\*\s*(?:request\.(?:json|data|form|POST)|req\.body|payload|body)\b"
        r"|\bObject\.assign\s*\([^,\n]+,\s*req\.body\b"
        r"|\.(?:create|update|updateOne|updateMany|findByIdAndUpdate)\s*\(\s*(?:\{[^}\n]*\.\.\.req\.body|req\.body)\b)"
    )
    allowlist_guard_re = re.compile(
        r"\b(?:ALLOWED_FIELDS|allowed_fields|only\s*=|fields\s*=|exclude\s*=|pick\s*\(|"
        r"model_validate|Serializer|Schema)\b"
    )
    for match in mass_assign_re.finditer(raw_content):
        window = _extract_enclosing_window(raw_content, match.start(), before=250, after=250)
        if not allowlist_guard_re.search(window):
            line_no = _line_number_for_offset(raw_content, match.start())
            snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else match.group(0)
            _add(
                _make_busl_finding(
                    severity="high",
                    category="authorization",
                    title="Doğrudan istek gövdesiyle toplu atama: Mass Assignment / BOPLA riski",
                    description=(
                        "İstek gövdesi (request.json / req.body) alan beyaz listesi (allowlist) veya "
                        "sıkı şema filtrelemesi olmadan doğrudan model oluşturma/güncelleme çağrısına "
                        "aktarılıyor; saldırgan is_admin, role veya balance alanlarını ezebilir."
                    ),
                    evidence=snippet,
                    recommendation=(
                        "İstek verisini modele aktarmadan önce açık bir alan beyaz listesi (DTO/Pydantic/Serializer) "
                        "uygulayın ve ayrıcalıklı alanları (role, is_admin, balance, tenant_id) dışlayın."
                    ),
                    cwe="CWE-915",
                    control_id="SNIPER-AUTHZ-03",
                    filename=clean_filename,
                    line=line_no,
                )
            )

    # 6. Client-Side Price / Discount Manipulation (critical, CWE-472, SNIPER-BUSL-02)
    client_price_re = re.compile(
        r"(?im)^[^\n#]*(?:request\.(?:json|data|form|args|POST|GET)|req\.(?:body|query))\s*"
        r"(?:\[\s*['\"](?:unit_price|price|discount|discount_rate|total_price|fee)['\"]\s*\]"
        r"|\.get\s*\(\s*['\"](?:unit_price|price|discount|discount_rate|total_price|fee)['\"]"
        r"|\.(?:unit_price|price|discount|discount_rate|total_price|fee)\b)"
    )
    catalog_lookup_re = re.compile(
        r"\b(?:catalog_price|db_price|server_price|Product\.objects|get_product_price|verify_price)\b",
        re.IGNORECASE,
    )
    for match in client_price_re.finditer(raw_content):
        window = _extract_enclosing_window(raw_content, match.start(), before=200, after=350)
        if not catalog_lookup_re.search(window):
            line_no = _line_number_for_offset(raw_content, match.start())
            snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else match.group(0)
            _add(
                _make_busl_finding(
                    severity="critical",
                    category="business_logic",
                    title="İstemciden gelen fiyat/indirim/ücret parametresine doğrudan güvenilmesi",
                    description=(
                        "Birim fiyat (price/unit_price), indirim oranı (discount) veya işlem ücreti (fee) "
                        "sunucu tarafı ürün kataloğundan sorgulanmak yerine doğrudan istemci isteğinden "
                        "(request.json / req.body) okunuyor; 0 TL veya %100 indirimle sipariş geçilebilir."
                    ),
                    evidence=snippet,
                    recommendation=(
                        "İstemciden yalnızca ürün kimliği (product_id) ve miktar (quantity) alın; "
                        "birim fiyat, indirim ve vergi oranlarını her zaman sunucu veritabanından hesaplayın."
                    ),
                    cwe="CWE-472",
                    control_id="SNIPER-BUSL-02",
                    filename=clean_filename,
                    line=line_no,
                )
            )

    # 7. Multi-Tenant / Object Ownership Filter Gap — BOLA / IDOR (high, CWE-639, SNIPER-AUTHZ-BOLA-04)
    bola_handler_re = re.compile(
        r"(?im)^[ \t]*(?:"
        r"@(?:app|router|bp|api)\.(?:get|post|put|delete|patch|route)\s*\([^\n]*\)"
        r"(?:\s*\n[ \t]*@[^\n]+)*"
        r"(?:\s*\n[ \t]*(?:async\s+)?def\s+\w+\s*\([^)]*\))?"
        r"|(?:async\s+)?def\s+\w+\s*\([^)]*\b(?:item_id|order_id|doc_id|invoice_id|record_id|account_id|patient_id)\b[^)]*\)"
        r"|(?:app|router)\.(?:get|post|put|delete|patch)\s*\([^\n]*"
        r")"
    )
    bola_lookup_re = re.compile(
        r"(?:\b(?:filter_by|filter|get|get_object_or_404)\s*\(\s*(?:[A-Za-z0-9_]+\s*,\s*)?(?:id|pk)\s*="
        r"|\bfilter\s*\(\s*[A-Za-z0-9_]+\.id\s*=="
        r"|\.get\s*\(\s*(?:[A-Za-z0-9_]+\s*,\s*)?(?:item_id|order_id|doc_id|invoice_id|record_id|account_id|patient_id)\b"
        r"|\bfindUnique\s*\(\s*\{\s*where\s*:\s*\{\s*id\b"
        r"|\b(?:delete_one|find_one|update_one)\s*\(\s*\{\s*[\"']_?id[\"']"
        r"|\bfindById(?:AndDelete|AndUpdate|AndRemove)?\s*\()"
    )
    bola_guard_re = re.compile(
        r"\b(?:tenant_id|org_id|organization_id|workspace_id|user_id|owner_id|"
        r"current_user|request\.user|req\.user|check_owner|authorize_resource)\b"
    )
    for match in bola_handler_re.finditer(raw_content):
        raw_window = _extract_enclosing_window(raw_content, match.start(), before=0, after=650)
        rel_body_start = min(len(raw_window), match.end() - match.start())
        next_boundary = re.search(
            r"(?m)^[ \t]*(?:@(?:app|router|bp|api)\.(?:get|post|put|delete|patch|route)\b|(?:async\s+)?def\s+\w+\s*\()",
            raw_window[rel_body_start:],
        )
        window = raw_window[: rel_body_start + next_boundary.start()] if next_boundary else raw_window
        lookup_match = bola_lookup_re.search(window)
        if lookup_match and not bola_guard_re.search(window):
            line_no = _line_number_for_offset(raw_content, match.start() + lookup_match.start())
            snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else lookup_match.group(0)
            _add(
                _make_busl_finding(
                    severity="high",
                    category="authorization",
                    title="Çoklu kiracı (Multi-Tenant) veya nesne sahipliği filtresi eksikliği (BOLA / IDOR)",
                    description=(
                        "Rota veya işleyici içinde tekil kayıt kimliği (id / order_id / doc_id vb.) ile "
                        "doğrudan veritabanı sorgusu veya silme/güncelleme işlemi yapılıyor; ancak sorguda "
                        "kiracı (tenant_id / org_id) veya nesne sahipliği (user_id / owner_id / current_user) "
                        "kısıtı bulunmuyor."
                    ),
                    evidence=snippet,
                    recommendation=(
                        "Tüm tekil nesne sorgularını ve mutasyonlarını oturumdaki kiracı ve kullanıcı "
                        "kimliğiyle sınırlandırın (ör. filter_by(id=item_id, tenant_id=current_user.tenant_id))."
                    ),
                    cwe="CWE-639",
                    control_id="SNIPER-AUTHZ-BOLA-04",
                    filename=clean_filename,
                    line=line_no,
                )
            )

    # 8. Financial / Inventory Read-Modify-Write Race Condition — TOCTOU (critical, CWE-362, SNIPER-FIN-TOCTOU-05)
    fin_race_report = audit_financial_race_conditions(raw_content, filename=clean_filename)
    for fin_finding in fin_race_report["findings"]:
        _add(fin_finding)

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


_FIN_RMW_HANDLER_RE = re.compile(
    r"(?im)^[ \t]*(?:"
    r"@(?:app|router|bp|api)\.(?:get|post|put|delete|patch|route)\s*\([^\n]*\)"
    r"(?:\s*\n[ \t]*@[^\n]+)*"
    r"(?:\s*\n[ \t]*(?:async\s+)?def\s+\w+\s*\([^)]*\))?"
    r"|(?:async\s+)?(?:def|function)\s+\w+\s*\([^)]*\)"
    r"|(?:app|router)\.(?:get|post|put|delete|patch)\s*\([^\n]*"
    r"|func\s+(?:\([^)]+\)\s*)?\w+\s*\([^)]*\)"
    r")"
)
_FIN_RMW_STATE_RE = re.compile(
    r"\b(?:balance|wallet|credits|funds|coupon|voucher|redeem|withdraw|inventory|stock)\b",
    re.IGNORECASE,
)
_FIN_RMW_READ_CHECK_RE = re.compile(
    r"(?:\b(?:get|filter|filter_by|findUnique|findOne|SELECT)\b"
    r"|if\s+[^:\n]*(?:balance|wallet|credits|funds|stock|inventory|used|redeemed))",
    re.IGNORECASE,
)
_FIN_RMW_MUTATION_RE = re.compile(
    r"(?:\b(?:balance|wallet|credits|funds|stock|inventory)\s*(?:-=|\+=|(?<![!<>=])=(?!=))"
    r"|\b(?:coupon|voucher)\.(?:used|is_used|redeemed)\s*=\s*(?:True|true|1)\b"
    r"|\.(?:save|update|commit)\s*\("
    r"|updateOne\s*\()",
    re.IGNORECASE,
)
_FIN_RMW_LOCK_GUARD_RE = re.compile(
    r"(?:\b(?:with_for_update|select_for_update|FOR\s+UPDATE|atomic\s*\(|"
    r"F\s*\(\s*[\"'](?:balance|wallet|credits|funds|stock|inventory)|"
    r"distributed_lock|redis\.lock|mutex|RLock|Lock\s*\(|SERIALIZABLE)\b|\$inc\b)",
    re.IGNORECASE,
)


def audit_financial_race_conditions(
    raw_content: str,
    *,
    filename: str = "payments.py",
) -> dict[str, Any]:
    if not isinstance(filename, str) or not filename.strip():
        filename = "payments.py"
    clean_filename = filename.strip()
    if not isinstance(raw_content, str) or not raw_content.strip():
        return {"findings": [], "count": 0, "filename": clean_filename}

    lines = raw_content.splitlines()
    findings: list[dict[str, Any]] = []
    seen_lines: set[int] = set()

    handler_matches = list(_FIN_RMW_HANDLER_RE.finditer(raw_content))
    windows: list[tuple[int, str]] = []
    if handler_matches:
        for idx, match in enumerate(handler_matches):
            win_start = match.start()
            next_start = (
                handler_matches[idx + 1].start()
                if idx + 1 < len(handler_matches)
                else len(raw_content)
            )
            win_end = min(len(raw_content), next_start, win_start + 1200)
            windows.append((win_start, raw_content[win_start:win_end]))
    else:
        windows.append((0, raw_content[:2400]))

    for win_start, window in windows:
        if not _FIN_RMW_STATE_RE.search(window):
            continue
        if _FIN_RMW_LOCK_GUARD_RE.search(window):
            continue
        read_match = _FIN_RMW_READ_CHECK_RE.search(window)
        if not read_match:
            continue
        mut_match = None
        for candidate in _FIN_RMW_MUTATION_RE.finditer(window):
            if candidate.start() >= read_match.start():
                mut_match = candidate
                break
        if mut_match is None:
            continue

        line_no = _line_number_for_offset(raw_content, win_start + mut_match.start())
        if line_no in seen_lines:
            continue
        seen_lines.add(line_no)
        snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else mut_match.group(0)
        finding = _make_busl_finding(
            severity="critical",
            category="business_logic",
            title="Finansal bakiye/kupon işleminde atomik satır kilidi eksikliği (Double-Spend / Yarış Koşulu — TOCTOU)",
            description=(
                "Finansal bakiye, cüzdan, kupon veya stok durumu okuma/kontrol (Read-Check) adımından "
                "sonra satır düzeyinde veritabanı kilidi (SELECT ... FOR UPDATE / with_for_update), "
                "atomik artırma/azaltma (F() / $inc) veya dağıtık kilit olmadan güncelleniyor."
            ),
            evidence=snippet,
            recommendation=(
                "Bakiye ve kupon işlemlerini transaction.atomic() + select_for_update() / FOR UPDATE "
                "satır kilidi veya atomik veritabanı ifadeleri (F('balance') / $inc) ile koruyun."
            ),
            cwe="CWE-362",
            control_id="SNIPER-FIN-TOCTOU-05",
            filename=clean_filename,
            line=line_no,
        )
        finding["reference"] = "CWE-362"
        findings.append(finding)

    return {
        "findings": findings,
        "count": len(findings),
        "filename": clean_filename,
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

    with ProjectTree(root) as tree:
        for project_file in tree.iter_files(skip_dirs=SKIP_DIRS, reject_unsafe=False):
            if scanned_files >= MAX_PROJECT_FILES:
                continue
            if any(part.casefold() in SKIP_DIRS for part in project_file.path.parts[:-1]):
                continue
            ext = project_file.path.suffix.lower()
            if ext not in BUSINESS_LOGIC_EXTENSIONS:
                continue
            if project_file.size == 0 or project_file.size > MAX_INLINE_BYTES:
                continue
            content = tree.read_text(project_file, MAX_INLINE_BYTES, errors="replace")
            if not content.strip():
                continue
            rel_name = project_file.path.as_posix()
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


_WEB3_CALL_VALUE_RE = re.compile(
    r"(?:\.call\s*\{[^}]*\bvalue\s*:|\.call\.value\s*\()",
    re.IGNORECASE,
)
_WEB3_STATE_MUTATION_RE = re.compile(
    r"\b(?:balances|shares|credits|userBalance|stakes)\s*\[[^\]]+\]\s*(?:-=|(?<![!<>=])=(?!=))",
    re.IGNORECASE,
)
_WEB3_NON_REENTRANT_RE = re.compile(r"\bnonReentrant\b", re.IGNORECASE)
_WEB3_DELEGATE_OR_TX_ORIGIN_RE = re.compile(
    r"(?:\btx\.origin\s*[!=]=|[!=]=\s*tx\.origin\b|\.delegatecall\s*\()",
    re.IGNORECASE,
)
_WEB3_ECRECOVER_RE = re.compile(r"\becrecover\s*\(", re.IGNORECASE)
_WEB3_ZERO_ADDR_RE = re.compile(r"(?:address\s*\(\s*0\s*\)|0x0{1,40}\b)", re.IGNORECASE)
_WEB3_CHAINID_RE = re.compile(r"\bchainid\b", re.IGNORECASE)


def audit_web3_smart_contracts(
    raw_content: str,
    *,
    filename: str = "Vault.sol",
) -> dict[str, Any]:
    if not isinstance(filename, str) or not filename.strip():
        filename = "Vault.sol"
    clean_filename = filename.strip()
    if not isinstance(raw_content, str) or not raw_content.strip():
        return {
            "format": "sniper-web3-smart-contract-audit/1",
            "filename": clean_filename,
            "count": 0,
            "findings": [],
        }

    lines = raw_content.splitlines()
    findings: list[dict[str, Any]] = []

    # (a) SNIPER-WEB3-REENT-01: Reentrancy (Checks-Effects-Interactions violation)
    call_match = _WEB3_CALL_VALUE_RE.search(raw_content)
    if call_match is not None and not _WEB3_NON_REENTRANT_RE.search(raw_content):
        mut_after_call = None
        for candidate in _WEB3_STATE_MUTATION_RE.finditer(raw_content):
            if candidate.start() > call_match.start():
                mut_after_call = candidate
                break
        if mut_after_call is not None:
            line_no = _line_number_for_offset(raw_content, call_match.start())
            snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else call_match.group(0)
            finding = _make_busl_finding(
                severity="critical",
                category="business_logic",
                title=(
                    "Akıllı sözleşmede Checks-Effects-Interactions ihlali "
                    "(Reentrancy — harici çağrı sonrası bakiye güncelleme)"
                ),
                description=(
                    "Akıllı sözleşmede harici ETH/değer transferi (.call{value: ...} / .call.value(...)) "
                    "yapıldıktan sonra durum değişkeni (balances/shares/credits/userBalance/stakes) "
                    "güncelleniyor ve nonReentrant koruması bulunmuyor."
                ),
                evidence=snippet,
                recommendation=(
                    "Checks-Effects-Interactions desenini uygulayarak bakiye düşümünü harici çağrıdan "
                    "önce gerçekleştirin ve OpenZeppelin ReentrancyGuard (nonReentrant) kullanın."
                ),
                cwe="CWE-841",
                control_id="SNIPER-WEB3-REENT-01",
                filename=clean_filename,
                line=line_no,
            )
            finding["reference"] = "CWE-841"
            findings.append(finding)

    # (b) SNIPER-WEB3-DELEG-02: tx.origin authorization or unrestricted delegatecall
    deleg_match = _WEB3_DELEGATE_OR_TX_ORIGIN_RE.search(raw_content)
    if deleg_match is not None:
        line_no = _line_number_for_offset(raw_content, deleg_match.start())
        snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else deleg_match.group(0)
        finding = _make_busl_finding(
            severity="critical",
            category="authorization",
            title="Akıllı sözleşmede tx.origin yetkilendirmesi veya kısıtsız delegatecall enjeksiyonu",
            description=(
                "Kimlik doğrulama/yetkilendirme için oltalama (phishing) saldırılarına açık tx.origin "
                "kullanılıyor veya hedef adresi/fonksiyon seçicisi kısıtlanmamış delegatecall çağrısı "
                "ile depolama alanı (storage) ele geçirilmesine izin veriliyor."
            ),
            evidence=snippet,
            recommendation=(
                "Yetkilendirme kontrollerinde tx.origin yerine msg.sender kullanın ve kullanıcı "
                "girdisiyle kontrol edilen hedeflere delegatecall yapmaktan kaçının."
            ),
            cwe="CWE-829",
            control_id="SNIPER-WEB3-DELEG-02",
            filename=clean_filename,
            line=line_no,
        )
        finding["reference"] = "CWE-829"
        findings.append(finding)

    # (c) SNIPER-WEB3-SIG-03: ecrecover missing zero-address or chainid replay protection
    ecrecover_match = _WEB3_ECRECOVER_RE.search(raw_content)
    if ecrecover_match is not None:
        has_zero_addr = bool(_WEB3_ZERO_ADDR_RE.search(raw_content))
        has_chainid = bool(_WEB3_CHAINID_RE.search(raw_content))
        if not (has_zero_addr and has_chainid):
            line_no = _line_number_for_offset(raw_content, ecrecover_match.start())
            snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else ecrecover_match.group(0)
            finding = _make_busl_finding(
                severity="high",
                category="crypto",
                title=(
                    "ecrecover imza doğrulamasında sıfır adres (address(0)) veya "
                    "chainid/nonce tekrar oynatma kontrolü eksik"
                ),
                description=(
                    "ecrecover() çağrısı geçersiz imzalarda address(0) döndürebilir; sıfır adres "
                    "kontrolü veya EIP-712 chainid/nonce tekrar oynatma (replay) koruması eksik."
                ),
                evidence=snippet,
                recommendation=(
                    "Kurtarılan adresin address(0) olmadığını doğrulayın (require(signer != address(0))) "
                    "ve imzalanan özete block.chainid ile tek kullanımlık nonce dahil edin."
                ),
                cwe="CWE-347",
                control_id="SNIPER-WEB3-SIG-03",
                filename=clean_filename,
                line=line_no,
            )
            finding["reference"] = "CWE-347"
            findings.append(finding)

    return {
        "format": "sniper-web3-smart-contract-audit/1",
        "filename": clean_filename,
        "count": len(findings),
        "findings": findings,
    }

