"""Wave 6 — Veritabanı Şema Göçü (Migration) ve Row-Level Security (RLS) Güvenlik Denetçisi.

PostgreSQL / Supabase / Flyway / Liquibase / Prisma (.sql), Alembic (Python) ve
Rails ActiveRecord göç dosyalarındaki çok-kiracılı (multi-tenant) izolasyon kayıplarını,
devre dışı bırakılan veya aşırı izinli (USING true) RLS politikalarını ve düz metin
parola/sır sütunlarını çevrimdışı olarak denetler.
"""

from __future__ import annotations

import re
from typing import Any

FORMAT = "sniper-schema-migration-security-audit/1"

RULE_RLS_DISABLED_OR_PERMISSIVE = "SNIPER-MIG-RLS-01"
RULE_TENANT_ISOLATION_DROPPED = "SNIPER-MIG-TENANT-DROP-02"
RULE_CLEARTEXT_SECRET_COLUMN = "SNIPER-MIG-CLEARTEXT-03"

TITLE_RLS_01 = (
    "Veritabanı göç dosyasında (Migration) Row-Level Security (RLS) devre dışı "
    "bırakıldı veya aşırı izinli politika (USING true) tanımlandı"
)
TITLE_TENANT_DROP_02 = (
    "Veritabanı şemasında kiracı/sahiplik (tenant_id / organization_id) kısıtının "
    "veya NOT NULL zorunluluğunun kaldırılması"
)
TITLE_CLEARTEXT_03 = (
    "Veritabanı şemasına şifrelenmemiş/özetlenmemiş düz metin sır veya parola sütunu eklendi"
)

_SENSITIVE_COLUMNS = frozenset(
    {
        "password",
        "raw_password",
        "user_password",
        "plaintext_password",
        "api_key",
        "secret_key",
        "private_key",
        "access_token",
        "refresh_token",
        "ssn",
    }
)

_SAFE_COLUMN_SUFFIXES = (
    "_hash",
    "_digest",
    "_encrypted",
    "_ciphertext",
    "_id",
    "_at",
    "_reset",
    "_salt",
    "_hint",
    "_alg",
    "_version",
    "_expires",
    "_revoked",
)

_TENANT_COLUMNS = ("tenant_id", "organization_id", "owner_id", "workspace_id", "org_id")
_TENANT_NULLABLE_COLUMNS = ("tenant_id", "organization_id", "owner_id", "user_id", "workspace_id", "org_id")

# 1. SNIPER-MIG-RLS-01 kalıpları
_DISABLE_RLS_RE = re.compile(
    r"\bALTER\s+TABLE\b[^;]*?\bDISABLE\s+ROW\s+LEVEL\s+SECURITY\b",
    re.IGNORECASE | re.DOTALL,
)
_ENABLE_RLS_TABLE_RE = re.compile(
    r"\bALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?([A-Za-z0-9_.\"`']+)\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY\b",
    re.IGNORECASE,
)
_PERMISSIVE_POLICY_RE = re.compile(
    r"\bCREATE\s+POLICY\b[^;]*?\b(?:USING|WITH\s+CHECK)\s*\(\s*true\s*\)",
    re.IGNORECASE | re.DOTALL,
)
_SQL_CREATE_TABLE_RE = re.compile(
    r"\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z0-9_.\"`']+)\s*\((.*?)\)\s*;",
    re.IGNORECASE | re.DOTALL,
)

# 2. SNIPER-MIG-TENANT-DROP-02 kalıpları
_SQL_DROP_TENANT_COL_RE = re.compile(
    r"\bDROP\s+COLUMN\s+(?:IF\s+EXISTS\s+)?[\"`']?(tenant_id|organization_id|owner_id|workspace_id|org_id)\b",
    re.IGNORECASE,
)
_SQL_DROP_TENANT_CONSTRAINT_RE = re.compile(
    r"\bDROP\s+CONSTRAINT\s+(?:IF\s+EXISTS\s+)?[\"`']?([A-Za-z0-9_]*(?:tenant|organization|workspace|owner)[A-Za-z0-9_]*)\b",
    re.IGNORECASE,
)
_SQL_DROP_NOT_NULL_RE = re.compile(
    r"\bALTER\s+COLUMN\s+[\"`']?(tenant_id|organization_id|owner_id|user_id|workspace_id|org_id)[\"`']?\s+DROP\s+NOT\s+NULL\b",
    re.IGNORECASE,
)
_ALEMBIC_DROP_TENANT_COL_RE = re.compile(
    r"\bop\.drop_column\s*\(\s*[^,]+,\s*['\"](tenant_id|organization_id|owner_id|workspace_id|org_id)['\"]",
    re.IGNORECASE,
)
_ALEMBIC_ALTER_NULLABLE_RE = re.compile(
    r"\bop\.alter_column\s*\(\s*[^,]+,\s*['\"](tenant_id|organization_id|owner_id|user_id|workspace_id|org_id)['\"][^)]*?\bnullable\s*=\s*True\b",
    re.IGNORECASE | re.DOTALL,
)
_RAILS_REMOVE_TENANT_COL_RE = re.compile(
    r"\bremove_column\s*[(\s]+:?\w+\s*,\s*:?(?:['\"])?(tenant_id|organization_id|owner_id|workspace_id|org_id)\b",
    re.IGNORECASE,
)
_RAILS_CHANGE_NULL_RE = re.compile(
    r"\bchange_column_null\s*[(\s]+:?\w+\s*,\s*:?(?:['\"])?(tenant_id|organization_id|owner_id|user_id|workspace_id|org_id)(?:['\"])?\s*,\s*true\b",
    re.IGNORECASE,
)

# 3. SNIPER-MIG-CLEARTEXT-03 kalıpları
_SQL_ADD_COLUMN_RE = re.compile(
    r"\bADD\s+(?:COLUMN\s+)?(?:IF\s+NOT\s+EXISTS\s+)?[\"`']?([A-Za-z_][A-Za-z0-9_]*)[\"`']?\s+"
    r"(?:VARCHAR|TEXT|CHAR|CHARACTER|STRING|BYTEA|JSONB?)",
    re.IGNORECASE,
)
_ALEMBIC_ADD_COLUMN_RE = re.compile(
    r"\b(?:op\.add_column|sa\.Column)\s*\([^)]*?['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]",
    re.IGNORECASE,
)
_RAILS_ADD_COLUMN_RE = re.compile(
    r"\b(?:add_column\s*[(\s]+:?\w+\s*,\s*|t\.(?:string|text)\s+):?(?:['\"])?([A-Za-z_][A-Za-z0-9_]*)\b",
    re.IGNORECASE,
)


def _line_number_for_offset(content: str, offset: int) -> int:
    return content.count("\n", 0, max(0, offset)) + 1


def _normalize_table_identifier(raw_table: str) -> str:
    cleaned = raw_table.strip().strip("\"`'").lower()
    if "." in cleaned:
        cleaned = cleaned.split(".")[-1].strip("\"`'")
    return cleaned


def _is_cleartext_secret_column(col_name: str) -> bool:
    name = col_name.strip().strip("\"`':").lower()
    if not name:
        return False
    if any(name.endswith(suffix) for suffix in _SAFE_COLUMN_SUFFIXES):
        return False
    if name in _SENSITIVE_COLUMNS:
        return True
    for base in _SENSITIVE_COLUMNS:
        if name.endswith(f"_{base}") and not any(name.endswith(s) for s in _SAFE_COLUMN_SUFFIXES):
            return True
    return False


def _strip_sql_comments(text: str) -> str:
    # Satır ve sütun konumlarını koruyan doğrusal yorum ayrıştırıcısı.
    out = list(text)
    index = 0
    state = "code"
    escaped = False
    while index < len(text):
        char = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if state == "code":
            if char in {"'", '"', "`"}:
                state, escaped = char, False
            elif char == "-" and following == "-":
                out[index] = out[index + 1] = " "
                state = "line"
                index += 1
            elif char == "/" and following == "*":
                out[index] = out[index + 1] = " "
                state = "block"
                index += 1
        elif state in {"'", '"', "`"}:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == state:
                state = "code"
        elif state == "line":
            if char == "\n":
                state = "code"
            else:
                out[index] = " "
        else:
            if char == "*" and following == "/":
                out[index] = out[index + 1] = " "
                state = "code"
                index += 1
            elif char != "\n":
                out[index] = " "
        index += 1
    return "".join(out)


def _build_finding(
    *,
    rule_id: str,
    cwe: str,
    severity: str,
    category: str,
    title: str,
    description: str,
    recommendation: str,
    filename: str,
    line: int,
    evidence: str,
) -> dict[str, Any]:
    clean_evidence = " ".join(evidence.strip().split())[:280]
    return {
        "id": rule_id,
        "rule_id": rule_id,
        "cwe": cwe,
        "severity": severity,
        "category": category,
        "title": title,
        "description": description,
        "recommendation": recommendation,
        "file": filename,
        "line": line,
        "evidence": clean_evidence,
    }


def audit_database_schema_migrations(
    migration_content: str,
    *,
    filename: str = "0002_update_tenants.sql",
) -> dict[str, Any]:
    """Veritabanı şema göç (migration) içeriğini RLS, kiracı izolasyonu ve düz metin sır açıklarına karşı denetler."""
    raw_text = migration_content if isinstance(migration_content, str) else ""
    clean_filename = str(filename or "0002_update_tenants.sql").strip() or "0002_update_tenants.sql"
    scannable = _strip_sql_comments(raw_text)

    findings: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, int, str]] = set()

    def _add(
        rule_id: str,
        cwe: str,
        severity: str,
        category: str,
        title: str,
        description: str,
        recommendation: str,
        offset: int,
        evidence: str,
        dedup_token: str,
    ) -> None:
        line_no = _line_number_for_offset(raw_text, offset)
        key = (rule_id, line_no, dedup_token)
        if key in seen_keys:
            return
        seen_keys.add(key)
        findings.append(
            _build_finding(
                rule_id=rule_id,
                cwe=cwe,
                severity=severity,
                category=category,
                title=title,
                description=description,
                recommendation=recommendation,
                filename=clean_filename,
                line=line_no,
                evidence=evidence,
            )
        )

    # -------------------------------------------------------------------------
    # Kural 1: SNIPER-MIG-RLS-01 (DISABLE ROW LEVEL SECURITY / USING (true) / eksik RLS)
    # -------------------------------------------------------------------------
    rls_flagged_in_file = False

    for match in _DISABLE_RLS_RE.finditer(scannable):
        rls_flagged_in_file = True
        snippet = raw_text[match.start() : match.end()]
        _add(
            RULE_RLS_DISABLED_OR_PERMISSIVE,
            "CWE-284",
            "critical",
            "authz",
            TITLE_RLS_01,
            "Tablo üzerinde Row-Level Security (RLS) açıkça devre dışı bırakılmış (DISABLE ROW LEVEL SECURITY). "
            "Bu işlem kiracılar arası (cross-tenant) tüm satırları yetkisiz okumaya/yazmaya açar.",
            "DISABLE ROW LEVEL SECURITY ifadesini kaldırın; tabloda ENABLE ROW LEVEL SECURITY ve FORCE ROW LEVEL SECURITY uygulayın.",
            match.start(),
            snippet,
            "disable_rls",
        )

    for match in _PERMISSIVE_POLICY_RE.finditer(scannable):
        snippet = raw_text[match.start() : match.end()]
        if re.search(r"\bON\s+(?:public\.)?(?:spatial_ref_sys|schema_migrations|ar_internal_metadata)\b", snippet, re.IGNORECASE):
            continue
        rls_flagged_in_file = True
        _add(
            RULE_RLS_DISABLED_OR_PERMISSIVE,
            "CWE-284",
            "critical",
            "authz",
            TITLE_RLS_01,
            "RLS politikasında USING (true) veya WITH CHECK (true) kullanılarak satır bazlı erişim kontrolü etkisizleştirilmiş.",
            "Politikayı kiracı bağlamına bağlayın (ör. USING (tenant_id = current_setting('app.current_tenant_id')::uuid)).",
            match.start(),
            snippet,
            "permissive_policy",
        )

    enabled_rls_tables = {
        _normalize_table_identifier(m.group(1))
        for m in _ENABLE_RLS_TABLE_RE.finditer(scannable)
    }
    has_any_enable_rls = bool(re.search(r"\bENABLE\s+ROW\s+LEVEL\s+SECURITY\b", scannable, re.IGNORECASE))

    for match in _SQL_CREATE_TABLE_RE.finditer(scannable):
        table_raw = match.group(1)
        table_norm = _normalize_table_identifier(table_raw)
        body_text = match.group(2)
        has_tenant_col = any(
            re.search(rf"\b{re.escape(t_col)}\b", body_text, re.IGNORECASE)
            for t_col in ("tenant_id", "organization_id", "workspace_id")
        )
        if has_tenant_col and table_norm not in enabled_rls_tables and not has_any_enable_rls and not rls_flagged_in_file:
            snippet = raw_text[match.start() : match.end()]
            _add(
                RULE_RLS_DISABLED_OR_PERMISSIVE,
                "CWE-284",
                "critical",
                "authz",
                TITLE_RLS_01,
                f"Çok-kiracılı '{table_norm}' tablosu kiracı sütunu içeriyor ancak göç dosyasında ENABLE ROW LEVEL SECURITY etkinleştirilmemiş.",
                f"ALTER TABLE {table_norm} ENABLE ROW LEVEL SECURITY; ve kiracı izolasyon politikası ekleyin.",
                match.start(),
                snippet,
                f"missing_rls:{table_norm}",
            )

    # -------------------------------------------------------------------------
    # Kural 2: SNIPER-MIG-TENANT-DROP-02 (Kiracı sütunu veya NOT NULL kaldırma)
    # -------------------------------------------------------------------------
    tenant_drop_patterns: tuple[tuple[re.Pattern[str], str], ...] = (
        (_SQL_DROP_TENANT_COL_RE, "sql_drop_col"),
        (_SQL_DROP_TENANT_CONSTRAINT_RE, "sql_drop_constraint"),
        (_SQL_DROP_NOT_NULL_RE, "sql_drop_not_null"),
        (_ALEMBIC_DROP_TENANT_COL_RE, "alembic_drop_col"),
        (_ALEMBIC_ALTER_NULLABLE_RE, "alembic_nullable"),
        (_RAILS_REMOVE_TENANT_COL_RE, "rails_remove_col"),
        (_RAILS_CHANGE_NULL_RE, "rails_change_null"),
    )
    for pattern, kind in tenant_drop_patterns:
        for match in pattern.finditer(scannable):
            col_or_const = match.group(1)
            snippet = raw_text[match.start() : match.end()]
            _add(
                RULE_TENANT_ISOLATION_DROPPED,
                "CWE-639",
                "high",
                "authz",
                TITLE_TENANT_DROP_02,
                f"Göç dosyasında kiracı/sahiplik izolasyonunu sağlayan '{col_or_const}' sütunu veya NOT NULL zorunluluğu kaldırılıyor.",
                f"'{col_or_const}' sütununu ve NOT NULL / FOREIGN KEY kısıtlarını koruyun; yetim (orphan) kiracı satırlarına izin vermeyin.",
                match.start(),
                snippet,
                f"{kind}:{col_or_const.lower()}",
            )

    # -------------------------------------------------------------------------
    # Kural 3: SNIPER-MIG-CLEARTEXT-03 (Düz metin parola / API anahtarı sütunu)
    # -------------------------------------------------------------------------
    recorded_secret_cols: set[tuple[int, str]] = set()

    for match in _SQL_ADD_COLUMN_RE.finditer(scannable):
        col_name = match.group(1)
        if _is_cleartext_secret_column(col_name):
            line_no = _line_number_for_offset(raw_text, match.start())
            recorded_secret_cols.add((line_no, col_name.lower()))
            snippet = raw_text[match.start() : match.end()]
            _add(
                RULE_CLEARTEXT_SECRET_COLUMN,
                "CWE-312",
                "high",
                "crypto",
                TITLE_CLEARTEXT_03,
                f"Şemaya şifrelenmemiş/özetlenmemiş düz metin sır sütunu ('{col_name}') eklendi.",
                f"'{col_name}' değerini düz metin saklamayın; Argon2id/SHA-256 özeti ('{col_name}_hash') veya AEAD şifreli ('{col_name}_encrypted') sütun kullanın.",
                match.start(),
                snippet,
                f"cleartext:{col_name.lower()}",
            )

    for match in _SQL_CREATE_TABLE_RE.finditer(scannable):
        body_text = match.group(2)
        body_start = match.start(2)
        for line_match in re.finditer(
            r"(?:^|,)\s*[\"`']?([A-Za-z_][A-Za-z0-9_]*)[\"`']?\s+(?:VARCHAR|TEXT|CHAR|CHARACTER|STRING|BYTEA)\b",
            body_text,
            re.IGNORECASE | re.MULTILINE,
        ):
            col_name = line_match.group(1)
            if col_name.upper() in {"CONSTRAINT", "PRIMARY", "FOREIGN", "UNIQUE", "CHECK"}:
                continue
            if _is_cleartext_secret_column(col_name):
                abs_offset = body_start + line_match.start(1)
                line_no = _line_number_for_offset(raw_text, abs_offset)
                if (line_no, col_name.lower()) in recorded_secret_cols:
                    continue
                recorded_secret_cols.add((line_no, col_name.lower()))
                snippet = raw_text[abs_offset : min(len(raw_text), abs_offset + 80)]
                _add(
                    RULE_CLEARTEXT_SECRET_COLUMN,
                    "CWE-312",
                    "high",
                    "crypto",
                    TITLE_CLEARTEXT_03,
                    f"Tablo tanımında şifrelenmemiş/özetlenmemiş düz metin sır sütunu ('{col_name}') bulundu.",
                    f"'{col_name}' yerine '{col_name}_hash' veya '{col_name}_encrypted' kullanın.",
                    abs_offset,
                    snippet,
                    f"cleartext:{col_name.lower()}",
                )

    for pattern in (_ALEMBIC_ADD_COLUMN_RE, _RAILS_ADD_COLUMN_RE):
        for match in pattern.finditer(scannable):
            col_name = match.group(1)
            if _is_cleartext_secret_column(col_name):
                line_no = _line_number_for_offset(raw_text, match.start())
                if (line_no, col_name.lower()) in recorded_secret_cols:
                    continue
                recorded_secret_cols.add((line_no, col_name.lower()))
                snippet = raw_text[match.start() : match.end()]
                _add(
                    RULE_CLEARTEXT_SECRET_COLUMN,
                    "CWE-312",
                    "high",
                    "crypto",
                    TITLE_CLEARTEXT_03,
                    f"Göç betiğinde şifrelenmemiş/özetlenmemiş düz metin sır sütunu ('{col_name}') eklendi.",
                    f"'{col_name}' yerine '{col_name}_hash' veya '{col_name}_encrypted' kullanın.",
                    match.start(),
                    snippet,
                    f"cleartext:{col_name.lower()}",
                )

    return {
        "format": FORMAT,
        "filename": clean_filename,
        "finding_count": len(findings),
        "findings": findings,
    }
