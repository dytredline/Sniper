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

DATABASE_SCHEMA_CONTROLS_EVALUATED: list[str] = [
    "SNIPER-AUTHZ-04",
    "SNIPER-DATA-02",
    "SNIPER-CONF-08",
    "SNIPER-INFR-03",
]

DB_SCAN_EXTENSIONS: set[str] = {".sql", ".prisma", ".conf", ".py", ".js", ".ts"}

SAFE_COLUMN_SUFFIXES: tuple[str, ...] = (
    "_hash",
    "_encrypted",
    "_cipher",
    "_digest",
    "_token",
    "_masked",
)


def calculate_score(findings: list[dict[str, Any]]) -> tuple[int, str]:
    score, grade, _counts = _scanner_calculate_score(findings)
    return score, grade


def _line_number_for_offset(content: str, offset: int) -> int:
    return content.count("\n", 0, max(0, offset)) + 1


def _make_db_finding(
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
    reference = f"OWASP ASVS V6 / CIS PostgreSQL & Database Security · {cwe}"
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


def audit_database_schema_inline(
    raw_content: str,
    *,
    filename: str = "schema.sql",
) -> dict[str, Any]:
    if not isinstance(raw_content, str) or not raw_content.strip():
        raise ValueError("Denetlenecek veritabanı şema / migrasyon içeriği boş olamaz.")
    encoded = raw_content.encode("utf-8", errors="replace")
    if len(encoded) > MAX_INLINE_BYTES:
        raise ValueError(f"İçerik boyutu güvenli sınırı ({MAX_INLINE_BYTES} bayt) aşıyor.")
    if not isinstance(filename, str) or not filename.strip():
        filename = "schema.sql"
    clean_filename = filename.strip()
    lines = raw_content.splitlines()

    findings: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str, int]] = set()

    def _add(finding: dict[str, Any]) -> None:
        key = (finding["control_id"], finding["cwe"], int(finding["line"]))
        if key not in seen_keys:
            seen_keys.add(key)
            findings.append(finding)

    # 1. Missing Row-Level Security (RLS) on Multi-Tenant Tables (high, CWE-284, SNIPER-AUTHZ-04)
    has_global_rls = bool(
        re.search(r"\b(?:ENABLE\s+ROW\s+LEVEL\s+SECURITY|CREATE\s+POLICY)\b", raw_content, re.IGNORECASE)
    )
    sql_table_re = re.compile(
        r"CREATE\s+TABLE(?:\s+IF\s+NOT\s+EXISTS)?\s+([A-Za-z0-9_.\"']+)\s*\((.*?)\)\s*;",
        re.IGNORECASE | re.DOTALL,
    )
    tenant_col_re = re.compile(
        r"\b(?:tenant_id|organization_id|org_id|workspace_id|account_id)\b",
        re.IGNORECASE,
    )
    rls_name_re = re.compile(
        r"ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?([A-Za-z0-9_.\"']+)\s+(?:FORCE|ENABLE)\s+ROW\s+LEVEL\s+SECURITY"
        r"|CREATE\s+POLICY\s+[^\n;]+?\s+ON\s+([A-Za-z0-9_.\"']+)",
        re.IGNORECASE,
    )

    def _short_name(identifier: str) -> str:
        return identifier.strip().strip("\"'").split(".")[-1].strip("\"'").casefold()

    rls_tables = {
        _short_name(found.group(1) or found.group(2))
        for found in rls_name_re.finditer(raw_content)
    }
    reported_tables: set[str] = set()
    for match in sql_table_re.finditer(raw_content):
        table_name = match.group(1).strip('"\'')
        short_table = table_name.split(".")[-1]
        table_body = match.group(2)
        if tenant_col_re.search(table_body):
            key = _short_name(short_table)
            if key not in rls_tables and key not in reported_tables:
                reported_tables.add(key)
                line_no = _line_number_for_offset(raw_content, match.start())
                snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else f"CREATE TABLE {table_name}"
                _add(
                    _make_db_finding(
                        severity="high",
                        category="authorization",
                        title=f"Çok kiracılı (multi-tenant) '{table_name}' tablosunda Row-Level Security (RLS) eksik",
                        description=(
                            f"'{table_name}' tablosu kiracı ayrımı sütunu (tenant_id / organization_id / workspace_id) "
                            "içeriyor ancak ENABLE ROW LEVEL SECURITY ve CREATE POLICY tanımlanmamış."
                        ),
                        evidence=snippet,
                        recommendation=(
                            f"ALTER TABLE {table_name} ENABLE ROW LEVEL SECURITY; ve FORCE ROW LEVEL SECURITY; "
                            "komutlarıyla birlikte current_setting('app.current_tenant_id') tabanlı CREATE POLICY ekleyin."
                        ),
                        cwe="CWE-284",
                        control_id="SNIPER-AUTHZ-04",
                        filename=clean_filename,
                        line=line_no,
                    )
                )

    prisma_model_re = re.compile(
        r"model\s+([A-Za-z0-9_]+)\s*\{([^}]*)\}",
        re.DOTALL,
    )
    prisma_tenant_re = re.compile(
        r"\b(?:tenant_id|tenantId|organization_id|organizationId|org_id|orgId|workspace_id|workspaceId|account_id|accountId)\b"
    )
    for match in prisma_model_re.finditer(raw_content):
        model_name = match.group(1)
        model_body = match.group(2)
        if prisma_tenant_re.search(model_body) and not has_global_rls and "rls" not in model_body.lower():
            line_no = _line_number_for_offset(raw_content, match.start())
            snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else f"model {model_name}"
            _add(
                _make_db_finding(
                    severity="high",
                    category="authorization",
                    title=f"Prisma çok kiracılı '{model_name}' modelinde RLS politikası referansı eksik",
                    description=(
                        f"Prisma '{model_name}' modeli kiracı kimliği alanı içeriyor ancak veritabanı düzeyinde "
                        "Row-Level Security (RLS) politikası tanımlanmamış."
                    ),
                    evidence=snippet,
                    recommendation=(
                        "Çok kiracılı Prisma modellerine karşılık gelen SQL migrasyonlarında "
                        "ENABLE ROW LEVEL SECURITY ve kiracı izolasyon politikalarını zorunlu kılın."
                    ),
                    cwe="CWE-284",
                    control_id="SNIPER-AUTHZ-04",
                    filename=clean_filename,
                    line=line_no,
                )
            )

    # 2. Plaintext Sensitive PII / Financial Columns (high, CWE-311, SNIPER-DATA-02)
    sensitive_col_re = re.compile(
        r"(?im)^\s*[\"`']?([A-Za-z0-9_]*(?:ssn|tc_kimlik|iban|card_number|cvv|pin|password|api_secret|private_key|tax_id)[A-Za-z0-9_]*)[\"`']?\s+"
        r"(?:VARCHAR|TEXT|CHAR|NVARCHAR|CHARACTER\s+VARYING|String\b)",
    )
    for match in sensitive_col_re.finditer(raw_content):
        col_name = match.group(1).lower()
        if any(col_name.endswith(suffix) for suffix in SAFE_COLUMN_SUFFIXES):
            continue
        line_no = _line_number_for_offset(raw_content, match.start())
        snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else match.group(0)
        _add(
            _make_db_finding(
                severity="high",
                category="data",
                title=f"Hassas PII / finansal sütun ('{match.group(1)}') şifrelenmemiş düz metin olarak tanımlanmış",
                description=(
                    f"Veritabanı şemasında '{match.group(1)}' sütunu (_hash, _encrypted, _cipher veya _digest "
                    "soneki olmadan) düz metin (VARCHAR/TEXT/String) tipinde tutuluyor."
                ),
                evidence=snippet,
                recommendation=(
                    "Parola ve PIN değerlerini Argon2id/bcrypt özeti (_hash) olarak; TC Kimlik, SSN, IBAN, "
                    "kart numarası ve API sırlarını ise uygulama katmanı AEAD şifrelemesi (_encrypted) veya "
                    "tokenizasyon ile saklayın."
                ),
                cwe="CWE-311",
                control_id="SNIPER-DATA-02",
                filename=clean_filename,
                line=line_no,
            )
        )

    # 3. Excessive Database Privileges & Dangerous Command Execution (critical, CWE-250, SNIPER-CONF-08)
    dangerous_db_priv_re = re.compile(
        r"(?im)(?:\bSUPERUSER\b"
        r"|\bGRANT\s+ALL(?:\s+PRIVILEGES)?\b"
        r"|\bCOPY\s+[^\n;]+\s+FROM\s+PROGRAM\b"
        r"|\bxp_cmdshell\b"
        r"|\bLOAD_FILE\s*\("
        r"|\bINTO\s+(?:OUTFILE|DUMPFILE)\b"
        r"|^(?:host|local)\s+\S+\s+\S+(?:\s+\S+)?\s+trust\b)"
    )
    for match in dangerous_db_priv_re.finditer(raw_content):
        if match.group(0).upper() == "SUPERUSER" and re.search(
            r"\bNOSUPERUSER\b", lines[_line_number_for_offset(raw_content, match.start()) - 1], re.IGNORECASE
        ):
            continue
        line_no = _line_number_for_offset(raw_content, match.start())
        snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else match.group(0)
        _add(
            _make_db_finding(
                severity="critical",
                category="configuration",
                title="Aşırı veritabanı yetkisi veya işletim sistemi komutu yürütme (SUPERUSER / GRANT ALL / PROGRAM)",
                description=(
                    "Veritabanı betiğinde SUPERUSER, GRANT ALL PRIVILEGES, COPY ... FROM PROGRAM, "
                    "xp_cmdshell, LOAD_FILE/INTO OUTFILE veya pg_hba.conf 'trust' kimlik doğrulaması tespit edildi."
                ),
                evidence=snippet,
                recommendation=(
                    "Uygulama veritabanı rollerinden SUPERUSER ve GRANT ALL yetkilerini kaldırın, "
                    "işletim sistemi dosya/komut erişimini kapatın ve scram-sha-256 kimlik doğrulaması kullanın."
                ),
                cwe="CWE-250",
                control_id="SNIPER-CONF-08",
                filename=clean_filename,
                line=line_no,
            )
        )

    # 4. Unsafe Schema Migration / Foreign Key Disablement (medium, CWE-400, SNIPER-INFR-03)
    unsafe_migration_re = re.compile(
        r"(?im)(?:\bSET\s+FOREIGN_KEY_CHECKS\s*=\s*(?:0|OFF)\b"
        r"|\bPRAGMA\s+foreign_keys\s*=\s*(?:0|OFF)\b"
        r"|\bDISABLE\s+TRIGGER\s+ALL\b"
        r"|\bDROP\s+TABLE\s+[^\n;]+\bCASCADE\b)"
    )
    for match in unsafe_migration_re.finditer(raw_content):
        line_no = _line_number_for_offset(raw_content, match.start())
        snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else match.group(0)
        _add(
            _make_db_finding(
                severity="medium",
                category="infrastructure",
                title="Güvensiz şema migrasyonu: Yabancı anahtar/tetikleyici devre dışı bırakma veya CASCADE silme",
                description=(
                    "Şema migrasyonunda SET FOREIGN_KEY_CHECKS = 0, DISABLE TRIGGER ALL veya "
                    "DROP TABLE ... CASCADE kullanılarak veri bütünlüğü ve bağımlı tablolar riske atılıyor."
                ),
                evidence=snippet,
                recommendation=(
                    "Üretim migrasyonlarında referans bütünlüğü kontrollerini devre dışı bırakmayın ve "
                    "DROP ... CASCADE yerine açık bağımlılık sırasıyla aşamalı migrasyon uygulayın."
                ),
                cwe="CWE-400",
                control_id="SNIPER-INFR-03",
                filename=clean_filename,
                line=line_no,
            )
        )

    score, grade = calculate_score(findings)
    return {
        "format": "sniper-database-schema-inline-audit-v1",
        "filename": clean_filename,
        "score": score,
        "grade": grade,
        "finding_count": len(findings),
        "findings_truncated": len(findings) > INLINE_FINDING_LIMIT,
        "finding_groups": summarize_finding_groups(findings),
        "findings": cap_findings(findings, INLINE_FINDING_LIMIT)[0],
        "controls_evaluated": list(DATABASE_SCHEMA_CONTROLS_EVALUATED),
    }


@project_scan_scope
def audit_database_schema_project(
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
            lower_name = name.lower()
            is_db_file = (
                ext in {".sql", ".prisma"}
                or lower_name == "pg_hba.conf"
                or (
                    ext in {".py", ".js", ".ts"}
                    and any(
                        token in str(file_path.relative_to(root)).lower()
                        for token in ("migration", "schema", "alembic", "prisma", "db")
                    )
                )
            )
            if not is_db_file:
                continue
            content = read_text_bounded(file_path, MAX_INLINE_BYTES)
            if content is None:
                continue
            if not content.strip():
                continue
            rel_name = str(file_path.relative_to(root))
            scanned_files += 1
            file_report = audit_database_schema_inline(content, filename=rel_name)
            findings.extend(file_report["findings"])

    score, grade = calculate_score(findings)
    return {
        "format": "sniper-database-schema-audit-v1",
        "project": root.name,
        "project_path": str(root),
        "scanned_files": scanned_files,
        "score": score,
        "grade": grade,
        "finding_count": len(findings),
        "findings_truncated": len(findings) > PROJECT_FINDING_LIMIT,
        "finding_groups": summarize_finding_groups(findings),
        "findings": cap_findings(findings, PROJECT_FINDING_LIMIT)[0],
        "controls_evaluated": list(DATABASE_SCHEMA_CONTROLS_EVALUATED),
    }
