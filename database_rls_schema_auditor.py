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


_SQL_TABLE_HEADER_RE = re.compile(
    r"\bCREATE\s+TABLE(?:\s+IF\s+NOT\s+EXISTS)?\s+([A-Za-z0-9_.\"']+)\s*\(", re.IGNORECASE
)
_PRISMA_MODEL_HEADER_RE = re.compile(r"\bmodel\s+([A-Za-z0-9_]+)\s*\{", re.IGNORECASE)
_ALTER_RLS_RE = re.compile(
    r"\bALTER TABLE (?:IF EXISTS )?(?:ONLY )?([A-Za-z0-9_.\"']+) (?:FORCE|ENABLE) ROW LEVEL SECURITY\b",
    re.IGNORECASE,
)
_SIMPLE_DANGEROUS_DB_RE = re.compile(
    r"\bSUPERUSER\b|\bGRANT\s+ALL(?:\s+PRIVILEGES)?\b|\bxp_cmdshell\b|"
    r"\bLOAD_FILE\s*\(|\bINTO\s+(?:OUTFILE|DUMPFILE)\b",
    re.IGNORECASE,
)
_SIMPLE_UNSAFE_MIGRATION_RE = re.compile(
    r"\bSET\s+FOREIGN_KEY_CHECKS\s*=\s*(?:0|OFF)\b|"
    r"\bPRAGMA\s+foreign_keys\s*=\s*(?:0|OFF)\b|"
    r"\bDISABLE\s+TRIGGER\s+ALL\b",
    re.IGNORECASE,
)
_COPY_WORD_RE = re.compile(r"\bcopy\b", re.IGNORECASE)
_FROM_PROGRAM_RE = re.compile(r"\bfrom[ \t]+program\b", re.IGNORECASE)
_DROP_TABLE_RE = re.compile(r"\bdrop[ \t]+table\b", re.IGNORECASE)
_CASCADE_RE = re.compile(r"\bcascade\b", re.IGNORECASE)


def _iter_statements(content: str):
    start = 0
    while start < len(content):
        end = content.find(";", start)
        if end < 0:
            yield start, content[start:]
            return
        yield start, content[start:end]
        start = end + 1


def _iter_rls_table_names(content: str):
    for start, statement in _iter_statements(content):
        normalized = " ".join(statement.split())
        if not normalized:
            continue
        alter = _ALTER_RLS_RE.search(normalized)
        if alter:
            yield start, alter.group(1)
        folded = normalized.casefold()
        policy = folded.find("create policy ")
        if policy < 0:
            continue
        on = folded.find(" on ", policy + len("create policy "))
        if on < 0:
            continue
        pos = on + len(" on ")
        end = pos
        while end < len(normalized) and normalized[end] in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.\"'":
            end += 1
        if end > pos:
            yield start, normalized[pos:end]


def _iter_sql_tables(content: str):
    cursor = 0
    while (header := _SQL_TABLE_HEADER_RE.search(content, cursor)) is not None:
        close = content.find(")", header.end())
        while close >= 0:
            tail = close + 1
            while tail < len(content) and content[tail].isspace():
                tail += 1
            if tail < len(content) and content[tail] == ";":
                yield header.start(), header.group(1), content[header.end():close]
                cursor = tail + 1
                break
            close = content.find(")", close + 1)
        else:
            return


def _iter_prisma_models(content: str):
    cursor = 0
    while (header := _PRISMA_MODEL_HEADER_RE.search(content, cursor)) is not None:
        close = content.find("}", header.end())
        if close < 0:
            return
        yield header.start(), header.group(1), content[header.end():close]
        cursor = close + 1


def _iter_dangerous_db_privileges(content: str):
    for match in _SIMPLE_DANGEROUS_DB_RE.finditer(content):
        yield match.start(), match.group(0)
    offset = 0
    for raw_line in content.splitlines(keepends=True):
        line = raw_line.rstrip("\r\n")
        segment_start = 0
        while segment_start <= len(line):
            segment_end = line.find(";", segment_start)
            if segment_end < 0:
                segment_end = len(line)
            segment = line[segment_start:segment_end]
            search_from = 0
            while (copy := _COPY_WORD_RE.search(segment, search_from)) is not None:
                marker = _FROM_PROGRAM_RE.search(segment, copy.end())
                if marker:
                    yield offset + segment_start + copy.start(), segment[copy.start():marker.end()]
                    search_from = marker.end()
                else:
                    search_from = copy.end()
            if segment_end == len(line):
                break
            segment_start = segment_end + 1
        fields = line.split()
        if fields and fields[0].casefold() in {"host", "local"} and len(fields) >= 4:
            trust_index = 3 if len(fields) == 4 else 4
            if trust_index < len(fields) and fields[trust_index].casefold() == "trust":
                yield offset, line
        offset += len(raw_line)


def _iter_unsafe_migrations(content: str):
    for match in _SIMPLE_UNSAFE_MIGRATION_RE.finditer(content):
        yield match.start(), match.group(0)
    offset = 0
    for raw_line in content.splitlines(keepends=True):
        line = raw_line.rstrip("\r\n")
        segment_start = 0
        while segment_start <= len(line):
            segment_end = line.find(";", segment_start)
            if segment_end < 0:
                segment_end = len(line)
            segment = line[segment_start:segment_end]
            search_from = 0
            while (drop := _DROP_TABLE_RE.search(segment, search_from)) is not None:
                cascade = _CASCADE_RE.search(segment, drop.end())
                if cascade:
                    yield offset + segment_start + drop.start(), segment[drop.start():cascade.end()]
                    search_from = cascade.end()
                else:
                    search_from = drop.end()
            if segment_end == len(line):
                break
            segment_start = segment_end + 1
        offset += len(raw_line)


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
    tenant_col_re = re.compile(
        r"\b(?:tenant_id|organization_id|org_id|workspace_id|account_id)\b",
        re.IGNORECASE,
    )
    def _short_name(identifier: str) -> str:
        return identifier.strip().strip("\"'").split(".")[-1].strip("\"'").casefold()

    rls_tables = {_short_name(table) for _offset, table in _iter_rls_table_names(raw_content)}
    reported_tables: set[str] = set()
    for table_start, raw_table_name, table_body in _iter_sql_tables(raw_content):
        table_name = raw_table_name.strip('"\'')
        short_table = table_name.split(".")[-1]
        if tenant_col_re.search(table_body):
            key = _short_name(short_table)
            if key not in rls_tables and key not in reported_tables:
                reported_tables.add(key)
                line_no = _line_number_for_offset(raw_content, table_start)
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

    prisma_tenant_re = re.compile(
        r"\b(?:tenant_id|tenantId|organization_id|organizationId|org_id|orgId|workspace_id|workspaceId|account_id|accountId)\b"
    )
    for model_start, model_name, model_body in _iter_prisma_models(raw_content):
        if prisma_tenant_re.search(model_body) and not has_global_rls and "rls" not in model_body.lower():
            line_no = _line_number_for_offset(raw_content, model_start)
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
    for privilege_start, privilege_text in _iter_dangerous_db_privileges(raw_content):
        if privilege_text.upper() == "SUPERUSER" and re.search(
            r"\bNOSUPERUSER\b", lines[_line_number_for_offset(raw_content, privilege_start) - 1], re.IGNORECASE
        ):
            continue
        line_no = _line_number_for_offset(raw_content, privilege_start)
        snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else privilege_text
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
    for migration_start, migration_text in _iter_unsafe_migrations(raw_content):
        line_no = _line_number_for_offset(raw_content, migration_start)
        snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else migration_text
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
