from __future__ import annotations

import json
import hashlib
import os
import re
import secrets
import sqlite3
from contextlib import contextmanager
from collections.abc import Iterator
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from audit_chain_verifier import (
    GENESIS_HASH as AUDIT_GENESIS_HASH,
    StoredAuditChainVerifier,
    compute_audit_entry_hash,
)
from audit_integrity import (
    compute_hmac_entry_hash,
    is_hmac_hash,
    load_key as load_audit_key,
    read_anchor as read_audit_anchor,
    write_anchor as write_audit_anchor,
)
import ai_triage
import finding_tracking
import unified_findings
import portfolio
from methodology import CATEGORIES, TEST_CATALOG
from storage_canonical import (
    _compare_finding_sets,
    _count_by_severity,
    _filter_by_severity,
    _finding_sort_key,
)
from scanner import NormalizedTarget, utc_now
from tool_report_semgrep import SEVERITY_VALUES
from request_context import with_actor


LIVE_SNIPER_ROOT = Path.home() / ".local" / "share" / "sniper"
LIVE_APP_DIR = LIVE_SNIPER_ROOT / "app"
SCHEMA_MIGRATIONS = ((1, "network-finding-lifecycle"),)


class LiveDataProtected(PermissionError):
    """Aday kopyası, kurulu Sniper'ın canlı verisini açamaz (okuma dahil)."""


class DependencyExportTooLarge(ValueError):
    """Dependency export payload exceeds safe row or byte limits."""


def _guard_live_path(path: Path) -> None:
    # Kurulu uygulama (LIVE_APP_DIR altındaki storage.py) canlı veriyi açabilir; aday veya kopyaları açamaz.
    # HOME'a bağlı değildir; SNIPER_ALLOW_LIVE_DB=1 yalnız bilinçli bakım için.
    here = Path(__file__).resolve().parent
    if here == LIVE_APP_DIR.resolve() or os.environ.get("SNIPER_ALLOW_LIVE_DB") == "1":
        return
    resolved = Path(path).expanduser().resolve()
    if resolved == LIVE_SNIPER_ROOT or LIVE_SNIPER_ROOT in resolved.parents:
        raise LiveDataProtected(
            f"Aday kopyası canlı Sniper verisini açamaz: {resolved}. Sentetik bir veritabanı yolu kullanın."
        )


def _restrict_mode(path: Path, mode: int, *, only_if_private: bool) -> None:
    """İzinleri daralt; sahibi olmadığımız veya herkese açık (sticky) ortak dizinlerde sessizce atla."""
    try:
        info = path.stat()
        if info.st_uid != os.getuid():
            return
        if only_if_private and info.st_mode & 0o1000:  # /tmp gibi sticky ortak dizin
            return
        os.chmod(path, mode)
    except PermissionError:
        return


class _AuditConnection(sqlite3.Connection):
    """İşlem başarıyla kapandıktan sonra yazılacak denetim çapasını taşır."""

    sniper_db_path: Path | None = None
    audit_anchor_pending: dict[str, Any] | None = None


class Store:
    def __init__(self, path: Path):
        _guard_live_path(Path(path))
        object.__setattr__(self, "path", path)  # koruma yukarıda çalıştı; __setattr__ yolu ikinci kez çözmesin
        parent_existed = self.path.parent.exists()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Yalnız kendi oluşturduğumuz (ya da sahibi olduğumuz, paylaşımsız) veri dizinini kısıtla. `/tmp` gibi
        # ortak dizinlerde chmod PermissionError verir ve sentetik DB oluşturmayı engellerdi (r9 T06 bulgusu).
        # Yan etki: Mevcut ebeveyn dizinlerin izinlerini (örn. 0755) 0700'e düşürmemek için
        # sadece yeni oluşturulmuş dizinleri kısıtla.
        if not parent_existed:
            _restrict_mode(self.path.parent, 0o700, only_if_private=False)
        self._initialize()
        if self.path.exists():
            _restrict_mode(self.path, 0o600, only_if_private=False)

    def __setattr__(self, name: str, value: Any) -> None:
        # Oluşturma sonrası `store.path = ...`, vekil iletimiyle `server.STORE.path = ...` ve
        # `patch.object(store, "path", ...)` da oluşturmayla aynı canlı yol korumasından geçer; aksi halde
        # `_connect` canlı DB'yi açar, WAL kipi -wal/-shm (dosya yoksa yeni DB) yaratabilirdi. Yol dosya açılmadan
        # reddedilir. `path` düz örnek özniteliği kalır: patch.object'in çıkıştaki delattr/setattr adımları güvenli
        # asıl yolla çalışmaya devam eder.
        if name == "path":
            _guard_live_path(Path(value))
        object.__setattr__(self, name, value)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=10, factory=_AuditConnection)
        connection.sniper_db_path = Path(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        try:
            with connection:
                yield connection
            pending = connection.audit_anchor_pending
            if pending:
                # Çapa yalnız işlem kalıcılaştıktan sonra ilerler; geri alınan bir ekleme çapayı
                # veritabanının önüne geçirip yanlış "kuyruk silindi" alarmı üretmesin.
                connection.audit_anchor_pending = None
                write_audit_anchor(self.path, **pending)
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS targets (
                    id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    url TEXT NOT NULL,
                    scheme TEXT NOT NULL,
                    hostname TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    path TEXT NOT NULL,
                    status TEXT NOT NULL,
                    verification_token TEXT NOT NULL,
                    verified_at TEXT,
                    verification_proof TEXT
                );

                CREATE UNIQUE INDEX IF NOT EXISTS targets_url_idx ON targets(url);

                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    finished_at TEXT,
                    score INTEGER,
                    grade TEXT,
                    findings_json TEXT,
                    summary_json TEXT,
                    error TEXT
                );

                CREATE INDEX IF NOT EXISTS scans_target_idx ON scans(target_id, created_at DESC);

                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    occurred_at TEXT NOT NULL,
                    action TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    details_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS engagements (
                    id TEXT PRIMARY KEY,
                    target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
                    name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    authorization_ref TEXT NOT NULL,
                    scope_notes TEXT NOT NULL,
                    out_of_scope TEXT NOT NULL,
                    test_window TEXT NOT NULL,
                    special_approvals_json TEXT NOT NULL,
                    executive_summary TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS engagements_target_idx ON engagements(target_id, created_at DESC);

                CREATE TABLE IF NOT EXISTS manual_tests (
                    id TEXT PRIMARY KEY,
                    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
                    control_id TEXT NOT NULL,
                    category TEXT NOT NULL,
                    category_title TEXT NOT NULL,
                    title TEXT NOT NULL,
                    objective TEXT NOT NULL,
                    reference TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'not_tested',
                    notes TEXT NOT NULL DEFAULT '',
                    evidence TEXT NOT NULL DEFAULT '',
                    tested_at TEXT,
                    UNIQUE(engagement_id, control_id)
                );

                CREATE INDEX IF NOT EXISTS manual_tests_engagement_idx ON manual_tests(engagement_id, category, control_id);

                CREATE TABLE IF NOT EXISTS tool_evidence_links (
                    id TEXT PRIMARY KEY,
                    engagement_id TEXT NOT NULL,
                    control_id TEXT NOT NULL,
                    tool_identity TEXT NOT NULL CHECK(tool_identity = 'nmap-xml'),
                    report_sha256 TEXT NOT NULL,
                    host_count INTEGER NOT NULL CHECK(host_count BETWEEN 0 AND 500),
                    up_host_count INTEGER NOT NULL CHECK(up_host_count BETWEEN 0 AND 500),
                    open_port_count INTEGER NOT NULL CHECK(open_port_count BETWEEN 0 AND 5000),
                    open_tcp_count INTEGER NOT NULL CHECK(open_tcp_count BETWEEN 0 AND 5000),
                    open_udp_count INTEGER NOT NULL CHECK(open_udp_count BETWEEN 0 AND 5000),
                    well_known_count INTEGER NOT NULL CHECK(well_known_count BETWEEN 0 AND 5000),
                    registered_count INTEGER NOT NULL CHECK(registered_count BETWEEN 0 AND 5000),
                    dynamic_count INTEGER NOT NULL CHECK(dynamic_count BETWEEN 0 AND 5000),
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(engagement_id, control_id) REFERENCES manual_tests(engagement_id, control_id) ON DELETE CASCADE,
                    UNIQUE(engagement_id, control_id, tool_identity, report_sha256)
                );
                CREATE INDEX IF NOT EXISTS tool_evidence_engagement_idx ON tool_evidence_links(engagement_id, created_at DESC);

                CREATE TABLE IF NOT EXISTS trivy_tool_evidence_links (
                    id TEXT PRIMARY KEY,
                    engagement_id TEXT NOT NULL,
                    control_id TEXT NOT NULL,
                    tool_identity TEXT NOT NULL CHECK(tool_identity = 'trivy-native-json'),
                    report_sha256 TEXT NOT NULL,
                    result_count INTEGER NOT NULL CHECK(result_count BETWEEN 0 AND 500),
                    class_counts_json TEXT NOT NULL,
                    vuln_counts_json TEXT NOT NULL,
                    finding_counts_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(engagement_id, control_id) REFERENCES manual_tests(engagement_id, control_id) ON DELETE CASCADE,
                    UNIQUE(engagement_id, control_id, report_sha256)
                );

                CREATE TABLE IF NOT EXISTS gitleaks_tool_evidence_links (
                    id TEXT PRIMARY KEY,
                    engagement_id TEXT NOT NULL,
                    control_id TEXT NOT NULL,
                    tool_identity TEXT NOT NULL CHECK(tool_identity = 'gitleaks-native-json'),
                    report_sha256 TEXT NOT NULL,
                    total_findings INTEGER NOT NULL CHECK(total_findings BETWEEN 0 AND 500),
                    rules_triggered INTEGER NOT NULL CHECK(rules_triggered BETWEEN 0 AND 500),
                    files_affected INTEGER NOT NULL CHECK(files_affected BETWEEN 0 AND 500),
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(engagement_id, control_id) REFERENCES manual_tests(engagement_id, control_id) ON DELETE CASCADE,
                    UNIQUE(engagement_id, control_id, report_sha256)
                );
                CREATE INDEX IF NOT EXISTS trivy_tool_evidence_engagement_idx ON trivy_tool_evidence_links(engagement_id, created_at DESC);

                CREATE TABLE IF NOT EXISTS nuclei_tool_evidence_links (
                    id TEXT PRIMARY KEY,
                    engagement_id TEXT NOT NULL,
                    control_id TEXT NOT NULL,
                    tool_identity TEXT NOT NULL CHECK(tool_identity = 'nuclei-jsonl'),
                    report_sha256 TEXT NOT NULL,
                    record_count INTEGER NOT NULL CHECK(record_count BETWEEN 0 AND 500),
                    unique_template_count INTEGER NOT NULL CHECK(unique_template_count BETWEEN 0 AND 500),
                    severity_counts_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(engagement_id, control_id) REFERENCES manual_tests(engagement_id, control_id) ON DELETE CASCADE,
                    UNIQUE(engagement_id, control_id, report_sha256)
                );
                CREATE INDEX IF NOT EXISTS nuclei_tool_evidence_engagement_idx ON nuclei_tool_evidence_links(engagement_id, created_at DESC);

                CREATE TABLE IF NOT EXISTS burp_sitemap_tool_evidence_links (
                    id TEXT PRIMARY KEY,
                    engagement_id TEXT NOT NULL,
                    control_id TEXT NOT NULL,
                    tool_identity TEXT NOT NULL CHECK(tool_identity = 'burp-sitemap-xml'),
                    report_sha256 TEXT NOT NULL CHECK(length(report_sha256) = 64),
                    item_count INTEGER NOT NULL CHECK(item_count BETWEEN 0 AND 500),
                    status_counts_json TEXT NOT NULL,
                    mimetype_counts_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(engagement_id, control_id) REFERENCES manual_tests(engagement_id, control_id) ON DELETE CASCADE,
                    UNIQUE(engagement_id, control_id, report_sha256)
                );
                CREATE INDEX IF NOT EXISTS burp_sitemap_evidence_engagement_idx ON burp_sitemap_tool_evidence_links(engagement_id, created_at DESC);

                CREATE TABLE IF NOT EXISTS testssl_tool_evidence_links (
                    id TEXT PRIMARY KEY,
                    engagement_id TEXT NOT NULL,
                    control_id TEXT NOT NULL,
                    tool_identity TEXT NOT NULL CHECK(tool_identity = 'testssl-flat-json'),
                    report_sha256 TEXT NOT NULL CHECK(length(report_sha256) = 64),
                    record_count INTEGER NOT NULL CHECK(record_count BETWEEN 0 AND 500),
                    severity_counts_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(engagement_id, control_id) REFERENCES manual_tests(engagement_id, control_id) ON DELETE CASCADE,
                    UNIQUE(engagement_id, control_id, report_sha256)
                );
                CREATE INDEX IF NOT EXISTS testssl_tool_evidence_engagement_idx ON testssl_tool_evidence_links(engagement_id, created_at DESC);

                CREATE TABLE IF NOT EXISTS zap_tool_evidence_links (
                    id TEXT PRIMARY KEY,
                    engagement_id TEXT NOT NULL,
                    control_id TEXT NOT NULL,
                    tool_identity TEXT NOT NULL CHECK(tool_identity = 'zap-traditional-json'),
                    report_sha256 TEXT NOT NULL CHECK(length(report_sha256) = 64),
                    site_count INTEGER NOT NULL CHECK(site_count BETWEEN 0 AND 20),
                    alert_type_count INTEGER NOT NULL CHECK(alert_type_count BETWEEN 0 AND 500),
                    instance_count INTEGER NOT NULL CHECK(instance_count BETWEEN 0 AND 5000),
                    risk_counts_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(engagement_id, control_id) REFERENCES manual_tests(engagement_id, control_id) ON DELETE CASCADE,
                    UNIQUE(engagement_id, control_id, report_sha256)
                );
                CREATE INDEX IF NOT EXISTS zap_tool_evidence_engagement_idx ON zap_tool_evidence_links(engagement_id, created_at DESC);

                CREATE TABLE IF NOT EXISTS semgrep_tool_evidence_links (
                    id TEXT PRIMARY KEY,
                    engagement_id TEXT NOT NULL,
                    control_id TEXT NOT NULL,
                    tool_identity TEXT NOT NULL CHECK(tool_identity = 'semgrep-local'),
                    report_sha256 TEXT NOT NULL CHECK(length(report_sha256) = 64),
                    profile TEXT NOT NULL CHECK(profile = 'local-trusted-rules-v1'),
                    result_count INTEGER NOT NULL CHECK(result_count BETWEEN 0 AND 500),
                    severity_counts_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(engagement_id, control_id) REFERENCES manual_tests(engagement_id, control_id) ON DELETE CASCADE,
                    UNIQUE(engagement_id, control_id, report_sha256)
                );
                CREATE INDEX IF NOT EXISTS semgrep_evidence_engagement_idx ON semgrep_tool_evidence_links(engagement_id, created_at DESC);

                CREATE TABLE IF NOT EXISTS manual_findings (
                    id TEXT PRIMARY KEY,
                    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    affected_asset TEXT NOT NULL,
                    description TEXT NOT NULL,
                    impact TEXT NOT NULL,
                    evidence TEXT NOT NULL,
                    reproduction TEXT NOT NULL,
                    recommendation TEXT NOT NULL,
                    owasp_category TEXT NOT NULL DEFAULT '',
                    cwe_id TEXT NOT NULL DEFAULT '',
                    cvss_vector TEXT NOT NULL DEFAULT '',
                    cvss_score REAL,
                    remediation_owner TEXT NOT NULL DEFAULT '',
                    due_date TEXT NOT NULL DEFAULT '',
                    resolution_notes TEXT NOT NULL DEFAULT '',
                    resolved_at TEXT,
                    last_retested_at TEXT,
                    status TEXT NOT NULL DEFAULT 'open',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS manual_findings_engagement_idx ON manual_findings(engagement_id, severity, created_at DESC);

                CREATE TABLE IF NOT EXISTS manual_finding_status_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    finding_id TEXT NOT NULL REFERENCES manual_findings(id) ON DELETE CASCADE,
                    occurred_at TEXT NOT NULL,
                    from_status TEXT NOT NULL,
                    to_status TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS manual_finding_status_history_finding_idx ON manual_finding_status_history(finding_id);

                CREATE TABLE IF NOT EXISTS lab_runs (
                    id TEXT PRIMARY KEY,
                    engagement_id TEXT REFERENCES engagements(id) ON DELETE SET NULL,
                    scenario_type TEXT NOT NULL,
                    name TEXT NOT NULL,
                    environment TEXT NOT NULL,
                    authorization_ref TEXT NOT NULL,
                    assumptions_json TEXT NOT NULL,
                    results_json TEXT NOT NULL,
                    evidence_summary TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'planned',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS lab_runs_created_idx ON lab_runs(created_at DESC);
                CREATE INDEX IF NOT EXISTS lab_runs_engagement_idx ON lab_runs(engagement_id, created_at DESC);

                CREATE TABLE IF NOT EXISTS project_audits (
                    id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    project_path TEXT NOT NULL,
                    project_name TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    grade TEXT NOT NULL,
                    file_count INTEGER NOT NULL,
                    bytes_scanned INTEGER NOT NULL,
                    summary_json TEXT NOT NULL,
                    findings_json TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS project_audits_created_idx ON project_audits(created_at DESC);

                CREATE TABLE IF NOT EXISTS project_audit_finding_triage (
                    audit_id TEXT NOT NULL,
                    finding_index INTEGER NOT NULL,
                    disposition TEXT NOT NULL CHECK (disposition IN ('needs_review', 'false_positive', 'confirmed', 'accepted_risk')),
                    note TEXT NOT NULL,
                    reviewed_at TEXT,
                    PRIMARY KEY (audit_id, finding_index),
                    FOREIGN KEY (audit_id) REFERENCES project_audits(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS project_runtime_proofs (
                    id TEXT PRIMARY KEY,
                    audit_id TEXT NOT NULL REFERENCES project_audits(id) ON DELETE CASCADE,
                    finding_index INTEGER NOT NULL CHECK(finding_index >= 0),
                    proof_type TEXT NOT NULL CHECK(proof_type = 'open_redirect_loopback'),
                    verdict TEXT NOT NULL CHECK(verdict IN ('confirmed', 'not_reproduced')),
                    http_status INTEGER NOT NULL CHECK(http_status BETWEEN 100 AND 599),
                    evidence_sha256 TEXT NOT NULL CHECK(length(evidence_sha256) = 64),
                    created_at TEXT NOT NULL,
                    UNIQUE(audit_id, finding_index, evidence_sha256)
                );

                CREATE INDEX IF NOT EXISTS project_runtime_proofs_audit_idx
                    ON project_runtime_proofs(audit_id, finding_index, created_at DESC);

                CREATE TABLE IF NOT EXISTS project_reflection_runtime_proofs (
                    id TEXT PRIMARY KEY,
                    audit_id TEXT NOT NULL REFERENCES project_audits(id) ON DELETE CASCADE,
                    finding_index INTEGER NOT NULL CHECK(finding_index >= 0),
                    verdict TEXT NOT NULL CHECK(verdict IN ('confirmed', 'not_reproduced')),
                    http_status INTEGER NOT NULL CHECK(http_status BETWEEN 100 AND 599),
                    marker_reflected INTEGER NOT NULL CHECK(marker_reflected IN (0, 1)),
                    content_type_html INTEGER NOT NULL CHECK(content_type_html IN (0, 1)),
                    evidence_sha256 TEXT NOT NULL CHECK(length(evidence_sha256) = 64),
                    created_at TEXT NOT NULL,
                    UNIQUE(audit_id, finding_index, evidence_sha256)
                );

                CREATE INDEX IF NOT EXISTS project_reflection_runtime_proofs_audit_idx
                    ON project_reflection_runtime_proofs(audit_id, finding_index, created_at DESC);

                CREATE TABLE IF NOT EXISTS project_cors_runtime_proofs (
                    id TEXT PRIMARY KEY,
                    audit_id TEXT NOT NULL REFERENCES project_audits(id) ON DELETE CASCADE,
                    finding_index INTEGER NOT NULL CHECK(finding_index >= 0),
                    verdict TEXT NOT NULL CHECK(verdict IN ('confirmed', 'not_reproduced')),
                    http_status INTEGER NOT NULL CHECK(http_status BETWEEN 100 AND 599),
                    origin_reflected INTEGER NOT NULL CHECK(origin_reflected IN (0, 1)),
                    credentials_allowed INTEGER NOT NULL CHECK(credentials_allowed IN (0, 1)),
                    evidence_sha256 TEXT NOT NULL CHECK(length(evidence_sha256) = 64),
                    created_at TEXT NOT NULL,
                    UNIQUE(audit_id, finding_index, evidence_sha256)
                );

                CREATE INDEX IF NOT EXISTS project_cors_runtime_proofs_audit_idx
                    ON project_cors_runtime_proofs(audit_id, finding_index, created_at DESC);

                CREATE TABLE IF NOT EXISTS project_clickjacking_runtime_proofs (
                    id TEXT PRIMARY KEY,
                    audit_id TEXT NOT NULL REFERENCES project_audits(id) ON DELETE CASCADE,
                    finding_index INTEGER NOT NULL CHECK(finding_index >= 0),
                    verdict TEXT NOT NULL CHECK(verdict IN ('confirmed', 'not_reproduced')),
                    http_status INTEGER NOT NULL CHECK(http_status BETWEEN 100 AND 599),
                    x_frame_options_effective INTEGER NOT NULL CHECK(x_frame_options_effective IN (0, 1)),
                    frame_ancestors_present INTEGER NOT NULL CHECK(frame_ancestors_present IN (0, 1)),
                    effective_protection INTEGER NOT NULL CHECK(effective_protection IN (0, 1)),
                    content_type_html INTEGER NOT NULL CHECK(content_type_html IN (0, 1)),
                    body_capable INTEGER NOT NULL CHECK(body_capable IN (0, 1)),
                    evidence_sha256 TEXT NOT NULL CHECK(length(evidence_sha256) = 64),
                    created_at TEXT NOT NULL,
                    UNIQUE(audit_id, finding_index, evidence_sha256)
                );

                CREATE INDEX IF NOT EXISTS project_clickjacking_runtime_proofs_audit_idx
                    ON project_clickjacking_runtime_proofs(audit_id, finding_index, created_at DESC);

                CREATE TABLE IF NOT EXISTS project_asan_runtime_proofs (
                    id TEXT PRIMARY KEY,
                    audit_id TEXT NOT NULL REFERENCES project_audits(id) ON DELETE CASCADE,
                    finding_index INTEGER NOT NULL CHECK(finding_index >= 0),
                    verdict TEXT NOT NULL CHECK(verdict IN ('confirmed', 'not_reproduced')),
                    expected_error_class TEXT NOT NULL,
                    observed_error_class TEXT NOT NULL,
                    asan_error INTEGER NOT NULL CHECK(asan_error IN (0, 1)),
                    exit_code INTEGER NOT NULL,
                    binary_sha256 TEXT NOT NULL CHECK(length(binary_sha256) = 64),
                    evidence_sha256 TEXT NOT NULL CHECK(length(evidence_sha256) = 64),
                    created_at TEXT NOT NULL,
                    UNIQUE(audit_id, finding_index, evidence_sha256)
                );

                CREATE INDEX IF NOT EXISTS project_asan_runtime_proofs_audit_idx
                    ON project_asan_runtime_proofs(audit_id, finding_index, created_at DESC);

                CREATE TABLE IF NOT EXISTS network_scan_findings (
                    id TEXT PRIMARY KEY,
                    request_id TEXT NOT NULL,
                    scanner_job_id TEXT NOT NULL,
                    target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
                    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
                    template_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL CHECK(severity IN ('info', 'low', 'medium', 'high', 'critical', 'unknown')),
                    fingerprint_sha256 TEXT NOT NULL CHECK(length(fingerprint_sha256) = 64),
                    evidence_sha256 TEXT NOT NULL CHECK(length(evidence_sha256) = 64),
                    created_at TEXT NOT NULL,
                    UNIQUE(request_id, fingerprint_sha256)
                );

                CREATE INDEX IF NOT EXISTS network_scan_findings_request_idx
                    ON network_scan_findings(request_id, severity, id);

                CREATE TABLE IF NOT EXISTS network_scan_triage_suggestions (
                    id TEXT PRIMARY KEY,
                    finding_id TEXT NOT NULL REFERENCES network_scan_findings(id) ON DELETE CASCADE,
                    verdict TEXT NOT NULL CHECK(verdict IN ('likely_true', 'likely_false', 'uncertain')),
                    confidence REAL NOT NULL CHECK(confidence >= 0 AND confidence <= 1),
                    rationale TEXT NOT NULL,
                    agent TEXT NOT NULL,
                    model TEXT NOT NULL,
                    submitted_by TEXT NOT NULL,
                    decision TEXT NOT NULL CHECK(decision = 'pending'),
                    created_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS network_scan_triage_finding_idx
                    ON network_scan_triage_suggestions(finding_id, created_at DESC, id DESC);

                CREATE TABLE IF NOT EXISTS network_direct_scan_findings (
                    id TEXT PRIMARY KEY,
                    request_id TEXT NOT NULL,
                    scanner_job_id TEXT NOT NULL,
                    target_sha256 TEXT NOT NULL CHECK(length(target_sha256) = 64),
                    template_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL CHECK(severity IN ('info', 'low', 'medium', 'high', 'critical', 'unknown')),
                    fingerprint_sha256 TEXT NOT NULL CHECK(length(fingerprint_sha256) = 64),
                    evidence_sha256 TEXT NOT NULL CHECK(length(evidence_sha256) = 64),
                    created_at TEXT NOT NULL,
                    UNIQUE(request_id, fingerprint_sha256)
                );

                CREATE INDEX IF NOT EXISTS network_direct_scan_findings_request_idx
                    ON network_direct_scan_findings(request_id, severity, id);

                CREATE TABLE IF NOT EXISTS network_direct_scan_triage_suggestions (
                    id TEXT PRIMARY KEY,
                    finding_id TEXT NOT NULL REFERENCES network_direct_scan_findings(id) ON DELETE CASCADE,
                    verdict TEXT NOT NULL CHECK(verdict IN ('likely_true', 'likely_false', 'uncertain')),
                    confidence REAL NOT NULL CHECK(confidence >= 0 AND confidence <= 1),
                    rationale TEXT NOT NULL,
                    agent TEXT NOT NULL,
                    model TEXT NOT NULL,
                    submitted_by TEXT NOT NULL,
                    decision TEXT NOT NULL CHECK(decision = 'pending'),
                    created_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS network_direct_scan_triage_finding_idx
                    ON network_direct_scan_triage_suggestions(finding_id, created_at DESC, id DESC);

                CREATE TABLE IF NOT EXISTS dependency_sboms (
                    id TEXT PRIMARY KEY,
                    project_path TEXT NOT NULL,
                    project_name TEXT NOT NULL,
                    format TEXT NOT NULL,
                    component_count INTEGER NOT NULL,
                    document_hash TEXT NOT NULL,
                    document_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(project_path, document_hash)
                );

                CREATE INDEX IF NOT EXISTS dependency_sboms_created_idx ON dependency_sboms(created_at DESC);

                CREATE TABLE IF NOT EXISTS dependency_imports (
                    id TEXT PRIMARY KEY,
                    project_path TEXT NOT NULL,
                    source TEXT NOT NULL,
                    source_path TEXT NOT NULL,
                    source_timestamp TEXT NOT NULL,
                    document_hash TEXT NOT NULL,
                    finding_count INTEGER NOT NULL,
                    imported_at TEXT NOT NULL,
                    UNIQUE(project_path, source, document_hash)
                );

                CREATE INDEX IF NOT EXISTS dependency_imports_created_idx ON dependency_imports(imported_at DESC);

                CREATE TABLE IF NOT EXISTS dependency_findings (
                    id TEXT PRIMARY KEY,
                    fingerprint TEXT NOT NULL UNIQUE,
                    project_path TEXT NOT NULL,
                    package_name TEXT NOT NULL,
                    installed_version TEXT NOT NULL,
                    vulnerability_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    fixed_version TEXT NOT NULL,
                    source TEXT NOT NULL,
                    title TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    target TEXT NOT NULL,
                    references_json TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open',
                    resolution_notes TEXT NOT NULL DEFAULT '',
                    first_seen_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    source_timestamp TEXT NOT NULL,
                    latest_import_id TEXT REFERENCES dependency_imports(id) ON DELETE SET NULL
                );

                CREATE INDEX IF NOT EXISTS dependency_findings_project_idx
                    ON dependency_findings(project_path, status, severity, last_seen_at DESC);

                -- 17. tur: VEX kararları (analist ya da içe aktarılan tedarikçi VEX'i). Bulgu silinirse karar da gider.
                CREATE TABLE IF NOT EXISTS dependency_vex_decisions (
                    finding_id TEXT PRIMARY KEY REFERENCES dependency_findings(id) ON DELETE CASCADE,
                    status TEXT NOT NULL CHECK (status IN ('not_affected', 'affected', 'fixed', 'under_investigation')),
                    justification TEXT NOT NULL DEFAULT '',
                    impact_statement TEXT NOT NULL DEFAULT '',
                    action_statement TEXT NOT NULL DEFAULT '',
                    status_notes TEXT NOT NULL DEFAULT '',
                    basis TEXT NOT NULL CHECK (basis IN ('analyst', 'imported')),
                    source_name TEXT NOT NULL DEFAULT '',
                    source_hash TEXT NOT NULL DEFAULT '',
                    author TEXT NOT NULL DEFAULT '',
                    decided_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS zap_scan_authorizations (
                    id TEXT PRIMARY KEY,
                    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
                    target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
                    requester_principal_id TEXT NOT NULL,
                    approved_by TEXT NOT NULL,
                    authorization_ref TEXT NOT NULL,
                    root_url TEXT NOT NULL,
                    approved_ips_json TEXT NOT NULL,
                    allowed_paths_json TEXT NOT NULL,
                    excluded_paths_json TEXT NOT NULL,
                    allow_query INTEGER NOT NULL CHECK(allow_query IN (0, 1)),
                    not_before TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    lease_generation INTEGER NOT NULL CHECK(lease_generation >= 1),
                    active INTEGER NOT NULL CHECK(active IN (0, 1)),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS zap_scan_authorizations_engagement_idx
                    ON zap_scan_authorizations(engagement_id, active, lease_generation DESC);
                """
            )
            finding_columns = {row["name"] for row in db.execute("PRAGMA table_info(manual_findings)")}
            migrations = (
                ("owasp_category", "ALTER TABLE manual_findings ADD COLUMN owasp_category TEXT NOT NULL DEFAULT ''"),
                ("cwe_id", "ALTER TABLE manual_findings ADD COLUMN cwe_id TEXT NOT NULL DEFAULT ''"),
                ("cvss_vector", "ALTER TABLE manual_findings ADD COLUMN cvss_vector TEXT NOT NULL DEFAULT ''"),
                ("cvss_score", "ALTER TABLE manual_findings ADD COLUMN cvss_score REAL"),
                ("remediation_owner", "ALTER TABLE manual_findings ADD COLUMN remediation_owner TEXT NOT NULL DEFAULT ''"),
                ("due_date", "ALTER TABLE manual_findings ADD COLUMN due_date TEXT NOT NULL DEFAULT ''"),
                ("resolution_notes", "ALTER TABLE manual_findings ADD COLUMN resolution_notes TEXT NOT NULL DEFAULT ''"),
                ("resolved_at", "ALTER TABLE manual_findings ADD COLUMN resolved_at TEXT"),
                ("last_retested_at", "ALTER TABLE manual_findings ADD COLUMN last_retested_at TEXT"),
            )
            for column, statement in migrations:
                if column not in finding_columns:
                    db.execute(statement)
            # Denetim günlüğü hash zinciri: mevcut kayıtlara dokunmadan (NULL kalırlar = legacy)
            # yalnız sütun ekle. Zincir ilk hash'li kayıttan başlar.
            audit_columns = {row["name"] for row in db.execute("PRAGMA table_info(audit_log)")}
            audit_migrations = (
                ("prev_hash", "ALTER TABLE audit_log ADD COLUMN prev_hash TEXT"),
                ("entry_hash", "ALTER TABLE audit_log ADD COLUMN entry_hash TEXT"),
            )
            for column, statement in audit_migrations:
                if column not in audit_columns:
                    db.execute(statement)
            # 20. tur: bağımlılık bulgusu önceliklendirmesi (erişilebilirlik + kullanım); yalnız eksik sütun eklenir.
            dep_columns = {row["name"] for row in db.execute("PRAGMA table_info(dependency_findings)")}
            dep_migrations = (
                ("priority_score", "ALTER TABLE dependency_findings ADD COLUMN priority_score INTEGER"),
                ("priority_tier", "ALTER TABLE dependency_findings ADD COLUMN priority_tier TEXT NOT NULL DEFAULT ''"),
                ("usage_state", "ALTER TABLE dependency_findings ADD COLUMN usage_state TEXT NOT NULL DEFAULT ''"),
                ("reach_verdict", "ALTER TABLE dependency_findings ADD COLUMN reach_verdict TEXT NOT NULL DEFAULT ''"),
                ("reach_evidence_json", "ALTER TABLE dependency_findings ADD COLUMN reach_evidence_json TEXT NOT NULL DEFAULT '[]'"),
                ("priority_updated_at", "ALTER TABLE dependency_findings ADD COLUMN priority_updated_at TEXT"),
            )
            for column, statement in dep_migrations:
                if column not in dep_columns:
                    db.execute(statement)
            clickjacking_columns = {
                row["name"] for row in db.execute("PRAGMA table_info(project_clickjacking_runtime_proofs)")
            }
            if "body_capable" not in clickjacking_columns:
                db.execute(
                    "ALTER TABLE project_clickjacking_runtime_proofs "
                    "ADD COLUMN body_capable INTEGER NOT NULL DEFAULT 1 CHECK(body_capable IN (0, 1))"
                )
            # Legacy releases used pending/verified states for ownership-file checks.
            # The local-only workflow now treats every saved public target as ready.
            db.execute(
                """
                UPDATE targets
                SET status = 'ready', verification_token = '', verified_at = NULL, verification_proof = NULL
                WHERE status IN ('pending', 'verified', 'authorized')
                """
            )
            self._sync_test_catalog(db)
            # Bulgu takibi tabloları (geriye uyumlu: yalnız eksikse oluşturulur, mevcut veriye dokunmaz).
            finding_tracking.ensure_schema(db)
            # 25. tur: AI/ajan triyaj önerileri (yalnız eksikse oluşturulur).
            ai_triage.ensure_schema(db)

    def _sync_test_catalog(self, db: sqlite3.Connection) -> None:
        """Backfill new methodology controls without changing recorded test results."""
        engagements = db.execute(
            "SELECT id, special_approvals_json FROM engagements"
        ).fetchall()
        for engagement in engagements:
            approvals = json.loads(engagement["special_approvals_json"] or "{}")
            for control in TEST_CATALOG:
                required = control.get("requires_approval")
                if required and not approvals.get(required):
                    continue
                db.execute(
                    """
                    INSERT OR IGNORE INTO manual_tests(
                        id, engagement_id, control_id, category, category_title, title, objective, reference
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        self._id("tst"), engagement["id"], control["control_id"], control["category"],
                        control["category_title"], control["title"], control["objective"], control["reference"],
                    ),
                )
                db.execute(
                    """
                    UPDATE manual_tests
                    SET category = ?, category_title = ?, title = ?, objective = ?, reference = ?
                    WHERE engagement_id = ? AND control_id = ?
                    """,
                    (
                        control["category"], control["category_title"], control["title"],
                        control["objective"], control["reference"], engagement["id"], control["control_id"],
                    ),
                )

    @staticmethod
    def _id(prefix: str) -> str:
        return f"{prefix}_{secrets.token_hex(6)}"

    @staticmethod
    def _append_audit_log(
        db: sqlite3.Connection,
        action: str,
        entity_id: str,
        details_json: str,
        occurred_at: str | None = None,
    ) -> None:
        """Hash zincirli denetim kaydı ekle.

        Çağıran, `db` üzerinde yazma kilidini tutan bir işlem (BEGIN IMMEDIATE) içinde olmalıdır;
        aksi hâlde iki eşzamanlı ekleme aynı prev_hash'e bağlanabilir.
        """
        if not db.in_transaction:
            raise sqlite3.ProgrammingError("_append_audit_log BEGIN IMMEDIATE işlemi içinde çağrılmalı.")
        details_json = with_actor(details_json)  # giriş etkinse işlemi yapan kullanıcı (yoksa değişmez)
        last = db.execute(
            "SELECT entry_hash FROM audit_log WHERE entry_hash IS NOT NULL ORDER BY id DESC LIMIT 1"
        ).fetchone()
        prev_hash = last["entry_hash"] if last else AUDIT_GENESIS_HASH
        db_path = getattr(db, "sniper_db_path", None)
        key_state = load_audit_key(create=False, db_path=db_path)
        if key_state.status == "missing" and not Store._chain_has_hmac(db, prev_hash):
            # Anahtar yalnız zincir henüz anahtarlı değilken üretilir; HMAC'li kayıtlar varken kaybolan
            # anahtar sessizce yenilenmez (aksi hâlde eski kayıtlar "kurcalanmış" görünürdü).
            key_state = load_audit_key(create=True, db_path=db_path)
        when = occurred_at or utc_now()
        if key_state.usable and key_state.key:
            entry_hash = compute_hmac_entry_hash(key_state.key, prev_hash, when, action, entity_id, details_json)
        else:
            entry_hash = compute_audit_entry_hash(prev_hash, when, action, entity_id, details_json)
        cursor = db.execute(
            """INSERT INTO audit_log(occurred_at, action, entity_id, details_json, prev_hash, entry_hash)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (when, action, entity_id, details_json, prev_hash, entry_hash),
        )
        if isinstance(db, _AuditConnection):
            chained = db.execute("SELECT COUNT(*) FROM audit_log WHERE entry_hash IS NOT NULL").fetchone()[0]
            db.audit_anchor_pending = {
                "last_id": int(cursor.lastrowid),
                "head_hash": entry_hash,
                "chained_count": int(chained),
                "updated_at": when,
                "key_state": key_state,
            }

    @staticmethod
    def _chain_has_hmac(db: sqlite3.Connection, last_hash: str) -> bool:
        if is_hmac_hash(last_hash):
            return True
        row = db.execute(
            "SELECT 1 FROM audit_log WHERE substr(entry_hash, 1, 6) = 'hmac1:' LIMIT 1"
        ).fetchone()
        if row is not None:
            return True
        db_path = getattr(db, "sniper_db_path", None)
        if db_path is not None:
            # Daha önce anahtarla imzalanmış bir çapa varsa da anahtar kaybolmuş demektir.
            anchor = read_audit_anchor(db_path, load_audit_key(create=False, db_path=db_path))
            if anchor.get("status") not in {"missing", "unauthenticated"}:
                return True
        return False

    def log(self, action: str, entity_id: str, details: dict[str, Any] | None = None) -> None:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._append_audit_log(db, action, entity_id, json.dumps(details or {}, ensure_ascii=False))

    def verify_audit_chain(self, page_size: int = 500) -> dict[str, Any]:
        """Tüm audit_log tablosunu id ASC, sayfalı (keyset) tarayıp kalıcı hash zincirini doğrula."""
        page_size = max(1, min(int(page_size), 5000))
        key_state = load_audit_key(create=False, db_path=self.path)
        anchor = read_audit_anchor(self.path, key_state)
        watch_id = anchor.get("last_id") if isinstance(anchor.get("last_id"), int) else None
        verifier = StoredAuditChainVerifier(key=key_state.key if key_state.usable else None, watch_id=watch_id)
        with self._connect() as db:
            # Tek okuma işlemi: WAL anlık görüntüsü tarama boyunca tutarlı kalır.
            db.execute("BEGIN")
            last_id = -1
            while True:
                rows = db.execute(
                    """SELECT id, occurred_at, action, entity_id, details_json, prev_hash, entry_hash
                       FROM audit_log WHERE id > ? ORDER BY id ASC LIMIT ?""",
                    (last_id, page_size),
                ).fetchall()
                if not rows:
                    break
                for row in rows:
                    verifier.feed(row)
                last_id = rows[-1]["id"]
                if len(rows) < page_size:
                    break
        return verifier.apply_anchor(verifier.result(), anchor, key_state)

    def create_project_audit(self, result: dict[str, Any]) -> dict:
        audit_id = self._id("prj")
        summary = {
            key: value for key, value in result.items()
            if key not in {"findings", "project_path", "project_name", "created_at", "score", "grade", "file_count", "bytes_scanned"}
        }
        with self._connect() as db:
            db.execute(
                """
                INSERT INTO project_audits(
                    id, created_at, project_path, project_name, score, grade,
                    file_count, bytes_scanned, summary_json, findings_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    audit_id, result["created_at"], result["project_path"], result["project_name"],
                    int(result["score"]), result["grade"], int(result["file_count"]),
                    int(result["bytes_scanned"]), json.dumps(summary, ensure_ascii=False),
                    json.dumps(result.get("findings", []), ensure_ascii=False),
                ),
            )
            # Bulgu takibi aynı işlemde; takip hatası analizin kaydını engellemez (kayıt noktasına geri alınır).
            db.execute("SAVEPOINT finding_tracking")
            try:
                finding_tracking.record_audit(db, audit_id, result, when=result["created_at"],
                                              sla_days=portfolio.auto_due_days(portfolio.load_policy()[0]))
            except (sqlite3.Error, ValueError, TypeError, KeyError, OSError):
                db.execute("ROLLBACK TO SAVEPOINT finding_tracking")
            db.execute("RELEASE SAVEPOINT finding_tracking")
        self.log(
            "project_audit.completed", audit_id,
            {"project_name": result["project_name"], "score": result["score"], "finding_count": len(result.get("findings", []))},
        )
        return self.get_project_audit(audit_id)

    def list_project_audits(self, limit: int = 30) -> list[dict]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT * FROM project_audits ORDER BY rowid DESC LIMIT ?",
                (max(1, min(limit, 100)),),
            ).fetchall()
        audits = [self._project_audit_dict(row, include_findings=False) for row in rows]
        for audit in audits:  # liste görünümü: rota yetki envanterinin yalnız özeti (rotalar ayrıntı ucunda)
            inventory = audit.get("route_inventory")
            if isinstance(inventory, dict):
                audit["route_inventory"] = {"summary": inventory.get("summary", {})}
            for heavy in ("components", "language_packages"):  # konteyner taraması: bileşen listeleri ayrıntı ucunda
                audit.pop(heavy, None)
            sbom = audit.get("sbom")
            if isinstance(sbom, dict):  # 20. tur: SBOM taramasının bağımlılık bulguları (VEX girdisi) ayrıntı ucunda
                audit["sbom"] = {k: v for k, v in sbom.items() if k != "dependency_findings"}
            licenses = audit.get("licenses")
            if isinstance(licenses, dict):  # lisans raporunun yalnız özeti (bileşen listesi ayrıntı ucunda)
                audit["licenses"] = {key: licenses.get(key) for key in ("format", "component_count", "by_category", "project_license")}
        return audits
    def count_project_audits(self) -> int:
        with self._connect() as db:
            row = db.execute("SELECT COUNT(*) FROM project_audits").fetchone()
            return row[0]

    def _project_audit_detail_from_db(self, db: sqlite3.Connection, audit_id: str) -> dict | None:
        row = db.execute("SELECT * FROM project_audits WHERE id = ?", (audit_id,)).fetchone()
        if not row:
            return None
        audit = self._project_audit_dict(row, include_findings=False)
        findings = json.loads(row["findings_json"] or "[]")
        triage_rows = db.execute(
            "SELECT finding_index, disposition, note, reviewed_at FROM project_audit_finding_triage WHERE audit_id = ? ORDER BY finding_index",
            (audit_id,),
        ).fetchall()
        triage_map = {
            t["finding_index"]: {
                "disposition": t["disposition"],
                "note": t["note"],
                "reviewed_at": t["reviewed_at"],
            }
            for t in triage_rows
        }
        tracking = finding_tracking.tracking_for_audit(db, audit_id)
        proof_rows = db.execute(
            "SELECT * FROM project_runtime_proofs WHERE audit_id = ? ORDER BY created_at DESC, id DESC",
            (audit_id,),
        ).fetchall()
        proofs_by_finding: dict[int, list[dict]] = {}
        for proof in proof_rows:
            proofs_by_finding.setdefault(int(proof["finding_index"]), []).append(dict(proof))
        reflection_rows = db.execute(
            """SELECT id, audit_id, finding_index, 'reflected_html_loopback' AS proof_type, verdict,
                      http_status, marker_reflected, content_type_html, evidence_sha256, created_at
               FROM project_reflection_runtime_proofs WHERE audit_id = ?
               ORDER BY created_at DESC, id DESC""",
            (audit_id,),
        ).fetchall()
        for proof in reflection_rows:
            item = dict(proof)
            item["marker_reflected"] = bool(item["marker_reflected"])
            item["content_type_html"] = bool(item["content_type_html"])
            item["request_count"] = 1
            item["script_executed"] = False
            proofs_by_finding.setdefault(int(item["finding_index"]), []).append(item)
        cors_rows = db.execute(
            """SELECT id, audit_id, finding_index, 'cors_credentials_loopback' AS proof_type, verdict,
                      http_status, origin_reflected, credentials_allowed, evidence_sha256, created_at
               FROM project_cors_runtime_proofs WHERE audit_id = ?
               ORDER BY created_at DESC, id DESC""",
            (audit_id,),
        ).fetchall()
        for proof in cors_rows:
            item = dict(proof)
            item.update(origin_reflected=bool(item["origin_reflected"]),
                        credentials_allowed=bool(item["credentials_allowed"]), request_count=1, body_read=False)
            proofs_by_finding.setdefault(int(item["finding_index"]), []).append(item)
        clickjacking_rows = db.execute(
            """SELECT id, audit_id, finding_index, 'clickjacking_headers_loopback' AS proof_type, verdict,
                      http_status, x_frame_options_effective, frame_ancestors_present, effective_protection,
                      content_type_html, body_capable, evidence_sha256, created_at
               FROM project_clickjacking_runtime_proofs WHERE audit_id = ?
               ORDER BY created_at DESC, id DESC""",
            (audit_id,),
        ).fetchall()
        for proof in clickjacking_rows:
            item = dict(proof)
            item.update(x_frame_options_effective=bool(item["x_frame_options_effective"]),
                        frame_ancestors_present=bool(item["frame_ancestors_present"]),
                        effective_protection=bool(item["effective_protection"]),
                        content_type_html=bool(item["content_type_html"]),
                        body_capable=bool(item["body_capable"]), request_count=1, body_read=False)
            proofs_by_finding.setdefault(int(item["finding_index"]), []).append(item)
        asan_rows = db.execute(
            """SELECT id, audit_id, finding_index, 'asan_prebuilt_binary' AS proof_type, verdict,
                      expected_error_class, observed_error_class, asan_error, exit_code, binary_sha256,
                      evidence_sha256, created_at
               FROM project_asan_runtime_proofs WHERE audit_id = ?
               ORDER BY created_at DESC, id DESC""",
            (audit_id,),
        ).fetchall()
        for proof in asan_rows:
            item = dict(proof)
            item.update(asan_error=bool(item["asan_error"]), network_available=False, argument_count=0,
                        stdin_available=False, timed_out=False)
            proofs_by_finding.setdefault(int(item["finding_index"]), []).append(item)
        asan_source_table = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'project_asan_source_proofs'"
        ).fetchone()
        asan_source_rows = [] if not asan_source_table else db.execute(
            """SELECT id, audit_id, finding_index, 'asan_source_fixed_profile' AS proof_type, verdict,
                      expected_error_class, observed_error_class, asan_error, exit_code, binary_sha256,
                      source_sha256, compiler_sha256, source_language, build_profile, evidence_sha256, created_at
               FROM project_asan_source_proofs WHERE audit_id = ?
               ORDER BY created_at DESC, id DESC""",
            (audit_id,),
        ).fetchall()
        for proof in asan_source_rows:
            item = dict(proof)
            item.update(asan_error=bool(item["asan_error"]), network_available=False, argument_count=0,
                        stdin_available=False, timed_out=False, project_build_scripts_executed=False)
            proofs_by_finding.setdefault(int(item["finding_index"]), []).append(item)
        asan_compile_table = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'project_asan_compile_database_proofs'"
        ).fetchone()
        asan_compile_rows = [] if not asan_compile_table else db.execute(
            """SELECT id, audit_id, finding_index, 'asan_compile_database_single_tu' AS proof_type, verdict,
                      expected_error_class, observed_error_class, asan_error, exit_code, binary_sha256,
                      source_sha256, compiler_sha256, compile_database_sha256, compile_entry_sha256,
                      snapshot_sha256, snapshot_file_count, source_language, build_profile,
                      evidence_sha256, created_at
               FROM project_asan_compile_database_proofs WHERE audit_id = ?
               ORDER BY created_at DESC, id DESC""",
            (audit_id,),
        ).fetchall()
        for proof in asan_compile_rows:
            item = dict(proof)
            item.update(asan_error=bool(item["asan_error"]), network_available=False, argument_count=0,
                        stdin_available=False, timed_out=False, project_build_scripts_executed=False,
                        snapshot_scope="bounded_c_cpp_sources_headers_only")
            proofs_by_finding.setdefault(int(item["finding_index"]), []).append(item)
        enriched_findings = []
        for idx, finding in enumerate(findings):
            default_triage = {
                "disposition": "unreviewed",
                "note": "",
                "reviewed_at": None,
            }
            track = tracking.get(idx)
            if track and idx not in triage_map and track["status"] in finding_tracking.STATUS_TO_TRIAGE:
                # Önceki analizde verilen yanlış alarm / risk kabulü kararı parmak iziyle taşınır.
                default_triage = {
                    "disposition": finding_tracking.STATUS_TO_TRIAGE[track["status"]],
                    "note": track["status_note"],
                    "reviewed_at": None,
                    "inherited": True,
                }
            item = {**finding, "triage": triage_map.get(idx, default_triage)}
            item["runtime_proofs"] = proofs_by_finding.get(idx, [])
            if track:
                item["tracking"] = track
            enriched_findings.append(item)
        try:
            import eval_metrics

            eval_metrics.annotate_corroboration(enriched_findings)
            rule_stats = eval_metrics.triage_rule_stats(self.path)
            eval_metrics.annotate_rule_feedback(enriched_findings, rule_stats.get("rules") or [])
        except (OSError, sqlite3.Error, TypeError, ValueError):
            # Güven üst verisi denetim kaydının kendisini okunamaz hâle getirmemeli.
            pass
        audit["findings"] = enriched_findings
        counts = finding_tracking.audit_tracking_counts(db, audit_id)
        if counts:
            audit["tracking"] = counts
        return audit

    def get_project_audit(self, audit_id: str) -> dict | None:
        with self._connect() as db:
            return self._project_audit_detail_from_db(db, audit_id)

    def update_project_audit_finding_triage(
        self,
        audit_id: str,
        finding_index: int,
        *,
        disposition: str,
        note: str,
    ) -> dict:
        # Validate all inputs and perform atomic read/check/update/upsert in ONE transaction
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE;")
            # Fetch audit and its findings
            audit_row = db.execute(
                "SELECT id, findings_json FROM project_audits WHERE id = ?",
                (audit_id,)
            ).fetchone()
            if not audit_row:
                raise ValueError(f"'{audit_id}' kimlikli denetim bulunamadı")

            findings_json = audit_row[1]
            findings = json.loads(findings_json) if findings_json else []

            # Validate finding_index (non-boolean integer, non-negative, in-range)
            if not isinstance(finding_index, int) or isinstance(finding_index, bool):
                raise ValueError("finding_index mantıksal değer olmayan bir tamsayı olmalı")
            if finding_index < 0:
                raise ValueError("finding_index negatif olmamalı")
            if finding_index >= len(findings):
                raise ValueError(f"finding_index {len(findings)} değerinden küçük olmalı (verilen {finding_index})")

            # Validate disposition
            allowed_dispositions = {"needs_review", "false_positive", "confirmed", "accepted_risk"}
            if not isinstance(disposition, str) or disposition not in allowed_dispositions:
                raise ValueError(f"disposition şunlardan biri olmalı: {sorted(allowed_dispositions)}")

            # Validate note
            if not isinstance(note, str):
                raise TypeError("note bir metin olmalı")
            if len(note) > 2000:
                raise ValueError("note 2000 karakteri aşmamalı")

            # Perform atomic upsert of triage row
            now = utc_now()
            db.execute(
                """
                INSERT INTO project_audit_finding_triage (audit_id, finding_index, disposition, note, reviewed_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(audit_id, finding_index) DO UPDATE SET
                    disposition = excluded.disposition,
                    note = excluded.note,
                    reviewed_at = excluded.reviewed_at
                """,
                (audit_id, finding_index, disposition, note, now),
            )
            finding_tracking.sync_triage(db, audit_id, finding_index, disposition, note, when=now,
                                         default_risk_days=portfolio.load_policy()[0]["risk_acceptance_days"])
            self._append_audit_log(
                db,
                "project_audit.finding_triaged",
                audit_id,
                json.dumps({"finding_index": finding_index, "disposition": disposition}, ensure_ascii=False),
                occurred_at=now,
            )
            result = self._project_audit_detail_from_db(db, audit_id)
            if result is None:
                raise sqlite3.DatabaseError("Denetim kaydı ayıklama işlemi sırasında kayboldu")

        return result

    set_project_audit_finding_triage = update_project_audit_finding_triage

    def add_project_runtime_proof(self, audit_id: str, finding_index: int, proof: dict[str, Any]) -> dict:
        """Gövde/hedef/parametre saklamadan sabit şemalı loopback kanıtını bulguya bağla."""
        expected = {"format", "audit_id", "finding_index", "finding_reference", "finding_kind", "verdict",
                    "http_status", "external_location_reflected", "request_count", "redirect_followed",
                    "evidence_sha256"}
        if not isinstance(proof, dict) or set(proof) != expected or proof.get("format") != "sniper-open-redirect-runtime-proof/1" \
                or proof.get("audit_id") != audit_id or proof.get("finding_index") != finding_index \
                or proof.get("finding_kind") != "redirect" or proof.get("verdict") not in {"confirmed", "not_reproduced"} \
                or type(proof.get("http_status")) is not int or not 100 <= proof["http_status"] <= 599 \
                or type(proof.get("external_location_reflected")) is not bool \
                or proof.get("request_count") != 1 or proof.get("redirect_followed") is not False \
                or not isinstance(proof.get("evidence_sha256"), str) \
                or not re.fullmatch(r"[0-9a-f]{64}", proof["evidence_sha256"]):
            raise ValueError("Geçersiz çalışma zamanı kanıtı.")
        now = utc_now()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT findings_json FROM project_audits WHERE id = ?", (audit_id,)).fetchone()
            findings = json.loads(row["findings_json"] or "[]") if row else []
            if not row or type(finding_index) is not int or not 0 <= finding_index < len(findings):
                raise ValueError("Proje analizi veya bulgu bulunamadı.")
            db.execute(
                """INSERT OR IGNORE INTO project_runtime_proofs(
                       id, audit_id, finding_index, proof_type, verdict, http_status, evidence_sha256, created_at
                   ) VALUES (?, ?, ?, 'open_redirect_loopback', ?, ?, ?, ?)""",
                (self._id("rtp"), audit_id, finding_index, proof["verdict"], proof["http_status"],
                 proof["evidence_sha256"], now),
            )
            saved = db.execute(
                """SELECT * FROM project_runtime_proofs
                   WHERE audit_id = ? AND finding_index = ? AND evidence_sha256 = ?""",
                (audit_id, finding_index, proof["evidence_sha256"]),
            ).fetchone()
        self.log("project_audit.runtime_proof_added", audit_id,
                 {"finding_index": finding_index, "verdict": proof["verdict"],
                  "evidence_sha256": proof["evidence_sha256"]})
        return {**dict(saved), "format": proof["format"], "finding_reference": proof["finding_reference"],
                "finding_kind": "redirect", "external_location_reflected": proof["external_location_reflected"],
                "request_count": 1, "redirect_followed": False}

    def add_project_reflection_runtime_proof(
        self, audit_id: str, finding_index: int, proof: dict[str, Any],
    ) -> dict[str, Any]:
        """Yanıt gövdesi ve işaretleyiciyi saklamadan loopback HTML yansıma kanıtını bağla."""
        expected = {"format", "audit_id", "finding_index", "finding_reference", "finding_kind", "verdict",
                    "http_status", "marker_reflected", "content_type_html", "request_count", "script_executed",
                    "evidence_sha256"}
        if not isinstance(proof, dict) or set(proof) != expected \
                or proof.get("format") != "sniper-reflected-html-runtime-proof/1" \
                or proof.get("audit_id") != audit_id or proof.get("finding_index") != finding_index \
                or proof.get("finding_kind") != "html" or proof.get("verdict") not in {"confirmed", "not_reproduced"} \
                or type(proof.get("http_status")) is not int or not 100 <= proof["http_status"] <= 599 \
                or type(proof.get("marker_reflected")) is not bool \
                or type(proof.get("content_type_html")) is not bool \
                or proof.get("request_count") != 1 or proof.get("script_executed") is not False \
                or not re.fullmatch(r"[0-9a-f]{64}", str(proof.get("evidence_sha256"))):
            raise ValueError("Geçersiz HTML yansıma kanıtı.")
        now = utc_now()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT findings_json FROM project_audits WHERE id = ?", (audit_id,)).fetchone()
            findings = json.loads(row["findings_json"] or "[]") if row else []
            if not row or type(finding_index) is not int or not 0 <= finding_index < len(findings):
                raise ValueError("Proje analizi veya bulgu bulunamadı.")
            db.execute(
                """INSERT OR IGNORE INTO project_reflection_runtime_proofs(
                       id, audit_id, finding_index, verdict, http_status, marker_reflected,
                       content_type_html, evidence_sha256, created_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (self._id("rtp"), audit_id, finding_index, proof["verdict"], proof["http_status"],
                 int(proof["marker_reflected"]), int(proof["content_type_html"]), proof["evidence_sha256"], now),
            )
            saved = db.execute(
                """SELECT id, audit_id, finding_index, verdict, http_status, marker_reflected,
                          content_type_html, evidence_sha256, created_at
                   FROM project_reflection_runtime_proofs
                   WHERE audit_id = ? AND finding_index = ? AND evidence_sha256 = ?""",
                (audit_id, finding_index, proof["evidence_sha256"]),
            ).fetchone()
        self.log("project_audit.reflection_runtime_proof_added", audit_id,
                 {"finding_index": finding_index, "verdict": proof["verdict"],
                  "evidence_sha256": proof["evidence_sha256"]})
        return {**dict(saved), "proof_type": "reflected_html_loopback", "format": proof["format"],
                "finding_reference": proof["finding_reference"], "finding_kind": "html",
                "marker_reflected": bool(saved["marker_reflected"]),
                "content_type_html": bool(saved["content_type_html"]),
                "request_count": 1, "script_executed": False}

    def add_project_cors_runtime_proof(
        self, audit_id: str, finding_index: int, proof: dict[str, Any],
    ) -> dict[str, Any]:
        """Origin değerini veya başlıkları saklamadan loopback CORS kanıtını bulguya bağla."""
        expected = {"format", "audit_id", "finding_index", "finding_reference", "finding_kind", "verdict",
                    "http_status", "origin_reflected", "credentials_allowed", "request_count", "body_read",
                    "evidence_sha256"}
        if not isinstance(proof, dict) or set(proof) != expected \
                or proof.get("format") != "sniper-cors-runtime-proof/1" \
                or proof.get("audit_id") != audit_id or proof.get("finding_index") != finding_index \
                or proof.get("finding_kind") != "cors" or proof.get("verdict") not in {"confirmed", "not_reproduced"} \
                or type(proof.get("http_status")) is not int or not 100 <= proof["http_status"] <= 599 \
                or type(proof.get("origin_reflected")) is not bool \
                or type(proof.get("credentials_allowed")) is not bool \
                or proof.get("request_count") != 1 or proof.get("body_read") is not False \
                or not re.fullmatch(r"[0-9a-f]{64}", str(proof.get("evidence_sha256"))):
            raise ValueError("Geçersiz CORS çalışma zamanı kanıtı.")
        now = utc_now()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT findings_json FROM project_audits WHERE id = ?", (audit_id,)).fetchone()
            findings = json.loads(row["findings_json"] or "[]") if row else []
            if not row or type(finding_index) is not int or not 0 <= finding_index < len(findings):
                raise ValueError("Proje analizi veya bulgu bulunamadı.")
            db.execute(
                """INSERT OR IGNORE INTO project_cors_runtime_proofs(
                       id, audit_id, finding_index, verdict, http_status, origin_reflected,
                       credentials_allowed, evidence_sha256, created_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (self._id("rtp"), audit_id, finding_index, proof["verdict"], proof["http_status"],
                 int(proof["origin_reflected"]), int(proof["credentials_allowed"]), proof["evidence_sha256"], now),
            )
            saved = db.execute(
                """SELECT id, audit_id, finding_index, verdict, http_status, origin_reflected,
                          credentials_allowed, evidence_sha256, created_at
                   FROM project_cors_runtime_proofs
                   WHERE audit_id = ? AND finding_index = ? AND evidence_sha256 = ?""",
                (audit_id, finding_index, proof["evidence_sha256"]),
            ).fetchone()
        self.log("project_audit.cors_runtime_proof_added", audit_id,
                 {"finding_index": finding_index, "verdict": proof["verdict"],
                  "evidence_sha256": proof["evidence_sha256"]})
        return {**dict(saved), "proof_type": "cors_credentials_loopback", "format": proof["format"],
                "finding_reference": proof["finding_reference"], "finding_kind": "cors",
                "origin_reflected": bool(saved["origin_reflected"]),
                "credentials_allowed": bool(saved["credentials_allowed"]),
                "request_count": 1, "body_read": False}

    def add_project_clickjacking_runtime_proof(
        self, audit_id: str, finding_index: int, proof: dict[str, Any],
    ) -> dict[str, Any]:
        expected = {"format", "audit_id", "finding_index", "finding_reference", "finding_kind", "verdict",
                    "http_status", "x_frame_options_effective", "frame_ancestors_present",
                    "effective_protection", "content_type_html", "body_capable", "request_count", "body_read",
                    "evidence_sha256"}
        if not isinstance(proof, dict) or set(proof) != expected \
                or proof.get("format") != "sniper-clickjacking-runtime-proof/1" \
                or proof.get("audit_id") != audit_id or proof.get("finding_index") != finding_index \
                or proof.get("finding_kind") != "clickjacking" \
                or proof.get("verdict") not in {"confirmed", "not_reproduced"} \
                or type(proof.get("http_status")) is not int or not 100 <= proof["http_status"] <= 599 \
                or any(type(proof.get(key)) is not bool for key in (
                    "x_frame_options_effective", "frame_ancestors_present", "effective_protection",
                    "content_type_html", "body_capable")) \
                or (proof["x_frame_options_effective"] and not proof["effective_protection"]) \
                or (proof["effective_protection"] and not (
                    proof["x_frame_options_effective"] or proof["frame_ancestors_present"])) \
                or proof.get("request_count") != 1 or proof.get("body_read") is not False \
                or not re.fullmatch(r"[0-9a-f]{64}", str(proof.get("evidence_sha256"))):
            raise ValueError("Geçersiz clickjacking çalışma zamanı kanıtı.")
        should_confirm = 200 <= proof["http_status"] <= 299 and proof["content_type_html"] \
            and proof["body_capable"] and not proof["effective_protection"]
        if (proof["verdict"] == "confirmed") != should_confirm:
            raise ValueError("Geçersiz clickjacking çalışma zamanı kararı.")
        now = utc_now()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT findings_json FROM project_audits WHERE id = ?", (audit_id,)).fetchone()
            findings = json.loads(row["findings_json"] or "[]") if row else []
            if not row or type(finding_index) is not int or not 0 <= finding_index < len(findings):
                raise ValueError("Proje analizi veya bulgu bulunamadı.")
            db.execute(
                """INSERT OR IGNORE INTO project_clickjacking_runtime_proofs(
                       id, audit_id, finding_index, verdict, http_status, x_frame_options_effective,
                       frame_ancestors_present, effective_protection, content_type_html,
                       body_capable, evidence_sha256, created_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (self._id("rtp"), audit_id, finding_index, proof["verdict"], proof["http_status"],
                 int(proof["x_frame_options_effective"]), int(proof["frame_ancestors_present"]),
                 int(proof["effective_protection"]), int(proof["content_type_html"]),
                 int(proof["body_capable"]), proof["evidence_sha256"], now),
            )
            saved = db.execute(
                """SELECT * FROM project_clickjacking_runtime_proofs
                   WHERE audit_id = ? AND finding_index = ? AND evidence_sha256 = ?""",
                (audit_id, finding_index, proof["evidence_sha256"]),
            ).fetchone()
        self.log("project_audit.clickjacking_runtime_proof_added", audit_id,
                 {"finding_index": finding_index, "verdict": proof["verdict"],
                  "evidence_sha256": proof["evidence_sha256"]})
        return {**dict(saved), "proof_type": "clickjacking_headers_loopback", "format": proof["format"],
                "finding_reference": proof["finding_reference"], "finding_kind": "clickjacking",
                "x_frame_options_effective": bool(saved["x_frame_options_effective"]),
                "frame_ancestors_present": bool(saved["frame_ancestors_present"]),
                "effective_protection": bool(saved["effective_protection"]), "request_count": 1,
                "content_type_html": bool(saved["content_type_html"]),
                "body_capable": bool(saved["body_capable"]), "body_read": False}

    def add_project_asan_runtime_proof(
        self, audit_id: str, finding_index: int, proof: dict[str, Any],
    ) -> dict[str, Any]:
        expected_fields = {"format", "audit_id", "finding_index", "finding_reference", "verdict",
                           "expected_error_class", "observed_error_class", "asan_error", "exit_code",
                           "binary_sha256", "network_available", "argument_count", "stdin_available",
                           "timed_out", "evidence_sha256"}
        allowed_expected = {"heap-use-after-free", "double-free", "buffer-overflow"}
        allowed_observed = {"", "heap-use-after-free", "double-free", "heap-buffer-overflow",
                            "stack-buffer-overflow", "global-buffer-overflow", "address-sanitizer-error"}
        if not isinstance(proof, dict) or set(proof) != expected_fields \
                or proof.get("format") != "sniper-asan-project-proof/1" \
                or proof.get("audit_id") != audit_id or proof.get("finding_index") != finding_index \
                or proof.get("verdict") not in {"confirmed", "not_reproduced"} \
                or proof.get("expected_error_class") not in allowed_expected \
                or proof.get("observed_error_class") not in allowed_observed \
                or type(proof.get("asan_error")) is not bool or type(proof.get("exit_code")) is not int \
                or not -255 <= proof["exit_code"] <= 255 \
                or not re.fullmatch(r"[0-9a-f]{64}", str(proof.get("binary_sha256"))) \
                or proof.get("network_available") is not False or proof.get("argument_count") != 0 \
                or proof.get("stdin_available") is not False or proof.get("timed_out") is not False \
                or not re.fullmatch(r"[0-9a-f]{64}", str(proof.get("evidence_sha256"))):
            raise ValueError("Geçersiz ASan proje kanıtı.")
        now = utc_now()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT findings_json FROM project_audits WHERE id = ?", (audit_id,)).fetchone()
            findings = json.loads(row["findings_json"] or "[]") if row else []
            if not row or type(finding_index) is not int or not 0 <= finding_index < len(findings):
                raise ValueError("Proje analizi veya bulgu bulunamadı.")
            db.execute(
                """INSERT OR IGNORE INTO project_asan_runtime_proofs(
                       id, audit_id, finding_index, verdict, expected_error_class, observed_error_class,
                       asan_error, exit_code, binary_sha256, evidence_sha256, created_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (self._id("rtp"), audit_id, finding_index, proof["verdict"], proof["expected_error_class"],
                 proof["observed_error_class"], int(proof["asan_error"]), proof["exit_code"],
                 proof["binary_sha256"], proof["evidence_sha256"], now),
            )
            saved = db.execute(
                """SELECT * FROM project_asan_runtime_proofs
                   WHERE audit_id = ? AND finding_index = ? AND evidence_sha256 = ?""",
                (audit_id, finding_index, proof["evidence_sha256"]),
            ).fetchone()
        self.log("project_audit.asan_runtime_proof_added", audit_id,
                 {"finding_index": finding_index, "verdict": proof["verdict"],
                  "binary_sha256": proof["binary_sha256"], "evidence_sha256": proof["evidence_sha256"]})
        return {**dict(saved), "proof_type": "asan_prebuilt_binary", "format": proof["format"],
                "finding_reference": proof["finding_reference"], "asan_error": bool(saved["asan_error"]),
                "network_available": False, "argument_count": 0, "stdin_available": False,
                "timed_out": False}

    def add_project_asan_source_proof(
        self, audit_id: str, finding_index: int, proof: dict[str, Any],
    ) -> dict[str, Any]:
        expected_fields = {"format", "audit_id", "finding_index", "finding_reference", "verdict",
                           "expected_error_class", "observed_error_class", "asan_error", "exit_code",
                           "binary_sha256", "source_sha256", "compiler_sha256", "source_language",
                           "build_profile", "network_available", "argument_count", "stdin_available",
                           "timed_out", "project_build_scripts_executed", "evidence_sha256"}
        allowed_expected = {"heap-use-after-free", "double-free", "buffer-overflow"}
        allowed_observed = {"", "heap-use-after-free", "double-free", "heap-buffer-overflow",
                            "stack-buffer-overflow", "global-buffer-overflow", "address-sanitizer-error"}
        profiles_for_language = {"c": {"c11-asan-fixed-v1", "c11-asan-fixed-multifile-v1"},
                                 "cpp": {"cpp17-asan-fixed-v1", "cpp17-asan-fixed-multifile-v1"}}
        if not isinstance(proof, dict) or set(proof) != expected_fields \
                or proof.get("format") != "sniper-asan-source-proof/1" \
                or proof.get("audit_id") != audit_id or proof.get("finding_index") != finding_index \
                or proof.get("verdict") not in {"confirmed", "not_reproduced"} \
                or proof.get("expected_error_class") not in allowed_expected \
                or proof.get("observed_error_class") not in allowed_observed \
                or type(proof.get("asan_error")) is not bool or type(proof.get("exit_code")) is not int \
                or not -255 <= proof["exit_code"] <= 255 \
                or any(not re.fullmatch(r"[0-9a-f]{64}", str(proof.get(key)))
                       for key in ("binary_sha256", "source_sha256", "compiler_sha256", "evidence_sha256")) \
                or proof.get("build_profile") not in profiles_for_language.get(proof.get("source_language"), set()) \
                or proof.get("network_available") is not False or proof.get("argument_count") != 0 \
                or proof.get("stdin_available") is not False or proof.get("timed_out") is not False \
                or proof.get("project_build_scripts_executed") is not False:
            raise ValueError("Geçersiz ASan kaynak kanıtı.")
        now = utc_now()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS project_asan_source_proofs (
                    id TEXT PRIMARY KEY,
                    audit_id TEXT NOT NULL REFERENCES project_audits(id) ON DELETE CASCADE,
                    finding_index INTEGER NOT NULL CHECK(finding_index >= 0),
                    verdict TEXT NOT NULL CHECK(verdict IN ('confirmed', 'not_reproduced')),
                    expected_error_class TEXT NOT NULL,
                    observed_error_class TEXT NOT NULL,
                    asan_error INTEGER NOT NULL CHECK(asan_error IN (0, 1)),
                    exit_code INTEGER NOT NULL,
                    binary_sha256 TEXT NOT NULL CHECK(length(binary_sha256) = 64),
                    source_sha256 TEXT NOT NULL CHECK(length(source_sha256) = 64),
                    compiler_sha256 TEXT NOT NULL CHECK(length(compiler_sha256) = 64),
                    source_language TEXT NOT NULL CHECK(source_language IN ('c', 'cpp')),
                    build_profile TEXT NOT NULL CHECK(build_profile IN (
                        'c11-asan-fixed-v1', 'cpp17-asan-fixed-v1',
                        'c11-asan-fixed-multifile-v1', 'cpp17-asan-fixed-multifile-v1')),
                    evidence_sha256 TEXT NOT NULL CHECK(length(evidence_sha256) = 64),
                    created_at TEXT NOT NULL,
                    UNIQUE(audit_id, finding_index, evidence_sha256)
                );
                CREATE INDEX IF NOT EXISTS project_asan_source_proofs_audit_idx
                    ON project_asan_source_proofs(audit_id, finding_index, created_at DESC);
                """
            )
            row = db.execute("SELECT findings_json FROM project_audits WHERE id = ?", (audit_id,)).fetchone()
            findings = json.loads(row["findings_json"] or "[]") if row else []
            if not row or type(finding_index) is not int or not 0 <= finding_index < len(findings):
                raise ValueError("Proje analizi veya bulgu bulunamadı.")
            db.execute(
                """INSERT OR IGNORE INTO project_asan_source_proofs(
                       id, audit_id, finding_index, verdict, expected_error_class, observed_error_class,
                       asan_error, exit_code, binary_sha256, source_sha256, compiler_sha256, source_language,
                       build_profile, evidence_sha256, created_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (self._id("rtp"), audit_id, finding_index, proof["verdict"], proof["expected_error_class"],
                 proof["observed_error_class"], int(proof["asan_error"]), proof["exit_code"],
                 proof["binary_sha256"], proof["source_sha256"], proof["compiler_sha256"],
                 proof["source_language"], proof["build_profile"], proof["evidence_sha256"], now),
            )
            saved = db.execute(
                """SELECT * FROM project_asan_source_proofs
                   WHERE audit_id = ? AND finding_index = ? AND evidence_sha256 = ?""",
                (audit_id, finding_index, proof["evidence_sha256"]),
            ).fetchone()
        self.log("project_audit.asan_source_proof_added", audit_id,
                 {"finding_index": finding_index, "verdict": proof["verdict"],
                  "source_sha256": proof["source_sha256"], "compiler_sha256": proof["compiler_sha256"],
                  "evidence_sha256": proof["evidence_sha256"]})
        return {**dict(saved), "proof_type": "asan_source_fixed_profile", "format": proof["format"],
                "finding_reference": proof["finding_reference"], "asan_error": bool(saved["asan_error"]),
                "network_available": False, "argument_count": 0, "stdin_available": False,
                "timed_out": False, "project_build_scripts_executed": False}

    def add_project_asan_compile_database_proof(
        self, audit_id: str, finding_index: int, proof: dict[str, Any],
    ) -> dict[str, Any]:
        expected_fields = {
            "format", "audit_id", "finding_index", "finding_reference", "verdict",
            "expected_error_class", "observed_error_class", "asan_error", "exit_code",
            "binary_sha256", "source_sha256", "compiler_sha256", "compile_database_sha256",
            "compile_entry_sha256", "snapshot_sha256", "snapshot_file_count", "source_language",
            "build_profile", "snapshot_scope", "network_available", "argument_count",
            "stdin_available", "timed_out", "project_build_scripts_executed", "evidence_sha256",
        }
        allowed_expected = {"heap-use-after-free", "double-free", "buffer-overflow"}
        allowed_observed = {"", "heap-use-after-free", "double-free", "heap-buffer-overflow",
                            "stack-buffer-overflow", "global-buffer-overflow", "address-sanitizer-error"}
        digest_fields = ("binary_sha256", "source_sha256", "compiler_sha256", "compile_database_sha256",
                         "compile_entry_sha256", "snapshot_sha256", "evidence_sha256")
        if not isinstance(proof, dict) or set(proof) != expected_fields \
                or proof.get("format") != "sniper-asan-compile-database-proof/1" \
                or proof.get("audit_id") != audit_id or proof.get("finding_index") != finding_index \
                or proof.get("verdict") not in {"confirmed", "not_reproduced"} \
                or proof.get("expected_error_class") not in allowed_expected \
                or proof.get("observed_error_class") not in allowed_observed \
                or type(proof.get("asan_error")) is not bool or type(proof.get("exit_code")) is not int \
                or not -255 <= proof["exit_code"] <= 255 \
                or any(not re.fullmatch(r"[0-9a-f]{64}", str(proof.get(key))) for key in digest_fields) \
                or proof.get("source_language") not in {"c", "cpp"} \
                or proof.get("build_profile") != "compile-database-single-tu-v1" \
                or proof.get("snapshot_scope") != "bounded_c_cpp_sources_headers_only" \
                or type(proof.get("snapshot_file_count")) is not int \
                or not 1 <= proof["snapshot_file_count"] <= 2048 \
                or proof.get("network_available") is not False or proof.get("argument_count") != 0 \
                or proof.get("stdin_available") is not False or proof.get("timed_out") is not False \
                or proof.get("project_build_scripts_executed") is not False:
            raise ValueError("Geçersiz ASan compile-database kanıtı.")
        now = utc_now()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS project_asan_compile_database_proofs (
                    id TEXT PRIMARY KEY,
                    audit_id TEXT NOT NULL REFERENCES project_audits(id) ON DELETE CASCADE,
                    finding_index INTEGER NOT NULL CHECK(finding_index >= 0),
                    verdict TEXT NOT NULL CHECK(verdict IN ('confirmed', 'not_reproduced')),
                    expected_error_class TEXT NOT NULL,
                    observed_error_class TEXT NOT NULL,
                    asan_error INTEGER NOT NULL CHECK(asan_error IN (0, 1)),
                    exit_code INTEGER NOT NULL,
                    binary_sha256 TEXT NOT NULL CHECK(length(binary_sha256) = 64),
                    source_sha256 TEXT NOT NULL CHECK(length(source_sha256) = 64),
                    compiler_sha256 TEXT NOT NULL CHECK(length(compiler_sha256) = 64),
                    compile_database_sha256 TEXT NOT NULL CHECK(length(compile_database_sha256) = 64),
                    compile_entry_sha256 TEXT NOT NULL CHECK(length(compile_entry_sha256) = 64),
                    snapshot_sha256 TEXT NOT NULL CHECK(length(snapshot_sha256) = 64),
                    snapshot_file_count INTEGER NOT NULL CHECK(snapshot_file_count BETWEEN 1 AND 2048),
                    source_language TEXT NOT NULL CHECK(source_language IN ('c', 'cpp')),
                    build_profile TEXT NOT NULL CHECK(build_profile = 'compile-database-single-tu-v1'),
                    evidence_sha256 TEXT NOT NULL CHECK(length(evidence_sha256) = 64),
                    created_at TEXT NOT NULL,
                    UNIQUE(audit_id, finding_index, evidence_sha256)
                );
                CREATE INDEX IF NOT EXISTS project_asan_compile_database_proofs_audit_idx
                    ON project_asan_compile_database_proofs(audit_id, finding_index, created_at DESC);
                """
            )
            row = db.execute("SELECT findings_json FROM project_audits WHERE id = ?", (audit_id,)).fetchone()
            findings = json.loads(row["findings_json"] or "[]") if row else []
            if not row or type(finding_index) is not int or not 0 <= finding_index < len(findings):
                raise ValueError("Proje analizi veya bulgu bulunamadı.")
            db.execute(
                """INSERT OR IGNORE INTO project_asan_compile_database_proofs(
                       id, audit_id, finding_index, verdict, expected_error_class, observed_error_class,
                       asan_error, exit_code, binary_sha256, source_sha256, compiler_sha256,
                       compile_database_sha256, compile_entry_sha256, snapshot_sha256, snapshot_file_count,
                       source_language, build_profile, evidence_sha256, created_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (self._id("rtp"), audit_id, finding_index, proof["verdict"], proof["expected_error_class"],
                 proof["observed_error_class"], int(proof["asan_error"]), proof["exit_code"],
                 proof["binary_sha256"], proof["source_sha256"], proof["compiler_sha256"],
                 proof["compile_database_sha256"], proof["compile_entry_sha256"], proof["snapshot_sha256"],
                 proof["snapshot_file_count"], proof["source_language"], proof["build_profile"],
                 proof["evidence_sha256"], now),
            )
            saved = db.execute(
                """SELECT * FROM project_asan_compile_database_proofs
                   WHERE audit_id = ? AND finding_index = ? AND evidence_sha256 = ?""",
                (audit_id, finding_index, proof["evidence_sha256"]),
            ).fetchone()
        self.log("project_audit.asan_compile_database_proof_added", audit_id,
                 {"finding_index": finding_index, "verdict": proof["verdict"],
                  "compile_entry_sha256": proof["compile_entry_sha256"],
                  "evidence_sha256": proof["evidence_sha256"]})
        return {**dict(saved), "proof_type": "asan_compile_database_single_tu", "format": proof["format"],
                "finding_reference": proof["finding_reference"], "asan_error": bool(saved["asan_error"]),
                "snapshot_scope": "bounded_c_cpp_sources_headers_only", "network_available": False,
                "argument_count": 0, "stdin_available": False, "timed_out": False,
                "project_build_scripts_executed": False}

    def import_network_scan_findings(
        self,
        *,
        request_id: str,
        scanner_job_id: str,
        target_id: str,
        engagement_id: str,
        findings: list[dict[str, Any]],
    ) -> int:
        """Maskeli Nuclei bulgularını istek/denetim bağıyla yinelenmeden içe aktar."""
        if not re.fullmatch(r"msr_[0-9a-f]{16}", str(request_id)) \
                or not re.fullmatch(r"[0-9a-f]{16}", str(scanner_job_id)) \
                or not isinstance(findings, list) or len(findings) > 200:
            raise ValueError("Geçersiz ağ taraması bulgu paketi.")
        expected = {"template_id", "title", "severity", "fingerprint_sha256", "evidence_sha256"}
        severities = {"info", "low", "medium", "high", "critical", "unknown"}
        checked = []
        for finding in findings:
            if not isinstance(finding, dict) or set(finding) != expected \
                    or not isinstance(finding["template_id"], str) or not finding["template_id"] \
                    or len(finding["template_id"]) > 300 \
                    or not isinstance(finding["title"], str) or not finding["title"] or len(finding["title"]) > 200 \
                    or finding["severity"] not in severities \
                    or not re.fullmatch(r"[0-9a-f]{64}", str(finding["fingerprint_sha256"])) \
                    or not re.fullmatch(r"[0-9a-f]{64}", str(finding["evidence_sha256"])):
                raise ValueError("Geçersiz ağ taraması bulgusu.")
            checked.append(finding)
        now = utc_now()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            target = db.execute("SELECT id FROM targets WHERE id = ?", (target_id,)).fetchone()
            engagement = db.execute(
                "SELECT id FROM engagements WHERE id = ? AND target_id = ?",
                (engagement_id, target_id),
            ).fetchone()
            if target is None or engagement is None:
                raise ValueError("Tarama hedefi veya denetimi bulunamadı.")
            before = db.total_changes
            for finding in checked:
                db.execute(
                    """INSERT OR IGNORE INTO network_scan_findings(
                           id, request_id, scanner_job_id, target_id, engagement_id, template_id, title,
                           severity, fingerprint_sha256, evidence_sha256, created_at
                       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (self._id("nsf"), request_id, scanner_job_id, target_id, engagement_id,
                     finding["template_id"], finding["title"], finding["severity"],
                     finding["fingerprint_sha256"], finding["evidence_sha256"], now),
                )
            inserted = db.total_changes - before
            if inserted:
                self._append_audit_log(
                    db, "network_scan.findings_imported", request_id,
                    json.dumps({"scanner_job_id": scanner_job_id, "finding_count": len(checked),
                                "inserted_count": inserted}, ensure_ascii=False), occurred_at=now,
                )
        return inserted

    def list_network_scan_findings(self, request_id: str) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute(
                """SELECT id, request_id, scanner_job_id, template_id, title, severity,
                          fingerprint_sha256, evidence_sha256, created_at
                   FROM network_scan_findings WHERE request_id = ?
                   ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
                            WHEN 'low' THEN 3 WHEN 'info' THEN 4 ELSE 5 END, id""",
                (request_id,),
            ).fetchall()
            result = []
            for row in rows:
                item = dict(row)
                suggestion = db.execute(
                    """SELECT id, verdict, confidence, rationale, agent, model, submitted_by, decision, created_at
                       FROM network_scan_triage_suggestions WHERE finding_id = ?
                       ORDER BY created_at DESC, id DESC LIMIT 1""",
                    (item["id"],),
                ).fetchone()
                item["latest_triage"] = dict(suggestion) if suggestion else None
                result.append(item)
        return result

    def import_network_direct_scan_findings(
        self,
        *,
        request_id: str,
        scanner_job_id: str,
        target_sha256: str,
        findings: list[dict[str, Any]],
    ) -> int:
        """Hedef/denetim satırı yaratmadan maskeli doğrudan Nuclei bulgularını sakla."""
        if not re.fullmatch(r"msr_[0-9a-f]{16}", str(request_id)) \
                or not re.fullmatch(r"[0-9a-f]{16}", str(scanner_job_id)) \
                or not re.fullmatch(r"[0-9a-f]{64}", str(target_sha256)) \
                or not isinstance(findings, list) or len(findings) > 200:
            raise ValueError("Geçersiz doğrudan ağ taraması bulgu paketi.")
        expected = {"template_id", "title", "severity", "fingerprint_sha256", "evidence_sha256"}
        severities = {"info", "low", "medium", "high", "critical", "unknown"}
        checked: list[dict[str, Any]] = []
        for finding in findings:
            if not isinstance(finding, dict) or set(finding) != expected \
                    or not isinstance(finding["template_id"], str) or not finding["template_id"] \
                    or len(finding["template_id"]) > 300 \
                    or not isinstance(finding["title"], str) or not finding["title"] \
                    or len(finding["title"]) > 200 or finding["severity"] not in severities \
                    or not re.fullmatch(r"[0-9a-f]{64}", str(finding["fingerprint_sha256"])) \
                    or not re.fullmatch(r"[0-9a-f]{64}", str(finding["evidence_sha256"])):
                raise ValueError("Geçersiz doğrudan ağ taraması bulgusu.")
            checked.append(finding)
        now = utc_now()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            before = db.total_changes
            for finding in checked:
                db.execute(
                    """INSERT OR IGNORE INTO network_direct_scan_findings(
                           id, request_id, scanner_job_id, target_sha256, template_id, title,
                           severity, fingerprint_sha256, evidence_sha256, created_at
                       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (self._id("nsd"), request_id, scanner_job_id, target_sha256,
                     finding["template_id"], finding["title"], finding["severity"],
                     finding["fingerprint_sha256"], finding["evidence_sha256"], now),
                )
            inserted = db.total_changes - before
            if inserted:
                self._append_audit_log(
                    db, "network_direct_scan.findings_imported", request_id,
                    json.dumps({"scanner_job_id": scanner_job_id, "target_sha256": target_sha256,
                                "finding_count": len(checked), "inserted_count": inserted},
                               ensure_ascii=False), occurred_at=now,
                )
        return inserted

    def list_network_direct_scan_findings(self, request_id: str) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute(
                """SELECT id, request_id, scanner_job_id, target_sha256, template_id, title, severity,
                          fingerprint_sha256, evidence_sha256, created_at
                   FROM network_direct_scan_findings WHERE request_id = ?
                   ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
                            WHEN 'low' THEN 3 WHEN 'info' THEN 4 ELSE 5 END, id""",
                (request_id,),
            ).fetchall()
            result = []
            for row in rows:
                item = dict(row)
                suggestion = db.execute(
                    """SELECT id, verdict, confidence, rationale, agent, model, submitted_by, decision, created_at
                       FROM network_direct_scan_triage_suggestions WHERE finding_id = ?
                       ORDER BY created_at DESC, id DESC LIMIT 1""",
                    (item["id"],),
                ).fetchone()
                item["latest_triage"] = dict(suggestion) if suggestion else None
                result.append(item)
        return result

    def record_network_direct_scan_triage(
        self,
        finding_id: str,
        *,
        verdict: str,
        confidence: float,
        rationale: str,
        agent: str = "",
        model: str = "",
        submitted_by: str = "",
    ) -> dict[str, Any]:
        if verdict not in {"likely_true", "likely_false", "uncertain"} \
                or isinstance(confidence, bool) or not isinstance(confidence, (int, float)) \
                or not 0 <= float(confidence) <= 1 \
                or not isinstance(rationale, str) or not rationale.strip() or len(rationale) > 2000 \
                or not all(isinstance(value, str) and len(value) <= 120
                           for value in (agent, model, submitted_by)):
            raise ValueError("Geçersiz doğrudan ağ taraması triyaj önerisi.")
        now, suggestion_id = utc_now(), self._id("ndt")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            finding = db.execute(
                "SELECT id, request_id FROM network_direct_scan_findings WHERE id = ?", (finding_id,)
            ).fetchone()
            if finding is None:
                raise ValueError("Doğrudan ağ taraması bulgusu bulunamadı.")
            db.execute(
                """INSERT INTO network_direct_scan_triage_suggestions(
                       id, finding_id, verdict, confidence, rationale, agent, model, submitted_by,
                       decision, created_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)""",
                (suggestion_id, finding_id, verdict, float(confidence), rationale.strip(), agent, model,
                 submitted_by, now),
            )
            self._append_audit_log(
                db, "network_direct_scan.triage_suggested", finding_id,
                json.dumps({"request_id": finding["request_id"], "verdict": verdict,
                            "confidence": float(confidence)}, ensure_ascii=False), occurred_at=now,
            )
            row = db.execute(
                """SELECT id, finding_id, verdict, confidence, rationale, agent, model, submitted_by,
                          decision, created_at FROM network_direct_scan_triage_suggestions WHERE id = ?""",
                (suggestion_id,),
            ).fetchone()
        return dict(row)

    def record_network_scan_triage(
        self,
        finding_id: str,
        *,
        verdict: str,
        confidence: float,
        rationale: str,
        agent: str = "",
        model: str = "",
        submitted_by: str = "",
    ) -> dict[str, Any]:
        if verdict not in {"likely_true", "likely_false", "uncertain"} \
                or isinstance(confidence, bool) or not isinstance(confidence, (int, float)) \
                or not 0 <= float(confidence) <= 1 \
                or not isinstance(rationale, str) or not rationale.strip() or len(rationale) > 2000 \
                or not all(isinstance(value, str) and len(value) <= 120 for value in (agent, model, submitted_by)):
            raise ValueError("Geçersiz ağ taraması triyaj önerisi.")
        now, suggestion_id = utc_now(), self._id("nst")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            finding = db.execute(
                "SELECT id, request_id FROM network_scan_findings WHERE id = ?", (finding_id,)
            ).fetchone()
            if finding is None:
                raise ValueError("Ağ taraması bulgusu bulunamadı.")
            db.execute(
                """INSERT INTO network_scan_triage_suggestions(
                       id, finding_id, verdict, confidence, rationale, agent, model, submitted_by, decision, created_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)""",
                (suggestion_id, finding_id, verdict, float(confidence), rationale.strip(), agent, model,
                 submitted_by, now),
            )
            self._append_audit_log(
                db, "network_scan.triage_suggested", finding_id,
                json.dumps({"request_id": finding["request_id"], "verdict": verdict,
                            "confidence": float(confidence)}, ensure_ascii=False), occurred_at=now,
            )
            row = db.execute(
                """SELECT id, finding_id, verdict, confidence, rationale, agent, model, submitted_by,
                          decision, created_at FROM network_scan_triage_suggestions WHERE id = ?""",
                (suggestion_id,),
            ).fetchone()
        return dict(row)

    def update_network_finding(self, finding_id: str, *, status: str, assignee_name: str = "",
                               due_date: str = "") -> dict[str, Any]:
        allowed = {"open", "in_progress", "fixed", "risk_accepted", "false_positive", "reopened"}
        if status not in allowed:
            raise ValueError("Geçersiz ağ bulgusu durumu.")
        if not isinstance(assignee_name, str) or len(assignee_name) > 80:
            raise ValueError("Geçersiz sorumlu.")
        if not isinstance(due_date, str) or (due_date and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", due_date)):
            raise ValueError("Geçersiz son tarih.")
        now = utc_now()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if not db.execute("SELECT 1 FROM network_scan_findings WHERE id=?", (finding_id,)).fetchone():
                raise ValueError("Ağ taraması bulgusu bulunamadı.")
            db.execute("""CREATE TABLE IF NOT EXISTS schema_migrations(
                version INTEGER PRIMARY KEY CHECK(version>0), name TEXT NOT NULL UNIQUE, applied_at TEXT NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS network_finding_lifecycle(
                finding_id TEXT PRIMARY KEY REFERENCES network_scan_findings(id) ON DELETE CASCADE,
                status TEXT NOT NULL CHECK(status IN ('open','in_progress','fixed','risk_accepted','false_positive','reopened')),
                assignee_name TEXT NOT NULL DEFAULT '', due_date TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL)""")
            db.execute("INSERT OR IGNORE INTO schema_migrations(version,name,applied_at) VALUES(1,?,?)",
                       (SCHEMA_MIGRATIONS[0][1], now))
            db.execute("""INSERT INTO network_finding_lifecycle(finding_id,status,assignee_name,due_date,updated_at)
                VALUES(?,?,?,?,?) ON CONFLICT(finding_id) DO UPDATE SET status=excluded.status,
                assignee_name=excluded.assignee_name,due_date=excluded.due_date,updated_at=excluded.updated_at""",
                (finding_id, status, assignee_name.strip(), due_date, now))
            self._append_audit_log(db, "network_scan.finding_updated", finding_id,
                                   json.dumps({"status": status}, ensure_ascii=False), occurred_at=now)
            row = db.execute("""SELECT n.*,l.status,l.assignee_name,l.due_date,l.updated_at
                FROM network_scan_findings n JOIN network_finding_lifecycle l ON l.finding_id=n.id
                WHERE n.id=?""", (finding_id,)).fetchone()
        return dict(row)

    # ------------------------------------------------------------------
    # Bulgu takibi (finding_tracking)
    # ------------------------------------------------------------------
    def list_tracked_projects(self) -> list[dict]:
        with self._connect() as db:
            return finding_tracking.list_projects(db)

    def list_unified_findings(self, *, sources: set[str] | None = None, statuses: set[str] | None = None,
                              severities: set[str] | None = None, limit: int = 200,
                              offset: int = 0) -> dict[str, Any]:
        """Bulgu kaynaklarını ham kanıt alanları olmadan tek, filtrelenebilir görünümde döndür."""
        with self._connect() as db:
            return unified_findings.list_findings(db, sources=sources, statuses=statuses,
                                                  severities=severities, limit=limit, offset=offset)

    def list_tracked_findings(self, project_path: str, statuses: set[str] | None = None, limit: int = 500) -> list[dict]:
        with self._connect() as db:
            items = finding_tracking.list_tracked(db, project_path, statuses, limit)
            ai_triage.annotate_tracked(db, items)  # 25. tur: son AI/ajan önerisinin özeti (öneri; karar değil)
            return items

    def get_tracked_finding(self, tracked_id: str) -> dict | None:
        with self._connect() as db:
            return finding_tracking.get_tracked(db, tracked_id)

    def set_tracked_finding_status(self, tracked_id: str, status: str, note: str, expires_at: str | None = None) -> dict:
        default_risk_days = portfolio.load_policy()[0]["risk_acceptance_days"]
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            now = utc_now()
            result = finding_tracking.set_status(db, tracked_id, status, note, when=now, expires_at=expires_at,
                                                 default_risk_days=default_risk_days)
            details = {"status": status, "project_path": result.get("project_path")}
            if result.get("risk_expires_at"):
                details["risk_expires_at"] = result["risk_expires_at"]
            self._append_audit_log(
                db, "tracked_finding.status_changed", tracked_id, json.dumps(details, ensure_ascii=False), occurred_at=now,
            )
        return result

    def tracked_project_summary(self, project_path: str, trend_limit: int = 10, as_of_audit_id: str | None = None) -> dict:
        with self._connect() as db:
            return finding_tracking.project_summary(db, project_path, trend_limit=trend_limit, as_of_audit_id=as_of_audit_id)

    # -- iş birliği: sorumlu, son tarih, yorumlar (16. tur) --------------------------------
    def assign_tracked_finding(self, tracked_id: str, assignee_id: str | None, assignee_name: str) -> dict:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            now = utc_now()
            outcome = finding_tracking.assign(db, tracked_id, assignee_id=assignee_id, assignee_name=assignee_name, when=now)
            if outcome["changed"]:
                self._append_audit_log(
                    db, "tracked_finding.assigned", tracked_id,
                    json.dumps({"assignee_id": assignee_id, "assignee_name": assignee_name,
                                "previous_assignee_id": outcome["previous"]["assignee_id"],
                                "previous_assignee_name": outcome["previous"]["assignee_name"],
                                "project_path": outcome["finding"].get("project_path")}, ensure_ascii=False),
                    occurred_at=now,
                )
        return outcome

    def set_tracked_finding_due(self, tracked_id: str, due_date: str | None) -> dict:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            now = utc_now()
            outcome = finding_tracking.set_due(db, tracked_id, due_date, when=now)
            if outcome["changed"]:
                self._append_audit_log(
                    db, "tracked_finding.due_changed", tracked_id,
                    json.dumps({"due_date": due_date, "previous_due_date": outcome["previous"],
                                "project_path": outcome["finding"].get("project_path")}, ensure_ascii=False),
                    occurred_at=now,
                )
        return outcome

    def add_tracked_finding_comment(self, tracked_id: str, author_id: str | None, author_name: str, body: str) -> dict:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            now = utc_now()
            comment = finding_tracking.add_comment(db, tracked_id, author_id=author_id, author_name=author_name,
                                                   body=body, when=now)
            # Yorum metni denetim kaydına kopyalanmaz (yalnız kimlik ve uzunluk).
            self._append_audit_log(
                db, "tracked_finding.comment_added", tracked_id,
                json.dumps({"comment_id": comment["id"], "length": len(comment["body"])}, ensure_ascii=False),
                occurred_at=now,
            )
        return comment

    def delete_tracked_finding_comment(self, tracked_id: str, comment_id: int, actor_id: str | None, is_admin: bool) -> dict:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            now = utc_now()
            comment = finding_tracking.delete_comment(db, tracked_id, comment_id, actor_id=actor_id, is_admin=is_admin, when=now)
            self._append_audit_log(
                db, "tracked_finding.comment_deleted", tracked_id,
                json.dumps({"comment_id": comment["id"], "author_id": comment["author_id"]}, ensure_ascii=False),
                occurred_at=now,
            )
        return comment

    def list_assigned_findings(self, **filters) -> list[dict]:
        with self._connect() as db:
            return finding_tracking.list_assigned(db, **filters)

    def tracked_assignee_names(self) -> list[str]:
        with self._connect() as db:
            return finding_tracking.assignee_names(db)

    def tracked_due_candidates(self, today, days_before: int) -> list[dict]:
        with self._connect() as db:
            return finding_tracking.due_candidates(db, today, days_before)

    def mark_tracked_due_notices(self, notices: list[tuple[str, str]]) -> None:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            for tracked_id, notice in notices:
                finding_tracking.mark_due_notice(db, tracked_id, notice)

    # -- portföy / SLA / dışa aktarım (17. tur) ----------------------------------------------
    def portfolio_overview(self, policy: dict, weeks: int = 12, project_filter=None) -> dict:
        with self._connect() as db:
            return portfolio.overview(db, policy, weeks=weeks, project_filter=project_filter)

    def portfolio_export_rows(self, policy: dict, *, project_path: str | None, statuses: set[str]) -> list[dict]:
        with self._connect() as db:
            return portfolio.export_rows(db, policy, project_path=project_path, statuses=statuses)

    def apply_sla_due_dates(self, policy: dict) -> dict:
        """Son tarihi olmayan etkin bulgulara SLA son tarihi (yönetici, onaylı). Denetim kaydına tek özet satırı."""
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            now = utc_now()
            changed = finding_tracking.apply_sla_due_dates(db, policy["days"], when=now)
            by_severity: dict[str, int] = {}
            for item in changed:
                by_severity[item["severity"]] = by_severity.get(item["severity"], 0) + 1
            self._append_audit_log(db, "tracked_finding.sla_due_applied", "sla-policy",
                                   json.dumps({"count": len(changed), "by_severity": by_severity}, ensure_ascii=False),
                                   occurred_at=now)
        return {"updated": len(changed), "by_severity": by_severity}

    def expire_risk_acceptances(self, today) -> list[dict]:
        """Bitiş tarihi gelen risk kabullerini yeniden aç; her biri denetim kaydına yazılır."""
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            now = utc_now()
            expired = finding_tracking.expire_risk_acceptances(db, today, when=now)
            for item in expired:
                self._append_audit_log(db, "tracked_finding.risk_expired", item["id"],
                                       json.dumps({"expired_on": item["expired_on"], "project_path": item["project_path"]},
                                                  ensure_ascii=False), occurred_at=now)
        return expired

    def sla_breach_candidates(self, policy: dict, today) -> list[dict]:
        with self._connect() as db:
            return portfolio.breach_candidates(db, policy, today)

    def mark_sla_notices(self, notices: list[tuple[str, str]]) -> None:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            for tracked_id, notice in notices:
                finding_tracking.mark_sla_notice(db, tracked_id, notice)

    def backfill_finding_tracking(self) -> dict:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            result = finding_tracking.backfill(db)
            self._append_audit_log(db, "tracked_finding.backfill", "project_audits", json.dumps(result, ensure_ascii=False))
        return result

    def save_dependency_sbom(self, project_path: str, document: dict[str, Any]) -> dict:
        serialized = json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        document_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        components = document.get("components", [])
        now = utc_now()
        with self._connect() as db:
            existing = db.execute(
                "SELECT * FROM dependency_sboms WHERE project_path = ? AND document_hash = ?",
                (project_path, document_hash),
            ).fetchone()
            if existing:
                return self._dependency_sbom_dict(existing, include_document=True)
            sbom_id = self._id("sbom")
            try:
                db.execute(
                    """
                    INSERT INTO dependency_sboms(
                        id, project_path, project_name, format, component_count,
                        document_hash, document_json, created_at
                    ) VALUES (?, ?, ?, 'cyclonedx-1.5', ?, ?, ?, ?)
                    """,
                    (sbom_id, project_path, Path(project_path).name, len(components), document_hash, serialized, now),
                )
            except sqlite3.IntegrityError:
                existing = db.execute(
                    "SELECT * FROM dependency_sboms WHERE project_path = ? AND document_hash = ?",
                    (project_path, document_hash),
                ).fetchone()
                if existing:
                    return self._dependency_sbom_dict(existing, include_document=True)
                raise
            row = db.execute("SELECT * FROM dependency_sboms WHERE id = ?", (sbom_id,)).fetchone()
        self.log("dependency_sbom.created", sbom_id, {"project_path": project_path, "component_count": len(components)})
        return self._dependency_sbom_dict(row, include_document=True)

    def compare_dependency_sboms(self, before_id: str, after_id: str) -> dict | None:
        with self._connect() as db:
            before_row = db.execute(
                "SELECT * FROM dependency_sboms WHERE id = ?", (before_id,)
            ).fetchone()
            after_row = db.execute(
                "SELECT * FROM dependency_sboms WHERE id = ?", (after_id,)
            ).fetchone()

        if not before_row or not after_row:
            return None

        before = self._dependency_sbom_dict(before_row, include_document=True)
        after = self._dependency_sbom_dict(after_row, include_document=True)

        if before["project_path"] != after["project_path"]:
            raise ValueError("Farklı projelerin SBOM'ları karşılaştırılamaz")

        if before_id == after_id:
            return {
                "before_id": before_id,
                "after_id": after_id,
                "project_path": before["project_path"],
                "added": [],
                "removed": [],
                "changed": [],
                "summary": {"added": 0, "removed": 0, "changed": 0},
            }

        def extract_components(doc: dict) -> list[dict]:
            return doc.get("components", [])

        before_comps = extract_components(before.get("document", {}))
        after_comps = extract_components(after.get("document", {}))

        def purl_to_identity(purl: str) -> str:
            return purl.rsplit("@", 1)[0] if "@" in purl else purl

        def group_by_identity_and_version(comps: list[dict]) -> dict[str, dict[str | None, list[dict]]]:
            result: dict[str, dict[str | None, list[dict]]] = {}
            for comp in comps:
                purl = comp.get("purl", "")
                identity = purl_to_identity(purl)
                version = comp.get("version")
                name = comp.get("name", identity.split("/")[-1] if "/" in identity else identity)
                entry = {"name": name, "version": version, "purl": purl, "_comp": comp}
                result.setdefault(identity, {}).setdefault(version, []).append(entry)
            return result

        before_by = group_by_identity_and_version(before_comps)
        after_by = group_by_identity_and_version(after_comps)

        added, removed, changed = [], [], []
        all_identities = sorted(set(before_by.keys()) | set(after_by.keys()))

        for identity in all_identities:
            b_map = before_by.get(identity, {})
            a_map = after_by.get(identity, {})

            b_counts = {ver: len(items) for ver, items in b_map.items()}
            a_counts = {ver: len(items) for ver, items in a_map.items()}

            for ver in set(b_counts) & set(a_counts):
                common = min(b_counts[ver], a_counts[ver])
                b_counts[ver] -= common
                a_counts[ver] -= common

            b_remaining = []
            for ver, cnt in b_counts.items():
                b_remaining.extend([ver] * cnt)

            a_remaining = []
            for ver, cnt in a_counts.items():
                a_remaining.extend([ver] * cnt)

            b_remaining.sort(key=lambda x: (x is None, x or ""))
            a_remaining.sort(key=lambda x: (x is None, x or ""))

            min_len = min(len(b_remaining), len(a_remaining))
            for i in range(min_len):
                from_v, to_v = b_remaining[i], a_remaining[i]
                from_item = next(x for x in b_map[from_v] if x["version"] == from_v)
                to_item = next(x for x in a_map[to_v] if x["version"] == to_v)
                changed.append({
                    "name": from_item["name"],
                    "from_version": from_v,
                    "to_version": to_v,
                    "from_purl": from_item["purl"],
                    "to_purl": to_item["purl"]
                })

            for v in b_remaining[min_len:]:
                from_item = next(x for x in b_map[v] if x["version"] == v)
                removed.append({
                    "name": from_item["name"],
                    "version": v,
                    "purl": from_item["purl"]
                })

            for v in a_remaining[min_len:]:
                to_item = next(x for x in a_map[v] if x["version"] == v)
                added.append({
                    "name": to_item["name"],
                    "version": v,
                    "purl": to_item["purl"]
                })

        return {
            "before_id": before_id,
            "after_id": after_id,
            "project_path": before["project_path"],
            "added": added,
            "removed": removed,
            "changed": changed,
            "summary": {"added": len(added), "removed": len(removed), "changed": len(changed)},
        }

    def list_dependency_sboms(self, limit: int = 20) -> list[dict]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT * FROM dependency_sboms ORDER BY rowid DESC LIMIT ?",
                (max(1, min(limit, 100)),),
            ).fetchall()
        return [self._dependency_sbom_dict(row, include_document=False) for row in rows]

    def get_dependency_sbom(self, sbom_id: str) -> dict | None:
        with self._connect() as db:
            row = db.execute("SELECT * FROM dependency_sboms WHERE id = ?", (sbom_id,)).fetchone()
        return self._dependency_sbom_dict(row, include_document=True) if row else None

    def import_dependency_findings(self, report: dict[str, Any]) -> dict:
        now = utc_now()
        import_id = self._id("depimp")
        findings = report.get("findings", [])
        with self._connect() as db:
            existing = db.execute(
                "SELECT * FROM dependency_imports WHERE project_path = ? AND source = ? AND document_hash = ?",
                (report["project_path"], report["source"], report["document_hash"]),
            ).fetchone()
            if existing:
                return {**dict(existing), "deduplicated": True}
            db.execute(
                """
                INSERT INTO dependency_imports(
                    id, project_path, source, source_path, source_timestamp,
                    document_hash, finding_count, imported_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (import_id, report["project_path"], report["source"], report["source_path"],
                 report["source_timestamp"], report["document_hash"], len(findings), now),
            )
            for finding in findings:
                if any(chr(0) in finding[key] for key in ("project_path", "source", "vulnerability_id", "package_name", "installed_version")):
                    raise ValueError("bulgu kimliği NUL karakteri içeriyor")
                fingerprint_source = "\0".join((
                    finding["project_path"], finding["source"], finding["vulnerability_id"],
                    finding["package_name"], finding["installed_version"],
                ))
                fingerprint = hashlib.sha256(fingerprint_source.encode("utf-8")).hexdigest()
                existing_finding = db.execute(
                    "SELECT id, source_timestamp FROM dependency_findings WHERE fingerprint = ?", (fingerprint,),
                ).fetchone()
                if existing_finding and existing_finding[1] and existing_finding[1] > report["source_timestamp"]:
                    continue
                values = (
                    finding["severity"], finding["fixed_version"], finding["title"], finding["summary"],
                    finding.get("target", ""), json.dumps(finding.get("references", []), ensure_ascii=False),
                    now, report["source_timestamp"], import_id, fingerprint,
                )
                if existing_finding:
                    db.execute(
                        """
                        UPDATE dependency_findings
                        SET severity = ?, fixed_version = ?, title = ?, summary = ?, target = ?,
                            references_json = ?, last_seen_at = ?, source_timestamp = ?, latest_import_id = ?,
                            status = CASE WHEN status = 'resolved' THEN 'reopened' ELSE status END
                        WHERE fingerprint = ?
                        """,
                        values,
                    )
                else:
                    db.execute(
                        """
                        INSERT INTO dependency_findings(
                            id, fingerprint, project_path, package_name, installed_version,
                            vulnerability_id, severity, fixed_version, source, title, summary,
                            target, references_json, status, resolution_notes, first_seen_at,
                            last_seen_at, source_timestamp, latest_import_id
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', '', ?, ?, ?, ?)
                        """,
                        (self._id("depfnd"), fingerprint, finding["project_path"], finding["package_name"],
                         finding["installed_version"], finding["vulnerability_id"], finding["severity"],
                         finding["fixed_version"], finding["source"], finding["title"], finding["summary"],
                         finding.get("target", ""), json.dumps(finding.get("references", []), ensure_ascii=False),
                         now, now, report["source_timestamp"], import_id),
                    )
            row = db.execute("SELECT * FROM dependency_imports WHERE id = ?", (import_id,)).fetchone()
        self.log("dependency_report.imported", import_id, {"source": report["source"], "finding_count": len(findings)})
        return {**dict(row), "deduplicated": False}

    def dependency_security(
        self,
        limit: int = 500,
        *,
        offset: int = 0,
        query: str = "",
        source: str = "all",
        severity: str = "all",
        status: str = "all",
        complete_export: bool = False,
    ) -> dict:
        if not isinstance(complete_export, bool):
            raise ValueError("Geçersiz complete_export bayrağı")
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1 or limit > 2_000:
            raise ValueError("Geçersiz bağımlılık bulgusu sınırı")
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0 or offset > 1_000_000:
            raise ValueError("Geçersiz bağımlılık bulgusu başlangıç konumu")
        if not isinstance(query, str):
            raise ValueError("Geçersiz bağımlılık bulgusu sorgusu")
        normalized_query = query.strip().lower()
        if len(normalized_query) > 160:
            raise ValueError("Bağımlılık bulgusu sorgusu çok uzun")

        allowed_sources = {"all", "trivy", "osv"}
        if not isinstance(source, str) or source not in allowed_sources:
            raise ValueError(f"Geçersiz bağımlılık kaynağı filtresi: {source!r}")
        allowed_severities = {"all", "critical", "high", "medium", "low", "info"}
        if not isinstance(severity, str) or severity not in allowed_severities:
            raise ValueError(f"Geçersiz bağımlılık önem filtresi: {severity!r}")
        allowed_statuses = {"all", "open", "in_progress", "retest_required", "resolved", "reopened", "risk_accepted"}
        if not isinstance(status, str) or status not in allowed_statuses:
            raise ValueError(f"Geçersiz bağımlılık durum filtresi: {status!r}")

        filter_params: tuple[Any, ...] = (
            source,
            source,
            severity,
            severity,
            status,
            status,
            normalized_query,
            normalized_query,
            normalized_query,
            normalized_query,
            normalized_query,
            normalized_query,
        )

        with self._connect() as db:
            if complete_export:
                db.execute("BEGIN")
            filtered_total_row = db.execute(
                """
                SELECT COUNT(*) AS count FROM dependency_findings
                WHERE (? = 'all' OR source = ?)
                  AND (? = 'all' OR severity = ?)
                  AND (? = 'all' OR status = ?)
                  AND (
                      ? = ''
                      OR instr(lower(vulnerability_id), ?) > 0
                      OR instr(lower(package_name), ?) > 0
                      OR instr(lower(installed_version), ?) > 0
                      OR instr(lower(title), ?) > 0
                      OR instr(lower(project_path), ?) > 0
                  )
                """,
                filter_params,
            ).fetchone()
            filtered_total = int(filtered_total_row["count"] if filtered_total_row else 0)
            if complete_export:
                if filtered_total > 10_000:
                    raise DependencyExportTooLarge(
                        f"Bağımlılık dışa aktarımı {filtered_total} bulguyla eşleşiyor; filtreleri 10000 satırın altına daraltın."
                    )
                findings = db.execute(
                    """
                    SELECT * FROM dependency_findings
                    WHERE (? = 'all' OR source = ?)
                      AND (? = 'all' OR severity = ?)
                      AND (? = 'all' OR status = ?)
                      AND (
                          ? = ''
                          OR instr(lower(vulnerability_id), ?) > 0
                          OR instr(lower(package_name), ?) > 0
                          OR instr(lower(installed_version), ?) > 0
                          OR instr(lower(title), ?) > 0
                          OR instr(lower(project_path), ?) > 0
                      )
                    ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
                        WHEN 'low' THEN 3 WHEN 'info' THEN 4 ELSE 5 END, last_seen_at DESC, id ASC
                    """,
                    filter_params,
                ).fetchall()
                report_findings = findings
            else:
                findings = db.execute(
                    """
                    SELECT * FROM dependency_findings
                    WHERE (? = 'all' OR source = ?)
                      AND (? = 'all' OR severity = ?)
                      AND (? = 'all' OR status = ?)
                      AND (
                          ? = ''
                          OR instr(lower(vulnerability_id), ?) > 0
                          OR instr(lower(package_name), ?) > 0
                          OR instr(lower(installed_version), ?) > 0
                          OR instr(lower(title), ?) > 0
                          OR instr(lower(project_path), ?) > 0
                      )
                    ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
                        WHEN 'low' THEN 3 WHEN 'info' THEN 4 ELSE 5 END, last_seen_at DESC, id ASC
                    LIMIT ? OFFSET ?
                    """,
                    (*filter_params, limit, offset),
                ).fetchall()
                report_findings = (
                    findings
                    if offset == 0 and limit >= 500
                    else db.execute(
                        """
                        SELECT * FROM dependency_findings
                        WHERE (? = 'all' OR source = ?)
                          AND (? = 'all' OR severity = ?)
                          AND (? = 'all' OR status = ?)
                          AND (
                              ? = ''
                              OR instr(lower(vulnerability_id), ?) > 0
                              OR instr(lower(package_name), ?) > 0
                              OR instr(lower(installed_version), ?) > 0
                              OR instr(lower(title), ?) > 0
                              OR instr(lower(project_path), ?) > 0
                          )
                        ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
                            WHEN 'low' THEN 3 WHEN 'info' THEN 4 ELSE 5 END, last_seen_at DESC, id ASC
                        LIMIT 500
                        """,
                        filter_params,
                    ).fetchall()
                )
            all_findings = db.execute("SELECT status, severity FROM dependency_findings").fetchall()
            priority_rows = db.execute(
                "SELECT * FROM dependency_findings WHERE status IN ('open', 'in_progress', 'retest_required', 'reopened') "
                "AND priority_score IS NOT NULL ORDER BY priority_score DESC, package_name ASC, installed_version ASC, "
                "vulnerability_id ASC, id ASC LIMIT 20").fetchall()
            tier_rows = db.execute(
                "SELECT priority_tier, COUNT(*) AS n FROM dependency_findings WHERE status IN "
                "('open', 'in_progress', 'retest_required', 'reopened') GROUP BY priority_tier").fetchall()
            imports = db.execute("SELECT * FROM dependency_imports ORDER BY rowid DESC LIMIT 30").fetchall()
            sbom_rows = (
                db.execute("SELECT * FROM dependency_sboms ORDER BY rowid DESC LIMIT 20").fetchall()
                if complete_export
                else None
            )
        normalized_imports = []
        now = datetime.now(timezone.utc)
        for row in imports:
            item = dict(row)
            try:
                source_time = datetime.fromisoformat(item["source_timestamp"].replace("Z", "+00:00"))
                delta = now - source_time.astimezone(timezone.utc)
                item["age_days"] = max(0, delta.days)
                item["stale"] = delta.total_seconds() > 7 * 24 * 3600
            except (TypeError, ValueError):
                item["age_days"] = None
                item["stale"] = True
            normalized_imports.append(item)
        if complete_export:
            normalized_findings = []
            export_bytes = 0
            for row in findings:
                item = self._dependency_finding_dict(row)
                export_bytes += len(json.dumps(item, ensure_ascii=False).encode("utf-8"))
                if export_bytes > 30_000_000:
                    raise DependencyExportTooLarge(
                        "Bağımlılık dışa aktarımı 30 MB'ı aşıyor; dışa aktarmadan önce filtreleri daraltın."
                    )
                normalized_findings.append(item)
            normalized_report_findings = normalized_findings
            sboms = [self._dependency_sbom_dict(row, include_document=False) for row in (sbom_rows or [])]
        else:
            normalized_findings = [self._dependency_finding_dict(row) for row in findings]
            normalized_report_findings = [self._dependency_finding_dict(row) for row in report_findings]
            sboms = self.list_dependency_sboms()
        all_normalized_findings = [dict(row) for row in all_findings]
        active = {"open", "in_progress", "retest_required", "reopened"}
        seen_sources = set()
        stale_sources_count = 0
        for item in normalized_imports:
            key = (item["project_path"], item["source"])
            if key not in seen_sources:
                seen_sources.add(key)
                if item["stale"]:
                    stale_sources_count += 1
        result = {
            "findings": normalized_findings,
            "report_findings": normalized_report_findings,
            "imports": normalized_imports,
            "sboms": sboms,
            "page": {
                "limit": filtered_total if complete_export else limit,
                "offset": 0 if complete_export else offset,
                "returned": len(normalized_findings),
                "filtered_total": filtered_total,
                "has_more": False if complete_export else (offset + len(normalized_findings) < filtered_total),
                "query": query.strip(),
                "source": source,
                "severity": severity,
                "status": status,
            },
            "summary": {
                "total": len(all_normalized_findings),
                "filtered": filtered_total,
                "active": sum(1 for item in all_normalized_findings if item["status"] in active),
                "critical": sum(1 for item in all_normalized_findings if item["status"] in active and item["severity"] == "critical"),
                "high": sum(1 for item in all_normalized_findings if item["status"] in active and item["severity"] == "high"),
                "retest": sum(1 for item in all_normalized_findings if item["status"] in {"retest_required", "reopened"}),
                "in_progress": sum(1 for item in all_normalized_findings if item["status"] == "in_progress"),
                "resolved": sum(1 for item in all_normalized_findings if item["status"] == "resolved"),
                "risk_accepted": sum(1 for item in all_normalized_findings if item["status"] == "risk_accepted"),
                "stale_sources": stale_sources_count,
            },
        }
        tiers = {"fix_first": 0, "plan": 0, "monitor": 0, "unscored": 0}
        for row in tier_rows:
            tiers[row["priority_tier"] if row["priority_tier"] in tiers else "unscored"] += int(row["n"])
        result["priority"] = {
            "tiers": tiers,
            "fix_first": [self._dependency_finding_dict(row) for row in priority_rows],
        }
        if complete_export:
            result["export_complete"] = True
            result["exported_count"] = len(normalized_findings)
        return result

    def apply_dependency_priorities(self, items: list[dict[str, Any]], *, source: str = "osv") -> dict[str, int]:
        """20. tur: erişilebilirlik analizinin öncelik/kullanım sonucunu kayıtlı bulgulara yazar (bulgu kimliği ya da
        içe aktarmadaki parmak izi ile eşleşir). Durum/yaşam döngüsü değişmez; denetim kaydına özet yazılır."""
        now = utc_now()
        updated = 0
        with self._connect() as db:
            for item in items:
                prio = item.get("priority") if isinstance(item.get("priority"), dict) else None
                usage = item.get("usage") if isinstance(item.get("usage"), dict) else {}
                reach = item.get("reachability") if isinstance(item.get("reachability"), dict) else {}
                if not prio:
                    continue
                evidence = [
                    {"file": str(e.get("file") or "")[:300], "line": int(e.get("line") or 0)}
                    for e in (usage.get("evidence") or [])[:5] if isinstance(e, dict)
                ]
                values = (int(prio.get("score") or 0), str(prio.get("tier") or "")[:20], str(usage.get("state") or "")[:20],
                          str(reach.get("verdict") or "")[:30], json.dumps(evidence, ensure_ascii=False), now)
                finding_id = item.get("id") if isinstance(item.get("id"), str) and item["id"].startswith("depfnd") else None
                if finding_id:
                    cursor = db.execute(
                        "UPDATE dependency_findings SET priority_score = ?, priority_tier = ?, usage_state = ?, "
                        "reach_verdict = ?, reach_evidence_json = ?, priority_updated_at = ? WHERE id = ?",
                        (*values, finding_id))
                else:
                    keys = ("project_path", "vulnerability_id", "package_name", "installed_version")
                    if not all(isinstance(item.get(k), str) and item.get(k) for k in keys):
                        continue
                    fingerprint = hashlib.sha256("\0".join((
                        item["project_path"], str(item.get("source") or source), item["vulnerability_id"],
                        item["package_name"], item["installed_version"])).encode("utf-8")).hexdigest()
                    cursor = db.execute(
                        "UPDATE dependency_findings SET priority_score = ?, priority_tier = ?, usage_state = ?, "
                        "reach_verdict = ?, reach_evidence_json = ?, priority_updated_at = ? WHERE fingerprint = ?",
                        (*values, fingerprint))
                updated += cursor.rowcount
        if updated:
            self.log("dependency_priority.updated", "dependency_findings", {"updated": updated})
        return {"updated": updated}

    def update_dependency_finding(self, finding_id: str, *, status: str, resolution_notes: str | None) -> dict | None:
        allowed_statuses = {"open", "in_progress", "retest_required", "resolved", "reopened", "risk_accepted"}
        if not isinstance(status, str) or status not in allowed_statuses:
            raise ValueError(f"Geçersiz yaşam döngüsü durumu: {status!r}")
        with self._connect() as db:
            if resolution_notes is None:
                cursor = db.execute(
                    "UPDATE dependency_findings SET status = ? WHERE id = ?",
                    (status, finding_id),
                )
            else:
                cursor = db.execute(
                    "UPDATE dependency_findings SET status = ?, resolution_notes = ? WHERE id = ?",
                    (status, resolution_notes, finding_id),
                )
            row = db.execute("SELECT * FROM dependency_findings WHERE id = ?", (finding_id,)).fetchone()
        if not cursor.rowcount:
            return None
        self.log("dependency_finding.updated", finding_id, {"status": status})
        return self._dependency_finding_dict(row)

    # -- VEX kararları (17. tur) -------------------------------------------------
    def dependency_findings_for_project(self, project_path: str) -> list[dict]:
        """Bir projenin (tam yol) tüm bağımlılık bulguları; VEX üretimi için sayfasız."""
        with self._connect() as db:
            rows = db.execute(
                "SELECT * FROM dependency_findings WHERE project_path = ? ORDER BY package_name, vulnerability_id, id",
                (project_path,),
            ).fetchall()
        return [self._dependency_finding_dict(row) for row in rows]

    def vex_decisions(self, finding_ids: list[str] | None = None) -> dict[str, dict]:
        """VEX kararları (bulgu kimliği → karar). Tablo küçüktür; sabit sorgu + Python süzgeci (dinamik SQL yok)."""
        with self._connect() as db:
            rows = db.execute("SELECT * FROM dependency_vex_decisions").fetchall()
        wanted = None if finding_ids is None else {str(i) for i in finding_ids}
        return {row["finding_id"]: dict(row) for row in rows if wanted is None or row["finding_id"] in wanted}

    def set_vex_decision(self, finding_id: str, decision: dict[str, str], *, basis: str, author: str = "",
                         source_name: str = "", source_hash: str = "", overwrite_analyst: bool = True) -> dict | None:
        """Kararı yazar (varsa değiştirir). İçe aktarma ``overwrite_analyst=False`` ile analist kararını ezmez."""
        if basis not in {"analyst", "imported"}:
            raise ValueError("Geçersiz VEX kararı dayanağı")
        now = utc_now()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if not db.execute("SELECT 1 FROM dependency_findings WHERE id = ?", (finding_id,)).fetchone():
                return None
            existing = db.execute("SELECT basis FROM dependency_vex_decisions WHERE finding_id = ?", (finding_id,)).fetchone()
            if existing and existing["basis"] == "analyst" and not overwrite_analyst:
                return {"skipped": True, "finding_id": finding_id}
            db.execute(
                """
                INSERT INTO dependency_vex_decisions(
                    finding_id, status, justification, impact_statement, action_statement, status_notes,
                    basis, source_name, source_hash, author, decided_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(finding_id) DO UPDATE SET
                    status = excluded.status, justification = excluded.justification,
                    impact_statement = excluded.impact_statement, action_statement = excluded.action_statement,
                    status_notes = excluded.status_notes, basis = excluded.basis, source_name = excluded.source_name,
                    source_hash = excluded.source_hash, author = excluded.author, decided_at = excluded.decided_at
                """,
                (finding_id, decision["status"], decision.get("justification", ""), decision.get("impact_statement", ""),
                 decision.get("action_statement", ""), decision.get("status_notes", ""), basis, source_name[:200],
                 source_hash[:64], author[:120], now),
            )
            if basis == "analyst":
                self._append_audit_log(db, "dependency_vex.decided", finding_id, json.dumps(
                    {"status": decision["status"], "justification": decision.get("justification", "")}, ensure_ascii=False))
            row = db.execute("SELECT * FROM dependency_vex_decisions WHERE finding_id = ?", (finding_id,)).fetchone()
        return dict(row)

    def clear_vex_decision(self, finding_id: str) -> bool:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            cursor = db.execute("DELETE FROM dependency_vex_decisions WHERE finding_id = ?", (finding_id,))
            if cursor.rowcount:
                self._append_audit_log(db, "dependency_vex.cleared", finding_id, "{}")
        return bool(cursor.rowcount)

    @staticmethod
    def _project_audit_dict(row: sqlite3.Row, *, include_findings: bool) -> dict:
        summary = json.loads(row["summary_json"] or "{}")
        findings = json.loads(row["findings_json"] or "[]")
        result = {
            **summary,
            "id": row["id"], "created_at": row["created_at"],
            "project_path": row["project_path"], "project_name": row["project_name"],
            "score": int(row["score"]), "grade": row["grade"],
            "file_count": int(row["file_count"]), "bytes_scanned": int(row["bytes_scanned"]),
            "finding_count": len(findings),
        }
        if include_findings:
            result["findings"] = findings
        return result

    def create_target(self, target: NormalizedTarget) -> dict:
        with self._connect() as db:
            existing = db.execute("SELECT * FROM targets WHERE url = ?", (target.url,)).fetchone()
            if existing:
                return self._target_dict(existing)
            target_id = self._id("tgt")
            now = utc_now()
            try:
                db.execute(
                    """
                    INSERT INTO targets(id, created_at, url, scheme, hostname, port, path, status, verification_token)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'ready', '')
                    """,
                    (target_id, now, target.url, target.scheme, target.hostname, target.port, target.path),
                )
            except sqlite3.IntegrityError:
                existing = db.execute("SELECT * FROM targets WHERE url = ?", (target.url,)).fetchone()
                if existing:
                    return self._target_dict(existing)
                raise
        self.log("target.created", target_id, {"url": target.url, "ownership_check": "disabled"})
        return self.get_target(target_id)

    def list_targets(self) -> list[dict]:
        with self._connect() as db:
            rows = db.execute(
                """
                SELECT t.*,
                       (SELECT COUNT(*) FROM scans s WHERE s.target_id = t.id) AS scan_count,
                       (SELECT score FROM scans s WHERE s.target_id = t.id AND s.status = 'completed' ORDER BY s.rowid DESC LIMIT 1) AS latest_score,
                       (SELECT grade FROM scans s WHERE s.target_id = t.id AND s.status = 'completed' ORDER BY s.rowid DESC LIMIT 1) AS latest_grade
                FROM targets t ORDER BY t.created_at DESC, t.rowid DESC
                """
            ).fetchall()
        return [self._target_dict(row) for row in rows]

    def get_target(self, target_id: str) -> dict | None:
        with self._connect() as db:
            row = db.execute("SELECT * FROM targets WHERE id = ?", (target_id,)).fetchone()
        return self._target_dict(row) if row else None

    def find_target(self, reference: str) -> dict | None:
        """Kimlik, tam URL veya hostname ile hedef bul (CLI kolaylığı; canlı veriye yazmaz)."""
        target = self.get_target(reference)
        if target:
            return target
        needle = str(reference or "").strip().lower()
        if not needle:
            return None
        with self._connect() as db:
            rows = db.execute(
                "SELECT * FROM targets WHERE lower(hostname) = ? OR rtrim(lower(url), '/') = ? LIMIT 2",
                (needle, needle.rstrip("/")),
            ).fetchall()
        if not rows:
            return None
        if len(rows) == 1:
            return self._target_dict(rows[0])
        raise ValueError(
            f"Belirsiz hedef: '{reference}'. Tam URL veya hedef kimliği kullanın (örnek: https://example.com/path veya tgt_xxx)."
        )

    def latest_completed_pair(self, target_id: str) -> tuple[str, str] | None:
        """Aynı hedefin en yeni tamamlanmış taramasını, ondan kesinlikle daha eski en yakın tamamlanmış taramayla
        (eski, yeni) döndür; yoksa None. compare_scans eşit zamanları reddeder: aynı saniyede biten iki tarama
        "son çift" olarak seçilirse karşılaştırma ve sağlık denetimi yanlışlıkla başarısız olur."""
        with self._connect() as db:
            newest = db.execute(
                "SELECT id, created_at FROM scans WHERE target_id = ? AND status = 'completed' ORDER BY created_at DESC, rowid DESC LIMIT 1",
                (target_id,),
            ).fetchone()
            if newest is None:
                return None
            older = db.execute(
                "SELECT id FROM scans WHERE target_id = ? AND status = 'completed' AND created_at < ? ORDER BY created_at DESC, rowid DESC LIMIT 1",
                (target_id, newest["created_at"]),
            ).fetchone()
        if older is None:
            return None
        return older["id"], newest["id"]

    def create_scan(self, target_id: str) -> dict:
        scan_id = self._id("scn")
        with self._connect() as db:
            db.execute(
                "INSERT INTO scans(id, target_id, status, created_at) VALUES (?, ?, 'queued', ?)",
                (scan_id, target_id, utc_now()),
            )
        self.log("scan.queued", scan_id, {"target_id": target_id, "profile": "safe-baseline-v2"})
        return self.get_scan(scan_id)

    def mark_scan_running(self, scan_id: str) -> None:
        with self._connect() as db:
            db.execute("UPDATE scans SET status = 'running', started_at = ? WHERE id = ?", (utc_now(), scan_id))
        self.log("scan.started", scan_id)

    def complete_scan(self, scan_id: str, result: dict) -> None:
        summary = {key: value for key, value in result.items() if key != "findings"}
        with self._connect() as db:
            db.execute(
                """
                UPDATE scans SET status = 'completed', finished_at = ?, score = ?, grade = ?,
                    findings_json = ?, summary_json = ?, error = NULL WHERE id = ?
                """,
                (
                    utc_now(), result["score"], result["grade"],
                    json.dumps(result["findings"], ensure_ascii=False),
                    json.dumps(summary, ensure_ascii=False), scan_id,
                ),
            )
        self.log("scan.completed", scan_id, {"score": result["score"], "grade": result["grade"]})

    def fail_scan(self, scan_id: str, error: str) -> None:
        with self._connect() as db:
            db.execute(
                "UPDATE scans SET status = 'failed', finished_at = ?, error = ? WHERE id = ?",
                (utc_now(), error[:500], scan_id),
            )
        self.log("scan.failed", scan_id, {"error": error[:240]})

    def list_scans(self, limit: int = 50) -> list[dict]:
        with self._connect() as db:
            rows = db.execute(
                """
                SELECT s.*, s.rowid AS storage_order, t.url AS target_url, t.hostname AS target_hostname
                FROM scans s JOIN targets t ON t.id = s.target_id
                ORDER BY s.rowid DESC LIMIT ?
                """,
                (max(1, min(limit, 200)),),
            ).fetchall()
            scans = []
            for row in rows:
                scan = self._scan_dict(row, include_findings=False)
                scan["comparison"] = self._scan_comparison(db, row, include_details=False)
                scans.append(scan)
        return scans

    def list_scans_page(self, limit: int = 50, offset: int = 0, anchor: int | None = None) -> dict:
        if type(offset) is not int or offset < 0 or offset > 1_000_000:
            raise ValueError("Geçersiz tarama geçmişi başlangıç konumu")
        if anchor is not None and (type(anchor) is not int or anchor < 0 or anchor > 9_223_372_036_854_775_807):
            raise ValueError("Geçersiz tarama geçmişi çapası")
        if type(limit) is not int:
            raise ValueError("Geçersiz tarama geçmişi sınırı")
        page_limit = max(1, min(limit, 200))
        fetch_limit = page_limit + 1
        with self._connect() as db:
            if anchor is None:
                max_row = db.execute("SELECT COALESCE(MAX(rowid), 0) FROM scans").fetchone()
                anchor = int(max_row[0] or 0)
            rows = db.execute(
                """
                SELECT s.*, s.rowid AS storage_order, t.url AS target_url, t.hostname AS target_hostname
                FROM scans s JOIN targets t ON t.id = s.target_id
                WHERE s.rowid <= ?
                ORDER BY s.rowid DESC LIMIT ? OFFSET ?
                """,
                (anchor, fetch_limit, offset),
            ).fetchall()
            has_more = len(rows) > page_limit
            scans = []
            for row in rows[:page_limit]:
                scan = self._scan_dict(row, include_findings=False)
                scan["comparison"] = self._scan_comparison(db, row, include_details=False)
                scans.append(scan)
        return {
            "scans": scans,
            "anchor": anchor,
            "has_more": has_more,
            "next_offset": offset + len(scans) if has_more else None,
        }

    def get_scan(self, scan_id: str) -> dict | None:
        with self._connect() as db:
            row = db.execute(
                """
                SELECT s.*, s.rowid AS storage_order, t.url AS target_url, t.hostname AS target_hostname
                FROM scans s JOIN targets t ON t.id = s.target_id WHERE s.id = ?
                """,
                (scan_id,),
            ).fetchone()
            if not row:
                return None
            scan = self._scan_dict(row, include_findings=True)
            scan["comparison"] = self._scan_comparison(db, row, include_details=True)
        return scan

    def target_trend(self, target_id: str, limit: int = 12) -> dict | None:
        target = self.get_target(target_id)
        if not target:
            return None
        with self._connect() as db:
            rows = db.execute(
                """
                SELECT s.*, s.rowid AS storage_order, t.url AS target_url, t.hostname AS target_hostname
                FROM scans s JOIN targets t ON t.id = s.target_id
                WHERE s.target_id = ? AND s.status = 'completed'
                ORDER BY s.rowid DESC LIMIT ?
                """,
                (target_id, max(1, min(limit, 50))),
            ).fetchall()
            points = []
            earlier: list[tuple[str, str]] = []
            for row in reversed(rows):
                scan = self._scan_dict(row, include_findings=False)
                comparison = self._scan_comparison(db, row, include_details=False)
                point = {
                    "scan_id": scan["id"], "finished_at": scan["finished_at"],
                    "score": scan["score"], "grade": scan["grade"],
                    "finding_count": scan["finding_count"], "comparison": comparison,
                }
                # Scan Diff bağlantıları: trend noktası, bir önceki tamamlanmış taramayla
                # karşılaştırmayı tek tıkla açabilsin (JSON ve yazdırılabilir HTML). Önceki tarama,
                # oluşturulma zamanı kesinlikle daha eski olan en yakın taramadır (eşit zaman reddedilir).
                previous_scan_id = next(
                    (scan_id for scan_id, created_at in reversed(earlier) if str(created_at) < str(row["created_at"])),
                    None,
                )
                if not previous_scan_id:
                    prev_row = db.execute(
                        """
                        SELECT id, created_at, rowid
                        FROM scans
                        WHERE target_id = ? AND status = 'completed' AND created_at < ? AND rowid < ?
                        ORDER BY rowid DESC
                        LIMIT 1
                        """,
                        (target_id, row["created_at"], row["storage_order"]),
                    ).fetchone()
                    if prev_row:
                        previous_scan_id = prev_row["id"]
                if previous_scan_id:
                    base = f"/api/scans/diff/{previous_scan_id}/{scan['id']}"
                    point["diff_links"] = {
                        "previous_scan_id": previous_scan_id,
                        "json": base,
                        "html": f"{base}/report.html",
                        "csv": f"{base}/report.csv",
                    }
                points.append(point)
                earlier.append((scan["id"], row["created_at"]))
        return {"target": target, "points": points}

    def dashboard(self) -> dict:
        with self._connect() as db:
            row = db.execute(
                """
                SELECT
                    (SELECT COUNT(*) FROM targets) AS target_count,
                    (SELECT COUNT(*) FROM targets WHERE status = 'ready') AS ready_count,
                    (SELECT COUNT(*) FROM scans) AS scan_count,
                    (SELECT COUNT(*) FROM scans WHERE status IN ('queued', 'running')) AS active_count,
                    (SELECT CAST(ROUND(AVG(score)) AS INTEGER) FROM scans WHERE status = 'completed') AS average_score,
                    (SELECT COUNT(*) FROM engagements WHERE status = 'active') AS engagement_count,
                    (SELECT COUNT(*) FROM manual_findings WHERE status IN ('open', 'in_progress', 'retest_required', 'reopened')) AS manual_finding_count,
                    (SELECT COUNT(*) FROM manual_findings WHERE status IN ('open', 'in_progress', 'retest_required', 'reopened') AND due_date != '' AND due_date < date('now')) AS overdue_finding_count,
                    (SELECT COUNT(*) FROM manual_findings WHERE status IN ('retest_required', 'reopened')) AS retest_finding_count,
                    (SELECT COUNT(*) FROM lab_runs) AS lab_run_count,
                    (SELECT COUNT(*) FROM dependency_findings WHERE status IN ('open', 'in_progress', 'retest_required', 'reopened')) AS dependency_finding_count
                """
            ).fetchone()
            finding_rows = db.execute(
                "SELECT findings_json FROM scans WHERE status = 'completed' ORDER BY rowid DESC LIMIT 100"
            ).fetchall()
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding_row in finding_rows:
            for finding in json.loads(finding_row["findings_json"] or "[]"):
                if not isinstance(finding, dict):
                    continue
                severity = finding.get("severity", "info")
                if not isinstance(severity, str):
                    severity = "info"
                else:
                    severity = severity.strip().lower()
                    if severity not in {"critical", "high", "medium", "low"}:
                        severity = "info"
                counts[severity] += 1
        return {**dict(row), "average_score": row["average_score"] or 0, "finding_counts": counts}

    def create_engagement(
        self,
        *,
        target_id: str,
        name: str,
        authorization_ref: str,
        scope_notes: str,
        out_of_scope: str,
        test_window: str,
        special_approvals: dict[str, bool],
    ) -> dict:
        engagement_id = self._id("eng")
        now = utc_now()
        # Validate all provided approval values are actual booleans before using
        for key in special_approvals:
            val = special_approvals[key]
            if not isinstance(val, bool):
                raise ValueError("Geçersiz onay değeri: mantıksal değer bekleniyor")

        allowed_keys = {"controlled_lockout", "staging_capacity", "redacted_data_proof"}
        for key in special_approvals:
            if key not in allowed_keys:
                raise ValueError("Geçersiz onay anahtarı")

        approvals = {key: special_approvals.get(key, False) for key in (
            "controlled_lockout", "staging_capacity", "redacted_data_proof",
        )}
        with self._connect() as db:
            db.execute(
                """
                INSERT INTO engagements(
                    id, target_id, name, status, authorization_ref, scope_notes, out_of_scope,
                    test_window, special_approvals_json, created_at, updated_at
                ) VALUES (?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    engagement_id, target_id, name, authorization_ref, scope_notes, out_of_scope,
                    test_window, json.dumps(approvals, ensure_ascii=False), now, now,
                ),
            )
            for control in TEST_CATALOG:
                required = control.get("requires_approval")
                if required and not approvals.get(required):
                    continue
                db.execute(
                    """
                    INSERT INTO manual_tests(
                        id, engagement_id, control_id, category, category_title, title, objective, reference
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        self._id("tst"), engagement_id, control["control_id"], control["category"],
                        control["category_title"], control["title"], control["objective"], control["reference"],
                    ),
                )
        self.log("engagement.created", engagement_id, {"target_id": target_id, "approvals": approvals})
        return self.get_engagement(engagement_id)

    def list_engagements(self) -> list[dict]:
        with self._connect() as db:
            rows = db.execute(
                """
                SELECT e.*, t.url AS target_url, t.hostname AS target_hostname,
                       COALESCE(test_stats.test_count, 0) AS test_count,
                       COALESCE(test_stats.completed_test_count, 0) AS completed_test_count,
                       COALESCE(finding_stats.finding_count, 0) AS finding_count,
                       COALESCE(finding_stats.priority_finding_count, 0) AS priority_finding_count,
                       COALESCE(finding_stats.overdue_finding_count, 0) AS overdue_finding_count,
                       COALESCE(finding_stats.retest_finding_count, 0) AS retest_finding_count
                FROM engagements e
                JOIN targets t ON t.id = e.target_id
                LEFT JOIN (
                    SELECT engagement_id,
                           COUNT(DISTINCT id) AS test_count,
                           COUNT(DISTINCT CASE WHEN status != 'not_tested' THEN id END) AS completed_test_count
                    FROM manual_tests
                    GROUP BY engagement_id
                ) test_stats ON test_stats.engagement_id = e.id
                LEFT JOIN (
                    SELECT engagement_id,
                           COUNT(DISTINCT id) AS finding_count,
                           COUNT(DISTINCT CASE WHEN status IN ('open', 'in_progress', 'retest_required', 'reopened') AND severity IN ('critical', 'high') THEN id END) AS priority_finding_count,
                           COUNT(DISTINCT CASE WHEN status IN ('open', 'in_progress', 'retest_required', 'reopened') AND due_date != '' AND due_date < date('now') THEN id END) AS overdue_finding_count,
                           COUNT(DISTINCT CASE WHEN status IN ('retest_required', 'reopened') THEN id END) AS retest_finding_count
                    FROM manual_findings
                    GROUP BY engagement_id
                ) finding_stats ON finding_stats.engagement_id = e.id
                ORDER BY e.updated_at DESC
                """
            ).fetchall()
        return [self._engagement_dict(row, include_details=False) for row in rows]

    def get_engagement(self, engagement_id: str) -> dict | None:
        with self._connect() as db:
            row = db.execute(
                """
                SELECT e.*, t.url AS target_url, t.hostname AS target_hostname
                FROM engagements e JOIN targets t ON t.id = e.target_id WHERE e.id = ?
                """,
                (engagement_id,),
            ).fetchone()
            if not row:
                return None
            tests = db.execute(
                """SELECT * FROM manual_tests WHERE engagement_id = ? ORDER BY
                   CASE category
                     WHEN 'information' THEN 1 WHEN 'configuration' THEN 2 WHEN 'identity' THEN 3
                     WHEN 'authentication' THEN 4 WHEN 'authorization' THEN 5 WHEN 'session' THEN 6
                     WHEN 'input' THEN 7 WHEN 'server' THEN 8 WHEN 'errors' THEN 9 WHEN 'crypto' THEN 10
                     WHEN 'data' THEN 11 WHEN 'business' THEN 12 WHEN 'client' THEN 13 WHEN 'api' THEN 14
                     WHEN 'infrastructure' THEN 15 WHEN 'supplychain' THEN 16 WHEN 'availability' THEN 17
                     WHEN 'logging' THEN 18 WHEN 'controlled' THEN 19 ELSE 99 END,
                   control_id""",
                (engagement_id,),
            ).fetchall()
            tool_evidence = db.execute(
                "SELECT * FROM tool_evidence_links WHERE engagement_id = ? ORDER BY created_at DESC, id DESC",
                (engagement_id,),
            ).fetchall()
            trivy_evidence = db.execute(
                "SELECT * FROM trivy_tool_evidence_links WHERE engagement_id = ? ORDER BY created_at DESC, id DESC",
                (engagement_id,),
            ).fetchall()
            gitleaks_evidence = db.execute(
                "SELECT * FROM gitleaks_tool_evidence_links WHERE engagement_id = ? ORDER BY created_at DESC, id DESC",
                (engagement_id,),
            ).fetchall()
            nuclei_evidence = db.execute(
                "SELECT * FROM nuclei_tool_evidence_links WHERE engagement_id = ? ORDER BY created_at DESC, id DESC",
                (engagement_id,),
            ).fetchall()
            burp_evidence = db.execute(
                "SELECT * FROM burp_sitemap_tool_evidence_links WHERE engagement_id = ? ORDER BY created_at DESC, id DESC",
                (engagement_id,),
            ).fetchall()
            testssl_evidence = db.execute(
                "SELECT * FROM testssl_tool_evidence_links WHERE engagement_id = ? ORDER BY created_at DESC, id DESC",
                (engagement_id,),
            ).fetchall()
            zap_evidence = db.execute(
                "SELECT * FROM zap_tool_evidence_links WHERE engagement_id = ? ORDER BY created_at DESC, id DESC",
                (engagement_id,),
            ).fetchall()
            semgrep_evidence = db.execute(
                "SELECT * FROM semgrep_tool_evidence_links WHERE engagement_id = ? ORDER BY created_at DESC, id DESC",
                (engagement_id,),
            ).fetchall()
            has_generic_table = db.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'generic_tool_evidence_links'"
            ).fetchone()
            generic_evidence = (
                db.execute(
                    "SELECT * FROM generic_tool_evidence_links WHERE engagement_id = ? ORDER BY created_at DESC, id DESC",
                    (engagement_id,),
                ).fetchall()
                if has_generic_table
                else []
            )
            findings = db.execute(
                "SELECT * FROM manual_findings WHERE engagement_id = ? ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, created_at DESC",
                (engagement_id,),
            ).fetchall()
            latest_scan = db.execute(
                """
                SELECT s.*, t.url AS target_url, t.hostname AS target_hostname
                FROM scans s JOIN targets t ON t.id = s.target_id
                WHERE s.target_id = ? AND s.status = 'completed' ORDER BY s.rowid DESC LIMIT 1
                """,
                (row["target_id"],),
            ).fetchone()
            # Fetch all status history rows for the engagement in one static query while connection is open
            if findings:
                finding_ids = [f["id"] for f in findings]
                history_rows = db.execute(
                    """SELECT h.finding_id, h.from_status, h.to_status, h.occurred_at
                       FROM manual_finding_status_history h
                       JOIN manual_findings f ON f.id = h.finding_id
                       WHERE f.engagement_id = ?
                       ORDER BY h.id ASC""",
                    (engagement_id,),
                ).fetchall()
                history_by_finding = {fid: [] for fid in finding_ids}
                for h in history_rows:
                    if h["finding_id"] in history_by_finding:
                        history_by_finding[h["finding_id"]].append(dict(h))
            else:
                history_by_finding = {}
        result = self._engagement_dict(row, include_details=True)
        result["tests"] = [dict(test) for test in tests]
        result["tool_evidence"] = sorted(
            [dict(link) for link in tool_evidence]
            + [self._trivy_evidence_dict(link) for link in trivy_evidence]
            + [self._gitleaks_evidence_dict(link) for link in gitleaks_evidence]
            + [self._nuclei_evidence_dict(link) for link in nuclei_evidence]
            + [self._burp_sitemap_evidence_dict(link) for link in burp_evidence]
            + [self._testssl_evidence_dict(link) for link in testssl_evidence]
            + [self._zap_evidence_dict(link) for link in zap_evidence]
            + [self._semgrep_evidence_dict(link) for link in semgrep_evidence]
            + [self._generic_evidence_dict(link) for link in generic_evidence],
            key=lambda link: (link["created_at"], link["id"]),
            reverse=True,
        )
        findings_list = []
        for finding in findings:
            f_dict = dict(finding)
            f_dict["status_history"] = history_by_finding.get(finding["id"], [])
            findings_list.append(f_dict)
        result["findings"] = findings_list
        result["latest_scan"] = self._scan_dict(latest_scan, include_findings=True) if latest_scan else None
        result["categories"] = self._coverage_by_category(result["tests"])
        result["coverage"] = self._coverage(result["tests"])
        result["remediation"] = self._remediation_summary(result["findings"])
        return result

    def update_engagement(self, engagement_id: str, updates: dict) -> dict | None:
        allowed = {"name", "status", "authorization_ref", "scope_notes", "out_of_scope", "test_window", "executive_summary"}
        if "status" in updates:
            status = updates["status"]
            if not isinstance(status, str) or status not in ("active", "paused", "completed"):
                raise ValueError("status 'active', 'paused', 'completed' değerlerinden biri olmalı")
        selected = {key: value for key, value in updates.items() if key in allowed}
        if not selected:
            return self.get_engagement(engagement_id)
        with self._connect() as db:
            # Oku-birleştir-yaz tek yazma kilidi altında: eşzamanlı istek 'paused' gibi bir alanı
            # eski satır değeriyle ezemez (kayıp güncelleme yarışı).
            db.execute("BEGIN IMMEDIATE")
            current = db.execute(
                """SELECT name, status, authorization_ref, scope_notes, out_of_scope, test_window, executive_summary
                   FROM engagements WHERE id = ?""",
                (engagement_id,),
            ).fetchone()
            if not current:
                return None
            merged = {**dict(current), **selected}
            db.execute(
                """UPDATE engagements
                   SET name = ?, status = ?, authorization_ref = ?, scope_notes = ?,
                       out_of_scope = ?, test_window = ?, executive_summary = ?, updated_at = ?
                   WHERE id = ?""",
                (
                    merged["name"], merged["status"], merged["authorization_ref"], merged["scope_notes"],
                    merged["out_of_scope"], merged["test_window"], merged["executive_summary"],
                    utc_now(), engagement_id,
                ),
            )
        self.log("engagement.updated", engagement_id, {"fields": sorted(selected)})
        return self.get_engagement(engagement_id)

    @staticmethod
    def _count_engagement_tool_evidence(db: sqlite3.Connection, engagement_id: str) -> int:
        row = db.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM tool_evidence_links WHERE engagement_id = ?) +
                (SELECT COUNT(*) FROM trivy_tool_evidence_links WHERE engagement_id = ?) +
                (SELECT COUNT(*) FROM gitleaks_tool_evidence_links WHERE engagement_id = ?) +
                (SELECT COUNT(*) FROM nuclei_tool_evidence_links WHERE engagement_id = ?) +
                (SELECT COUNT(*) FROM burp_sitemap_tool_evidence_links WHERE engagement_id = ?) +
                (SELECT COUNT(*) FROM testssl_tool_evidence_links WHERE engagement_id = ?) +
                (SELECT COUNT(*) FROM zap_tool_evidence_links WHERE engagement_id = ?) +
                (SELECT COUNT(*) FROM semgrep_tool_evidence_links WHERE engagement_id = ?)
            """,
            (engagement_id,) * 8,
        ).fetchone()
        base_total = int(row[0] or 0)
        has_generic_table = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'generic_tool_evidence_links'"
        ).fetchone()
        if not has_generic_table:
            return base_total
        gen_row = db.execute(
            "SELECT COUNT(*) FROM generic_tool_evidence_links WHERE engagement_id = ?",
            (engagement_id,),
        ).fetchone()
        return base_total + int(gen_row[0] or 0)

    @staticmethod
    def _generic_evidence_dict(row: sqlite3.Row) -> dict:
        result = dict(row)
        summary_fields = json.loads(result.pop("summary_json") or "{}")
        return {**summary_fields, **result}

    def add_generic_tool_evidence(
        self,
        engagement_id: str,
        control_id: str,
        tool_identity: str,
        summary: dict,
        note_label: str,
    ) -> tuple[dict, bool]:
        """Link parser-produced aggregate evidence without persisting the raw source report."""
        now = utc_now()
        digest = summary["report_sha256"]
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("Geçersiz rapor özeti SHA-256.")
        summary_fields = {k: v for k, v in summary.items() if k not in {"format", "report_sha256"}}
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                """CREATE TABLE IF NOT EXISTS generic_tool_evidence_links (
                    id TEXT PRIMARY KEY,
                    engagement_id TEXT NOT NULL,
                    control_id TEXT NOT NULL,
                    tool_identity TEXT NOT NULL,
                    report_sha256 TEXT NOT NULL CHECK(length(report_sha256) = 64),
                    summary_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(engagement_id, control_id) REFERENCES manual_tests(engagement_id, control_id) ON DELETE CASCADE,
                    UNIQUE(engagement_id, control_id, tool_identity, report_sha256)
                )"""
            )
            db.execute(
                "CREATE INDEX IF NOT EXISTS generic_tool_evidence_engagement_idx ON generic_tool_evidence_links(engagement_id, created_at DESC)"
            )
            engagement = db.execute(
                "SELECT status, authorization_ref, special_approvals_json FROM engagements WHERE id = ?",
                (engagement_id,),
            ).fetchone()
            if not engagement:
                raise ValueError("Manuel denetim bulunamadı.")
            approvals = json.loads(engagement["special_approvals_json"] or "{}")
            if (
                engagement["status"] != "active"
                or not engagement["authorization_ref"].strip()
                or not approvals.get("redacted_data_proof")
            ):
                raise ValueError("Etkin, yetkili ve maskeli kanıt onaylı denetim gerekli.")
            test = db.execute(
                "SELECT status FROM manual_tests WHERE engagement_id = ? AND control_id = ?",
                (engagement_id, control_id),
            ).fetchone()
            if not test:
                raise ValueError("Test adımı bulunamadı.")
            existing = db.execute(
                """SELECT * FROM generic_tool_evidence_links
                   WHERE engagement_id = ? AND control_id = ? AND tool_identity = ? AND report_sha256 = ?""",
                (engagement_id, control_id, tool_identity, digest),
            ).fetchone()
            if existing:
                return self._generic_evidence_dict(existing), False
            if self._count_engagement_tool_evidence(db, engagement_id) >= 100:
                raise ValueError("Bu denetimin toplu kanıt bağlantı sınırına ulaşıldı.")
            cursor = db.execute(
                """INSERT INTO generic_tool_evidence_links(
                    id, engagement_id, control_id, tool_identity, report_sha256, summary_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(engagement_id, control_id, tool_identity, report_sha256) DO NOTHING""",
                (
                    self._id("tev"),
                    engagement_id,
                    control_id,
                    tool_identity,
                    digest,
                    json.dumps(summary_fields, sort_keys=True, ensure_ascii=False),
                    now,
                ),
            )
            created = cursor.rowcount == 1
            if created and test["status"] == "not_tested":
                db.execute(
                    """UPDATE manual_tests SET status = 'needs_review', tested_at = ?,
                       notes = CASE WHEN notes = '' THEN ? ELSE notes END,
                       evidence = CASE WHEN evidence = '' THEN ? ELSE evidence END
                       WHERE engagement_id = ? AND control_id = ?""",
                    (
                        now,
                        f"{note_label} toplu kanıtı uzman incelemesi bekliyor.",
                        f"{note_label} özet SHA-256: {digest}",
                        engagement_id,
                        control_id,
                    ),
                )
            if created:
                db.execute("UPDATE engagements SET updated_at = ? WHERE id = ?", (now, engagement_id))
            row = db.execute(
                """SELECT * FROM generic_tool_evidence_links
                   WHERE engagement_id = ? AND control_id = ? AND tool_identity = ? AND report_sha256 = ?""",
                (engagement_id, control_id, tool_identity, digest),
            ).fetchone()
        if created:
            self.log("tool_evidence.linked", engagement_id, {"tool_identity": tool_identity, "control_id": control_id})
        return self._generic_evidence_dict(row), created

    def add_nmap_tool_evidence(self, engagement_id: str, control_id: str, summary: dict) -> tuple[dict, bool]:
        """Link parser-produced aggregate evidence without persisting the source XML.

        The caller supplies only the fixed-schema result of parse_nmap_inline_summary.
        This association records what a user submitted, not proof that the XML was
        produced for the engagement's target.
        """
        now = utc_now()
        digest = summary["report_sha256"]
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            engagement = db.execute(
                "SELECT status, authorization_ref, special_approvals_json FROM engagements WHERE id = ?",
                (engagement_id,),
            ).fetchone()
            if not engagement:
                raise ValueError("Manuel denetim bulunamadı.")
            approvals = json.loads(engagement["special_approvals_json"] or "{}")
            if engagement["status"] != "active" or not engagement["authorization_ref"].strip() or not approvals.get("redacted_data_proof"):
                raise ValueError("Etkin, yetkili ve maskeli kanıt onaylı denetim gerekli.")
            test = db.execute(
                "SELECT status FROM manual_tests WHERE engagement_id = ? AND control_id = ?",
                (engagement_id, control_id),
            ).fetchone()
            if not test:
                raise ValueError("Test adımı bulunamadı.")
            existing = db.execute(
                """SELECT * FROM tool_evidence_links WHERE engagement_id = ? AND control_id = ?
                   AND tool_identity = 'nmap-xml' AND report_sha256 = ?""",
                (engagement_id, control_id, digest),
            ).fetchone()
            if existing:
                return dict(existing), False
            if self._count_engagement_tool_evidence(db, engagement_id) >= 100:
                raise ValueError("Bu denetimin toplu kanıt bağlantı sınırına ulaşıldı.")
            values = (
                self._id("tev"), engagement_id, control_id, "nmap-xml", digest,
                summary["host_count"], summary["up_host_count"], summary["open_port_count"],
                summary["open_protocol_counts"]["tcp"], summary["open_protocol_counts"]["udp"],
                summary["open_port_bands"]["well_known"], summary["open_port_bands"]["registered"],
                summary["open_port_bands"]["dynamic"], now,
            )
            cursor = db.execute(
                """INSERT INTO tool_evidence_links(
                    id, engagement_id, control_id, tool_identity, report_sha256,
                    host_count, up_host_count, open_port_count, open_tcp_count, open_udp_count,
                    well_known_count, registered_count, dynamic_count, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(engagement_id, control_id, tool_identity, report_sha256) DO NOTHING""",
                values,
            )
            created = cursor.rowcount == 1
            if created and test["status"] == "not_tested":
                db.execute(
                    """UPDATE manual_tests SET status = 'needs_review', tested_at = ?,
                       notes = CASE WHEN notes = '' THEN 'Nmap XML toplu kanıtı uzman incelemesi bekliyor.' ELSE notes END,
                       evidence = CASE WHEN evidence = '' THEN ? ELSE evidence END
                       WHERE engagement_id = ? AND control_id = ?""",
                    (now, f"Nmap XML SHA-256: {digest}", engagement_id, control_id),
                )
            if created:
                db.execute("UPDATE engagements SET updated_at = ? WHERE id = ?", (now, engagement_id))
            row = db.execute(
                """SELECT * FROM tool_evidence_links WHERE engagement_id = ? AND control_id = ?
                   AND tool_identity = 'nmap-xml' AND report_sha256 = ?""",
                (engagement_id, control_id, digest),
            ).fetchone()
        if created:
            self.log("tool_evidence.linked", engagement_id, {"tool_identity": "nmap-xml", "control_id": control_id})
        return dict(row), created

    def add_nuclei_tool_evidence(self, engagement_id: str, control_id: str, summary: dict) -> tuple[dict, bool]:
        """Link parser-produced aggregate Nuclei evidence without persisting the source report.

        The caller supplies only the fixed-schema result of parse_nuclei_jsonl_summary.
        This association records what a user submitted, not proof that the report was
        produced for the engagement's target.
        """
        now = utc_now()
        digest = summary["report_sha256"]
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            engagement = db.execute(
                "SELECT status, authorization_ref, special_approvals_json FROM engagements WHERE id = ?",
                (engagement_id,),
            ).fetchone()
            if not engagement:
                raise ValueError("Manuel denetim bulunamadı.")
            approvals = json.loads(engagement["special_approvals_json"] or "{}")
            if engagement["status"] != "active" or not engagement["authorization_ref"].strip() or not approvals.get("redacted_data_proof"):
                raise ValueError("Etkin, yetkili ve maskeli kanıt onaylı denetim gerekli.")
            test = db.execute(
                "SELECT status FROM manual_tests WHERE engagement_id = ? AND control_id = ?",
                (engagement_id, control_id),
            ).fetchone()
            if not test:
                raise ValueError("Test adımı bulunamadı.")
            existing = db.execute(
                """SELECT * FROM nuclei_tool_evidence_links WHERE engagement_id = ? AND control_id = ?
                   AND report_sha256 = ?""",
                (engagement_id, control_id, digest),
            ).fetchone()
            if existing:
                return self._nuclei_evidence_dict(existing), False
            if self._count_engagement_tool_evidence(db, engagement_id) >= 100:
                raise ValueError("Bu denetimin toplu kanıt bağlantı sınırına ulaşıldı.")
            values = (
                self._id("tev"), engagement_id, control_id, "nuclei-jsonl", digest,
                summary["record_count"],
                summary["unique_template_count"],
                json.dumps(summary["severity_counts"], sort_keys=True, ensure_ascii=False),
                now,
            )
            cursor = db.execute(
                """INSERT INTO nuclei_tool_evidence_links(
                    id, engagement_id, control_id, tool_identity, report_sha256,
                    record_count, unique_template_count, severity_counts_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(engagement_id, control_id, report_sha256) DO NOTHING""",
                values,
            )
            created = cursor.rowcount == 1
            if created and test["status"] == "not_tested":
                db.execute(
                    """UPDATE manual_tests SET status = 'needs_review', tested_at = ?,
                       notes = CASE WHEN notes = '' THEN 'Nuclei JSONL toplu kanıtı uzman incelemesi bekliyor.' ELSE notes END,
                       evidence = CASE WHEN evidence = '' THEN ? ELSE evidence END
                       WHERE engagement_id = ? AND control_id = ?""",
                    (now, f"Nuclei JSONL SHA-256: {digest}", engagement_id, control_id),
                )
            if created:
                db.execute("UPDATE engagements SET updated_at = ? WHERE id = ?", (now, engagement_id))
            row = db.execute(
                """SELECT * FROM nuclei_tool_evidence_links WHERE engagement_id = ? AND control_id = ?
                   AND report_sha256 = ?""",
                (engagement_id, control_id, digest),
            ).fetchone()
        if created:
            self.log("tool_evidence.linked", engagement_id, {"tool_identity": "nuclei-jsonl", "control_id": control_id})
        return self._nuclei_evidence_dict(row), created

    @staticmethod
    def _nuclei_evidence_dict(row: sqlite3.Row) -> dict:
        """Expose only fixed aggregate objects, not SQLite serialization fields."""
        result = dict(row)
        result["severity_counts"] = json.loads(result.pop("severity_counts_json"))
        return result

    @staticmethod
    def _burp_sitemap_evidence_dict(row: sqlite3.Row) -> dict:
        """Expose only the validated aggregate, never the source XML."""
        result = dict(row)
        result["status_counts"] = json.loads(result.pop("status_counts_json"))
        result["mimetype_counts"] = json.loads(result.pop("mimetype_counts_json"))
        return result

    @staticmethod
    def _testssl_evidence_dict(row: sqlite3.Row) -> dict:
        """Expose only fixed aggregate counts and the report digest."""
        result = dict(row)
        result["severity_counts"] = json.loads(result.pop("severity_counts_json"))
        return result

    @staticmethod
    def _zap_evidence_dict(row: sqlite3.Row) -> dict:
        """Expose only ZAP aggregate counts and the report digest."""
        result = dict(row)
        result["risk_counts"] = json.loads(result.pop("risk_counts_json"))
        return result

    def add_zap_tool_evidence(self, engagement_id: str, control_id: str, summary: dict) -> tuple[dict, bool]:
        """Link a parsed ZAP traditional JSON aggregate, never the source report."""
        now = utc_now()
        digest = summary["report_sha256"]
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            engagement = db.execute(
                "SELECT status, authorization_ref, special_approvals_json FROM engagements WHERE id = ?",
                (engagement_id,),
            ).fetchone()
            if not engagement:
                raise ValueError("Manuel denetim bulunamadı.")
            approvals = json.loads(engagement["special_approvals_json"] or "{}")
            if engagement["status"] != "active" or not engagement["authorization_ref"].strip() or not approvals.get("redacted_data_proof"):
                raise ValueError("Etkin, yetkili ve maskeli kanıt onaylı denetim gerekli.")
            test = db.execute(
                "SELECT status FROM manual_tests WHERE engagement_id = ? AND control_id = ?",
                (engagement_id, control_id),
            ).fetchone()
            if not test:
                raise ValueError("Test adımı bulunamadı.")
            existing = db.execute(
                "SELECT * FROM zap_tool_evidence_links WHERE engagement_id = ? AND control_id = ? AND report_sha256 = ?",
                (engagement_id, control_id, digest),
            ).fetchone()
            if existing:
                return self._zap_evidence_dict(existing), False
            if self._count_engagement_tool_evidence(db, engagement_id) >= 100:
                raise ValueError("Bu denetimin toplu kanıt bağlantı sınırına ulaşıldı.")
            cursor = db.execute(
                """INSERT INTO zap_tool_evidence_links(
                    id, engagement_id, control_id, tool_identity, report_sha256,
                    site_count, alert_type_count, instance_count, risk_counts_json, created_at
                ) VALUES (?, ?, ?, 'zap-traditional-json', ?, ?, ?, ?, ?, ?)
                ON CONFLICT(engagement_id, control_id, report_sha256) DO NOTHING""",
                (
                    self._id("tev"), engagement_id, control_id, digest,
                    summary["site_count"], summary["alert_type_count"], summary["instance_count"],
                    json.dumps(summary["risk_counts"], sort_keys=True, ensure_ascii=False), now,
                ),
            )
            created = cursor.rowcount == 1
            if created and test["status"] == "not_tested":
                db.execute(
                    """UPDATE manual_tests SET status = 'needs_review', tested_at = ?,
                       notes = CASE WHEN notes = '' THEN 'ZAP JSON toplu kanıtı uzman incelemesi bekliyor.' ELSE notes END,
                       evidence = CASE WHEN evidence = '' THEN ? ELSE evidence END
                       WHERE engagement_id = ? AND control_id = ?""",
                    (now, f"ZAP JSON özet SHA-256: {digest}", engagement_id, control_id),
                )
            if created:
                db.execute("UPDATE engagements SET updated_at = ? WHERE id = ?", (now, engagement_id))
            row = db.execute(
                "SELECT * FROM zap_tool_evidence_links WHERE engagement_id = ? AND control_id = ? AND report_sha256 = ?",
                (engagement_id, control_id, digest),
            ).fetchone()
        if created:
            self.log("tool_evidence.linked", engagement_id, {"tool_identity": "zap-traditional-json", "control_id": control_id})
        return self._zap_evidence_dict(row), created

    def add_testssl_tool_evidence(self, engagement_id: str, control_id: str, summary: dict) -> tuple[dict, bool]:
        """Link parser-produced TestSSL aggregate evidence, never the source report."""
        now = utc_now()
        digest = summary["report_sha256"]
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            engagement = db.execute(
                "SELECT status, authorization_ref, special_approvals_json FROM engagements WHERE id = ?",
                (engagement_id,),
            ).fetchone()
            if not engagement:
                raise ValueError("Manuel denetim bulunamadı.")
            approvals = json.loads(engagement["special_approvals_json"] or "{}")
            if engagement["status"] != "active" or not engagement["authorization_ref"].strip() or not approvals.get("redacted_data_proof"):
                raise ValueError("Etkin, yetkili ve maskeli kanıt onaylı denetim gerekli.")
            test = db.execute(
                "SELECT status FROM manual_tests WHERE engagement_id = ? AND control_id = ?",
                (engagement_id, control_id),
            ).fetchone()
            if not test:
                raise ValueError("Test adımı bulunamadı.")
            existing = db.execute(
                "SELECT * FROM testssl_tool_evidence_links WHERE engagement_id = ? AND control_id = ? AND report_sha256 = ?",
                (engagement_id, control_id, digest),
            ).fetchone()
            if existing:
                return self._testssl_evidence_dict(existing), False
            if self._count_engagement_tool_evidence(db, engagement_id) >= 100:
                raise ValueError("Bu denetimin toplu kanıt bağlantı sınırına ulaşıldı.")
            cursor = db.execute(
                """INSERT INTO testssl_tool_evidence_links(
                    id, engagement_id, control_id, tool_identity, report_sha256,
                    record_count, severity_counts_json, created_at
                ) VALUES (?, ?, ?, 'testssl-flat-json', ?, ?, ?, ?)
                ON CONFLICT(engagement_id, control_id, report_sha256) DO NOTHING""",
                (
                    self._id("tev"), engagement_id, control_id, digest,
                    summary["record_count"],
                    json.dumps(summary["severity_counts"], sort_keys=True, ensure_ascii=False),
                    now,
                ),
            )
            created = cursor.rowcount == 1
            if created and test["status"] == "not_tested":
                db.execute(
                    """UPDATE manual_tests SET status = 'needs_review', tested_at = ?,
                       notes = CASE WHEN notes = '' THEN 'testssl.sh JSON toplu kanıtı uzman incelemesi bekliyor.' ELSE notes END,
                       evidence = CASE WHEN evidence = '' THEN ? ELSE evidence END
                       WHERE engagement_id = ? AND control_id = ?""",
                    (now, f"testssl.sh JSON özet SHA-256: {digest}", engagement_id, control_id),
                )
            if created:
                db.execute("UPDATE engagements SET updated_at = ? WHERE id = ?", (now, engagement_id))
            row = db.execute(
                "SELECT * FROM testssl_tool_evidence_links WHERE engagement_id = ? AND control_id = ? AND report_sha256 = ?",
                (engagement_id, control_id, digest),
            ).fetchone()
        if created:
            self.log("tool_evidence.linked", engagement_id, {"tool_identity": "testssl-flat-json", "control_id": control_id})
        return self._testssl_evidence_dict(row), created

    def add_burp_sitemap_tool_evidence(self, engagement_id: str, control_id: str, summary: dict) -> tuple[dict, bool]:
        """Link a parser-produced Burp sitemap aggregate with explicit user consent.

        The summary digest covers only the aggregate counts. This records a user
        association, not proof that the XML came from the engagement target.
        """
        now = utc_now()
        digest = summary["report_sha256"]
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            engagement = db.execute(
                "SELECT status, authorization_ref, special_approvals_json FROM engagements WHERE id = ?",
                (engagement_id,),
            ).fetchone()
            if not engagement:
                raise ValueError("Manuel denetim bulunamadı.")
            approvals = json.loads(engagement["special_approvals_json"] or "{}")
            if engagement["status"] != "active" or not engagement["authorization_ref"].strip() or not approvals.get("redacted_data_proof"):
                raise ValueError("Etkin, yetkili ve maskeli kanıt onaylı denetim gerekli.")
            test = db.execute(
                "SELECT status FROM manual_tests WHERE engagement_id = ? AND control_id = ?",
                (engagement_id, control_id),
            ).fetchone()
            if not test:
                raise ValueError("Test adımı bulunamadı.")
            existing = db.execute(
                "SELECT * FROM burp_sitemap_tool_evidence_links WHERE engagement_id = ? AND control_id = ? AND report_sha256 = ?",
                (engagement_id, control_id, digest),
            ).fetchone()
            if existing:
                return self._burp_sitemap_evidence_dict(existing), False
            if self._count_engagement_tool_evidence(db, engagement_id) >= 100:
                raise ValueError("Bu denetimin toplu kanıt bağlantı sınırına ulaşıldı.")
            values = (
                self._id("tev"), engagement_id, control_id, "burp-sitemap-xml", digest,
                summary["item_count"],
                json.dumps(summary["status_counts"], sort_keys=True, ensure_ascii=False),
                json.dumps(summary["mimetype_counts"], sort_keys=True, ensure_ascii=False),
                now,
            )
            cursor = db.execute(
                """INSERT INTO burp_sitemap_tool_evidence_links(
                    id, engagement_id, control_id, tool_identity, report_sha256, item_count,
                    status_counts_json, mimetype_counts_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(engagement_id, control_id, report_sha256) DO NOTHING""",
                values,
            )
            created = cursor.rowcount == 1
            if created and test["status"] == "not_tested":
                db.execute(
                    """UPDATE manual_tests SET status = 'needs_review', tested_at = ?,
                       notes = CASE WHEN notes = '' THEN 'Burp Site-map XML toplu kanıtı uzman incelemesi bekliyor.' ELSE notes END,
                       evidence = CASE WHEN evidence = '' THEN ? ELSE evidence END
                       WHERE engagement_id = ? AND control_id = ?""",
                    (now, f"Burp Site-map XML özet SHA-256: {digest}", engagement_id, control_id),
                )
            if created:
                db.execute("UPDATE engagements SET updated_at = ? WHERE id = ?", (now, engagement_id))
            row = db.execute(
                "SELECT * FROM burp_sitemap_tool_evidence_links WHERE engagement_id = ? AND control_id = ? AND report_sha256 = ?",
                (engagement_id, control_id, digest),
            ).fetchone()
        if created:
            self.log("tool_evidence.linked", engagement_id, {"tool_identity": "burp-sitemap-xml", "control_id": control_id})
        return self._burp_sitemap_evidence_dict(row), created

    def add_gitleaks_tool_evidence(self, engagement_id: str, control_id: str, summary: dict) -> tuple[dict, bool]:
        """Link parser-produced aggregate Gitleaks evidence without persisting the source report.

        The caller supplies only the fixed-schema result of parse_gitleaks_json_summary.
        This association records what a user submitted, not proof that the report was
        produced for the engagement's target.
        """
        now = utc_now()
        digest = summary["report_sha256"]
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            engagement = db.execute(
                "SELECT status, authorization_ref, special_approvals_json FROM engagements WHERE id = ?",
                (engagement_id,),
            ).fetchone()
            if not engagement:
                raise ValueError("Manuel denetim bulunamadı.")
            approvals = json.loads(engagement["special_approvals_json"] or "{}")
            if engagement["status"] != "active" or not engagement["authorization_ref"].strip() or not approvals.get("redacted_data_proof"):
                raise ValueError("Etkin, yetkili ve maskeli kanıt onaylı denetim gerekli.")
            test = db.execute(
                "SELECT status FROM manual_tests WHERE engagement_id = ? AND control_id = ?",
                (engagement_id, control_id),
            ).fetchone()
            if not test:
                raise ValueError("Test adımı bulunamadı.")
            existing = db.execute(
                """SELECT * FROM gitleaks_tool_evidence_links WHERE engagement_id = ? AND control_id = ?
                   AND report_sha256 = ?""",
                (engagement_id, control_id, digest),
            ).fetchone()
            if existing:
                return self._gitleaks_evidence_dict(existing), False
            if self._count_engagement_tool_evidence(db, engagement_id) >= 100:
                raise ValueError("Bu denetimin toplu kanıt bağlantı sınırına ulaşıldı.")
            values = (
                self._id("tev"), engagement_id, control_id, "gitleaks-native-json", digest,
                summary["total_findings"], summary["rules_triggered"], summary["files_affected"],
                now,
            )
            cursor = db.execute(
                """INSERT INTO gitleaks_tool_evidence_links(
                    id, engagement_id, control_id, tool_identity, report_sha256,
                    total_findings, rules_triggered, files_affected, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(engagement_id, control_id, report_sha256) DO NOTHING""",
                values,
            )
            created = cursor.rowcount == 1
            if created and test["status"] == "not_tested":
                db.execute(
                    """UPDATE manual_tests SET status = 'needs_review', tested_at = ?,
                       notes = CASE WHEN notes = '' THEN 'Gitleaks JSON toplu kanıtı uzman incelemesi bekliyor.' ELSE notes END,
                       evidence = CASE WHEN evidence = '' THEN ? ELSE evidence END
                       WHERE engagement_id = ? AND control_id = ?""",
                    (now, f"Gitleaks JSON SHA-256: {digest}", engagement_id, control_id),
                )
            if created:
                db.execute("UPDATE engagements SET updated_at = ? WHERE id = ?", (now, engagement_id))
            row = db.execute(
                """SELECT * FROM gitleaks_tool_evidence_links WHERE engagement_id = ? AND control_id = ?
                   AND report_sha256 = ?""",
                (engagement_id, control_id, digest),
            ).fetchone()
        if created:
            self.log("tool_evidence.linked", engagement_id, {"tool_identity": "gitleaks-native-json", "control_id": control_id})
        return self._gitleaks_evidence_dict(row), created

    @staticmethod
    def _gitleaks_evidence_dict(row: sqlite3.Row) -> dict:
        """Expose only fixed aggregate objects, not SQLite serialization fields."""
        return dict(row)

    @staticmethod
    def _semgrep_evidence_dict(row: sqlite3.Row) -> dict:
        result = dict(row)
        result["severity_counts"] = json.loads(result.pop("severity_counts_json"))
        return result

    def add_semgrep_tool_evidence(self, engagement_id: str, control_id: str, summary: dict) -> tuple[dict, bool]:
        """Link a fresh, local Semgrep run using only its fixed aggregate summary."""
        if not isinstance(summary, dict) or set(summary) != {
            "format", "profile", "result_count", "severity_counts", "report_sha256"
        }:
            raise ValueError("Geçersiz Semgrep özeti.")
        digest = summary["report_sha256"]
        count = summary["result_count"]
        severities = summary["severity_counts"]
        if (summary["format"] != "semgrep-native-json" or summary["profile"] != "local-trusted-rules-v1"
                or not isinstance(digest, str) or len(digest) != 64
                or any(char not in "0123456789abcdef" for char in digest)
                or type(count) is not int or not 0 <= count <= 500
                or not isinstance(severities, dict) or set(severities) != SEVERITY_VALUES
                or any(type(value) is not int or value < 0 or value > 500 for value in severities.values())
                or sum(severities.values()) != count):
            raise ValueError("Geçersiz Semgrep özeti.")
        now = utc_now()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            engagement = db.execute(
                "SELECT status, authorization_ref, special_approvals_json FROM engagements WHERE id = ?",
                (engagement_id,),
            ).fetchone()
            if not engagement:
                raise ValueError("Manuel denetim bulunamadı.")
            approvals = json.loads(engagement["special_approvals_json"] or "{}")
            if (engagement["status"] != "active" or not engagement["authorization_ref"].strip()
                    or not approvals.get("redacted_data_proof")):
                raise ValueError("Etkin, yetkili ve maskeli kanıt onaylı denetim gerekli.")
            test = db.execute(
                "SELECT status FROM manual_tests WHERE engagement_id = ? AND control_id = ?",
                (engagement_id, control_id),
            ).fetchone()
            if not test:
                raise ValueError("Test adımı bulunamadı.")
            row = db.execute(
                "SELECT * FROM semgrep_tool_evidence_links WHERE engagement_id = ? AND control_id = ? AND report_sha256 = ?",
                (engagement_id, control_id, digest),
            ).fetchone()
            if row:
                return self._semgrep_evidence_dict(row), False
            if self._count_engagement_tool_evidence(db, engagement_id) >= 100:
                raise ValueError("Bu denetimin toplu kanıt bağlantı sınırına ulaşıldı.")
            db.execute(
                """INSERT INTO semgrep_tool_evidence_links(
                    id, engagement_id, control_id, tool_identity, report_sha256,
                    profile, result_count, severity_counts_json, created_at
                ) VALUES (?, ?, ?, 'semgrep-local', ?, 'local-trusted-rules-v1', ?, ?, ?)""",
                (self._id("tev"), engagement_id, control_id, digest, count,
                 json.dumps(severities, sort_keys=True), now),
            )
            if test["status"] == "not_tested":
                db.execute(
                    """UPDATE manual_tests SET status = 'needs_review', tested_at = ?,
                       notes = CASE WHEN notes = '' THEN 'Yerel Semgrep toplu kanıtı uzman incelemesi bekliyor.' ELSE notes END,
                       evidence = CASE WHEN evidence = '' THEN ? ELSE evidence END
                       WHERE engagement_id = ? AND control_id = ?""",
                    (now, f"Semgrep JSON SHA-256: {digest}", engagement_id, control_id),
                )
            db.execute("UPDATE engagements SET updated_at = ? WHERE id = ?", (now, engagement_id))
            row = db.execute(
                "SELECT * FROM semgrep_tool_evidence_links WHERE engagement_id = ? AND control_id = ? AND report_sha256 = ?",
                (engagement_id, control_id, digest),
            ).fetchone()
        self.log("tool_evidence.linked", engagement_id, {"tool_identity": "semgrep-local", "control_id": control_id})
        return self._semgrep_evidence_dict(row), True

    def add_trivy_tool_evidence(self, engagement_id: str, control_id: str, summary: dict) -> tuple[dict, bool]:
        """Link parser-produced aggregate Trivy evidence without persisting the source report.

        The caller supplies only the fixed-schema result of parse_trivy_native_json_summary.
        This association records what a user submitted, not proof that the report was
        produced for the engagement's target.
        """
        now = utc_now()
        digest = summary["report_sha256"]
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            engagement = db.execute(
                "SELECT status, authorization_ref, special_approvals_json FROM engagements WHERE id = ?",
                (engagement_id,),
            ).fetchone()
            if not engagement:
                raise ValueError("Manuel denetim bulunamadı.")
            approvals = json.loads(engagement["special_approvals_json"] or "{}")
            if engagement["status"] != "active" or not engagement["authorization_ref"].strip() or not approvals.get("redacted_data_proof"):
                raise ValueError("Etkin, yetkili ve maskeli kanıt onaylı denetim gerekli.")
            test = db.execute(
                "SELECT status FROM manual_tests WHERE engagement_id = ? AND control_id = ?",
                (engagement_id, control_id),
            ).fetchone()
            if not test:
                raise ValueError("Test adımı bulunamadı.")
            existing = db.execute(
                """SELECT * FROM trivy_tool_evidence_links WHERE engagement_id = ? AND control_id = ?
                   AND report_sha256 = ?""",
                (engagement_id, control_id, digest),
            ).fetchone()
            if existing:
                return self._trivy_evidence_dict(existing), False
            if self._count_engagement_tool_evidence(db, engagement_id) >= 100:
                raise ValueError("Bu denetimin toplu kanıt bağlantı sınırına ulaşıldı.")
            values = (
                self._id("tev"), engagement_id, control_id, "trivy-native-json", digest,
                summary["result_count"],
                json.dumps(summary["class_counts"], sort_keys=True, ensure_ascii=False),
                json.dumps(summary["vuln_counts"], sort_keys=True, ensure_ascii=False),
                json.dumps(summary["finding_counts"], sort_keys=True, ensure_ascii=False),
                now,
            )
            cursor = db.execute(
                """INSERT INTO trivy_tool_evidence_links(
                    id, engagement_id, control_id, tool_identity, report_sha256,
                    result_count, class_counts_json, vuln_counts_json, finding_counts_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(engagement_id, control_id, report_sha256) DO NOTHING""",
                values,
            )
            created = cursor.rowcount == 1
            if created and test["status"] == "not_tested":
                db.execute(
                    """UPDATE manual_tests SET status = 'needs_review', tested_at = ?,
                       notes = CASE WHEN notes = '' THEN 'Trivy JSON toplu kanıtı uzman incelemesi bekliyor.' ELSE notes END,
                       evidence = CASE WHEN evidence = '' THEN ? ELSE evidence END
                       WHERE engagement_id = ? AND control_id = ?""",
                    (now, f"Trivy JSON SHA-256: {digest}", engagement_id, control_id),
                )
            if created:
                db.execute("UPDATE engagements SET updated_at = ? WHERE id = ?", (now, engagement_id))
            row = db.execute(
                """SELECT * FROM trivy_tool_evidence_links WHERE engagement_id = ? AND control_id = ?
                   AND report_sha256 = ?""",
                (engagement_id, control_id, digest),
            ).fetchone()
        if created:
            self.log("tool_evidence.linked", engagement_id, {"tool_identity": "trivy-native-json", "control_id": control_id})
        return self._trivy_evidence_dict(row), created

    @staticmethod
    def _trivy_evidence_dict(row: sqlite3.Row) -> dict:
        """Expose only fixed aggregate objects, not SQLite serialization fields."""
        result = dict(row)
        for name in ("class_counts", "vuln_counts", "finding_counts"):
            result[name] = json.loads(result.pop(f"{name}_json"))
        return result

    def update_manual_test(self, engagement_id: str, control_id: str, *, status: str, notes: str, evidence: str) -> dict | None:
        VALID_STATUSES = {"not_tested", "passed", "failed", "needs_review", "not_applicable"}
        if status not in VALID_STATUSES:
            raise ValueError(f"Desteklenmeyen elle test durumu: {status!r}")
        with self._connect() as db:
            # old_status/tested_at hesabı yazmayla aynı işlemde (BEGIN IMMEDIATE) yapılır.
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM manual_tests WHERE engagement_id = ? AND control_id = ?",
                (engagement_id, control_id),
            ).fetchone()
            if row:
                old_status = row["status"]
                if status != "not_tested":
                    tested_at = row["tested_at"] if status == old_status and old_status != "not_tested" else utc_now()
                else:
                    tested_at = None
            else:
                tested_at = utc_now() if status != "not_tested" else None
            cursor = db.execute(
                """
                UPDATE manual_tests SET status = ?, notes = ?, evidence = ?, tested_at = ?
                WHERE engagement_id = ? AND control_id = ?
                """,
                (status, notes, evidence, tested_at, engagement_id, control_id),
            )
            row = db.execute(
                "SELECT * FROM manual_tests WHERE engagement_id = ? AND control_id = ?",
                (engagement_id, control_id),
            ).fetchone()
            if cursor.rowcount and row:
                db.execute("UPDATE engagements SET updated_at = ? WHERE id = ?", (utc_now(), engagement_id))
        if not cursor.rowcount or not row:
            return None
        self.log("manual_test.updated", engagement_id, {"control_id": control_id, "status": status})
        return dict(row)

    def create_manual_finding(self, engagement_id: str, finding: dict) -> dict:
        finding_id = self._id("fnd")
        now = utc_now()
        status = finding.get("status", "open")
        resolved_at = now if status == "resolved" else None
        last_retested_at = now if status in {"resolved", "reopened"} else None
        with self._connect() as db:
            db.execute(
                """
                INSERT INTO manual_findings(
                    id, engagement_id, severity, title, affected_asset, description, impact,
                    evidence, reproduction, recommendation, owasp_category, cwe_id, cvss_vector,
                    cvss_score, remediation_owner, due_date, resolution_notes, status,
                    resolved_at, last_retested_at, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding_id, engagement_id, finding["severity"], finding["title"], finding["affected_asset"],
                    finding["description"], finding["impact"], finding["evidence"], finding["reproduction"],
                    finding["recommendation"], finding.get("owasp_category", ""), finding.get("cwe_id", ""),
                    finding.get("cvss_vector", ""), finding.get("cvss_score"),
                    finding.get("remediation_owner", ""), finding.get("due_date", ""),
                    finding.get("resolution_notes", ""), status, resolved_at, last_retested_at, now, now,
                ),
            )
            db.execute("UPDATE engagements SET updated_at = ? WHERE id = ?", (now, engagement_id))
            row = db.execute("SELECT * FROM manual_findings WHERE id = ?", (finding_id,)).fetchone()
        self.log("manual_finding.created", finding_id, {"engagement_id": engagement_id, "severity": finding["severity"]})
        return dict(row)

    def update_manual_finding(self, finding_id: str, updates: dict) -> dict | None:
        allowed = {
            "severity", "title", "affected_asset", "description", "impact", "evidence",
            "reproduction", "recommendation", "owasp_category", "cwe_id", "cvss_vector",
            "cvss_score", "remediation_owner", "due_date", "resolution_notes", "status",
        }
        selected = {key: value for key, value in updates.items() if key in allowed}
        if not selected:
            return None
        new_status = selected.get("status")
        if new_status == "resolved":
            selected["resolved_at"] = utc_now()
            selected["last_retested_at"] = utc_now()
        elif new_status == "reopened":
            selected["resolved_at"] = None
            selected["last_retested_at"] = utc_now()
        elif new_status in {"open", "in_progress", "retest_required", "risk_accepted"}:
            selected["resolved_at"] = None
        with self._connect() as db:
            # Birleştirme ve durum geçmişinin from_status'u aynı yazma kilidi altındaki satırdan gelir.
            db.execute("BEGIN IMMEDIATE")
            row_before = db.execute("SELECT * FROM manual_findings WHERE id = ?", (finding_id,)).fetchone()
            if not row_before:
                return None
            old_status = row_before["status"]
            if new_status and new_status != old_status:
                db.execute(
                    "INSERT INTO manual_finding_status_history (finding_id, occurred_at, from_status, to_status) VALUES (?, ?, ?, ?)",
                    (finding_id, utc_now(), old_status, new_status)
                )
            merged = {**dict(row_before), **selected}
            now = utc_now()
            db.execute(
                """UPDATE manual_findings
                   SET severity = ?, title = ?, affected_asset = ?, description = ?, impact = ?,
                       evidence = ?, reproduction = ?, recommendation = ?, owasp_category = ?,
                       cwe_id = ?, cvss_vector = ?, cvss_score = ?, remediation_owner = ?,
                       due_date = ?, resolution_notes = ?, status = ?, resolved_at = ?,
                       last_retested_at = ?, updated_at = ?
                   WHERE id = ?""",
                (
                    merged["severity"], merged["title"], merged["affected_asset"], merged["description"],
                    merged["impact"], merged["evidence"], merged["reproduction"], merged["recommendation"],
                    merged["owasp_category"], merged["cwe_id"], merged["cvss_vector"], merged["cvss_score"],
                    merged["remediation_owner"], merged["due_date"], merged["resolution_notes"],
                    merged["status"], merged["resolved_at"], merged["last_retested_at"], now, finding_id,
                ),
            )
            db.execute("UPDATE engagements SET updated_at = ? WHERE id = ?", (now, row_before["engagement_id"]))
            row = db.execute("SELECT * FROM manual_findings WHERE id = ?", (finding_id,)).fetchone()
        self.log("manual_finding.updated", finding_id, {"fields": sorted(selected)})
        return dict(row)

    def list_manual_findings(
        self,
        engagement_id: str,
        *,
        status: str = "all",
        severity: str = "all",
    ) -> list[dict]:
        allowed_statuses = {
            "all",
            "active",
            "open",
            "in_progress",
            "retest_required",
            "resolved",
            "reopened",
            "risk_accepted",
        }
        if not isinstance(status, str) or status not in allowed_statuses:
            raise ValueError(f"Geçersiz elle bulgu durum filtresi: {status!r}")
        allowed_severities = {"all", "critical", "high", "medium", "low", "info"}
        if not isinstance(severity, str) or severity not in allowed_severities:
            raise ValueError(f"Geçersiz elle bulgu önem filtresi: {severity!r}")
        engagement = self.get_engagement(engagement_id)
        if not engagement:
            raise ValueError(f"Görev '{engagement_id}' bulunamadı")
        active_statuses = {"open", "in_progress", "retest_required", "reopened"}
        filtered: list[dict] = []
        for finding in engagement.get("findings", []):
            f_status = finding.get("status", "open")
            f_severity = finding.get("severity", "info")
            if status == "active":
                if f_status not in active_statuses:
                    continue
            elif status != "all" and f_status != status:
                continue
            if severity != "all" and f_severity != severity:
                continue
            filtered.append(finding)
        return filtered

    def get_engagement_evidence_provenance(self, engagement_id: str) -> dict | None:
        engagement = self.get_engagement(engagement_id)
        if not engagement:
            return None
        tool_evidence = engagement.get("tool_evidence", [])
        by_tool: dict[str, int] = {}
        by_control: dict[str, int] = {}
        records: list[dict[str, Any]] = []
        for item in tool_evidence:
            tool_id = str(item.get("tool_identity") or "unknown")
            ctrl_id = str(item.get("control_id") or "")
            by_tool[tool_id] = by_tool.get(tool_id, 0) + 1
            if ctrl_id:
                by_control[ctrl_id] = by_control.get(ctrl_id, 0) + 1
            records.append({
                "id": item.get("id"),
                "control_id": ctrl_id,
                "tool_identity": tool_id,
                "report_sha256": item.get("report_sha256"),
                "created_at": item.get("created_at"),
            })
        return {
            "engagement_id": engagement_id,
            "total_count": len(records),
            "by_tool_identity": by_tool,
            "by_control_id": by_control,
            "records": records,
        }

    def create_lab_run(
        self,
        *,
        scenario_type: str,
        name: str,
        environment: str,
        authorization_ref: str,
        assumptions: dict,
        results: dict,
        evidence_summary: str = "",
        engagement_id: str | None = None,
    ) -> dict:
        # Enforce invariant: Sniper-generated traffic/request counts must be zero
        # Normalize results fields based on scenario_type to safe zero values
        normalized_results = dict(results)
        if scenario_type in ("capacity_plan", "lockout_plan"):
            normalized_results["traffic_generated"] = False
            normalized_results["requests_generated"] = 0
        elif scenario_type == "external_result":
            normalized_results["traffic_generated_by_sniper"] = False
            normalized_results["requests_generated_by_sniper"] = 0
        # For other scenario_types, preserve original results fields

        run_id = self._id("lab")
        now = utc_now()
        with self._connect() as db:
            db.execute(
                """
                INSERT INTO lab_runs(
                    id, engagement_id, scenario_type, name, environment, authorization_ref,
                    assumptions_json, results_json, evidence_summary, status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'planned', ?, ?)
                """,
                (
                    run_id, engagement_id, scenario_type, name, environment, authorization_ref,
                    json.dumps(assumptions, ensure_ascii=False, allow_nan=False), json.dumps(normalized_results, ensure_ascii=False, allow_nan=False),
                    evidence_summary, now, now,
                ),
            )
        self.log("lab_run.created", run_id, {
            "scenario_type": scenario_type,
            "environment": environment,
            "traffic_generated": False,
            "requests_generated": 0,
        })
        return self.get_lab_run(run_id)

    def list_lab_runs(self) -> list[dict]:
        with self._connect() as db:
            rows = db.execute(
                """
                SELECT lr.*, e.name AS engagement_name
                FROM lab_runs lr LEFT JOIN engagements e ON e.id = lr.engagement_id
                ORDER BY lr.created_at DESC
                """
            ).fetchall()
        return [self._lab_run_dict(row) for row in rows]

    def get_lab_run(self, run_id: str) -> dict | None:
        with self._connect() as db:
            row = db.execute(
                """
                SELECT lr.*, e.name AS engagement_name
                FROM lab_runs lr LEFT JOIN engagements e ON e.id = lr.engagement_id
                WHERE lr.id = ?
                """,
                (run_id,),
            ).fetchone()
        return self._lab_run_dict(row) if row else None

    def update_lab_run(self, run_id: str, *, status: str, evidence_summary: str) -> dict | None:
        VALID_STATUSES = {"planned", "completed", "cancelled"}
        if not isinstance(status, str) or status not in VALID_STATUSES:
            raise ValueError(f"Geçersiz durum: {status}")
        if evidence_summary is not None and not isinstance(evidence_summary, str):
            raise ValueError("evidence_summary bir metin veya None olmalı")
        with self._connect() as db:
            if evidence_summary is None:
                cursor = db.execute(
                    "UPDATE lab_runs SET status = ?, updated_at = ? WHERE id = ?",
                    (status, utc_now(), run_id),
                )
            else:
                cursor = db.execute(
                    "UPDATE lab_runs SET status = ?, evidence_summary = ?, updated_at = ? WHERE id = ?",
                    (status, evidence_summary, utc_now(), run_id),
                )
        if not cursor.rowcount:
            return None
        self.log("lab_run.updated", run_id, {"status": status})
        return self.get_lab_run(run_id)

    @staticmethod
    def _coverage(tests: list[dict]) -> dict:
        total = len(tests)
        completed = sum(1 for test in tests if test["status"] != "not_tested")
        return {"total": total, "completed": completed, "percent": round((completed / total) * 100) if total else 0}

    @staticmethod
    def _remediation_summary(findings: list[dict]) -> dict:
        active_statuses = {"open", "in_progress", "retest_required", "reopened"}
        today = datetime.now(timezone.utc).date().isoformat()
        active = [finding for finding in findings if finding.get("status") in active_statuses]
        return {
            "total": len(findings),
            "active": len(active),
            "in_progress": sum(1 for finding in findings if finding.get("status") == "in_progress"),
            "retest": sum(1 for finding in findings if finding.get("status") in {"retest_required", "reopened"}),
            "resolved": sum(1 for finding in findings if finding.get("status") == "resolved"),
            "risk_accepted": sum(1 for finding in findings if finding.get("status") == "risk_accepted"),
            "overdue": sum(
                1 for finding in active
                if finding.get("due_date") and finding["due_date"] < today
            ),
        }

    @classmethod
    def _coverage_by_category(cls, tests: list[dict]) -> list[dict]:
        categories = []
        for slug, title, reference in CATEGORIES:
            rows = [test for test in tests if test["category"] == slug]
            if rows:
                categories.append({"slug": slug, "title": title, "reference": reference, **cls._coverage(rows)})
        return categories

    @staticmethod
    def _engagement_dict(row: sqlite3.Row, *, include_details: bool) -> dict:
        data = dict(row)
        data["special_approvals"] = json.loads(data.pop("special_approvals_json", "{}") or "{}")
        if not include_details:
            total = int(data.get("test_count") or 0)
            completed = int(data.get("completed_test_count") or 0)
            data["coverage_percent"] = round((completed / total) * 100) if total else 0
        return data

    def recent_audit_log(self, limit: int = 30) -> list[dict]:
        with self._connect() as db:
            rows = db.execute(
                # prev_hash/entry_hash bilinçli olarak dışarıda: eski `verify_audit_log_chain` farklı
                # formülle karşılaştırıp yanlış alarm üretmesin; zincir için `verify_audit_chain()`.
                "SELECT id, occurred_at, action, entity_id, details_json FROM audit_log ORDER BY id DESC LIMIT ?",
                (max(1, min(limit, 100)),),
            ).fetchall()
        return [
            {**dict(row), "details": json.loads(row["details_json"] or "{}")}
            for row in rows
        ]

    @staticmethod
    def _dependency_sbom_dict(row: sqlite3.Row, *, include_document: bool) -> dict:
        data = dict(row)
        document_json = data.pop("document_json", "{}") or "{}"
        document = json.loads(document_json) if include_document else {}
        if include_document:
            data["document"] = document
        return data

    @staticmethod
    def _dependency_finding_dict(row: sqlite3.Row) -> dict:
        data = dict(row)
        data["references"] = json.loads(data.pop("references_json", "[]") or "[]")
        if "reach_evidence_json" in data:
            data["reach_evidence"] = json.loads(data.pop("reach_evidence_json") or "[]")
        data.pop("fingerprint", None)
        return data

    @staticmethod
    def _lab_run_dict(row: sqlite3.Row) -> dict:
        data = dict(row)
        data["assumptions"] = json.loads(data.pop("assumptions_json", "{}") or "{}")
        data["results"] = json.loads(data.pop("results_json", "{}") or "{}")
        return data

    @staticmethod
    def _target_dict(row: sqlite3.Row) -> dict:
        data = dict(row)
        data.pop("verification_token", None)
        data.pop("verification_proof", None)
        data.pop("verified_at", None)
        return data

    @staticmethod
    def _scan_dict(row: sqlite3.Row, *, include_findings: bool) -> dict:
        data = dict(row)
        data.pop("storage_order", None)
        findings = json.loads(data.pop("findings_json", None) or "[]")
        summary = json.loads(data.pop("summary_json", None) or "{}")
        for key, value in summary.items():
            if key not in data:
                data[key] = value
        if include_findings:
            data["findings"] = findings
        else:
            data["finding_count"] = len(findings)
        return data

    @staticmethod
    def _scan_comparison(db: sqlite3.Connection, row: sqlite3.Row, *, include_details: bool) -> dict | None:
        if row["status"] != "completed":
            return None
        previous = db.execute(
            """
            SELECT s.*, s.rowid AS storage_order
            FROM scans s
            WHERE s.target_id = ? AND s.status = 'completed' AND s.rowid < ?
            ORDER BY s.rowid DESC LIMIT 1
            """,
            (row["target_id"], row["storage_order"]),
        ).fetchone()

        current_findings = json.loads(row["findings_json"] or "[]")
        previous_findings = json.loads(previous["findings_json"] or "[]") if previous else []

        # Canonical helper: deterministic comparison and severity/title/id ordering.
        new_findings, resolved_findings, persistent_findings = _compare_finding_sets(
            previous_findings, current_findings, sort_key=_finding_sort_key
        )

        comparison = {
            "baseline": previous is None,
            "previous_scan_id": previous["id"] if previous else None,
            "previous_finished_at": previous["finished_at"] if previous else None,
            "previous_score": previous["score"] if previous else None,
            "score_delta": (int(row["score"]) - int(previous["score"])) if previous and row["score"] is not None and previous["score"] is not None else None,
            "new_count": len(new_findings),
            "resolved_count": len(resolved_findings),
            "persistent_count": len(persistent_findings),
        }
        if include_details:
            comparison["new_findings"] = new_findings
            comparison["resolved_findings"] = resolved_findings
            comparison["persistent_findings"] = persistent_findings
        return comparison


    def _scan_snapshot(self, scan_id):
        with self._connect() as db:
            row = db.execute(
                """
                SELECT s.*, s.rowid AS storage_order, t.url AS target_url, t.hostname AS target_hostname
                FROM scans s JOIN targets t ON t.id = s.target_id WHERE s.id = ?
                """,
                (scan_id,),
            ).fetchone()
            if not row:
                return None
            scan = self._scan_dict(row, include_findings=True)
            return scan

    def compare_scans(self, scan_id_1, scan_id_2, *, include_details=True):
        # Instance patch (vars) veya class override (type) varsa: get_scan çağrısı kullan
        # Her iki durumda da get_scan çağrısı gerçek bulguları döndürür (veya mock dönüyor)
        if "get_scan" in vars(self) or type(self).get_scan is not Store.get_scan:
            scan_1 = self.get_scan(scan_id_1)
            scan_2 = self.get_scan(scan_id_2)
        else:
            # Normal path: SQL + _scan_dict çalışır
            scan_1 = self._scan_snapshot(scan_id_1)
            scan_2 = self._scan_snapshot(scan_id_2)

        if not scan_1:
            raise ValueError("İlk tarama bulunamadı.")
        if not scan_2:
            raise ValueError("İkinci tarama bulunamadı.")

        if scan_id_1 == scan_id_2:
            raise ValueError("Aynı tarama karşılaştırılamaz.")

        if scan_1["target_id"] != scan_2["target_id"]:
            raise ValueError("Aynı hedefe ait taramalar karşılaştırılmalı.")

        if scan_1["status"] != "completed":
            raise ValueError("İlk tarama 'completed' durumda olmalı.")
        if scan_2["status"] != "completed":
            raise ValueError("İkinci tarama 'completed' durumda olmalı.")

        if scan_1["created_at"] >= scan_2["created_at"]:
            raise ValueError("İlk tarama, ikinci taramadan önce olmalı (eşit zamanlar da kabul edilmez).")

        findings_1 = scan_1.get("findings", [])
        findings_2 = scan_2.get("findings", [])

        new_findings, resolved_findings, persistent_findings = _compare_finding_sets(
            findings_1, findings_2, sort_key=_finding_sort_key
        )

        score_1 = scan_1.get("score")
        score_2 = scan_2.get("score")
        try:
            score_delta = None if score_1 is None or score_2 is None else int(score_2) - int(score_1)
        except (TypeError, ValueError):
            score_delta = None

        summary = {
            "target_id": scan_1["target_id"],
            "target_hostname": scan_1.get("target_hostname"),
            "scan_1_id": scan_id_1,
            "scan_2_id": scan_id_2,
            "scan_1_finished_at": scan_1.get("finished_at"),
            "scan_2_finished_at": scan_2.get("finished_at"),
            "scan_1_score": scan_1.get("score"),
            "scan_2_score": scan_2.get("score"),
            "score_delta": score_delta,
            "new_count": len(new_findings),
            "resolved_count": len(resolved_findings),
            "persistent_count": len(persistent_findings),
            "new_by_severity": _count_by_severity(new_findings),
            "resolved_by_severity": _count_by_severity(resolved_findings),
            "persistent_by_severity": _count_by_severity(persistent_findings),
        }

        result = {"summary": summary}
        if include_details:
            result["new_findings"] = new_findings
            result["resolved_findings"] = resolved_findings
            result["persistent_findings"] = persistent_findings
            result["scan_1"] = {"id": scan_id_1, "score": scan_1.get("score"), "grade": scan_1.get("grade"), "finished_at": scan_1.get("finished_at")}
            result["scan_2"] = {"id": scan_id_2, "score": scan_2.get("score"), "grade": scan_2.get("grade"), "finished_at": scan_2.get("finished_at")}

        return result

    def get_new_findings(self, scan_id_1: str, scan_id_2: str, *, severity_filter: str | None = None) -> list:
        """Yeni bulguları döndür."""
        result = self.compare_scans(scan_id_1, scan_id_2, include_details=True)
        return _filter_by_severity(result["new_findings"], severity_filter)

    def get_resolved_findings(self, scan_id_1: str, scan_id_2: str, *, severity_filter: str | None = None) -> list:
        """Giderilmiş bulguları döndür."""
        result = self.compare_scans(scan_id_1, scan_id_2, include_details=True)
        return _filter_by_severity(result["resolved_findings"], severity_filter)

    def get_persistent_findings(self, scan_id_1: str, scan_id_2: str, *, severity_filter: str | None = None) -> list:
        """Devam eden bulguları döndür."""
        result = self.compare_scans(scan_id_1, scan_id_2, include_details=True)
        return _filter_by_severity(result["persistent_findings"], severity_filter)

    # Geriye uyumlu statik erişim; tek kaynak storage_canonical._count_by_severity.
    _count_by_severity = staticmethod(_count_by_severity)

    @staticmethod
    def _canonical_zap_scope_path(raw: str) -> str:
        from urllib.parse import unquote_to_bytes
        import re
        if not isinstance(raw, str) or not raw.startswith("/") or raw.startswith("//"):
            raise ValueError("Geçersiz ZAP kapsam yolu.")
        try:
            raw.encode("ascii")
            if re.search(r"%2f|%5c", raw, flags=re.IGNORECASE):
                raise ValueError("ZAP kapsam yolunda kodlanmış eğik çizgi yasak.")
            decoded = unquote_to_bytes(raw).decode("utf-8")
        except (UnicodeError, ValueError) as exc:
            raise ValueError("Geçersiz ZAP kapsam yolu.") from exc
        if any(ord(c) < 0x20 or ord(c) == 0x7f for c in decoded):
            raise ValueError("ZAP kapsam yolunda denetim karakterleri yasak.")
        if any(c in decoded for c in ("%", "\\", ";", "?", "#")) or "//" in decoded:
            raise ValueError("ZAP kapsam yolunda belirsiz karakterler yasak.")
        if any(part in (".", "..") for part in decoded.split("/")):
            raise ValueError("ZAP kapsam yolunda nokta bölümleri yasak.")
        if decoded != raw:
            raise ValueError("Kanonik olmayan ZAP kapsam yolu.")
        return decoded

    @staticmethod
    def _parse_utc_iso_epoch(raw: str, label: str = "timestamp") -> float:
        import re
        if not isinstance(raw, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", raw):
            raise ValueError(f"Geçersiz {label}.")
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"Geçersiz {label}.") from exc
        if parsed.tzinfo != timezone.utc:
            raise ValueError(f"Geçersiz {label} saat dilimi.")
        return parsed.timestamp()

    @classmethod
    def _validate_zap_scope_paths(cls, paths: list[str] | tuple[str, ...], *, required: bool) -> list[str]:
        if not isinstance(paths, (list, tuple)) or (required and not paths) or len(paths) > 32:
            raise ValueError("Geçersiz ZAP kapsam yolu listesi.")
        result: list[str] = []
        for item in paths:
            canonical = cls._canonical_zap_scope_path(item)
            result.append(canonical)
        if len(set(result)) != len(result):
            raise ValueError("Yinelenen ZAP kapsam yolu.")
        return result

    @staticmethod
    def _validate_zap_approved_ips(ips: list[str] | tuple[str, ...]) -> list[str]:
        import ipaddress
        from scanner import _is_public_ip
        if not isinstance(ips, (list, tuple)) or not (1 <= len(ips) <= 16):
            raise ValueError("Bir ile on altı arasında onaylı genel IP gerekli.")
        result: list[str] = []
        for raw in ips:
            if not isinstance(raw, str):
                raise ValueError("Geçersiz onaylı IP adresi.")
            try:
                canonical = str(ipaddress.ip_address(raw))
            except ValueError as exc:
                raise ValueError("Geçersiz onaylı IP adresi.") from exc
            if canonical != raw or not _is_public_ip(canonical):
                raise ValueError("Onaylı IP kanonik ve genel değil.")
            result.append(canonical)
        if len(set(result)) != len(result):
            raise ValueError("Yinelenen onaylı IP adresi.")
        return result

    @staticmethod
    def _zap_scan_authorization_dict(row: sqlite3.Row) -> dict:
        data = dict(row)
        data["approved_ips"] = json.loads(data.pop("approved_ips_json", "[]") or "[]")
        data["allowed_paths"] = json.loads(data.pop("allowed_paths_json", "[]") or "[]")
        data["excluded_paths"] = json.loads(data.pop("excluded_paths_json", "[]") or "[]")
        data["allow_query"] = bool(data.get("allow_query"))
        data["active"] = bool(data.get("active"))
        data["lease_generation"] = int(data["lease_generation"])
        return data

    def create_zap_scan_authorization(
        self,
        *,
        engagement_id: str,
        target_id: str,
        requester_principal_id: str,
        approved_by: str,
        allowed_paths: list[str] | tuple[str, ...],
        approved_ips: list[str] | tuple[str, ...],
        not_before: str,
        expires_at: str,
        excluded_paths: list[str] | tuple[str, ...] | None = None,
        allow_query: bool = False,
        job_id: str | None = None,
    ) -> dict:
        import re
        from urllib.parse import urlsplit, urlunsplit
        if not isinstance(requester_principal_id, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,64}", requester_principal_id):
            raise ValueError("Geçersiz requester_principal_id.")
        if not isinstance(approved_by, str) or not approved_by.strip():
            raise ValueError("Geçersiz approved_by.")
        if not isinstance(allow_query, bool):
            raise ValueError("allow_query bir mantıksal değer olmalı.")
        resolved_job_id = job_id if job_id is not None else self._id("zapjob")
        if not isinstance(resolved_job_id, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", resolved_job_id):
            raise ValueError("Geçersiz job_id.")

        clean_allowed = self._validate_zap_scope_paths(allowed_paths, required=True)
        clean_excluded = self._validate_zap_scope_paths(excluded_paths or [], required=False)
        clean_ips = self._validate_zap_approved_ips(approved_ips)
        nb_epoch = self._parse_utc_iso_epoch(not_before, "not_before")
        exp_epoch = self._parse_utc_iso_epoch(expires_at, "expires_at")
        if not (nb_epoch < exp_epoch and (exp_epoch - nb_epoch) <= 3600):
            raise ValueError("ZAP kiralama penceresi pozitif ve en fazla 3600 saniye olmalı.")

        now = utc_now()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE;")
            eng = db.execute("SELECT * FROM engagements WHERE id = ?", (engagement_id,)).fetchone()
            tgt = db.execute("SELECT * FROM targets WHERE id = ?", (target_id,)).fetchone()
            if not eng or not tgt:
                raise ValueError("Kayıtlı görev veya hedef bulunamadı.")
            if eng["target_id"] != target_id or eng["status"] != "active" or tgt["status"] != "ready":
                raise ValueError("Görev ve hedef etkin, hazır ve bağlı olmalı.")
            if not str(eng["authorization_ref"] or "").strip() or not str(eng["scope_notes"] or "").strip():
                raise ValueError("Görev authorization_ref ve scope_notes alanları gerekli.")
            if str(eng["out_of_scope"] or "").strip():
                raise ValueError("Yetkili ZAP iş deposu için görevin out_of_scope alanı boş olmalı.")

            window_raw = str(eng["test_window"] or "")
            parts = window_raw.split("/")
            if len(parts) != 2:
                raise ValueError("Geçersiz görev test_window değeri.")
            eng_start = self._parse_utc_iso_epoch(parts[0], "engagement_start")
            eng_end = self._parse_utc_iso_epoch(parts[1], "engagement_end")
            if not (eng_start < eng_end and (eng_end - eng_start) <= 86400):
                raise ValueError("Geçersiz görev test_window sınırları.")
            if not (eng_start <= nb_epoch < exp_epoch <= eng_end):
                raise ValueError("ZAP kiralaması görev test_window aralığını aşıyor.")

            parsed = urlsplit(tgt["url"])
            origin = urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))
            target_path = self._canonical_zap_scope_path(tgt["path"])
            if not all(
                target_path == "/" or p == target_path or p.startswith(target_path.rstrip("/") + "/")
                for p in clean_allowed
            ):
                raise ValueError("ZAP allowed_paths hedef yolu aşıyor.")

            max_gen_row = db.execute("SELECT COALESCE(MAX(lease_generation), 0) FROM zap_scan_authorizations").fetchone()
            next_gen = int(max_gen_row[0]) + 1

            # Deactivate prior active authorizations for the same engagement so stale generations cannot be replayed.
            db.execute(
                "UPDATE zap_scan_authorizations SET active = 0, updated_at = ? WHERE engagement_id = ? AND active = 1",
                (now, engagement_id),
            )
            db.execute(
                """
                INSERT INTO zap_scan_authorizations(
                    id, engagement_id, target_id, requester_principal_id, approved_by,
                    authorization_ref, root_url, approved_ips_json, allowed_paths_json,
                    excluded_paths_json, allow_query, not_before, expires_at,
                    lease_generation, active, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (
                    resolved_job_id,
                    engagement_id,
                    target_id,
                    requester_principal_id,
                    approved_by.strip(),
                    eng["authorization_ref"],
                    origin,
                    json.dumps(clean_ips, ensure_ascii=True),
                    json.dumps(clean_allowed, ensure_ascii=True),
                    json.dumps(clean_excluded, ensure_ascii=True),
                    1 if allow_query else 0,
                    not_before,
                    expires_at,
                    next_gen,
                    now,
                    now,
                ),
            )
            row = db.execute("SELECT * FROM zap_scan_authorizations WHERE id = ?", (resolved_job_id,)).fetchone()
        self.log(
            "zap_scan_authorization.created",
            resolved_job_id,
            {
                "engagement_id": engagement_id,
                "target_id": target_id,
                "requester_principal_id": requester_principal_id,
                "lease_generation": next_gen,
            },
        )
        return self._zap_scan_authorization_dict(row)

    def get_zap_scan_authorization(self, job_id: str) -> dict | None:
        with self._connect() as db:
            row = db.execute("SELECT * FROM zap_scan_authorizations WHERE id = ?", (job_id,)).fetchone()
        return self._zap_scan_authorization_dict(row) if row else None

    def revoke_zap_scan_authorization(self, job_id: str, *, revoked_by: str = "") -> dict | None:
        now = utc_now()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE;")
            existing = db.execute("SELECT * FROM zap_scan_authorizations WHERE id = ?", (job_id,)).fetchone()
            if not existing:
                return None
            max_gen_row = db.execute("SELECT COALESCE(MAX(lease_generation), 0) FROM zap_scan_authorizations").fetchone()
            next_gen = int(max_gen_row[0]) + 1
            db.execute(
                "UPDATE zap_scan_authorizations SET active = 0, lease_generation = ?, updated_at = ? WHERE id = ?",
                (next_gen, now, job_id),
            )
            row = db.execute("SELECT * FROM zap_scan_authorizations WHERE id = ?", (job_id,)).fetchone()
        self.log(
            "zap_scan_authorization.revoked",
            job_id,
            {"revoked_by": revoked_by, "lease_generation": next_gen},
        )
        return self._zap_scan_authorization_dict(row)

    def verify_zap_scan_authorization(
        self,
        job_id: str,
        *,
        expected_actor: str | None = None,
        expected_generation: int | None = None,
        now_iso: str | None = None,
    ) -> dict:
        import re
        from urllib.parse import urlsplit, urlunsplit
        if not isinstance(job_id, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", job_id):
            raise ValueError("Geçersiz job_id.")
        if expected_actor is not None and (
            not isinstance(expected_actor, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,64}", expected_actor)
        ):
            raise ValueError("Geçersiz expected_actor.")
        if expected_generation is not None and (type(expected_generation) is not int or expected_generation < 1):
            raise ValueError("Geçersiz expected_generation.")

        current_epoch = (
            self._parse_utc_iso_epoch(now_iso, "now_iso")
            if now_iso is not None
            else datetime.now(timezone.utc).timestamp()
        )

        with self._connect() as db:
            mode_row = db.execute("PRAGMA journal_mode").fetchone()
            if not mode_row or str(mode_row[0]).lower() not in ("wal", "delete"):
                raise ValueError("ZAP yetki deposu için desteklenmeyen SQLite günlük kipi.")
            row = db.execute(
                """
                SELECT j.*, e.id AS engagement_record_id, e.target_id AS engagement_target_id,
                       e.status AS engagement_status, e.authorization_ref AS engagement_authorization_ref,
                       e.scope_notes, e.out_of_scope, e.test_window,
                       t.id AS target_record_id, t.url AS target_url, t.scheme AS target_scheme,
                       t.hostname AS target_hostname, t.port AS target_port, t.path AS target_path,
                       t.status AS target_status
                  FROM zap_scan_authorizations j
                  JOIN engagements e ON e.id = j.engagement_id
                  JOIN targets t ON t.id = j.target_id AND t.id = e.target_id
                 WHERE j.id = ?
                """,
                (job_id,),
            ).fetchone()
            max_gen_row = db.execute(
                "SELECT COALESCE(MAX(lease_generation), 0) FROM zap_scan_authorizations WHERE engagement_id = ?",
                (row["engagement_id"],) if row else ("",),
            ).fetchone()

        if not row:
            raise ValueError("Kayıtlı ZAP tarama yetkisi bulunamadı.")
        if (
            row["active"] != 1
            or row["engagement_status"] != "active"
            or row["target_status"] != "ready"
            or not str(row["approved_by"] or "").strip()
            or not str(row["requester_principal_id"] or "").strip()
            or not str(row["scope_notes"] or "").strip()
            or str(row["out_of_scope"] or "").strip()
            or not str(row["engagement_authorization_ref"] or "").strip()
            or row["authorization_ref"] != row["engagement_authorization_ref"]
        ):
            raise ValueError("Kayıtlı ZAP yetkisi veya görev etkin değil ya da yetkisiz.")
        if expected_actor is not None and row["requester_principal_id"] != expected_actor:
            raise ValueError("ZAP yetkisi requester_principal_id uyuşmuyor.")
        lease_gen = int(row["lease_generation"])
        max_gen = int(max_gen_row[0]) if max_gen_row else 0
        if lease_gen < 1 or lease_gen != max_gen:
            raise ValueError("ZAP yetkisi lease_generation bayat.")
        if expected_generation is not None and lease_gen != expected_generation:
            raise ValueError("ZAP yetkisi lease_generation uyuşmuyor.")

        parsed = urlsplit(row["target_url"])
        origin = urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))
        if origin != row["root_url"]:
            raise ValueError("ZAP yetkisi root_url uyuşmuyor.")
        allowed = self._validate_zap_scope_paths(json.loads(row["allowed_paths_json"]), required=True)
        excluded = self._validate_zap_scope_paths(json.loads(row["excluded_paths_json"]), required=False)
        approved_ips = self._validate_zap_approved_ips(json.loads(row["approved_ips_json"]))
        target_path = self._canonical_zap_scope_path(row["target_path"])
        if not all(
            target_path == "/" or p == target_path or p.startswith(target_path.rstrip("/") + "/")
            for p in allowed
        ):
            raise ValueError("ZAP yetki kapsamı hedef yolu aşıyor.")

        window_parts = str(row["test_window"] or "").split("/")
        if len(window_parts) != 2:
            raise ValueError("Geçersiz görev test_window değeri.")
        eng_start = self._parse_utc_iso_epoch(window_parts[0], "engagement_start")
        eng_end = self._parse_utc_iso_epoch(window_parts[1], "engagement_end")
        nb_epoch = self._parse_utc_iso_epoch(row["not_before"], "not_before")
        exp_epoch = self._parse_utc_iso_epoch(row["expires_at"], "expires_at")
        if not (eng_start <= nb_epoch < exp_epoch <= eng_end):
            raise ValueError("ZAP yetki kiralaması görev penceresini aşıyor.")
        if not (nb_epoch <= current_epoch < exp_epoch):
            raise ValueError("ZAP yetki kiralamasının süresi dolmuş veya henüz başlamamış.")

        result = self._zap_scan_authorization_dict(row)
        result["approved_ips"] = approved_ips
        result["allowed_paths"] = allowed
        result["excluded_paths"] = excluded
        return result
