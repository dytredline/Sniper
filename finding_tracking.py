"""Proje analizi bulgularının kalıcı takibi: satır kaymasına dayanıklı parmak izi ve yaşam döngüsü.

Her proje (çözülmüş ``project_path``) için bulgular analizler arasında eşleştirilir:

* Parmak izi satır numarası içermez: kategori + CWE + başlık + dosya + (taint akışında) kaynak→hedef özeti,
  (desen bulgusunda) rakamları ayıklanmış kanıt metni. Kaynak satırı okunmaz/saklanmaz.
* Aynı parmak izli birden çok bulgu (ör. aynı dosyada üç benzer çağrı) en yakın son satırla eşlenir; böylece
  kodun üstüne satır eklemek eşleşmeyi bozmaz.
* Durumlar: ``open``, ``in_progress``, ``fixed`` (yalnız otomatik: sonraki tam analizde yok ve dosya kapsamda),
  ``risk_accepted``, ``false_positive`` (kullanıcı; "bastırılmış" görünür, gizlenmez), ``reopened``.
* "Yalnız atlananlar" ek taramaları (``scope.skipped_only``) temel analize eklenir; hiçbir bulguyu "düzeldi"
  yapmaz. Tam analizde dosya kapsam dışıysa (atlanan dizin, tek dosya sınırı, üretilmiş dosya, bütçe/kodlama
  atlaması, proje kökü yok) bulgu açık kalır.
* İş birliği (16. tur): sorumlu (giriş açıkken kullanıcı kimliği, kapalıyken serbest metin), son tarih
  (``YYYY-MM-DD``, gecikme göstergesi), düz metin yorum dizisi. Değişiklikler olay geçmişine ve (Store üzerinden)
  denetim kaydına yazılır; yorum metni denetim kaydına kopyalanmaz.
* Portföy/SLA (17. tur): risk kabulüne bitiş tarihi (``risk_expires_at``; süre dolunca bulgu ``reopened`` olur,
  olay ``risk_expired``), SLA politikası açıksa yeni bulguya otomatik son tarih ve SLA ihlali hatırlatma işareti
  (``sla_notice``). Politika ve hesaplar ``portfolio.py`` içindedir.
"""
from __future__ import annotations

from datetime import date, datetime, timedelta
import hashlib
import json
from pathlib import Path
import re
import sqlite3
from typing import Any

import scan_scope

STATUSES = ("open", "in_progress", "fixed", "risk_accepted", "false_positive", "reopened")
USER_STATUSES = frozenset({"open", "in_progress", "risk_accepted", "false_positive"})
ACTIVE_STATUSES = frozenset({"open", "in_progress", "reopened"})
SUPPRESSED_STATUSES = frozenset({"risk_accepted", "false_positive"})
STATUS_LABELS = {
    "open": "Açık", "in_progress": "Üzerinde çalışılıyor", "fixed": "Düzeldi", "risk_accepted": "Risk kabulü",
    "false_positive": "Yanlış alarm", "reopened": "Yeniden açıldı",
}
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
PROJECT_WIDE_FILES = frozenset({"", "Proje geneli"})
# Analiz başına triaj kararı → takip durumu (needs_review durumu değiştirmez).
TRIAGE_TO_STATUS = {"false_positive": "false_positive", "accepted_risk": "risk_accepted", "confirmed": "open"}
STATUS_TO_TRIAGE = {"false_positive": "false_positive", "risk_accepted": "accepted_risk"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS tracked_findings (
    id TEXT PRIMARY KEY,
    project_path TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('open', 'in_progress', 'fixed', 'risk_accepted', 'false_positive', 'reopened')),
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    reference TEXT NOT NULL,
    title TEXT NOT NULL,
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    first_seen_at TEXT NOT NULL,
    first_audit_id TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    last_audit_id TEXT NOT NULL,
    fixed_at TEXT,
    fixed_audit_id TEXT,
    status_note TEXT NOT NULL DEFAULT '',
    status_changed_at TEXT,
    seen_count INTEGER NOT NULL DEFAULT 1,
    finding_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS tracked_findings_project_idx ON tracked_findings(project_path, status);
CREATE INDEX IF NOT EXISTS tracked_findings_fp_idx ON tracked_findings(project_path, fingerprint);

CREATE TABLE IF NOT EXISTS tracked_finding_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tracked_id TEXT NOT NULL,
    audit_id TEXT,
    occurred_at TEXT NOT NULL,
    event TEXT NOT NULL,
    from_status TEXT,
    to_status TEXT,
    note TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (tracked_id) REFERENCES tracked_findings(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS tracked_finding_events_idx ON tracked_finding_events(tracked_id, id);

CREATE TABLE IF NOT EXISTS tracked_finding_occurrences (
    audit_id TEXT NOT NULL,
    finding_index INTEGER NOT NULL,
    tracked_id TEXT NOT NULL,
    PRIMARY KEY (audit_id, finding_index),
    FOREIGN KEY (audit_id) REFERENCES project_audits(id) ON DELETE CASCADE,
    FOREIGN KEY (tracked_id) REFERENCES tracked_findings(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS tracked_finding_occurrences_tracked_idx ON tracked_finding_occurrences(tracked_id);

CREATE TABLE IF NOT EXISTS project_audit_tracking (
    audit_id TEXT PRIMARY KEY,
    project_path TEXT NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('full', 'supplement')),
    base_audit_id TEXT,
    recorded_at TEXT NOT NULL,
    new_count INTEGER NOT NULL,
    seen_count INTEGER NOT NULL,
    fixed_count INTEGER NOT NULL,
    reopened_count INTEGER NOT NULL,
    not_rescanned_count INTEGER NOT NULL,
    FOREIGN KEY (audit_id) REFERENCES project_audits(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS project_audit_tracking_project_idx ON project_audit_tracking(project_path, recorded_at);

CREATE TABLE IF NOT EXISTS tracked_finding_comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tracked_id TEXT NOT NULL,
    author_id TEXT,
    author_name TEXT NOT NULL DEFAULT '',
    body TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (tracked_id) REFERENCES tracked_findings(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS tracked_finding_comments_idx ON tracked_finding_comments(tracked_id, id);
"""

# İş birliği sütunları: eski veritabanlarına yalnız eksikse eklenir (mevcut satırlar değişmez).
COLLAB_COLUMNS = (
    ("assignee_id", "ALTER TABLE tracked_findings ADD COLUMN assignee_id TEXT"),
    ("assignee_name", "ALTER TABLE tracked_findings ADD COLUMN assignee_name TEXT NOT NULL DEFAULT ''"),
    ("assigned_at", "ALTER TABLE tracked_findings ADD COLUMN assigned_at TEXT"),
    ("due_date", "ALTER TABLE tracked_findings ADD COLUMN due_date TEXT"),
    ("due_notice", "ALTER TABLE tracked_findings ADD COLUMN due_notice TEXT NOT NULL DEFAULT ''"),
    # 17. tur: risk kabulü bitiş tarihi ve SLA ihlali hatırlatma işareti (yalnız eksikse eklenir).
    ("risk_expires_at", "ALTER TABLE tracked_findings ADD COLUMN risk_expires_at TEXT"),
    ("sla_notice", "ALTER TABLE tracked_findings ADD COLUMN sla_notice TEXT NOT NULL DEFAULT ''"),
)
MAX_ASSIGNEE_NAME = 80
MAX_COMMENT_CHARS = 4000
MAX_COMMENTS_PER_FINDING = 500
DUE_SOON_DAYS = 7  # özet/arayüz "yaklaşan" eşiği (bildirim eşiği ayrı: notifications.finding_due.days_before)
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}\Z")


class TrackingError(ValueError):
    """Geçersiz takip isteği."""


def ensure_schema(db: sqlite3.Connection) -> None:
    db.executescript(SCHEMA)
    columns = {row[1] for row in db.execute("PRAGMA table_info(tracked_findings)")}
    for name, statement in COLLAB_COLUMNS:
        if name not in columns:
            db.execute(statement)
    db.execute("CREATE INDEX IF NOT EXISTS tracked_findings_assignee_idx ON tracked_findings(assignee_id, assignee_name)")


# ---------------------------------------------------------------------------
# Parmak izi
# ---------------------------------------------------------------------------
_DIGITS_RE = re.compile(r"\d+")
_SPACE_RE = re.compile(r"\s+")


def _norm(value: Any) -> str:
    return _SPACE_RE.sub(" ", _DIGITS_RE.sub("#", str(value or ""))).strip().casefold()


def _finding_reference(finding: dict[str, Any]) -> str:
    for key in ("reference", "cwe", "cwe_id", "control_id"):
        raw = finding.get(key)
        if raw is None or isinstance(raw, bool):
            continue
        text = str(raw).strip()
        if not text:
            continue
        if text.isdigit():
            return f"CWE-{text}"
        if text.upper().startswith("CWE-"):
            return "CWE-" + text[4:].strip()
        return text
    return ""


def fingerprint(finding: dict[str, Any]) -> str:
    """Satır numarasından bağımsız parmak izi (sha256, 32 hex)."""
    parts = [
        str(finding.get("category") or ""), _finding_reference(finding), _norm(finding.get("title")),
        str(finding.get("file") or "").replace("\\", "/"),
    ]
    flow = finding.get("taint_flow")
    if isinstance(flow, dict):
        via = flow.get("via") if isinstance(flow.get("via"), list) else []
        parts += [
            "flow", str(flow.get("sink_kind") or ""), str(flow.get("sink") or ""), str(flow.get("source") or ""),
            str(flow.get("source_label") or ""), str(flow.get("source_file") or "").replace("\\", "/"),
            ">".join(str(item) for item in via),
        ]
    else:
        parts += ["pattern", _norm(finding.get("evidence"))]
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:32]


def flow_site_key(finding: dict[str, Any]) -> str | None:
    """Taint akışının kaynaktan bağımsız "yer" anahtarı (ikincil eşleme): kategori + kimlik + başlık + dosya + hedef
    türü/adı. Aynı hedefe birden çok kaynak ulaştığında motorun gösterdiği kaynak değişirse (ör. 19. tura kadar
    karma sırasına bağlı seçim) bulgu yeni sayılmasın, triyaj kararı kaybolmasın diye kullanılır."""
    flow = finding.get("taint_flow")
    if not isinstance(flow, dict):
        return None
    parts = [
        str(finding.get("category") or ""), _finding_reference(finding), _norm(finding.get("title")),
        str(finding.get("file") or "").replace("\\", "/"), "flow-site", str(flow.get("sink_kind") or ""),
        str(flow.get("sink") or ""),
    ]
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:32]


def _line(finding: dict[str, Any]) -> int:
    try:
        return int(finding.get("line") or 0)
    except (TypeError, ValueError):
        return 0


# ---------------------------------------------------------------------------
# Kapsam
# ---------------------------------------------------------------------------
def _scope_of(result: dict[str, Any]) -> scan_scope.ScanScope:
    try:
        return scan_scope.parse_scope(result.get("scope") if isinstance(result.get("scope"), dict) else None)
    except scan_scope.ScopeError:
        return scan_scope.DEFAULT_SCOPE


def file_covered(root: Path, relative: str, scope: scan_scope.ScanScope, skipped: dict[str, Any]) -> bool:
    """Tam analiz bu dosyayı gerçekten inceledi mi? Emin değilsek ``False`` (bulgu açık kalır)."""
    if relative in PROJECT_WIDE_FILES:
        return True
    try:
        if not root.is_dir():
            return False  # proje kökü yok/bağlı değil: hiçbir şey "düzeldi" sayılmaz
        rel = Path(relative)
        if rel.is_absolute() or ".." in rel.parts:
            return False
        if any(part.casefold() in scope.skip_dirs for part in rel.parts[:-1]):
            return False
        path = root / rel
        if not path.exists():
            return True  # dosya silindi: bulgu da gitti
        if path.is_symlink() or not path.is_file():
            return False
        size = path.stat().st_size
    except OSError:
        return False
    name = rel.name.casefold()
    if name.endswith(scan_scope.GENERATED_SUFFIXES) and not scope.include_generated:
        return False
    if size > scope.max_file_bytes:
        return False
    if int(skipped.get("budget") or 0) > 0 or int(skipped.get("time_budget") or 0) > 0:
        return False  # boyut/süre bütçesi aşımında hangi dosyanın atlandığı bilinmiyor
    if int(skipped.get("encoding") or 0) > 0 and not scope.include_non_utf8:
        try:
            with open(path, "rb") as handle:
                handle.read(min(size, scope.max_file_bytes)).decode("utf-8")
        except (OSError, UnicodeDecodeError):
            return False
    return True


# ---------------------------------------------------------------------------
# Kayıt
# ---------------------------------------------------------------------------
def _new_id() -> str:
    import secrets

    return f"trk_{secrets.token_hex(6)}"


def _event(db: sqlite3.Connection, tracked_id: str, audit_id: str | None, when: str, event: str,
           from_status: str | None = None, to_status: str | None = None, note: str = "") -> None:
    db.execute(
        "INSERT INTO tracked_finding_events(tracked_id, audit_id, occurred_at, event, from_status, to_status, note) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (tracked_id, audit_id, when, event, from_status, to_status, note),
    )


def _match(prior: list[sqlite3.Row], current: list[tuple[int, dict[str, Any]]]) -> list[tuple[sqlite3.Row, int, dict]]:
    """Aynı parmak izli önceki kayıtlarla mevcut bulguları en yakın satıra göre eşle (önce düzelmemiş olanlar)."""
    pairs = []
    for row in prior:
        for index, finding in current:
            pairs.append((row["status"] == "fixed", abs(int(row["line"]) - _line(finding)), row["id"], index, row, finding))
    pairs.sort(key=lambda item: item[:4])
    used_rows: set[str] = set()
    used_findings: set[int] = set()
    matched = []
    for _fixed, _distance, row_id, index, row, finding in pairs:
        if row_id in used_rows or index in used_findings:
            continue
        used_rows.add(row_id)
        used_findings.add(index)
        matched.append((row, index, finding))
    return matched


def record_audit(db: sqlite3.Connection, audit_id: str, result: dict[str, Any], *, when: str,
                 sla_days: dict[str, int | None] | None = None) -> dict[str, int]:
    """Yeni proje analizini takip tablolarına işle. Çağıran bir yazma işlemi içindedir.

    ``sla_days`` (önem → gün; SLA politikasında otomatik son tarih açıksa) verilirse yeni bulgulara ilk görülme
    günü + SLA süresi kadar son tarih yazılır (``due_changed`` olayı, not ``sla``)."""
    if db.execute("SELECT 1 FROM project_audit_tracking WHERE audit_id = ?", (audit_id,)).fetchone():
        return {}
    project_path = str(result.get("project_path") or "")
    scope = _scope_of(result)
    mode = "supplement" if scope.skipped_only else "full"
    base_audit_id = result.get("base_audit_id") if isinstance(result.get("base_audit_id"), str) else None
    skipped = result.get("skipped_files") if isinstance(result.get("skipped_files"), dict) else {}
    findings = [f for f in (result.get("findings") or []) if isinstance(f, dict)]

    groups: dict[str, list[tuple[int, dict[str, Any]]]] = {}
    for index, finding in enumerate(findings):
        groups.setdefault(fingerprint(finding), []).append((index, finding))
    prior_rows = db.execute("SELECT * FROM tracked_findings WHERE project_path = ?", (project_path,)).fetchall()
    prior_by_fp: dict[str, list[sqlite3.Row]] = {}
    for row in prior_rows:
        prior_by_fp.setdefault(row["fingerprint"], []).append(row)

    counts = {"new": 0, "seen": 0, "fixed": 0, "reopened": 0, "not_rescanned": 0}
    matched_ids: set[str] = set()

    def seen(row: sqlite3.Row, index: int, finding: dict[str, Any], new_fp: str | None = None) -> None:
        matched_ids.add(row["id"])
        status = row["status"]
        new_status = "reopened" if status == "fixed" else status
        db.execute(
            "UPDATE tracked_findings SET status = ?, severity = ?, title = ?, line = ?, last_seen_at = ?, "
            "last_audit_id = ?, seen_count = seen_count + 1, finding_json = ?, fingerprint = ?, "
            "fixed_at = CASE WHEN ? = 'reopened' AND status = 'fixed' THEN NULL ELSE fixed_at END, "
            "fixed_audit_id = CASE WHEN ? = 'reopened' AND status = 'fixed' THEN NULL ELSE fixed_audit_id END "
            "WHERE id = ?",
            (new_status, str(finding.get("severity") or "info"), str(finding.get("title") or ""), _line(finding),
             when, audit_id, json.dumps(finding, ensure_ascii=False), new_fp or row["fingerprint"], new_status,
             new_status, row["id"]),
        )
        if new_fp and new_fp != row["fingerprint"]:
            _event(db, row["id"], audit_id, when, "source_changed", status, status, note="aynı hedef, farklı kaynak")
        if new_status != status:
            _event(db, row["id"], audit_id, when, "reopened", status, new_status)
            counts["reopened"] += 1
        else:
            counts["seen"] += 1
        db.execute("INSERT OR REPLACE INTO tracked_finding_occurrences(audit_id, finding_index, tracked_id) VALUES (?, ?, ?)",
                   (audit_id, index, row["id"]))

    unmatched: list[tuple[str, int, dict[str, Any]]] = []
    for fp, current in groups.items():
        matched = _match(prior_by_fp.get(fp, []), current)
        matched_indexes = {index for _row, index, _finding in matched}
        for row, index, finding in matched:
            seen(row, index, finding)
        unmatched.extend((fp, index, finding) for index, finding in current if index not in matched_indexes)

    # İkincil eşleme (19. tur): parmak izi tutmayan taint akışı, aynı dosyada aynı hedefe (tür + ad) ulaşan ve bu
    # analizde eşleşmemiş, düzelmemiş bir önceki kayıtla eşleşir (kaynak değişti: kayıt ve triyaj korunur).
    loose_prior: dict[str, list[sqlite3.Row]] = {}
    for row in prior_rows:
        if row["id"] in matched_ids or row["status"] == "fixed":
            continue
        try:
            old_finding = json.loads(row["finding_json"] or "{}")
        except (TypeError, ValueError):
            continue
        key = flow_site_key(old_finding) if isinstance(old_finding, dict) else None
        if key:
            loose_prior.setdefault(key, []).append(row)
    loose_groups: dict[str, list[tuple[int, dict[str, Any]]]] = {}
    fp_of: dict[int, str] = {}
    for fp, index, finding in unmatched:
        fp_of[index] = fp
        key = flow_site_key(finding)
        if key and key in loose_prior:
            loose_groups.setdefault(key, []).append((index, finding))
    loose_matched: set[int] = set()
    for key, current in loose_groups.items():
        for row, index, finding in _match(loose_prior[key], current):
            seen(row, index, finding, new_fp=fp_of[index])
            loose_matched.add(index)

    for fp, index, finding in unmatched:
        if index in loose_matched:
            continue
        tracked_id = _new_id()
        db.execute(
            "INSERT INTO tracked_findings(id, project_path, fingerprint, status, severity, category, reference, title, "
            "file, line, first_seen_at, first_audit_id, last_seen_at, last_audit_id, finding_json) "
            "VALUES (?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (tracked_id, project_path, fp, str(finding.get("severity") or "info"), str(finding.get("category") or ""),
             _finding_reference(finding), str(finding.get("title") or ""), str(finding.get("file") or ""),
             _line(finding), when, audit_id, when, audit_id, json.dumps(finding, ensure_ascii=False)),
        )
        _event(db, tracked_id, audit_id, when, "new", None, "open")
        sla_due = _sla_due_from(when, str(finding.get("severity") or "info"), sla_days)
        if sla_due:
            db.execute("UPDATE tracked_findings SET due_date = ? WHERE id = ?", (sla_due, tracked_id))
            _event(db, tracked_id, audit_id, when, "due_changed", note=f"sla:{sla_due}")
        db.execute("INSERT OR REPLACE INTO tracked_finding_occurrences(audit_id, finding_index, tracked_id) VALUES (?, ?, ?)",
                   (audit_id, index, tracked_id))
        counts["new"] += 1

    # Konteyner ve (20. tur) dış SBOM taramaları: okunan paket veritabanı / SBOM dosyası kapsam sayılır.
    container = result.get("container") if result.get("audit_kind") == "container" else (
        result.get("sbom") if result.get("audit_kind") == "sbom" else None)
    covered_files = set((container or {}).get("covered_files") or []) if isinstance(container, dict) else set()
    # 25. tur: git tabanlı "yalnız değişenler" analizi yalnız değişen dosyaları inceler; değişmeyen dosyadaki bulgu
    # bu analizde görünmedi diye "düzeldi" sayılmaz (yalnız listelenen değişen dosyalar kapsamdadır).
    changed_only_files: set[str] | None = None
    changed_meta = result.get("changed_scan") if isinstance(result.get("changed_scan"), dict) else None
    if scope.changed_only and not scope.base_ref.startswith("prj_") and (changed_meta or {}).get("mode") != "audit":
        changed_only_files = {str(item) for item in (changed_meta or {}).get("changed_files") or []}
    if mode == "full":
        root = Path(project_path)
        for row in prior_rows:
            if row["id"] in matched_ids or row["status"] not in ACTIVE_STATUSES:
                continue
            # Konteyner taraması: paket veritabanı okunduysa o veritabanındaki kaybolan açık düzelmiştir.
            covered = (row["file"] in covered_files) if container is not None else file_covered(root, row["file"], scope, skipped)
            if covered and changed_only_files is not None and row["file"] not in changed_only_files:
                covered = False
            if covered:
                db.execute("UPDATE tracked_findings SET status = 'fixed', fixed_at = ?, fixed_audit_id = ? WHERE id = ?",
                           (when, audit_id, row["id"]))
                _event(db, row["id"], audit_id, when, "fixed", row["status"], "fixed")
                counts["fixed"] += 1
            else:
                counts["not_rescanned"] += 1

    db.execute(
        "INSERT INTO project_audit_tracking(audit_id, project_path, mode, base_audit_id, recorded_at, new_count, seen_count, "
        "fixed_count, reopened_count, not_rescanned_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (audit_id, project_path, mode, base_audit_id, when, counts["new"], counts["seen"], counts["fixed"],
         counts["reopened"], counts["not_rescanned"]),
    )
    return counts


def backfill(db: sqlite3.Connection) -> dict[str, Any]:
    """Takibi hiç olmayan projelerin eski analizlerini tarih sırasıyla işle (isteğe bağlı, tekrar güvenli)."""
    tracked_projects = {row[0] for row in db.execute("SELECT DISTINCT project_path FROM project_audit_tracking")}
    rows = db.execute("SELECT * FROM project_audits ORDER BY created_at, rowid").fetchall()
    processed, skipped_projects = 0, set()
    for row in rows:
        if row["project_path"] in tracked_projects:
            skipped_projects.add(row["project_path"])
            continue
        summary = json.loads(row["summary_json"] or "{}")
        result = {**summary, "project_path": row["project_path"], "findings": json.loads(row["findings_json"] or "[]")}
        record_audit(db, row["id"], result, when=row["created_at"])
        processed += 1
    return {"processed_audits": processed, "skipped_projects_already_tracked": len(skipped_projects)}


# ---------------------------------------------------------------------------
# Okuma
# ---------------------------------------------------------------------------
def today_local() -> date:
    """Son tarih karşılaştırmaları için yerel gün (zamanlayıcının saat dilimi; varsayılan Europe/Istanbul)."""
    try:
        import scheduler

        return datetime.now(scheduler.zone(scheduler.timezone_name())).date()
    except Exception:  # veri dizini/saat dilimi yoksa sistem yerel günü
        return date.today()


def due_state(due_date: str | None, status: str, today: date | None = None) -> tuple[bool, int | None]:
    """(gecikmiş mi, kalan gün). Yalnız etkin bulgularda gecikme olur; tarih yoksa (False, None)."""
    if not due_date:
        return False, None
    try:
        due = date.fromisoformat(due_date)
    except ValueError:
        return False, None
    remaining = (due - (today or today_local())).days
    return status in ACTIVE_STATUSES and remaining < 0, remaining


def _collab_fields(row: sqlite3.Row, today: date | None = None) -> dict[str, Any]:
    overdue, remaining = due_state(row["due_date"], row["status"], today)
    return {
        "assignee_id": row["assignee_id"], "assignee_name": row["assignee_name"] or "", "assigned_at": row["assigned_at"],
        "due_date": row["due_date"], "overdue": overdue, "due_in_days": remaining,
    }


def _tracked_dict(row: sqlite3.Row, *, include_finding: bool = False, today: date | None = None) -> dict[str, Any]:
    data = {
        key: row[key] for key in (
            "id", "project_path", "fingerprint", "status", "severity", "category", "reference", "title", "file", "line",
            "first_seen_at", "first_audit_id", "last_seen_at", "last_audit_id", "fixed_at", "fixed_audit_id",
            "status_note", "status_changed_at", "seen_count",
        )
    }
    data["status_label"] = STATUS_LABELS.get(row["status"], row["status"])
    data["suppressed"] = row["status"] in SUPPRESSED_STATUSES
    data.update(_collab_fields(row, today))
    data["risk_expires_at"] = row["risk_expires_at"] if row["status"] == "risk_accepted" else None
    finding = json.loads(row["finding_json"] or "{}")
    # 21. tur: rapor alanı (report_sections) ve bulgu türü — yönetici özeti/portföy aynı sınıflandırmayı kullanır
    import report_sections

    data["section"] = report_sections.section_of({"finding": finding, "category": row["category"], "title": row["title"]})
    data["verified_flow"] = bool(finding.get("taint_flow")) and str(finding.get("title") or "").startswith("Doğrulanmış")
    data["malicious"] = report_sections.is_malicious(finding) or report_sections.is_malicious(data)
    if include_finding:
        data["finding"] = finding
    return data


def tracking_for_audit(db: sqlite3.Connection, audit_id: str) -> dict[int, dict[str, Any]]:
    rows = db.execute(
        "SELECT o.finding_index, t.* FROM tracked_finding_occurrences o JOIN tracked_findings t ON t.id = o.tracked_id "
        "WHERE o.audit_id = ?",
        (audit_id,),
    ).fetchall()
    out = {}
    today = today_local()
    for row in rows:
        info = _tracked_dict(row, today=today)
        info["is_new"] = row["first_audit_id"] == audit_id
        out[int(row["finding_index"])] = {key: info[key] for key in (
            "id", "status", "status_label", "suppressed", "is_new", "first_seen_at", "first_audit_id", "seen_count",
            "status_note", "assignee_id", "assignee_name", "due_date", "overdue",
        )}
    return out


def audit_tracking_counts(db: sqlite3.Connection, audit_id: str) -> dict[str, Any] | None:
    row = db.execute("SELECT * FROM project_audit_tracking WHERE audit_id = ?", (audit_id,)).fetchone()
    if not row:
        return None
    return {key: row[key] for key in ("mode", "base_audit_id", "new_count", "seen_count", "fixed_count", "reopened_count",
                                      "not_rescanned_count")}


def list_tracked(db: sqlite3.Connection, project_path: str, statuses: set[str] | None = None,
                 limit: int = 500) -> list[dict[str, Any]]:
    if statuses and not statuses <= set(STATUSES):
        raise TrackingError("Geçersiz durum filtresi.")
    rows = db.execute("SELECT * FROM tracked_findings WHERE project_path = ?", (project_path,)).fetchall()
    today = today_local()
    items = [_tracked_dict(row, today=today) for row in rows if not statuses or row["status"] in statuses]
    items.sort(key=lambda item: (item["status"] == "fixed", item["suppressed"], SEVERITY_RANK.get(item["severity"], 9),
                                 item["first_seen_at"], item["file"], item["line"]))
    return items[: max(1, min(limit, 5000))]


def get_tracked(db: sqlite3.Connection, tracked_id: str) -> dict[str, Any] | None:
    row = db.execute("SELECT * FROM tracked_findings WHERE id = ?", (tracked_id,)).fetchone()
    if not row:
        return None
    data = _tracked_dict(row, include_finding=True)
    data["events"] = [
        {key: event[key] for key in ("occurred_at", "audit_id", "event", "from_status", "to_status", "note")}
        for event in db.execute("SELECT * FROM tracked_finding_events WHERE tracked_id = ? ORDER BY id", (tracked_id,))
    ]
    data["comments"] = list_comments(db, tracked_id)
    return data


def list_projects(db: sqlite3.Connection) -> list[dict[str, Any]]:
    out = []
    for row in db.execute("SELECT project_path, status, COUNT(*) AS n FROM tracked_findings GROUP BY project_path, status"):
        entry = next((item for item in out if item["project_path"] == row["project_path"]), None)
        if entry is None:
            entry = {"project_path": row["project_path"], "counts": {status: 0 for status in STATUSES}}
            out.append(entry)
        entry["counts"][row["status"]] = int(row["n"])
    for entry in out:
        last = db.execute(
            "SELECT p.project_name, p.created_at FROM project_audit_tracking t JOIN project_audits p ON p.id = t.audit_id "
            "WHERE t.project_path = ? ORDER BY t.recorded_at DESC, t.rowid DESC LIMIT 1",
            (entry["project_path"],),
        ).fetchone()
        entry["project_name"] = last["project_name"] if last else Path(entry["project_path"]).name
        entry["last_audit_at"] = last["created_at"] if last else None
        entry["active"] = sum(entry["counts"][status] for status in ACTIVE_STATUSES)
    out.sort(key=lambda item: item["last_audit_at"] or "", reverse=True)
    return out


def set_status(db: sqlite3.Connection, tracked_id: str, status: str, note: str, *, when: str,
               expires_at: str | None = None, default_risk_days: int = 0) -> dict[str, Any]:
    """Kullanıcı durumu. Risk kabulünde bitiş tarihi: ``expires_at`` (YYYY-MM-DD, bugünden sonra) ya da politika
    varsayılanı (``default_risk_days`` > 0 ise bugün + gün). Başka duruma geçişte bitiş tarihi silinir."""
    if status not in USER_STATUSES:
        raise TrackingError("Durum şunlardan biri olmalı: " + ", ".join(sorted(USER_STATUSES)))
    if not isinstance(note, str) or len(note) > 2000 or "\x00" in note:
        raise TrackingError("Not en fazla 2000 karakterlik metin olmalı.")
    row = db.execute("SELECT * FROM tracked_findings WHERE id = ?", (tracked_id,)).fetchone()
    if not row:
        raise LookupError("Takip edilen bulgu bulunamadı.")
    if row["status"] == "fixed" and status in {"open", "in_progress"}:
        raise TrackingError("Düzelmiş bulgu elle açılamaz; yeniden görülürse otomatik olarak yeniden açılır.")
    if expires_at not in (None, "") and status != "risk_accepted":
        raise TrackingError("Bitiş tarihi (expires_at) yalnız risk kabulünde verilebilir.")
    expiry = risk_expiry(expires_at, default_risk_days) if status == "risk_accepted" else None
    db.execute("UPDATE tracked_findings SET status = ?, status_note = ?, status_changed_at = ?, risk_expires_at = ? WHERE id = ?",
               (status, note.strip(), when, expiry, tracked_id))
    event_note = note.strip() + (f" (bitiş {expiry})" if expiry else "")
    _event(db, tracked_id, None, when, "status_changed", row["status"], status, event_note.strip())
    return get_tracked(db, tracked_id) or {}


def risk_expiry(expires_at: Any, default_risk_days: int = 0, today: date | None = None) -> str | None:
    """Risk kabulü bitiş tarihi: açık tarih (bugünden sonra, en çok 5 yıl) ya da politika varsayılanı; yoksa None."""
    today = today or today_local()
    if expires_at in (None, ""):
        if default_risk_days and default_risk_days > 0:
            return (today + timedelta(days=int(default_risk_days))).isoformat()
        return None
    if not isinstance(expires_at, str) or not _DATE_RE.fullmatch(expires_at):
        raise TrackingError("Bitiş tarihi YYYY-AA-GG biçiminde olmalı.")
    try:
        parsed = date.fromisoformat(expires_at)
    except ValueError:
        raise TrackingError("Geçersiz bitiş tarihi.") from None
    if parsed <= today:
        raise TrackingError("Risk kabulünün bitiş tarihi bugünden sonra olmalı.")
    if parsed > today + timedelta(days=5 * 366):
        raise TrackingError("Risk kabulünün bitiş tarihi en çok 5 yıl sonrası olabilir.")
    return parsed.isoformat()


def sync_triage(db: sqlite3.Connection, audit_id: str, finding_index: int, disposition: str, note: str, *, when: str,
                default_risk_days: int = 0) -> None:
    """Analiz başına triaj kararı takip durumuna yansır (sonraki analizlere taşınır)."""
    status = TRIAGE_TO_STATUS.get(disposition)
    if not status:
        return
    row = db.execute(
        "SELECT t.id, t.status FROM tracked_finding_occurrences o JOIN tracked_findings t ON t.id = o.tracked_id "
        "WHERE o.audit_id = ? AND o.finding_index = ?",
        (audit_id, finding_index),
    ).fetchone()
    if not row or row["status"] == "fixed":
        return
    if status == "open" and row["status"] in ACTIVE_STATUSES:
        return  # "doğrulandı" etkin bulguyu değiştirmez
    if row["status"] == status:
        return
    expiry = risk_expiry(None, default_risk_days) if status == "risk_accepted" else None
    db.execute("UPDATE tracked_findings SET status = ?, status_note = ?, status_changed_at = ?, risk_expires_at = ? WHERE id = ?",
               (status, note.strip(), when, expiry, row["id"]))
    _event(db, row["id"], audit_id, when, "triage", row["status"], status, note.strip())


# ---------------------------------------------------------------------------
# Özet
# ---------------------------------------------------------------------------
def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def project_summary(db: sqlite3.Connection, project_path: str, *, trend_limit: int = 10,
                    as_of_audit_id: str | None = None) -> dict[str, Any]:
    rows = db.execute("SELECT * FROM tracked_findings WHERE project_path = ?", (project_path,)).fetchall()
    counts = {status: 0 for status in STATUSES}
    active_by_severity = {severity: 0 for severity in SEVERITY_RANK}
    fix_hours = []
    today = today_local()
    ownership = {"assigned_active": 0, "unassigned_active": 0, "overdue": 0, "due_soon": 0}
    deadlines = []
    for row in rows:
        counts[row["status"]] += 1
        if row["status"] in ACTIVE_STATUSES:
            active_by_severity[row["severity"] if row["severity"] in active_by_severity else "info"] += 1
            ownership["assigned_active" if (row["assignee_id"] or row["assignee_name"]) else "unassigned_active"] += 1
            overdue, remaining = due_state(row["due_date"], row["status"], today)
            if overdue:
                ownership["overdue"] += 1
            elif remaining is not None and remaining <= DUE_SOON_DAYS:
                ownership["due_soon"] += 1
            if row["due_date"]:
                deadlines.append({key: row[key] for key in ("id", "severity", "title", "file", "line", "status", "due_date")}
                                 | {"assignee_name": row["assignee_name"] or "", "overdue": overdue, "due_in_days": remaining,
                                    "status_label": STATUS_LABELS.get(row["status"], row["status"])})
        if row["status"] == "fixed":
            start, end = _parse_time(row["first_seen_at"]), _parse_time(row["fixed_at"])
            if start and end and end >= start:
                fix_hours.append((end - start).total_seconds() / 3600)
    trend_rows = db.execute(
        "SELECT t.*, p.created_at AS audit_created_at, p.score, p.grade FROM project_audit_tracking t "
        "JOIN project_audits p ON p.id = t.audit_id WHERE t.project_path = ? ORDER BY t.recorded_at DESC, t.rowid DESC LIMIT ?",
        (project_path, max(1, min(trend_limit, 100))),
    ).fetchall()
    trend = [
        {"audit_id": row["audit_id"], "created_at": row["audit_created_at"], "mode": row["mode"], "score": row["score"],
         "grade": row["grade"], "new": row["new_count"], "fixed": row["fixed_count"], "reopened": row["reopened_count"],
         "seen": row["seen_count"], "not_rescanned": row["not_rescanned_count"]}
        for row in reversed(trend_rows)
    ]
    active = sum(counts[status] for status in ACTIVE_STATUSES)
    return {
        "project_path": project_path,
        "as_of_audit_id": as_of_audit_id,
        "counts": counts,
        "active": active,
        "suppressed": counts["risk_accepted"] + counts["false_positive"],
        "active_by_severity": active_by_severity,
        "fixed_total": counts["fixed"],
        "mean_time_to_fix_hours": round(sum(fix_hours) / len(fix_hours), 1) if fix_hours else None,
        "trend": trend,
        "ownership": ownership,
        "deadlines": sorted(deadlines, key=lambda item: (item["due_date"], SEVERITY_RANK.get(item["severity"], 9)))[:10],
    }


# ---------------------------------------------------------------------------
# İş birliği: sorumlu, son tarih, yorumlar
# ---------------------------------------------------------------------------
def _row_or_missing(db: sqlite3.Connection, tracked_id: str) -> sqlite3.Row:
    row = db.execute("SELECT * FROM tracked_findings WHERE id = ?", (tracked_id,)).fetchone()
    if not row:
        raise LookupError("Takip edilen bulgu bulunamadı.")
    return row


def clean_assignee_name(value: Any) -> str:
    """Giriş kapalıyken serbest metin sorumlu adı (tek satır, en çok 80 karakter)."""
    if not isinstance(value, str):
        raise TrackingError("Sorumlu adı metin olmalı.")
    name = " ".join(value.split())
    if not name or len(name) > MAX_ASSIGNEE_NAME or _CONTROL_RE.search(name):
        raise TrackingError(f"Sorumlu adı 1–{MAX_ASSIGNEE_NAME} karakterlik tek satır metin olmalı.")
    return name


def assign(db: sqlite3.Connection, tracked_id: str, *, assignee_id: str | None, assignee_name: str,
           when: str) -> dict[str, Any]:
    """Sorumluyu ata/değiştir/kaldır (ikisi de boşsa kaldırır). Kullanıcı doğrulaması çağıranda yapılır."""
    row = _row_or_missing(db, tracked_id)
    assignee_name = assignee_name or ""
    previous = {"assignee_id": row["assignee_id"], "assignee_name": row["assignee_name"] or ""}
    if previous == {"assignee_id": assignee_id, "assignee_name": assignee_name}:
        return {"changed": False, "previous": previous, "finding": get_tracked(db, tracked_id) or {}}
    db.execute("UPDATE tracked_findings SET assignee_id = ?, assignee_name = ?, assigned_at = ? WHERE id = ?",
               (assignee_id, assignee_name, when if (assignee_id or assignee_name) else None, tracked_id))
    _event(db, tracked_id, None, when, "assigned" if (assignee_id or assignee_name) else "unassigned",
           note=assignee_name)
    return {"changed": True, "previous": previous, "finding": get_tracked(db, tracked_id) or {}}


def parse_due_date(value: Any) -> str | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str) or not _DATE_RE.fullmatch(value):
        raise TrackingError("Son tarih YYYY-AA-GG biçiminde olmalı (boş değer tarihi kaldırır).")
    try:
        parsed = date.fromisoformat(value)
    except ValueError:
        raise TrackingError("Geçersiz son tarih.") from None
    if not 2000 <= parsed.year <= 2100:
        raise TrackingError("Son tarih 2000–2100 arasında olmalı.")
    return parsed.isoformat()


def set_due(db: sqlite3.Connection, tracked_id: str, due_date: str | None, *, when: str) -> dict[str, Any]:
    row = _row_or_missing(db, tracked_id)
    previous = row["due_date"]
    if previous == due_date:
        return {"changed": False, "previous": previous, "finding": get_tracked(db, tracked_id) or {}}
    # Tarih değişince hatırlatma aşaması sıfırlanır (yeni tarih için yeniden bildirilir).
    db.execute("UPDATE tracked_findings SET due_date = ?, due_notice = '' WHERE id = ?", (due_date, tracked_id))
    _event(db, tracked_id, None, when, "due_changed", note=due_date or "")
    return {"changed": True, "previous": previous, "finding": get_tracked(db, tracked_id) or {}}


def clean_comment(body: Any) -> str:
    if not isinstance(body, str):
        raise TrackingError("Yorum metin olmalı.")
    text = body.replace("\r\n", "\n").strip()
    if not text or len(text) > MAX_COMMENT_CHARS:
        raise TrackingError(f"Yorum 1–{MAX_COMMENT_CHARS} karakter olmalı.")
    if _CONTROL_RE.search(text):
        raise TrackingError("Yorumda denetim karakteri olamaz.")
    return text


def _comment_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {key: row[key] for key in ("id", "tracked_id", "author_id", "author_name", "body", "created_at")}


def list_comments(db: sqlite3.Connection, tracked_id: str) -> list[dict[str, Any]]:
    return [_comment_dict(row) for row in db.execute(
        "SELECT * FROM tracked_finding_comments WHERE tracked_id = ? ORDER BY id", (tracked_id,))]


def add_comment(db: sqlite3.Connection, tracked_id: str, *, author_id: str | None, author_name: str, body: Any,
                when: str) -> dict[str, Any]:
    _row_or_missing(db, tracked_id)
    text = clean_comment(body)
    count = db.execute("SELECT COUNT(*) FROM tracked_finding_comments WHERE tracked_id = ?", (tracked_id,)).fetchone()[0]
    if count >= MAX_COMMENTS_PER_FINDING:
        raise TrackingError(f"Bir bulguya en çok {MAX_COMMENTS_PER_FINDING} yorum yazılabilir.")
    cursor = db.execute(
        "INSERT INTO tracked_finding_comments(tracked_id, author_id, author_name, body, created_at) VALUES (?, ?, ?, ?, ?)",
        (tracked_id, author_id, author_name or "", text, when),
    )
    _event(db, tracked_id, None, when, "comment_added", note=f"#{cursor.lastrowid}")
    row = db.execute("SELECT * FROM tracked_finding_comments WHERE id = ?", (cursor.lastrowid,)).fetchone()
    return _comment_dict(row)


def delete_comment(db: sqlite3.Connection, tracked_id: str, comment_id: int, *, actor_id: str | None,
                   is_admin: bool, when: str) -> dict[str, Any]:
    """Yorumu sil. Giriş açıkken (``actor_id`` var): yalnız yazarı ya da yönetici. Giriş kapalıyken tek yerel kullanıcı."""
    row = db.execute("SELECT * FROM tracked_finding_comments WHERE id = ? AND tracked_id = ?",
                     (comment_id, tracked_id)).fetchone()
    if not row:
        raise LookupError("Yorum bulunamadı.")
    if actor_id is not None and not is_admin and row["author_id"] != actor_id:
        raise PermissionError("Başkasının yorumunu yalnız yönetici silebilir.")
    db.execute("DELETE FROM tracked_finding_comments WHERE id = ?", (comment_id,))
    _event(db, tracked_id, None, when, "comment_deleted", note=f"#{comment_id}")
    return _comment_dict(row)


def list_assigned(db: sqlite3.Connection, *, assignee_id: str | None = None, assignee_name: str | None = None,
                  statuses: set[str] | None = None, severities: set[str] | None = None, overdue_only: bool = False,
                  project_path: str | None = None, limit: int = 500) -> list[dict[str, Any]]:
    """Projeler arası atanmış bulgular. Kimlik ya da ad verilmezse sorumlusu olan tüm bulgular."""
    if statuses and not statuses <= set(STATUSES):
        raise TrackingError("Geçersiz durum filtresi.")
    if severities and not severities <= set(SEVERITY_RANK):
        raise TrackingError("Geçersiz önem filtresi.")
    by_id = assignee_id or ""
    by_name = "" if by_id else " ".join((assignee_name or "").split())
    rows = db.execute(
        "SELECT * FROM tracked_findings WHERE "
        "CASE WHEN ? != '' THEN assignee_id = ? "
        "WHEN ? != '' THEN assignee_name = ? COLLATE NOCASE "
        "ELSE (assignee_id IS NOT NULL OR assignee_name != '') END "
        "AND (? = '' OR project_path = ?)",
        (by_id, by_id, by_name, by_name, project_path or "", project_path or ""),
    ).fetchall()
    today = today_local()
    items = []
    for row in rows:
        if statuses and row["status"] not in statuses:
            continue
        if severities and row["severity"] not in severities:
            continue
        item = _tracked_dict(row, today=today)
        if overdue_only and not item["overdue"]:
            continue
        items.append(item)
    items.sort(key=lambda item: (not item["overdue"], item["due_date"] is None, item["due_date"] or "",
                                 SEVERITY_RANK.get(item["severity"], 9), item["project_path"], item["file"], item["line"]))
    return items[: max(1, min(limit, 5000))]


def assignee_names(db: sqlite3.Connection) -> list[str]:
    """Giriş kapalıyken kullanılmış serbest metin sorumlu adları (öneri listesi)."""
    return [row[0] for row in db.execute(
        "SELECT DISTINCT assignee_name FROM tracked_findings WHERE assignee_name != '' AND assignee_id IS NULL "
        "ORDER BY assignee_name COLLATE NOCASE LIMIT 200")]


def due_candidates(db: sqlite3.Connection, today: date, days_before: int) -> list[dict[str, Any]]:
    """Hatırlatma gereken etkin bulgular: aşama ``overdue`` (geçti) ya da ``soon`` (≤ days_before gün kaldı).
    Aynı tarih ve aşama için yalnız bir kez (``due_notice``)."""
    out = []
    for row in db.execute("SELECT * FROM tracked_findings WHERE due_date IS NOT NULL AND due_date != ''"):
        if row["status"] not in ACTIVE_STATUSES:
            continue
        overdue, remaining = due_state(row["due_date"], row["status"], today)
        if remaining is None:
            continue
        stage = "overdue" if overdue else "soon" if remaining <= days_before else None
        if stage is None:
            continue
        notice = f"{stage}:{row['due_date']}"
        if row["due_notice"] == notice:
            continue
        item = _tracked_dict(row, today=today)
        item["stage"] = stage
        item["notice"] = notice
        out.append(item)
    out.sort(key=lambda item: (item["due_date"], SEVERITY_RANK.get(item["severity"], 9)))
    return out


def mark_due_notice(db: sqlite3.Connection, tracked_id: str, notice: str) -> None:
    db.execute("UPDATE tracked_findings SET due_notice = ? WHERE id = ?", (notice, tracked_id))


# ---------------------------------------------------------------------------
# Portföy/SLA yardımcıları (17. tur; politika portfolio.py içinde)
# ---------------------------------------------------------------------------
def _sla_due_from(when: str, severity: str, sla_days: dict[str, int | None] | None) -> str | None:
    """İlk görülme anı + önem SLA süresi → son tarih (yerel gün). SLA yoksa None."""
    if not sla_days:
        return None
    days = sla_days.get(severity if severity in SEVERITY_RANK else "info")
    if not days:
        return None
    seen = local_date(when) or today_local()
    return (seen + timedelta(days=int(days))).isoformat()


def local_date(value: str | None) -> date | None:
    """ISO zaman damgasının yerel (zamanlayıcı saat dilimi) günü."""
    moment = _parse_time(value)
    if moment is None:
        return None
    if moment.tzinfo is None:
        return moment.date()
    try:
        import scheduler

        return moment.astimezone(scheduler.zone(scheduler.timezone_name())).date()
    except Exception:
        return moment.astimezone().date()


def expire_risk_acceptances(db: sqlite3.Connection, today: date, *, when: str) -> list[dict[str, Any]]:
    """Bitiş tarihi geçmiş (bitiş günü < bugün değil, ≤ bugün) risk kabullerini yeniden aç. Çağıran yazma işlemindedir."""
    expired = []
    for row in db.execute(
        "SELECT * FROM tracked_findings WHERE status = 'risk_accepted' AND risk_expires_at IS NOT NULL AND risk_expires_at != ''"
    ).fetchall():
        try:
            ends = date.fromisoformat(row["risk_expires_at"])
        except ValueError:
            continue
        if ends > today:
            continue
        db.execute("UPDATE tracked_findings SET status = 'reopened', status_changed_at = ?, risk_expires_at = NULL, "
                   "status_note = ? WHERE id = ?", (when, f"Risk kabulü {row['risk_expires_at']} tarihinde sona erdi.", row["id"]))
        _event(db, row["id"], None, when, "risk_expired", "risk_accepted", "reopened", row["risk_expires_at"])
        item = _tracked_dict(db.execute("SELECT * FROM tracked_findings WHERE id = ?", (row["id"],)).fetchone(), today=today)
        item["expired_on"] = row["risk_expires_at"]
        expired.append(item)
    return expired


def apply_sla_due_dates(db: sqlite3.Connection, sla_days: dict[str, int | None], *, when: str) -> list[dict[str, Any]]:
    """Son tarihi olmayan etkin bulgulara SLA son tarihi yaz (ilk görülme + süre; geçmişte kalabilir)."""
    changed = []
    for row in db.execute("SELECT * FROM tracked_findings WHERE (due_date IS NULL OR due_date = '')").fetchall():
        if row["status"] not in ACTIVE_STATUSES:
            continue
        due = _sla_due_from(row["first_seen_at"], row["severity"], sla_days)
        if not due:
            continue
        db.execute("UPDATE tracked_findings SET due_date = ?, due_notice = '' WHERE id = ?", (due, row["id"]))
        _event(db, row["id"], None, when, "due_changed", note=f"sla:{due}")
        changed.append({"id": row["id"], "project_path": row["project_path"], "due_date": due, "severity": row["severity"]})
    return changed


def mark_sla_notice(db: sqlite3.Connection, tracked_id: str, notice: str) -> None:
    db.execute("UPDATE tracked_findings SET sla_notice = ? WHERE id = ?", (notice, tracked_id))
