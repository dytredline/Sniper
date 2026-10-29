"""Projeler arası portföy, SLA politikası, MTTR ve dışa aktarım (17. tur).

* SLA politikası: önem → gün (``null`` = SLA yok), yeni bulguya otomatik son tarih (varsayılan kapalı) ve risk
  kabulü için varsayılan süre (0 = süresiz). ``$SNIPER_DATA_DIR/sla-policy.json`` (0600, ops_files kilidiyle).
* Etkin son tarih = bulgunun elle/otomatik ``due_date``'i, yoksa ilk görülme günü + SLA süresi. SLA ihlali: etkin
  bulgunun etkin son tarihi bugünden önce.
* MTTR: düzelen bulgularda ilk görülme → düzelme süresi (gün), önem başına ortalama/ortanca; son 90 gün ayrıca.
* Eğilim: olay geçmişinin (``tracked_finding_events``) durum değişiklikleri yeniden oynatılarak haftalık
  yeni/düzelen/etkin sayıları (yaklaşık değil: her bulgunun o andaki durumu).
* Dışa aktarım (ağ yok, yalnız dosya): DefectDojo "Generic Findings Import" JSON, Jira CSV, düz CSV. CSV hücreleri
  formül enjeksiyonuna karşı kaçışlanır (``= + - @`` ve sekme/satır başı ile başlayanlara ``'``).
"""
from __future__ import annotations

from bisect import bisect_right
import csv
from datetime import date, timedelta
import io
import json
import re
import sqlite3
from statistics import median
from typing import Any, Callable

import finding_tracking as ft
import report_sections

POLICY_FILE = "sla-policy.json"
SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_LABELS = {"critical": "Kritik", "high": "Yüksek", "medium": "Orta", "low": "Düşük", "info": "Bilgi"}
DEFAULT_POLICY: dict[str, Any] = {
    "format": 1,
    "days": {"critical": 7, "high": 30, "medium": 90, "low": 180, "info": None},
    "auto_due_date": False,
    "risk_acceptance_days": 0,
}
MAX_SLA_DAYS = 3650
MAX_RISK_DAYS = 5 * 365
# Portföy risk puanı: etkin bulguların önem ağırlıkları toplamı (+ SLA ihlali başına ek ağırlık).
RISK_WEIGHTS = {"critical": 10.0, "high": 5.0, "medium": 2.0, "low": 0.5, "info": 0.0}
SLA_BREACH_WEIGHT = 2.0
EXPORT_FORMATS = ("defectdojo", "jira", "csv")
STATUS_FILTERS = {"active": ft.ACTIVE_STATUSES, "fixed": frozenset({"fixed"}),
                  "suppressed": ft.SUPPRESSED_STATUSES, "all": frozenset(ft.STATUSES)}
MAX_EXPORT_ROWS = 10_000
_CWE_RE = re.compile(r"CWE-(\d{1,5})", re.IGNORECASE)


class PolicyError(ValueError):
    """Geçersiz SLA politikası."""


# ---------------------------------------------------------------------------
# Politika
# ---------------------------------------------------------------------------
def _copy(value: Any) -> Any:
    return json.loads(json.dumps(value))


def validate_policy(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise PolicyError("SLA politikası bir JSON nesnesi olmalı.")
    unknown = set(raw) - {"format", "days", "auto_due_date", "risk_acceptance_days"}
    if unknown:
        raise PolicyError("Bilinmeyen alan: " + ", ".join(sorted(unknown)))
    days_raw = raw.get("days", DEFAULT_POLICY["days"])
    if not isinstance(days_raw, dict) or set(days_raw) - set(SEVERITIES):
        raise PolicyError("days yalnız critical/high/medium/low/info anahtarlarını içerebilir.")
    days: dict[str, int | None] = {}
    for severity in SEVERITIES:
        value = days_raw.get(severity, DEFAULT_POLICY["days"][severity])
        if value is not None and (type(value) is not int or not 1 <= value <= MAX_SLA_DAYS):
            raise PolicyError(f"days.{severity} 1–{MAX_SLA_DAYS} arası tam sayı ya da null (SLA yok) olmalı.")
        days[severity] = value
    order = [days[s] for s in SEVERITIES if days[s] is not None]
    if order != sorted(order):
        raise PolicyError("Daha yüksek önemin SLA süresi daha düşük önemden uzun olamaz.")
    auto = raw.get("auto_due_date", DEFAULT_POLICY["auto_due_date"])
    if not isinstance(auto, bool):
        raise PolicyError("auto_due_date true/false olmalı.")
    risk_days = raw.get("risk_acceptance_days", DEFAULT_POLICY["risk_acceptance_days"])
    if type(risk_days) is not int or not 0 <= risk_days <= MAX_RISK_DAYS:
        raise PolicyError(f"risk_acceptance_days 0–{MAX_RISK_DAYS} arası tam sayı olmalı (0 = süresiz).")
    return {"format": 1, "days": days, "auto_due_date": auto, "risk_acceptance_days": risk_days}


def load_policy(environ: dict[str, str] | None = None) -> tuple[dict[str, Any], bool]:
    """(politika, özelleştirilmiş mi). Veri dizini yoksa ya da dosya bozuksa varsayılan."""
    import ops_files

    try:
        data = ops_files.read_json(POLICY_FILE, lambda: None, environ)
    except ops_files.OpsStoreError:
        return _copy(DEFAULT_POLICY), False
    if data is None:
        return _copy(DEFAULT_POLICY), False
    try:
        return validate_policy(data), True
    except PolicyError:
        return _copy(DEFAULT_POLICY), False


def save_policy(raw: Any, environ: dict[str, str] | None = None) -> dict[str, Any]:
    import ops_files

    policy = validate_policy(raw)
    ops_files.update_json(POLICY_FILE, lambda: None, lambda _current: policy, environ)
    return policy


def reset_policy(environ: dict[str, str] | None = None) -> dict[str, Any]:
    return save_policy(DEFAULT_POLICY, environ)


def auto_due_days(policy: dict[str, Any]) -> dict[str, int | None] | None:
    """Otomatik son tarih açıksa önem → gün; kapalıysa None (record_audit'e verilir)."""
    return dict(policy["days"]) if policy.get("auto_due_date") else None


# ---------------------------------------------------------------------------
# Satır yardımcıları
# ---------------------------------------------------------------------------
def sla_due(row: sqlite3.Row | dict, policy: dict[str, Any]) -> date | None:
    severity = row["severity"] if row["severity"] in SEVERITIES else "info"
    days = policy["days"].get(severity)
    seen = ft.local_date(row["first_seen_at"])
    if not days or seen is None:
        return None
    return seen + timedelta(days=int(days))


def effective_due(row: sqlite3.Row | dict, policy: dict[str, Any]) -> date | None:
    if row["due_date"]:
        try:
            return date.fromisoformat(row["due_date"])
        except ValueError:
            pass
    return sla_due(row, policy)


def _breached(row, policy: dict[str, Any], today: date) -> bool:
    due = effective_due(row, policy)
    return row["status"] in ft.ACTIVE_STATUSES and due is not None and due < today


def _fix_days(row) -> float | None:
    start, end = ft._parse_time(row["first_seen_at"]), ft._parse_time(row["fixed_at"])
    if not start or not end or end < start:
        return None
    return (end - start).total_seconds() / 86400


def _stats(values: list[float]) -> dict[str, Any]:
    if not values:
        return {"count": 0, "mean_days": None, "median_days": None}
    return {"count": len(values), "mean_days": round(sum(values) / len(values), 1),
            "median_days": round(median(values), 1)}


def mttr(rows: list[sqlite3.Row], today: date, *, window_days: int = 90) -> dict[str, Any]:
    """Önem başına ortalama/ortanca düzeltme süresi (gün); tümü ve son ``window_days`` gün."""
    since = today - timedelta(days=window_days)
    all_by: dict[str, list[float]] = {s: [] for s in SEVERITIES}
    recent_by: dict[str, list[float]] = {s: [] for s in SEVERITIES}
    for row in rows:
        if row["status"] != "fixed":
            continue
        days = _fix_days(row)
        if days is None:
            continue
        severity = row["severity"] if row["severity"] in SEVERITIES else "info"
        all_by[severity].append(days)
        fixed_on = ft.local_date(row["fixed_at"])
        if fixed_on and fixed_on >= since:
            recent_by[severity].append(days)
    return {
        "overall": _stats([v for values in all_by.values() for v in values]),
        "by_severity": {s: _stats(all_by[s]) for s in SEVERITIES},
        "recent": {"window_days": window_days, "overall": _stats([v for values in recent_by.values() for v in values]),
                   "by_severity": {s: _stats(recent_by[s]) for s in SEVERITIES}},
    }


def sla_compliance(rows: list[sqlite3.Row], policy: dict[str, Any], today: date) -> dict[str, Any]:
    """Düzelenlerde SLA içinde düzelme oranı; etkinlerde ihlal ve yaklaşan sayıları (önem başına)."""
    by = {s: {"active_breached": 0, "active_due_soon": 0, "fixed_in_sla": 0, "fixed_late": 0} for s in SEVERITIES}
    for row in rows:
        severity = row["severity"] if row["severity"] in SEVERITIES else "info"
        due = effective_due(row, policy)
        if due is None:
            continue
        if row["status"] in ft.ACTIVE_STATUSES:
            if due < today:
                by[severity]["active_breached"] += 1
            elif (due - today).days <= ft.DUE_SOON_DAYS:
                by[severity]["active_due_soon"] += 1
        elif row["status"] == "fixed":
            fixed_on = ft.local_date(row["fixed_at"])
            if fixed_on is not None:
                by[severity]["fixed_in_sla" if fixed_on <= due else "fixed_late"] += 1
    fixed_in = sum(v["fixed_in_sla"] for v in by.values())
    fixed_late = sum(v["fixed_late"] for v in by.values())
    return {
        "by_severity": by,
        "active_breached": sum(v["active_breached"] for v in by.values()),
        "active_due_soon": sum(v["active_due_soon"] for v in by.values()),
        "fixed_within_sla_ratio": round(fixed_in / (fixed_in + fixed_late), 3) if fixed_in + fixed_late else None,
    }


# ---------------------------------------------------------------------------
# Eğilim (olay geçmişi yeniden oynatılır)
# ---------------------------------------------------------------------------
def weekly_trend(db: sqlite3.Connection, today: date, weeks: int = 12,
                 project_path: str | None = None, project_filter: Callable[[str], bool] | None = None) -> list[dict[str, Any]]:
    """Son ``weeks`` haftanın her biri için: yeni, düzelen, yeniden açılan ve hafta sonunda etkin bulgu sayısı."""
    weeks = max(1, min(int(weeks), 104))
    ends = [today - timedelta(days=7 * (weeks - 1 - i)) for i in range(weeks)]
    start = ends[0] - timedelta(days=6)
    timeline: dict[str, tuple[list[date], list[str]]] = {}
    counters = [{"new": 0, "fixed": 0, "reopened": 0} for _ in ends]
    # Sabit sorgu metinleri (proje süzgeci yalnız bağlı parametre olarak).
    rows = db.execute(
        "SELECT e.tracked_id, e.occurred_at, e.event, e.to_status, t.project_path FROM tracked_finding_events e "
        "JOIN tracked_findings t ON t.id = e.tracked_id WHERE e.to_status IS NOT NULL "
        "AND (? = '' OR t.project_path = ?) ORDER BY e.id",
        (project_path or "", project_path or ""),
    )
    for row in rows:
        if project_filter is not None and not project_filter(row["project_path"]):
            continue
        when = ft.local_date(row["occurred_at"])
        if when is None:
            continue
        days, statuses = timeline.setdefault(row["tracked_id"], ([], []))
        days.append(when)
        statuses.append(row["to_status"])
        if start <= when <= ends[-1] and row["event"] in {"new", "fixed", "reopened", "risk_expired"}:
            # Hafta i: [ends[i]-6, ends[i]] = [start + 7i, start + 7i + 6].
            index = (when - start).days // 7
            key = "reopened" if row["event"] in {"reopened", "risk_expired"} else row["event"]
            counters[min(index, len(ends) - 1)][key] += 1
    out = []
    for i, end in enumerate(ends):
        active = 0
        for days, statuses in timeline.values():
            pos = bisect_right(days, end)
            if pos and statuses[pos - 1] in ft.ACTIVE_STATUSES:
                active += 1
        out.append({"week_end": end.isoformat(), **counters[i], "active": active})
    return out


# ---------------------------------------------------------------------------
# Portföy
# ---------------------------------------------------------------------------
def _project_meta(db: sqlite3.Connection) -> dict[str, dict[str, Any]]:
    meta: dict[str, dict[str, Any]] = {}
    for row in db.execute(
        "SELECT t.project_path, p.project_name, p.created_at, p.score, p.grade FROM project_audit_tracking t "
        "JOIN project_audits p ON p.id = t.audit_id ORDER BY t.recorded_at, t.rowid"
    ):
        meta[row["project_path"]] = {"project_name": row["project_name"], "last_audit_at": row["created_at"],
                                     "score": row["score"], "grade": row["grade"]}
    return meta


def overview(db: sqlite3.Connection, policy: dict[str, Any], *, today: date | None = None, weeks: int = 12,
             recent_days: int = 30, project_filter: Callable[[str], bool] | None = None) -> dict[str, Any]:
    """Projeler arası pano: proje başına önem dağılımı, SLA ihlali, MTTR, son 30 günde yeni/düzelen, risk puanı.

    ``project_filter`` (25. tur): yalnız süzgeçten geçen proje yolları (toplu tarama grubu / kök dizin)."""
    today = today or ft.today_local()
    since = today - timedelta(days=recent_days)
    rows = db.execute("SELECT * FROM tracked_findings").fetchall()
    if project_filter is not None:
        rows = [row for row in rows if project_filter(row["project_path"])]
    meta = _project_meta(db)
    malicious_tracked: dict[str, set[tuple[str, str]]] = {}
    projects: dict[str, dict[str, Any]] = {}
    by_project_rows: dict[str, list[sqlite3.Row]] = {}
    for row in rows:
        path = row["project_path"]
        by_project_rows.setdefault(path, []).append(row)
        entry = projects.get(path)
        if entry is None:
            info = meta.get(path, {})
            entry = projects[path] = {
                "project_path": path, "project_name": info.get("project_name") or path.rstrip("/").rsplit("/", 1)[-1],
                "last_audit_at": info.get("last_audit_at"), "score": info.get("score"), "grade": info.get("grade"),
                "active_by_severity": {s: 0 for s in SEVERITIES}, "active": 0, "suppressed": 0, "fixed": 0,
                "new_recent": 0, "fixed_recent": 0, "overdue": 0, "sla_breached": 0, "unassigned_active": 0,
                "risk_expiring": 0, "by_section": {key: 0 for key in report_sections.SECTION_ORDER},
            }
        severity = row["severity"] if row["severity"] in SEVERITIES else "info"
        status = row["status"]
        seen_on = ft.local_date(row["first_seen_at"])
        if seen_on and seen_on >= since:
            entry["new_recent"] += 1
        if status in ft.ACTIVE_STATUSES:
            entry["active"] += 1
            entry["active_by_severity"][severity] += 1
            # 21. tur: alan kırılımı (kod / bağımlılık / IaC / konteyner …) — yönetici özetiyle aynı sınıflandırma
            try:
                finding = json.loads(row["finding_json"] or "{}")
            except (ValueError, TypeError):
                finding = {}
            section = report_sections.section_of({"finding": finding, "category": row["category"], "title": row["title"]})
            entry["by_section"][section] += 1
            if section == "dependencies" and report_sections.is_malicious(finding):
                malicious_tracked.setdefault(path, set()).add(report_sections._malicious_key(finding) or ("", ""))
            if not (row["assignee_id"] or row["assignee_name"]):
                entry["unassigned_active"] += 1
            overdue, _remaining = ft.due_state(row["due_date"], status, today)
            if overdue:
                entry["overdue"] += 1
            if _breached(row, policy, today):
                entry["sla_breached"] += 1
        elif status in ft.SUPPRESSED_STATUSES:
            entry["suppressed"] += 1
            if status == "risk_accepted" and row["risk_expires_at"]:
                try:
                    if (date.fromisoformat(row["risk_expires_at"]) - today).days <= 30:
                        entry["risk_expiring"] += 1
                except ValueError:
                    pass
        elif status == "fixed":
            entry["fixed"] += 1
            fixed_on = ft.local_date(row["fixed_at"])
            if fixed_on and fixed_on >= since:
                entry["fixed_recent"] += 1
    for path, entry in projects.items():
        entry["mttr_days"] = mttr(by_project_rows[path], today)["overall"]["mean_days"]
        entry["risk_score"] = round(sum(RISK_WEIGHTS[s] * n for s, n in entry["active_by_severity"].items())
                                    + SLA_BREACH_WEIGHT * entry["sla_breached"], 1)
    ordered = sorted(projects.values(), key=lambda e: (-e["risk_score"], -e["active"], e["project_name"]))
    totals_keys = ("active", "suppressed", "fixed", "new_recent", "fixed_recent", "overdue", "sla_breached",
                   "unassigned_active", "risk_expiring")
    totals = {key: sum(e[key] for e in ordered) for key in totals_keys}
    totals["active_by_severity"] = {s: sum(e["active_by_severity"][s] for e in ordered) for s in SEVERITIES}
    totals["projects"] = len(ordered)
    dependency_projects = dependency_priority_summary(db)
    if project_filter is not None:
        dependency_projects = {path: summary for path, summary in dependency_projects.items() if project_filter(path)}
    duplicate_malicious = _malicious_dependency_duplicates(db, malicious_tracked)
    for entry in ordered:
        entry["dependencies"] = dependency_projects.get(entry["project_path"], _empty_dependency_summary())
        # bağımlılık açıkları (SCA) bağımlılık alanına eklenir; proje analizinde zaten sayılan kötü amaçlı paket@sürüm
        # tekrar sayılmaz
        entry["by_section"]["dependencies"] += max(
            0, entry["dependencies"]["active"] - duplicate_malicious.get(entry["project_path"], 0))
    totals["by_section"] = {key: sum(e["by_section"][key] for e in ordered) for key in report_sections.SECTION_ORDER}
    totals["dependencies"] = {key: sum(d[key] for d in dependency_projects.values()) for key in _DEP_KEYS}
    return {
        "generated_for": today.isoformat(),
        "recent_days": recent_days,
        "policy": policy,
        "totals": totals,
        "projects": ordered,
        # 20. tur: bağımlılık açıkları (SCA) proje başına öncelik katmanları; bulgu takibinde olmayan projeler dahil
        "dependency_projects": [
            {"project_path": path, "project_name": path.rstrip("/").rsplit("/", 1)[-1], **summary}
            for path, summary in sorted(dependency_projects.items(),
                                        key=lambda kv: (-kv[1]["fix_first"], -kv[1]["active"], kv[0]))
        ],
        "top_risk": [e["project_path"] for e in ordered if e["risk_score"] > 0][:5],
        "mttr": mttr(rows, today),
        "sla": sla_compliance(rows, policy, today),
        "trend": weekly_trend(db, today, weeks, project_filter=project_filter),
    }


def _malicious_dependency_duplicates(db: sqlite3.Connection, tracked: dict[str, set[tuple[str, str]]]) -> dict[str, int]:
    """Bulgu takibinde de olan (aynı paket@sürüm) etkin kötü amaçlı bağımlılık kayıtlarının proje başına sayısı."""
    if not tracked:
        return {}
    out: dict[str, int] = {}
    try:
        rows = db.execute(
            "SELECT project_path, package_name, installed_version, vulnerability_id, title FROM dependency_findings "
            "WHERE status IN ('open', 'in_progress', 'retest_required', 'reopened')").fetchall()
    except sqlite3.OperationalError:
        return out
    for row in rows:
        keys = tracked.get(row["project_path"])
        if not keys or not report_sections.is_malicious(dict(row)):
            continue
        if (str(row["package_name"] or "").lower(), str(row["installed_version"] or "")) in keys:
            out[row["project_path"]] = out.get(row["project_path"], 0) + 1
    return out


_DEP_KEYS = ("active", "fix_first", "plan", "monitor", "unscored", "used", "unused", "transitive_only")


def _empty_dependency_summary() -> dict[str, int]:
    return {key: 0 for key in _DEP_KEYS}


def dependency_priority_summary(db: sqlite3.Connection) -> dict[str, dict[str, int]]:
    """Etkin bağımlılık bulgularının proje başına öncelik katmanı ve kullanım durumu sayıları (20. tur)."""
    out: dict[str, dict[str, int]] = {}
    try:
        rows = db.execute(
            "SELECT project_path, priority_tier, usage_state, COUNT(*) AS n FROM dependency_findings "
            "WHERE status IN ('open', 'in_progress', 'retest_required', 'reopened') "
            "GROUP BY project_path, priority_tier, usage_state").fetchall()
    except sqlite3.OperationalError:  # eski şema / tablo yok
        return out
    for row in rows:
        entry = out.setdefault(row["project_path"], _empty_dependency_summary())
        n = int(row["n"])
        entry["active"] += n
        tier = row["priority_tier"] if row["priority_tier"] in {"fix_first", "plan", "monitor"} else "unscored"
        entry[tier] += n
        if row["usage_state"] in {"used", "unused", "transitive_only"}:
            entry[row["usage_state"]] += n
    return out


def breach_candidates(db: sqlite3.Connection, policy: dict[str, Any], today: date) -> list[dict[str, Any]]:
    """Elle son tarihi olmayan (SLA'dan hesaplanan) etkin bulgulardan SLA'sı geçenler; her SLA günü için bir kez.
    Elle/otomatik ``due_date``'i olanlar ``finding_due`` hatırlatmasıyla zaten bildirilir."""
    out = []
    for row in db.execute("SELECT * FROM tracked_findings WHERE (due_date IS NULL OR due_date = '')").fetchall():
        if row["status"] not in ft.ACTIVE_STATUSES:
            continue
        due = sla_due(row, policy)
        if due is None or due >= today:
            continue
        notice = f"breach:{due.isoformat()}"
        if row["sla_notice"] == notice:
            continue
        item = ft._tracked_dict(row, today=today)
        item["sla_due"] = due.isoformat()
        item["notice"] = notice
        out.append(item)
    out.sort(key=lambda item: (ft.SEVERITY_RANK.get(item["severity"], 9), item["sla_due"]))
    return out


# ---------------------------------------------------------------------------
# Dışa aktarım
# ---------------------------------------------------------------------------
def parse_status_filter(raw: str) -> set[str]:
    raw = (raw or "active").strip()
    if raw in STATUS_FILTERS:
        return set(STATUS_FILTERS[raw])
    statuses = {item for item in raw.split(",") if item}
    if not statuses or not statuses <= set(ft.STATUSES):
        raise ft.TrackingError("Geçersiz durum filtresi (active, fixed, suppressed, all ya da durum listesi).")
    return statuses


def export_rows(db: sqlite3.Connection, policy: dict[str, Any], *, project_path: str | None = None,
                statuses: set[str] | None = None, today: date | None = None) -> list[dict[str, Any]]:
    today = today or ft.today_local()
    statuses = statuses or set(ft.ACTIVE_STATUSES)
    out = []
    for row in db.execute("SELECT * FROM tracked_findings WHERE (? = '' OR project_path = ?)",
                          (project_path or "", project_path or "")).fetchall():
        if row["status"] not in statuses:
            continue
        item = ft._tracked_dict(row, include_finding=True, today=today)
        due = effective_due(row, policy)
        item["effective_due"] = due.isoformat() if due else None
        computed = sla_due(row, policy)
        item["sla_due"] = computed.isoformat() if computed else None
        item["sla_breached"] = _breached(row, policy, today)
        out.append(item)
    out.sort(key=lambda item: (item["project_path"], ft.SEVERITY_RANK.get(item["severity"], 9), item["file"], item["line"]))
    return out[:MAX_EXPORT_ROWS]


def _cwe(item: dict[str, Any]) -> int | None:
    finding = item.get("finding") or {}
    for value in (
        finding.get("cwe"),
        finding.get("cwe_id"),
        item.get("cwe"),
        item.get("cwe_id"),
        item.get("reference"),
        finding.get("reference"),
        item.get("title"),
    ):
        if isinstance(value, int) and 0 < value < 100000:
            return value
        text = str(value or "").strip()
        if text.isdigit() and 0 < int(text) < 100000:
            return int(text)
        match = _CWE_RE.search(text)
        if match:
            return int(match.group(1))
    return None


def _description(item: dict[str, Any]) -> str:
    import report_provenance

    finding = item.get("finding") or {}
    where = item.get("file") or "Proje geneli"
    if item.get("line"):
        where = f"{where}:{item['line']}"
    parts = [str(item.get("title") or ""), f"Konum: {where}", f"Proje: {item.get('project_path')}",
             f"Kategori: {item.get('category') or '-'} · Referans: {item.get('reference') or '-'}",
             f"Durum: {item.get('status_label')} · İlk görülme: {item.get('first_seen_at')}"]
    evidence = finding.get("evidence")
    if evidence:
        parts.append(f"Kanıt: {report_provenance.redact_evidence_text(evidence, max_len=4000)}")
    if item.get("status_note"):
        parts.append(f"Not: {item['status_note']}")
    parts.append(f"Sniper takip kimliği: {item.get('id')}")
    return "\n".join(str(p)[:4000] for p in parts)


def to_defectdojo(items: list[dict[str, Any]]) -> dict[str, Any]:
    """DefectDojo "Generic Findings Import" JSON (yerel dosya; içe aktarma DefectDojo arayüzünden)."""
    severity = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}
    findings = []
    for item in items:
        finding = item.get("finding") or {}
        status = item.get("status")
        entry: dict[str, Any] = {
            "title": str(item.get("title") or "")[:511],
            "description": _description(item),
            "severity": severity.get(item.get("severity"), "Info"),
            "date": (ft.local_date(item.get("first_seen_at")) or ft.today_local()).isoformat(),
            "file_path": item.get("file") or "",
            "line": int(item.get("line") or 0) or None,
            "mitigation": str(finding.get("recommendation") or "")[:4000],
            "references": str(item.get("reference") or ""),
            "active": status in ft.ACTIVE_STATUSES,
            "verified": False,
            "false_p": status == "false_positive",
            "risk_accepted": status == "risk_accepted",
            "is_mitigated": status == "fixed",
            "duplicate": False,
            "static_finding": True,
            "dynamic_finding": False,
            "unique_id_from_tool": item.get("fingerprint"),
            "vuln_id_from_tool": item.get("id"),
            "tags": ["sniper", str(item.get("category") or "genel")],
        }
        if status == "fixed" and item.get("fixed_at"):
            entry["mitigated"] = item["fixed_at"]
        cwe = _cwe(item)
        if cwe:
            entry["cwe"] = cwe
        if item.get("effective_due"):
            entry["sla_expiration_date"] = item["effective_due"]
        findings.append({key: value for key, value in entry.items() if value is not None})
    return {"findings": findings}


def csv_safe(value: Any) -> str | int | float:
    """CSV/elektronik tablo formül enjeksiyonuna karşı: tehlikeli ilk karakterlere ``'`` öneki."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "evet" if value else "hayır"
    if isinstance(value, (int, float)):
        return value
    rendered = str(value).replace("\x00", "")
    if rendered and rendered[0] in ("\t", "\r", "\n"):
        return "'" + rendered
    if rendered.lstrip().startswith(("=", "+", "-", "@", "|", "＝", "＋", "－", "＠", "｜")):
        return "'" + rendered
    return rendered


def _write_csv(header: list[str], rows: list[list[Any]]) -> str:
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL, lineterminator="\r\n")
    writer.writerow(header)
    for row in rows:
        writer.writerow([csv_safe(cell) for cell in row])
    return "﻿" + output.getvalue()


def to_jira_csv(items: list[dict[str, Any]]) -> str:
    """Jira "CSV içe aktarma" için: Summary, Issue Type, Priority, Description, Labels (×2), Due Date, Assignee."""
    priority = {"critical": "Highest", "high": "High", "medium": "Medium", "low": "Low", "info": "Lowest"}
    header = ["Summary", "Issue Type", "Priority", "Description", "Labels", "Labels", "Due Date", "Assignee",
              "Sniper ID"]
    rows = []
    for item in items:
        label = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(item.get("category") or "genel"))[:60] or "genel"
        summary = f"[{SEVERITY_LABELS.get(item.get('severity'), item.get('severity'))}] {item.get('title')}"
        rows.append([summary[:250], "Bug", priority.get(item.get("severity"), "Low"), _description(item), "sniper",
                     label, item.get("effective_due") or "", item.get("assignee_name") or "", item.get("id")])
    return _write_csv(header, rows)


def to_csv(items: list[dict[str, Any]]) -> str:
    header = ["id", "project_path", "severity", "status", "title", "category", "reference", "cwe", "file", "line",
              "first_seen_at", "last_seen_at", "fixed_at", "assignee", "due_date", "sla_due", "sla_breached",
              "risk_expires_at", "status_note"]
    rows = [[item.get("id"), item.get("project_path"), item.get("severity"), item.get("status"), item.get("title"),
             item.get("category"), item.get("reference"), _cwe(item) or "", item.get("file"), item.get("line"),
             item.get("first_seen_at"), item.get("last_seen_at"), item.get("fixed_at") or "", item.get("assignee_name"),
             item.get("due_date") or "", item.get("sla_due") or "", item.get("sla_breached"),
             item.get("risk_expires_at") or "", item.get("status_note")] for item in items]
    return _write_csv(header, rows)


def render_export(fmt: str, items: list[dict[str, Any]]) -> tuple[bytes, str, str]:
    """(gövde, içerik türü, dosya uzantısı)."""
    if fmt == "defectdojo":
        body = json.dumps(to_defectdojo(items), ensure_ascii=False, indent=1).encode("utf-8")
        return body, "application/json; charset=utf-8", "json"
    if fmt == "jira":
        return to_jira_csv(items).encode("utf-8"), "text/csv; charset=utf-8", "csv"
    if fmt == "csv":
        return to_csv(items).encode("utf-8"), "text/csv; charset=utf-8", "csv"
    raise ft.TrackingError("Biçim defectdojo, jira ya da csv olmalı.")
