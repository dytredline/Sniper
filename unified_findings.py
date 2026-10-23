"""Statik proje, manuel denetim ve ağ taraması bulguları için maskeli birleşik salt okunur görünüm."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
import sqlite3
from typing import Any

import finding_tracking

FORMAT = "sniper-unified-findings/1"
SOURCES = frozenset({"project", "manual", "network", "dependency"})
STATUSES = frozenset({"open", "in_progress", "fixed", "risk_accepted", "false_positive", "reopened"})
SEVERITIES = frozenset({"critical", "high", "medium", "low", "info", "unknown"})
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
STATUS_RANK = {"reopened": 0, "open": 1, "in_progress": 2, "risk_accepted": 3,
               "false_positive": 4, "fixed": 5}
MAX_LIMIT = 1000

_FILTERED_CTE = """
WITH all_findings AS (
  SELECT 'project' source,t.id source_id,t.status native_status,t.status status,t.severity,t.title,
         t.reference reference,t.file loc_a,CAST(t.line AS TEXT) loc_b,'file' loc_kind,
         t.project_path scope_id,COALESCE(p.project_name,'') scope_name,'project' scope_type,
         COALESCE(t.assignee_id,'') assignee_id,COALESCE(t.assignee_name,'') assignee_name,
         COALESCE(t.due_date,'') due_date,t.first_seen_at,t.last_seen_at updated_at
    FROM tracked_findings t LEFT JOIN project_audits p ON p.id=t.last_audit_id
  UNION ALL
  SELECT 'manual',f.id,f.status,CASE f.status WHEN 'resolved' THEN 'fixed' WHEN 'retest_required' THEN 'reopened' ELSE f.status END,
         f.severity,f.title,f.cwe_id,f.affected_asset,'','asset',f.engagement_id,e.name,'engagement','',
         f.remediation_owner,COALESCE(f.due_date,''),f.created_at,f.updated_at
    FROM manual_findings f JOIN engagements e ON e.id=f.engagement_id
  UNION ALL
  SELECT 'network',f.id,COALESCE(l.status,'open'),COALESCE(l.status,'open'),f.severity,f.title,f.template_id,'','','none',
         f.engagement_id,e.name,'engagement','',COALESCE(l.assignee_name,''),COALESCE(l.due_date,''),f.created_at,
         COALESCE(l.updated_at,f.created_at)
    FROM network_scan_findings f JOIN engagements e ON e.id=f.engagement_id
    LEFT JOIN network_finding_lifecycle l ON l.finding_id=f.id
  UNION ALL
  SELECT 'dependency',d.id,d.status,CASE d.status WHEN 'resolved' THEN 'fixed' WHEN 'retest_required' THEN 'reopened' ELSE d.status END,
         d.severity,d.title,d.vulnerability_id,d.package_name,d.installed_version,'package',d.project_path,'','project',
         '','', '',d.first_seen_at,d.last_seen_at FROM dependency_findings d
), filtered AS (
  SELECT * FROM all_findings WHERE
    ((?=1 AND source='project') OR (?=1 AND source='manual') OR (?=1 AND source='network') OR (?=1 AND source='dependency'))
    AND (?=1 OR status IN (?,?,?,?,?,?))
    AND (?=1 OR severity IN (?,?,?,?,?,?))
)
"""
_COUNT_SQL = _FILTERED_CTE + "SELECT COUNT(*) FROM filtered"
_GROUP_SQL = _FILTERED_CTE + "SELECT source,status,severity,COUNT(*) n FROM filtered GROUP BY source,status,severity"
_PAGE_SQL = _FILTERED_CTE + """
SELECT * FROM filtered
ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
         WHEN 'low' THEN 3 WHEN 'info' THEN 4 ELSE 5 END,
         CASE status WHEN 'reopened' THEN 0 WHEN 'open' THEN 1 WHEN 'in_progress' THEN 2
         WHEN 'risk_accepted' THEN 3 WHEN 'false_positive' THEN 4 WHEN 'fixed' THEN 5 ELSE 9 END,
         updated_at DESC, source, source_id LIMIT ? OFFSET ?
"""


def _filters(values: set[str] | None, allowed: frozenset[str], label: str) -> set[str] | None:
    if values is None:
        return None
    if not isinstance(values, set) or not values or not values <= allowed:
        raise ValueError(f"Geçersiz {label} filtresi.")
    return values


def _assignee(identifier: Any, name: Any) -> dict[str, str | None] | None:
    clean_id = str(identifier) if identifier else None
    clean_name = str(name or "")[:80]
    return {"id": clean_id, "name": clean_name} if clean_id or clean_name else None


def _time_key(value: Any) -> float:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError, OverflowError):
        return 0.0


def _project_items(db: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = db.execute(
        """SELECT t.*, p.project_name
           FROM tracked_findings t
           LEFT JOIN project_audits p ON p.id = t.last_audit_id"""
    ).fetchall()
    items = []
    for row in rows:
        overdue, _remaining = finding_tracking.due_state(row["due_date"], row["status"])
        project_path = str(row["project_path"] or "")
        items.append({
            "id": "project:" + row["id"], "source": "project", "source_id": row["id"],
            "status": row["status"], "native_status": row["status"],
            "severity": row["severity"] if row["severity"] in SEVERITIES else "unknown",
            "title": row["title"], "reference": row["reference"],
            "location": {"file": row["file"], "line": int(row["line"] or 0)},
            "scope": {"type": "project", "id": project_path,
                      "name": row["project_name"] or Path(project_path).name},
            "assignee": _assignee(row["assignee_id"], row["assignee_name"]),
            "due_date": row["due_date"], "overdue": overdue,
            "first_seen_at": row["first_seen_at"], "updated_at": row["last_seen_at"], "triage": None,
        })
    return items


def _manual_items(db: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = db.execute(
        """SELECT f.*, e.name AS engagement_name
           FROM manual_findings f JOIN engagements e ON e.id = f.engagement_id"""
    ).fetchall()
    normalized = {"resolved": "fixed", "retest_required": "reopened"}
    items = []
    for row in rows:
        status = normalized.get(row["status"], row["status"])
        if status not in STATUSES:
            status = "open"
        overdue, _remaining = finding_tracking.due_state(row["due_date"], status)
        items.append({
            "id": "manual:" + row["id"], "source": "manual", "source_id": row["id"],
            "status": status, "native_status": row["status"],
            "severity": row["severity"] if row["severity"] in SEVERITIES else "unknown",
            "title": row["title"], "reference": row["cwe_id"],
            "location": {"asset": row["affected_asset"]},
            "scope": {"type": "engagement", "id": row["engagement_id"], "name": row["engagement_name"]},
            "assignee": _assignee(None, row["remediation_owner"]),
            "due_date": row["due_date"] or None, "overdue": overdue,
            "first_seen_at": row["created_at"], "updated_at": row["updated_at"], "triage": None,
        })
    return items


def _network_items(db: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = db.execute(
        """SELECT f.id, f.engagement_id, f.template_id, f.title, f.severity, f.created_at,
                  f.status, f.assignee_name, f.due_date, f.updated_at,
                  e.name AS engagement_name
           FROM network_scan_findings f JOIN engagements e ON e.id = f.engagement_id"""
    ).fetchall()
    items = []
    for row in rows:
        triage = db.execute(
            """SELECT verdict, confidence, decision FROM network_scan_triage_suggestions
               WHERE finding_id = ? ORDER BY created_at DESC, id DESC LIMIT 1""", (row["id"],),
        ).fetchone()
        items.append({
            "id": "network:" + row["id"], "source": "network", "source_id": row["id"],
            "status": row["status"] if row["status"] in STATUSES else "open", "native_status": row["status"],
            "severity": row["severity"] if row["severity"] in SEVERITIES else "unknown",
            "title": row["title"], "reference": row["template_id"], "location": None,
            "scope": {"type": "engagement", "id": row["engagement_id"], "name": row["engagement_name"]},
            "assignee": _assignee(None, row["assignee_name"]), "due_date": row["due_date"] or None,
            "overdue": finding_tracking.due_state(row["due_date"], row["status"])[0],
            "first_seen_at": row["created_at"], "updated_at": row["updated_at"] or row["created_at"],
            "triage": ({"verdict": triage["verdict"], "confidence": float(triage["confidence"]),
                        "decision": triage["decision"]} if triage else None),
        })
    return items


def list_findings(db: sqlite3.Connection, *, sources: set[str] | None = None,
                  statuses: set[str] | None = None, severities: set[str] | None = None,
                  limit: int = 200, offset: int = 0) -> dict[str, Any]:
    sources = _filters(sources, SOURCES, "kaynak")
    statuses = _filters(statuses, STATUSES, "durum")
    severities = _filters(severities, SEVERITIES, "önem")
    if type(limit) is not int or not 1 <= limit <= MAX_LIMIT:
        raise ValueError(f"limit 1 ile {MAX_LIMIT} arasında tam sayı olmalı.")
    if type(offset) is not int or not 0 <= offset <= 1_000_000:
        raise ValueError("offset 0 ile 1000000 arasında tam sayı olmalı.")
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='network_finding_lifecycle'").fetchone():
        db.execute("""CREATE TEMP TABLE network_finding_lifecycle(
            finding_id TEXT PRIMARY KEY, status TEXT NOT NULL, assignee_name TEXT NOT NULL,
            due_date TEXT NOT NULL, updated_at TEXT NOT NULL)""")
    selected = sources or SOURCES
    status_values = sorted(statuses or ()) + [""] * (6 - len(statuses or ()))
    severity_values = sorted(severities or ()) + [""] * (6 - len(severities or ()))
    params: tuple[Any, ...] = (
        int("project" in selected), int("manual" in selected), int("network" in selected),
        int("dependency" in selected), int(statuses is None), *status_values,
        int(severities is None), *severity_values,
    )
    total = int(db.execute(_COUNT_SQL, params).fetchone()[0])
    rows = db.execute(_PAGE_SQL, (*params, limit, offset)).fetchall()
    groups = db.execute(_GROUP_SQL, params).fetchall()
    counts = {"by_source": {x: 0 for x in sorted(SOURCES)}, "by_status": {x: 0 for x in sorted(STATUSES)},
              "by_severity": {x: 0 for x in sorted(SEVERITIES, key=lambda x: SEVERITY_RANK[x])}}
    for row in groups:
        counts["by_source"][row["source"]] += row["n"]
        if row["status"] in counts["by_status"]: counts["by_status"][row["status"]] += row["n"]
        if row["severity"] in counts["by_severity"]: counts["by_severity"][row["severity"]] += row["n"]
    items = []
    for row in rows:
        location = ({"file": row["loc_a"], "line": int(row["loc_b"] or 0)} if row["loc_kind"] == "file" else
                    {"asset": row["loc_a"]} if row["loc_kind"] == "asset" else
                    {"package": row["loc_a"], "version": row["loc_b"]} if row["loc_kind"] == "package" else None)
        overdue, _ = finding_tracking.due_state(row["due_date"], row["status"])
        triage = None
        if row["source"] == "network":
            tr = db.execute("""SELECT verdict,confidence,decision FROM network_scan_triage_suggestions
                             WHERE finding_id=? ORDER BY created_at DESC,id DESC LIMIT 1""", (row["source_id"],)).fetchone()
            triage = ({"verdict": tr["verdict"], "confidence": float(tr["confidence"]), "decision": tr["decision"]}
                      if tr else None)
        items.append({"id": row["source"] + ":" + row["source_id"], "source": row["source"],
                      "source_id": row["source_id"], "status": row["status"], "native_status": row["native_status"],
                      "severity": row["severity"] if row["severity"] in SEVERITIES else "unknown",
                      "title": row["title"], "reference": row["reference"], "location": location,
                      "scope": {"type": row["scope_type"], "id": row["scope_id"],
                                "name": row["scope_name"] or Path(row["scope_id"]).name},
                      "assignee": _assignee(row["assignee_id"], row["assignee_name"]),
                      "due_date": row["due_date"] or None, "overdue": overdue,
                      "first_seen_at": row["first_seen_at"], "updated_at": row["updated_at"], "triage": triage})
    return {"format": FORMAT, "items": items, "total": total, "returned": len(items), "offset": offset,
            "next_offset": offset + len(items) if offset + len(items) < total else None,
            "truncated": offset + len(items) < total, "counts": counts}
