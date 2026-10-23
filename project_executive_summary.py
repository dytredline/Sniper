"""Tek proje için yönetici özeti: risk düzeyi, açık kritik/yüksek bulgular, trend, en önemli 5 bulgu,
düzelme hızı, tarama kapsamı ve ölçüm güveni notu (JSON + HTML).

Dil ve risk eşikleri ``executive_pentest_report.py`` ile tutarlıdır; veri bulgu takibinden (``finding_tracking``)
ve ilgili proje analizinden gelir. Kaynak kod satırı içermez.
"""
from __future__ import annotations

import html
from typing import Any

import finding_tracking
import license_compliance
import report_sections

FORMAT = "sniper-project-executive-summary-v1"
RISK_LABELS = {"critical": "Kritik", "high": "Yüksek", "medium": "Orta", "low": "Düşük"}
SEVERITY_LABELS = {"critical": "Kritik", "high": "Yüksek", "medium": "Orta", "low": "Düşük", "info": "Bilgi"}
SLA = {"critical": "0 - 7 gün", "high": "7 - 30 gün", "medium": "31 - 60 gün", "low": "61 - 90 gün", "info": "Sürekli izleme"}
# Bağımsız ölçüm (2026-10-20, 5. set: hiç ayar görmemiş 11 kasıtlı açıklı uygulama, 99 belgeli açık; 12. tur motoru).
MEASUREMENT_NOTE = (
    "Doğrulanmış veri akışı bulgularının kesinliği bağımsız ölçümde yaklaşık %97 (68 bulgudan 66'sı doğru); "
    "aynı sette belgeli açıkların 55/99'u doğrulanmış akışla, 60/99'u tüm kurallarla bulundu. Desen/hotspot "
    "bulguları gözden geçirme gerektirir. Statik analiz dinamik ve manuel testin yerini tutmaz."
)


def _risk_level(active_by_severity: dict[str, int], score: int | None) -> str:
    score = 100 if score is None else score
    if active_by_severity.get("critical") or score < 50:
        return "critical"
    if active_by_severity.get("high") or score < 70:
        return "high"
    if active_by_severity.get("medium") or score < 85:
        return "medium"
    return "low"


def build_project_executive_summary(store: Any, audit: dict[str, Any], *, trend_limit: int = 10) -> dict[str, Any]:
    project_path = str(audit.get("project_path") or "")
    tracking = store.tracked_project_summary(project_path, trend_limit=trend_limit, as_of_audit_id=audit.get("id"))
    active = store.list_tracked_findings(project_path, set(finding_tracking.ACTIVE_STATUSES), limit=5000)
    # 21. tur: alan bölümleri tek kaynaktan — bulgu takibinin etkin kayıtları + projenin kayıtlı bağımlılık açıkları
    # (çevrimdışı tarama; bulgu takibinde olmayan ayrı küme). Kötü amaçlı paket iki kaynakta da varsa bir kez sayılır.
    dependency_rows: list[dict[str, Any]] = []
    getter = getattr(store, "dependency_findings_for_project", None)
    if callable(getter) and project_path:
        try:
            dependency_rows = list(getter(project_path))
        except Exception:  # noqa: BLE001 — eski şema/test deposu: bölüm bağımlılık taraması olmadan üretilir
            dependency_rows = []
    sections = report_sections.build_sections(
        active, dependency_rows, licenses=audit.get("licenses"), api_contract=audit.get("api_contract"),
        supply_chain=audit.get("supply_chain"), container=audit.get("container"))
    code = next(sec for sec in sections["sections"] if sec["key"] == "code")
    verified = sum(int(item.get("verified_flow") or 0) for item in active)
    score = int(audit.get("score") or 0)
    overall = sections["totals"]["by_severity"]
    risk = _risk_level({k: v for k, v in overall.items() if k in SEVERITY_LABELS}, score)
    top = [
        {key: item.get(key) for key in ("id", "severity", "title", "file", "line", "reference", "status", "status_label",
                                        "first_seen_at", "assignee_name", "due_date", "overdue")}
        for item in active[:5]
    ]
    trend = tracking["trend"]
    previous = next((row for row in reversed(trend[:-1]) if row["mode"] == "full"), None) if trend else None
    direction = None
    if previous and trend:
        delta = trend[-1]["score"] - previous["score"]
        direction = "iyileşiyor" if delta > 0 else "kötüleşiyor" if delta < 0 else "değişmedi"
    scope = audit.get("scope") if isinstance(audit.get("scope"), dict) else {}
    return {
        "format": FORMAT,
        "project_name": audit.get("project_name"),
        "project_path": project_path,
        "audit_id": audit.get("id"),
        "audit_created_at": audit.get("created_at"),
        "score": score,
        "grade": audit.get("grade"),
        "risk_level": risk,
        "risk_label": RISK_LABELS[risk],
        "active_findings": tracking["active"],
        "active_by_severity": tracking["active_by_severity"],
        "suppressed_findings": tracking["suppressed"],
        "fixed_total": tracking["fixed_total"],
        "mean_time_to_fix_hours": tracking["mean_time_to_fix_hours"],
        "this_audit": audit.get("tracking") or {},
        "trend": trend,
        "trend_direction": direction,
        "top_findings": top,
        "verified_flow_findings": verified,
        "pattern_findings": max(0, code["active"] - verified),
        "audit_kind": audit.get("audit_kind") or "project",
        "sections": sections["sections"],
        "section_context": sections["context"],
        "overall_active": sections["totals"]["active"],
        "overall_by_severity": overall,
        "dependency_vulnerabilities": next(sec for sec in sections["sections"] if sec["key"] == "dependencies")["active"],
        "scope": scope,
        "coverage_warnings": [str(item) for item in (audit.get("warnings") or [])][:10],
        "measurement_note": MEASUREMENT_NOTE,
        "licenses": license_compliance.executive_summary(audit.get("licenses")),
        "ownership": tracking.get("ownership") or {},
        "deadlines": tracking.get("deadlines") or [],
    }


def _dependency_row(summary: dict[str, Any], esc) -> str:
    """Bağımlılık açıkları (çevrimdışı tarama) ayrı satırda; 'Açık bulgu' bulgu takibinden gelir, ikisi çakışmaz."""
    deps = int(summary.get("dependency_vulnerabilities") or 0)
    if not deps:
        return ""
    overall = summary.get("overall_by_severity") or {}
    return (f"<tr><th>Bağımlılık açığı</th><td>{deps} (toplam etkin {int(summary.get('overall_active') or 0)}: "
            f"kritik {int(overall.get('critical') or 0)}, yüksek {int(overall.get('high') or 0)})</td></tr>")


def _hours_text(hours: float | None) -> str:
    if hours is None:
        return "henüz düzelen bulgu yok"
    if hours < 48:
        return f"{hours:.1f} saat"
    return f"{hours / 24:.1f} gün"


def _owner_text(item: dict[str, Any], esc) -> str:
    parts = []
    if item.get("assignee_name"):
        parts.append(f"sorumlu: {esc(item['assignee_name'])}")
    if item.get("due_date"):
        parts.append(f"son tarih: {esc(item['due_date'])}{' (gecikmiş)' if item.get('overdue') else ''}")
    return "".join(f" · {part}" for part in parts)


_TIER_LABELS = {"fix_first": "önce düzelt", "plan": "planla", "monitor": "izle"}
_USAGE_LABELS = {"used": "kullanılıyor", "unused": "kullanılmıyor", "transitive_only": "yalnız geçişli"}


def _sev_label(value: Any) -> str:
    return SEVERITY_LABELS.get(str(value), "Belirsiz")


def _label(text: str, esc) -> str:
    """Çevrilebilir etiket: veriden ayrı metin düğümü (i18n katmanı düğüm düğüm çevirir)."""
    return f"<span>{esc(text)}</span>"


def _section_item_html(item: dict[str, Any], esc) -> str:
    mark = "<strong>KÖTÜ AMAÇLI</strong> " if item.get("malicious") else ""
    head = f"<strong>[{esc(_sev_label(item.get('severity')))}]</strong> {mark}"
    if item.get("source") == "dependency":
        fix = (f" → {esc(item['fixed_version'])}" if item.get("fixed_version")
               else " " + _label("(düzeltilmiş sürüm yok)", esc))
        extra = [label for label in (_TIER_LABELS.get(item.get("priority_tier") or ""),
                                     _USAGE_LABELS.get(item.get("usage") or "")) if label]
        extra_html = "".join(" · " + _label(label, esc) for label in extra)
        return (f"<li>{head}<code>{esc(item.get('package'))}@{esc(item.get('version'))}</code>{fix} · "
                f"{esc(item.get('reference'))}{extra_html} — {esc(item.get('title'))}</li>")
    loc = f"{esc(item.get('file'))}{':' + esc(item['line']) if item.get('line') else ''}"
    flow = " · " + _label("doğrulanmış akış", esc) if item.get("verified_flow") else ""
    status = " · " + _label(item["status_label"], esc) if item.get("status_label") else ""
    return (f"<li>{head}{esc(item.get('title'))} — <code>{loc}</code>"
            f"{' · ' + esc(item['reference']) if item.get('reference') else ''}{flow}{status}{_owner_text(item, esc)}</li>")


def _pairs_html(pairs: list[tuple[str, Any]], esc) -> str:
    """'Etiket sayı · Etiket sayı' — etiketler ayrı düğümde (çeviri), sayılar düz metin."""
    return " · ".join(f"{_label(label, esc)} {esc(value)}" for label, value in pairs)


def _context_html(key: str, context: dict[str, Any], esc) -> str:
    ctx = context.get(key) or {}
    if not ctx:
        return ""
    if key == "license":
        pairs = [("Proje lisansı:", ctx.get("project_license") or "—"), ("Bileşen", ctx["components"]),
                 ("izinli", ctx["allowed"]), ("dikkat", ctx["caution"]), ("yasak", ctx["denied"]),
                 ("inceleme", ctx["review"])]
    elif key == "api":
        pairs = [("Sözleşme", ctx["specs"]), ("İşlem", ctx["spec_operations"]), ("Eşleşen", ctx["matched_operations"]),
                 ("Koddaki rota", ctx["code_routes"]), ("Gölge uç", ctx["shadow_routes"]),
                 ("Kodda olmayan", ctx["missing_in_code"]), ("Kimlik uyuşmazlığı", ctx["auth_mismatch"])]
    elif key == "supply_chain":
        pairs = [("Kötü amaçlı paket", int(ctx.get("malicious") or 0)),
                 ("Şüpheli kurulum betiği", int(ctx.get("suspicious_install_scripts") or 0)),
                 ("Bağımlılık karışıklığı ipucu", int(ctx.get("confusion_hints") or 0))]
    elif key == "container":
        pairs = [("İşletim sistemi:", ctx.get("os") or "—"), ("Paket", ctx["packages"]), ("Düzeltilebilir", ctx["fixable"])]
    else:
        return ""
    return f"<p class=\"meta\">{_pairs_html(pairs, esc)}</p>"


def render_sections_html(summary: dict[str, Any]) -> str:
    """21. tur: alanlara göre durum tablosu + alan başına en önemli 5 madde ve önerilen eylem."""
    sections = summary.get("sections") or []
    if not sections:
        return ""
    esc = lambda value: html.escape(str(value if value is not None else ""))  # noqa: E731
    context = summary.get("section_context") or {}
    rows = "".join(
        f"<tr><td>{esc(sec['label'])}</td><td>{int(sec['active'])}</td><td>{int(sec['critical_high'])}</td>"
        f"<td>{esc(sec['action'])}</td></tr>"
        for sec in sections if sec["active"] or sec["key"] in context
    )
    if not rows:
        return ""
    details = []
    for sec in sections:
        if not sec["active"] and sec["key"] not in context:
            continue
        pairs = [(_sev_label(k), int(v)) for k, v in sec["by_severity"].items() if v]
        if sec["key"] == "dependencies" and sec["active"]:
            pairs += [("Kötü amaçlı", int(sec.get("malicious") or 0)), ("Önce düzelt", int(sec.get("fix_first") or 0))]
        counts = _pairs_html(pairs, esc) if pairs else _label("Etkin bulgu yok.", esc)
        items = "".join(_section_item_html(item, esc) for item in sec["top"])
        details.append(
            f"<h4>{esc(sec['label'])} <span class=\"count\">({int(sec['active'])})</span></h4>"
            f"{_context_html(sec['key'], context, esc)}"
            f"<p class=\"meta\">{counts}</p>"
            f"{'<ol>' + items + '</ol>' if items else ''}"
            f"<p><strong>Önerilen eylem:</strong> {esc(sec['action'])}</p>"
        )
    return (
        "<h3>Alanlara göre durum</h3>"
        "<table><thead><tr><th>Alan</th><th>Etkin</th><th>Kritik + yüksek</th><th>Önerilen eylem</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
        + "".join(details)
    )


def render_section_html(summary: dict[str, Any]) -> str:
    """Proje raporuna gömülen "Yönetici özeti" bölümü."""
    esc = lambda value: html.escape(str(value if value is not None else ""))  # noqa: E731
    sev = summary.get("active_by_severity") or {}
    this = summary.get("this_audit") or {}
    # Önem tablosu: proje bulguları + bağımlılık açıkları (tek kaynak: report_sections toplamı; yoksa bulgu takibi)
    sev_table = summary.get("overall_by_severity") or sev
    rows = "".join(
        f"<tr><td>{esc(SEVERITY_LABELS[key])}</td><td>{int(sev_table.get(key) or 0)}</td><td>{esc(SLA[key])}</td></tr>"
        for key in ("critical", "high", "medium", "low", "info")
    )
    top = "".join(
        f"<li><strong>[{esc(SEVERITY_LABELS.get(item['severity'], item['severity']))}]</strong> {esc(item['title'])} — "
        f"<code>{esc(item['file'])}{':' + esc(item['line']) if item.get('line') else ''}</code> · {esc(item['reference'])} · "
        f"{esc(item['status_label'])}{_owner_text(item, esc)}</li>"
        for item in summary.get("top_findings") or []
    ) or "<li>Açık bulgu yok.</li>"
    owner = summary.get("ownership") or {}
    deadlines = "".join(
        f"<tr><td>{esc(item['due_date'])}{' <strong>(gecikmiş)</strong>' if item.get('overdue') else ''}</td>"
        f"<td>{esc(item.get('assignee_name') or 'atanmamış')}</td>"
        f"<td>[{esc(SEVERITY_LABELS.get(item['severity'], item['severity']))}] {esc(item['title'])} — "
        f"<code>{esc(item['file'])}{':' + esc(item['line']) if item.get('line') else ''}</code></td>"
        f"<td>{esc(item.get('status_label'))}</td></tr>"
        for item in summary.get("deadlines") or []
    )
    trend = "".join(
        f"<tr><td>{esc(row['created_at'])}</td><td>{'ek tarama' if row['mode'] == 'supplement' else 'tam'}</td>"
        f"<td>{esc(row['score'])} ({esc(row['grade'])})</td><td>{int(row['new'])}</td><td>{int(row['fixed'])}</td>"
        f"<td>{int(row['reopened'])}</td></tr>"
        for row in summary.get("trend") or []
    )
    warnings = "".join(f"<li>{esc(item)}</li>" for item in summary.get("coverage_warnings") or [])
    licenses = summary.get("licenses") or None
    license_html = ""
    if licenses:
        cats = licenses.get("by_category") or {}
        flagged = "".join(
            f"<li><strong>[{esc(license_compliance.CATEGORY_LABELS.get(item['category'], item['category']))}]</strong> "
            f"{esc(item['name'])}{'@' + esc(item['version']) if item.get('version') else ''} — "
            f"{esc(item.get('expression') or item.get('raw') or '?')}</li>"
            for item in licenses.get("top") or []
        )
        license_html = (
            "<h3>Bağımlılık lisansları</h3><table>"
            f"<tr><th>Proje lisansı</th><td>{esc(licenses.get('project_license') or 'belirlenemedi')}</td></tr>"
            f"<tr><th>Bileşen</th><td>{int(licenses.get('component_count') or 0)} · izinli {int(cats.get('allowed') or 0)} · "
            f"dikkat {int(cats.get('caution') or 0)} · yasak {int(cats.get('denied') or 0)} · inceleme {int(cats.get('review') or 0)}</td></tr>"
            "</table>" + (f"<ol>{flagged}</ol>" if flagged else "")
        )
    direction = summary.get("trend_direction")
    return f"""<section class="executive-summary">
  <h2>Yönetici özeti</h2>
  <table>
    <tr><th>Risk düzeyi</th><td><strong>{esc(summary['risk_label'])}</strong></td></tr>
    <tr><th>Puan</th><td>{esc(summary['score'])}/100 ({esc(summary['grade'])}){' · eğilim: ' + esc(direction) if direction else ''}</td></tr>
    <tr><th>Açık bulgu</th><td>{int(summary['active_findings'])} (kritik {int(sev.get('critical') or 0)}, yüksek {int(sev.get('high') or 0)})</td></tr>{_dependency_row(summary, esc)}
    <tr><th>Bu analizde</th><td>{int(this.get('new_count') or 0)} yeni · {int(this.get('fixed_count') or 0)} düzelen · {int(this.get('reopened_count') or 0)} yeniden açılan · {int(this.get('not_rescanned_count') or 0)} kapsam dışı kaldığı için doğrulanamayan</td></tr>
    <tr><th>Bastırılan</th><td>{int(summary['suppressed_findings'])} (yanlış alarm / risk kabulü; gizlenmez)</td></tr>
    <tr><th>Düzelen (toplam)</th><td>{int(summary['fixed_total'])} · ortalama düzeltme süresi: {esc(_hours_text(summary.get('mean_time_to_fix_hours')))}</td></tr>
    <tr><th>Sahiplik</th><td>{int(owner.get('assigned_active') or 0)} atanmış · {int(owner.get('unassigned_active') or 0)} atanmamış açık bulgu · {int(owner.get('overdue') or 0)} gecikmiş · {int(owner.get('due_soon') or 0)} son tarihi yaklaşan</td></tr>
    <tr><th>Bulgu türü</th><td>{int(summary['verified_flow_findings'])} doğrulanmış veri akışı · {int(summary['pattern_findings'])} desen/gözden geçirme</td></tr>
  </table>
  {render_sections_html(summary)}
  <h3>Önem dağılımı ve müdahale hedefi</h3>
  <table><thead><tr><th>Önem</th><th>Açık</th><th>Hedef süre</th></tr></thead><tbody>{rows}</tbody></table>
  <h3>Öncelikli 5 bulgu</h3>
  <ol>{top}</ol>
  {f'<h3>Son tarihler</h3><table><thead><tr><th>Son tarih</th><th>Sorumlu</th><th>Bulgu</th><th>Durum</th></tr></thead><tbody>{deadlines}</tbody></table>' if deadlines else ''}
  <h3>Trend</h3>
  <table><thead><tr><th>Analiz</th><th>Tür</th><th>Puan</th><th>Yeni</th><th>Düzelen</th><th>Yeniden açılan</th></tr></thead><tbody>{trend}</tbody></table>
  {license_html}
  {f'<h3>Kapsam</h3><ul>{warnings}</ul>' if warnings else ''}
  <p class="meta"><strong>Ölçüm güveni:</strong> {esc(summary['measurement_note'])}</p>
</section>"""


def render_page_html(summary: dict[str, Any]) -> str:
    title = html.escape(str(summary.get("project_name") or "Proje"))
    return f"""<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sniper Yönetici Özeti — {title}</title>
<style>
body {{ font-family: system-ui, -apple-system, sans-serif; margin: 2rem; color: #0f172a; background: #f8fafc; max-width: 960px; }}
table {{ width: 100%; border-collapse: collapse; background: #fff; margin-bottom: 1.25rem; }}
th, td {{ border: 1px solid #cbd5e1; padding: 0.5rem 0.7rem; text-align: left; vertical-align: top; }}
th {{ background: #f1f5f9; width: 28%; }}
code {{ background: #f1f5f9; padding: 0 4px; }}
.meta {{ color: #475569; font-size: 0.9rem; }}
</style>
</head>
<body>
<h1>{title} — yönetici özeti</h1>
<p class="meta">Biçim: {FORMAT} · Analiz: {html.escape(str(summary.get('audit_id') or ''))} · {html.escape(str(summary.get('audit_created_at') or ''))}</p>
{render_section_html(summary)}
</body>
</html>"""
