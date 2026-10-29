from __future__ import annotations

from collections import deque
import hashlib
import re

import html
from typing import Any


SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK: dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _is_false_positive(finding: dict[str, Any]) -> bool:
    triage = finding.get("triage")
    if isinstance(triage, dict) and str(triage.get("disposition") or "").strip().lower() == "false_positive":
        return True
    if str(finding.get("disposition") or "").strip().lower() == "false_positive":
        return True
    tracking = finding.get("tracking")
    if isinstance(tracking, dict) and str(tracking.get("status") or "").strip().lower() == "false_positive":
        return True
    return False


def _active_findings(audit: dict[str, Any]) -> list[dict[str, Any]]:
    raw = audit.get("findings")
    if not isinstance(raw, list):
        return []
    return [f for f in raw if isinstance(f, dict) and not _is_false_positive(f)]


def _finding_key(finding: dict[str, Any]) -> tuple[str, str, str, str]:
    category = str(finding.get("category") or "").strip().lower()
    title = str(finding.get("title") or "").strip()
    file_loc = str(finding.get("file") or "").strip()
    if not file_loc:
        file_loc = str(finding.get("id") or finding.get("evidence") or "")[:120].strip()
    reference = str(finding.get("reference") or finding.get("cwe") or "").strip()
    return (category, title, file_loc, reference)


def _count_by_severity(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {sev: 0 for sev in SEVERITIES}
    for item in findings:
        sev = str(item.get("severity") or "info").strip().lower()
        if sev not in counts:
            sev = "info"
        counts[sev] += 1
    return counts


def _sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        findings,
        key=lambda f: (
            SEVERITY_RANK.get(str(f.get("severity") or "info").lower(), 5),
            str(f.get("category") or ""),
            str(f.get("title") or ""),
            str(f.get("file") or ""),
        ),
    )


def _line_num(finding: dict[str, Any]) -> int:
    try:
        return int(finding.get("line") or 0)
    except (TypeError, ValueError):
        return 0


def compare_project_audits(store: Any, audit_1_id: str, audit_2_id: str) -> dict[str, Any]:
    import finding_tracking

    audit_1 = store.get_project_audit(audit_1_id)
    audit_2 = store.get_project_audit(audit_2_id)
    if audit_1 is None or audit_2 is None:
        raise ValueError("Proje denetimi bulunamadı.")

    findings_1 = _active_findings(audit_1)
    findings_2 = _active_findings(audit_2)

    buckets_1: dict[tuple[str, str, str, str], list[dict[str, Any]]] = {}
    for f in findings_1:
        buckets_1.setdefault(_finding_key(f), []).append(f)

    buckets_2: dict[tuple[str, str, str, str], list[dict[str, Any]]] = {}
    for f in findings_2:
        buckets_2.setdefault(_finding_key(f), []).append(f)

    new_raw: list[dict[str, Any]] = []
    resolved_raw: list[dict[str, Any]] = []
    persistent_raw: list[dict[str, Any]] = []

    for key in set(buckets_1) | set(buckets_2):
        list_1 = buckets_1.get(key, [])
        list_2 = buckets_2.get(key, [])
        if not list_1:
            new_raw.extend(list_2)
            continue
        if not list_2:
            resolved_raw.extend(list_1)
            continue
        fps_1 = [finding_tracking.fingerprint(item) for item in list_1]
        fps_2 = [finding_tracking.fingerprint(item) for item in list_2]
        pairs: list[tuple[bool, int, int, int]] = []
        for idx_1, item_1 in enumerate(list_1):
            for idx_2, item_2 in enumerate(list_2):
                pairs.append((
                    fps_1[idx_1] != fps_2[idx_2],
                    abs(_line_num(item_1) - _line_num(item_2)),
                    idx_1,
                    idx_2,
                ))
        pairs.sort()
        used_1: set[int] = set()
        used_2: set[int] = set()
        for _fp_diff, _dist, idx_1, idx_2 in pairs:
            if idx_1 in used_1 or idx_2 in used_2:
                continue
            used_1.add(idx_1)
            used_2.add(idx_2)
            persistent_raw.append(list_2[idx_2])
        for idx_1, item_1 in enumerate(list_1):
            if idx_1 not in used_1:
                resolved_raw.append(item_1)
        for idx_2, item_2 in enumerate(list_2):
            if idx_2 not in used_2:
                new_raw.append(item_2)

    new_findings = _sort_findings(new_raw)
    resolved_findings = _sort_findings(resolved_raw)
    persistent_findings = _sort_findings(persistent_raw)

    score_1 = int(audit_1.get("score") if audit_1.get("score") is not None else 0)
    score_2 = int(audit_2.get("score") if audit_2.get("score") is not None else 0)

    return {
        "format": "sniper-project-audit-diff-v1",
        "audit_1_id": str(audit_1_id),
        "audit_2_id": str(audit_2_id),
        "project_name": str(audit_2.get("project_name") or audit_1.get("project_name") or ""),
        "score_1": score_1,
        "score_2": score_2,
        "score_delta": score_2 - score_1,
        "grade_1": str(audit_1.get("grade") or ""),
        "grade_2": str(audit_2.get("grade") or ""),
        "new_count": len(new_findings),
        "resolved_count": len(resolved_findings),
        "persistent_count": len(persistent_findings),
        "new_by_severity": _count_by_severity(new_findings),
        "resolved_by_severity": _count_by_severity(resolved_findings),
        "persistent_by_severity": _count_by_severity(persistent_findings),
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
        "persistent_findings": persistent_findings,
    }


SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}


def _cwe_number(value: str) -> str:
    match = re.search(r"CWE-(\d{1,5})", value or "", re.IGNORECASE)
    return match.group(1) if match else ""


def _sarif_location(uri: str, line: int, message: str | None = None) -> dict[str, Any]:
    location: dict[str, Any] = {
        "physicalLocation": {
            "artifactLocation": {"uri": uri},
            "region": {"startLine": max(1, line)},
        }
    }
    if message:
        location["message"] = {"text": message[:300]}
    return location


def _sarif_code_flow(flow: dict[str, Any], sink_uri: str, sink_line: int) -> dict[str, Any]:
    """Kaynak → (ara adımlar) → hedef yolunu SARIF threadFlow olarak ver (CodeQL biçimi)."""
    source_uri = str(flow.get("source_file") or sink_uri)
    try:
        source_line = int(flow.get("source_line") or 1)
    except (TypeError, ValueError):
        source_line = 1
    via = [str(item)[:80] for item in (flow.get("via") or [])][:8]
    steps = [{"location": _sarif_location(source_uri, source_line, f"Kaynak: {str(flow.get('source') or '')[:120]}")}]
    if via:
        steps.append({"location": _sarif_location(source_uri if len(via) == 1 else sink_uri,
                                                   source_line if len(via) == 1 else sink_line,
                                                   "Ara adımlar: " + " → ".join(via))})
    steps.append({"location": _sarif_location(sink_uri, sink_line, f"Hedef: {str(flow.get('sink') or '')[:120]}")})
    return {"threadFlows": [{"locations": steps}]}


def render_project_audit_sarif(audit: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(audit, dict):
        raise ValueError("Geçersiz proje denetimi verisi.")
    findings = _active_findings(audit)
    level_map = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }
    rules_by_id: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for index, finding in enumerate(findings, start=1):
        category = str(finding.get("category") or "security").strip()
        title = str(finding.get("title") or f"Bulgu #{index}").strip()
        description = str(finding.get("description") or title).strip()
        recommendation = str(finding.get("recommendation") or "").strip()
        cwe = str(finding.get("cwe") or "").strip()
        reference = str(finding.get("reference") or "").strip()
        severity = str(finding.get("severity") or "low").strip().lower()
        rule_id = str(finding.get("control_id") or cwe or reference or f"SNIPER-PROJ-{category.upper()}").strip()
        rule_id = "_".join(rule_id.split())[:64] or f"SNIPER-PROJ-{index}"

        if rule_id not in rules_by_id:
            rules_by_id[rule_id] = {
                "id": rule_id,
                "name": title[:120],
                "shortDescription": {"text": title},
                "fullDescription": {"text": description},
                "help": {"text": recommendation or description},
                "properties": {
                    "category": category,
                    "severity": severity,
                    "cwe": cwe,
                    "owasp": str(finding.get("owasp") or ""),
                },
            }

        uri = str(finding.get("file") or audit.get("project_name") or "project").strip() or "project"
        try:
            start_line = max(1, int(finding.get("line") or 1))
        except (TypeError, ValueError):
            start_line = 1
        cwe_id = _cwe_number(cwe or reference)
        rule = rules_by_id[rule_id]
        rule["properties"].setdefault("security-severity", SECURITY_SEVERITY.get(severity, "3.0"))
        tags = rule["properties"].setdefault("tags", ["security"])
        if cwe_id and f"external/cwe/cwe-{cwe_id}" not in tags:
            tags.append(f"external/cwe/cwe-{cwe_id}")

        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": level_map.get(severity, "note"),
            "message": {
                "text": f"{title}: {description}" + (f" | Öneri: {recommendation}" if recommendation else "")
            },
            "locations": [_sarif_location(uri, start_line)],
            "partialFingerprints": {
                # Hash only already-public result metadata.  Finding titles
                # and evidence can describe sensitive data and are excluded.
                "sniperFinding/v1": hashlib.sha256(
                    f"{rule_id}\0{uri}\0{start_line}".encode("utf-8")
                ).hexdigest()[:32],
            },
            "properties": {
                "id": str(finding.get("id") or ""),
                "severity": severity,
                "category": category,
                "evidence": str(finding.get("evidence") or "")[:300],
                "reference": reference,
            },
        }
        context_fp = str(finding.get("context_fingerprint") or "")
        if context_fp:
            # Satır kaymasına dayanıklı (kural + dosya + normalize kod satırı) parmak izi; yalnız değişenler modunda.
            result["partialFingerprints"]["sniperContext/v1"] = context_fp
        if isinstance(finding.get("is_new"), bool):
            result["baselineState"] = "new" if finding["is_new"] else "unchanged"
        flow = finding.get("taint_flow")
        if isinstance(flow, dict):
            result["codeFlows"] = [_sarif_code_flow(flow, uri, start_line)]
        results.append(result)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Sniper Project Security Analyzer",
                        "version": "2.0.0",
                        "informationUri": "https://owasp.org/www-project-web-security-testing-guide/",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
            }
        ],
    }


_DEP_TIER_LABELS = {"fix_first": "Önce düzelt", "plan": "Planla", "monitor": "İzle"}
_DEP_USAGE_LABELS = {"used": "kullanılıyor", "unused": "kullanılmıyor", "transitive_only": "yalnız geçişli",
                     "unknown": "bilinmiyor"}
MAX_DEPENDENCY_ROWS = 60


def _dependency_table_html(dependency_findings: list[dict[str, Any]] | None) -> str:
    """21. tur: projenin kayıtlı bağımlılık açıkları (çevrimdışı tarama) — kötü amaçlı paketler en üstte, sonra öncelik
    puanı. Yalnız etkin durumdakiler; ilk ``MAX_DEPENDENCY_ROWS`` satır."""
    import report_sections

    rows = [d for d in (dependency_findings or []) if isinstance(d, dict)
            and str(d.get("status") or "open") in report_sections.DEPENDENCY_ACTIVE]
    if not rows:
        return ""
    rows.sort(key=lambda d: (0 if report_sections.is_malicious(d) else 1, -(d.get("priority_score") or 0),
                             SEVERITY_RANK.get(str(d.get("severity") or "").lower(), 5),
                             str(d.get("package_name") or ""), str(d.get("vulnerability_id") or "")))
    esc = lambda value: html.escape(str(value if value is not None else ""))  # noqa: E731
    body = "".join(
        f"<tr class='{'dep-malicious' if report_sections.is_malicious(d) else ''}'>"
        f"<td>{'<strong>KÖTÜ AMAÇLI</strong> ' if report_sections.is_malicious(d) else ''}"
        f"<code>{esc(d.get('package_name'))}@{esc(d.get('installed_version'))}</code></td>"
        f"<td>{esc(d.get('vulnerability_id'))}</td><td>{esc(str(d.get('severity') or '').upper() or '-')}</td>"
        f"<td>{esc(d.get('fixed_version') or '-')}</td>"
        f"<td><span>{esc(_DEP_TIER_LABELS.get(d.get('priority_tier') or '', '-'))}</span>"
        f"{' <small>' + esc(d['priority_score']) + '</small>' if d.get('priority_score') is not None else ''}</td>"
        f"<td>{esc(_DEP_USAGE_LABELS.get(d.get('usage_state') or '', '-'))}</td></tr>"
        for d in rows[:MAX_DEPENDENCY_ROWS]
    )
    more = (f"<p class='meta'>İlk {MAX_DEPENDENCY_ROWS} satır gösteriliyor; toplam {len(rows)} etkin bağımlılık açığı.</p>"
            if len(rows) > MAX_DEPENDENCY_ROWS else "")
    return (
        f"<h3>Bağımlılık açıkları — çevrimdışı tarama ({len(rows)})</h3>"
        "<table><thead><tr><th>Paket</th><th>Kimlik</th><th>Önem</th><th>Düzeltilmiş sürüm</th><th>Öncelik</th>"
        f"<th>Kullanım</th></tr></thead><tbody>{body}</tbody></table>{more}"
    )


def render_project_audit_html(audit: dict[str, Any], executive_html: str | None = None,
                              dependency_findings: list[dict[str, Any]] | None = None,
                              ai_suggestions: list[dict[str, Any]] | None = None) -> str:
    if not isinstance(audit, dict):
        raise ValueError("Geçersiz proje denetimi verisi.")
    checks = audit.get("checks") if isinstance(audit.get("checks"), list) else []
    findings = _sort_findings(_active_findings(audit))

    check_rows: list[str] = []
    for chk in checks:
        if not isinstance(chk, dict):
            continue
        c_title = html.escape(str(chk.get("title") or chk.get("label") or chk.get("id") or ""))
        c_status = html.escape(str(chk.get("status") or ""))
        c_detail = html.escape(str(chk.get("detail") or chk.get("summary") or ""))
        check_rows.append(f"<tr><td>{c_title}</td><td>{c_status}</td><td>{c_detail}</td></tr>")
    checks_html = (
        "<table><thead><tr><th>Kontrol</th><th>Durum</th><th>Detay</th></tr></thead><tbody>"
        + "".join(check_rows)
        + "</tbody></table>"
        if check_rows
        else "<p>Kontrol özeti kaydı yok.</p>"
    )

    import report_sections

    # 21. tur: bulgular rapor alanlarına göre gruplanır (yönetici özetiyle aynı sınıflandırma); alan içinde kötü amaçlı
    # paketler en üstte, sonra önem sırası.
    grouped: dict[str, list[dict[str, Any]]] = {key: [] for key in report_sections.SECTION_ORDER}
    for f in findings:
        grouped[report_sections.section_of(f)].append(f)
    for key in grouped:
        grouped[key].sort(key=lambda f: (0 if report_sections.is_malicious(f) else 1,
                                         SEVERITY_RANK.get(str(f.get("severity") or "info").lower(), 5)))
    finding_cards: list[str] = []
    section_html: list[str] = []
    for key in report_sections.SECTION_ORDER:
        finding_cards = []
        for f in grouped[key]:
            finding_cards.append(_finding_card_html(f))
        dep_table = _dependency_table_html(dependency_findings) if key == "dependencies" else ""
        if finding_cards or dep_table:
            section_html.append(
                f"<section class='report-section' id='section-{key}'>"
                f"<h2>{html.escape(report_sections.SECTION_LABELS[key])} <span class='count'>({len(finding_cards)})</span></h2>"
                + "".join(finding_cards) + dep_table + "</section>"
            )
    findings_html = "".join(section_html) if section_html else "<p>Açık güvenlik bulgusu tespit edilmedi.</p>"
    findings_html += _ai_suggestions_html(ai_suggestions)
    try:
        import threat_model

        threat_html = threat_model.render_html_section(audit.get("threat_model"), list(audit.get("findings") or []))
    except Exception:  # rapor tehdit modeli olmadan da üretilir
        threat_html = ""
    return _project_page_html(audit, findings, checks_html, executive_html, findings_html, threat_html,
                              dependency_findings)


AI_DECISION_LABELS = {"pending": "Analist kararı bekliyor", "accepted": "Analist kabul etti", "rejected": "Analist reddetti",
                      "auto_applied": "Politikayla otomatik uygulandı", "reverted": "Geri alındı"}


def _ai_suggestions_html(suggestions: list[dict[str, Any]] | None) -> str:
    """25. tur: AI/ajan triyaj önerileri ayrı ve etiketli bölümde (öneridir; analist kararı değildir)."""
    rows = [s for s in (suggestions or []) if isinstance(s, dict)]
    if not rows:
        return ""
    esc = lambda value: html.escape(str(value if value is not None else ""))  # noqa: E731
    body = []
    for s in rows[:200]:
        loc = f"{esc(s.get('finding_file'))}:{esc(s.get('finding_line'))}" if s.get("finding_file") else "-"
        who = esc(s.get("agent") or s.get("source")) + (f" / {esc(s.get('model'))}" if s.get("model") else "")
        try:
            conf = f"{float(s.get('confidence') or 0):.2f}"
        except (TypeError, ValueError):
            conf = "-"
        body.append(f"<tr><td>{esc(s.get('finding_title'))}<br><code>{loc}</code></td>"
                    f"<td>{esc(s.get('verdict_label') or s.get('verdict'))} ({conf})</td><td>{who}</td>"
                    f"<td>{esc(AI_DECISION_LABELS.get(str(s.get('decision')), s.get('decision')))}</td>"
                    f"<td>{esc(s.get('rationale'))}</td></tr>")
    return ("<section class='report-section' id='section-ai-triage'>"
            f"<h2>AI/ajan triyaj önerileri <span class='count'>({len(rows)})</span></h2>"
            "<p class='meta'>Bu bölüm yapay zekâ ajanlarının <strong>önerileridir</strong>; analist kararı değildir. "
            "Bulgu durumları yalnız analist kabulüyle (ya da açıkça etkinleştirilmiş otomatik politika ile) değişir.</p>"
            "<table><thead><tr><th>Bulgu</th><th>AI önerisi (güven)</th><th>Ajan / model</th><th>Karar</th>"
            "<th>Gerekçe</th></tr></thead><tbody>" + "".join(body) + "</tbody></table></section>")


def _finding_card_html(f: dict[str, Any]) -> str:
    sev = html.escape(str(f.get("severity") or "info").upper())
    cat = html.escape(str(f.get("category") or ""))
    title = html.escape(str(f.get("title") or ""))
    desc = html.escape(str(f.get("description") or ""))
    file_loc = html.escape(str(f.get("file") or "-"))
    line_no = html.escape(str(f.get("line") or ""))
    evid = html.escape(str(f.get("evidence") or ""))
    rec = html.escape(str(f.get("recommendation") or ""))
    confidence = f.get("confidence") if isinstance(f.get("confidence"), dict) else None
    confidence_html = (f"<p class='meta'><strong>Güven:</strong> {html.escape(str(confidence.get('note') or ''))}</p>"
                       if confidence else "")
    loc_display = f"{file_loc}:{line_no}" if line_no else file_loc
    track = f.get("tracking") if isinstance(f.get("tracking"), dict) else {}
    owner_bits = []
    if track.get("assignee_name"):
        owner_bits.append(f"Sorumlu: {html.escape(str(track['assignee_name']))}")
    if track.get("due_date"):
        owner_bits.append(f"Son tarih: {html.escape(str(track['due_date']))}" + (" (gecikmiş)" if track.get("overdue") else ""))
    owner_html = f"<p class='meta'>{' · '.join(owner_bits)}</p>" if owner_bits else ""
    return (
        f"<div class='card sev-{sev.lower()}'>"
        f"<h3>[{sev}] {title}</h3>"
        f"<p class='meta'>Kategori: {cat} · Konum: <code>{loc_display}</code></p>"
        f"{owner_html}"
        f"<p>{desc}</p>"
        f"<pre>{evid}</pre>"
        f"<p><strong>Öneri:</strong> {rec}</p>"
        f"{confidence_html}"
        f"</div>"
    )


def _metrics_html(audit: dict[str, Any], findings: list[dict[str, Any]],
                  dependency_findings: list[dict[str, Any]] | None) -> str:
    """Başlık ölçütleri; konteyner ve SBOM kayıtlarında (audit_kind) imaj/bileşen bilgisi gösterilir."""
    import report_sections

    esc = lambda value: html.escape(str(value if value is not None else ""))  # noqa: E731
    score = int(audit.get("score") if audit.get("score") is not None else 0)
    grade = esc(audit.get("grade") or "-")
    summary = audit.get("summary") if isinstance(audit.get("summary"), dict) else {}
    kind = str(audit.get("audit_kind") or "project")
    metrics = [f"<div class=\"metric\"><strong>Puan / Harf Notu:</strong> {score} ({grade})</div>"]
    if kind == "container":
        container = audit.get("container") if isinstance(audit.get("container"), dict) else {}
        os_info = container.get("os") if isinstance(container.get("os"), dict) else {}
        metrics.append(f"<div class=\"metric\"><strong>İşletim sistemi:</strong> "
                       f"{esc(os_info.get('pretty_name') or os_info.get('id') or 'belirlenemedi')}</div>")
        metrics.append(f"<div class=\"metric\"><strong>Paket:</strong> "
                       f"{int(container.get('package_count') or audit.get('file_count') or 0)}</div>")
    elif kind == "sbom":
        sbom = audit.get("sbom") if isinstance(audit.get("sbom"), dict) else {}
        metrics.append(f"<div class=\"metric\"><strong>SBOM bileşeni:</strong> "
                       f"{int(sbom.get('component_count') or audit.get('file_count') or 0)}</div>")
    else:
        scanned_files = int(summary.get("scanned_files") or audit.get("scanned_files") or audit.get("file_count") or 0)
        scanned_bytes = int(summary.get("scanned_bytes") or audit.get("scanned_bytes") or audit.get("bytes_scanned") or 0)
        metrics.append(f"<div class=\"metric\"><strong>Taranan Dosya:</strong> {scanned_files}</div>")
        metrics.append(f"<div class=\"metric\"><strong>Taranan Bayt:</strong> {scanned_bytes}</div>")
    metrics.append(f"<div class=\"metric\"><strong>Bu analizdeki bulgu:</strong> {len(findings)}</div>")
    deps = [d for d in (dependency_findings or []) if isinstance(d, dict)
            and str(d.get("status") or "open") in report_sections.DEPENDENCY_ACTIVE]
    if deps:
        metrics.append(f"<div class=\"metric\"><strong>Bağımlılık açığı:</strong> {len(deps)}</div>")
    return "".join(metrics)


def _project_page_html(audit: dict[str, Any], findings: list[dict[str, Any]], checks_html: str,
                       executive_html: str | None, findings_html: str, threat_html: str,
                       dependency_findings: list[dict[str, Any]] | None) -> str:
    project_name = html.escape(str(audit.get("project_name") or "Proje Denetimi"))
    audit_id = html.escape(str(audit.get("id") or ""))
    created_at = html.escape(str(audit.get("created_at") or ""))
    metrics_html = _metrics_html(audit, findings, dependency_findings)
    return f"""<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="utf-8">
<title>Sniper Proje Güvenlik Raporu — {project_name}</title>
<style>
body {{ font-family: system-ui, -apple-system, sans-serif; margin: 2rem; color: #0f172a; background: #f8fafc; }}
header {{ background: #1e293b; color: #f8fafc; padding: 1.5rem; border-radius: 8px; margin-bottom: 1.5rem; }}
.metrics {{ display: flex; flex-wrap: wrap; gap: 1.5rem; margin-bottom: 1.5rem; }}
.metric {{ background: #fff; padding: 1rem 1.25rem; border-radius: 8px; border: 1px solid #cbd5e1; }}
table {{ width: 100%; border-collapse: collapse; background: #fff; margin-bottom: 1.5rem; }}
th, td {{ border: 1px solid #cbd5e1; padding: 0.6rem 0.8rem; text-align: left; vertical-align: top; }}
th {{ background: #f1f5f9; }}
.card {{ background: #fff; border: 1px solid #cbd5e1; border-left: 5px solid #475569; border-radius: 6px; padding: 1rem; margin-bottom: 1rem; }}
.sev-critical {{ border-left-color: #991b1b; }}
.sev-high {{ border-left-color: #dc2626; }}
.sev-medium {{ border-left-color: #d97706; }}
.sev-low {{ border-left-color: #2563eb; }}
.report-section {{ margin-bottom: 2rem; }}
.dep-malicious td {{ background: #fdecec; }}
.meta {{ color: #475569; font-size: 0.9rem; }}
pre {{ background: #f1f5f9; padding: 0.6rem; border-radius: 4px; overflow-x: auto; white-space: pre-wrap; }}
.threat-dfd {{ max-width: 100%; height: auto; }}
@media print {{ .card, tr {{ break-inside: avoid; }} }}
</style>
</head>
<body>
<header>
  <h1>Sniper Proje Güvenlik Denetimi: {project_name}</h1>
  <p>Denetim ID: {audit_id} · Tarih: {created_at}</p>
</header>
<section class="metrics">
  {metrics_html}
</section>
{executive_html or ""}
<section>
  <h2>Kontrol Özeti</h2>
  {checks_html}
</section>
{threat_html}
<section>
  <h2>Bulgular ({len(findings)})</h2>
  {findings_html}
</section>
</body>
</html>"""


_FUNC_DEF_RE = re.compile(
    r"(?:^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\("
    r"|^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_]\w*)\s*\("
    r"|^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_]\w*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_]\w*)\s*=>"
    r"|^\s*func\s+(?:\([^)]+\)\s*)?([A-Za-z_]\w*)\s*\("
    r"|^\s*(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z_]\w*)\s*\("
    r"|^\s*class\s+([A-Za-z_]\w*)\b)",
    re.MULTILINE,
)

_IMPORT_PATTERNS = (
    re.compile(r"^\s*from\s+([A-Za-z0-9_.]+)\s+import\s+([^\n#]+)", re.MULTILINE),
    re.compile(r"^\s*import\s+([A-Za-z0-9_.,\s]+)", re.MULTILINE),
    re.compile(r"""(?:from|import)\s+["']([^"']+)["']""", re.MULTILINE),
    re.compile(r"""require\s*\(\s*["']([^"']+)["']\s*\)""", re.MULTILINE),
)

_CALL_TOKEN_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_JVM_DOTNET_TYPE_DEF_RE = re.compile(
    r"^\s*(?:(?:public|protected|private|internal|abstract|final|sealed|static|partial)\s+)*"
    r"(?:class|interface|enum|record)\s+([A-Za-z_]\w*)\b",
    re.MULTILINE,
)
_MEMBER_CALL_OWNER_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\.\s*[A-Za-z_]\w*\s*\(")
_CSHARP_USING_RE = re.compile(
    r"^\s*(?:global\s+)?using\s+(?:[A-Za-z_]\w*\s*=\s*)?([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*;",
    re.MULTILINE,
)

_FRONTEND_EXTS = (".js", ".jsx", ".ts", ".tsx", ".vue")
_BACKEND_EXTS = (".py", ".go", ".rs", ".js", ".ts", ".java")

_FRONTEND_HTTP_RE = re.compile(
    r"""(?:fetch\s*\(\s*["'`](?P<fetch_url>/api/[^"'`\s?]+)|axios\.(?:get|post|put|delete|patch)\s*\(\s*["'`](?P<axios_url>/api/[^"'`\s?]+))"""
)

_BACKEND_ROUTE_RE = re.compile(
    r"""(?:@(?:app|router|bp)\.(?:get|post|put|delete|patch|route)\s*\(\s*["'](?P<py_url>/api/[^"'?]+)|(?:app|router|bp|r|mux|http)\.(?:get|post|put|delete|patch|route|handleFunc|HandleFunc)\s*\(\s*["'](?P<router_url>/api/[^"'?]+)|@(?:GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)\s*\(\s*(?:value\s*=\s*)?["'](?P<java_url>/api/[^"'?]+))"""
)


def _module_stems_for_path(file_path: str) -> set[str]:
    norm = file_path.replace("\\", "/").strip("/")
    base = norm.rsplit("/", 1)[-1]
    stem = base.rsplit(".", 1)[0] if "." in base else base
    stems = {stem} if stem else set()
    if stem == "__init__" and "/" in norm:
        pkg = norm.rsplit("/", 2)[-2]
        if pkg:
            stems.add(pkg)
    return stems


def _extract_file_dependencies(source: str) -> tuple[set[str], set[str], set[str]]:
    defined_symbols: set[str] = set()
    for match in _FUNC_DEF_RE.finditer(source):
        for group in match.groups():
            if group:
                defined_symbols.add(group)
    defined_symbols.update(_JVM_DOTNET_TYPE_DEF_RE.findall(source))

    imported_stems: set[str] = set()
    for match in _IMPORT_PATTERNS[0].finditer(source):
        mod_path, imported_names = match.group(1), match.group(2)
        for part in mod_path.split("."):
            if part:
                imported_stems.add(part)
        for item in imported_names.split(","):
            token = item.strip().split(" as ")[0].strip()
            if token and token != "*":
                imported_stems.add(token)

    for match in _IMPORT_PATTERNS[1].finditer(source):
        for item in match.group(1).split(","):
            mod_path = item.strip().split(" as ")[0].strip()
            for part in mod_path.split("."):
                if part:
                    imported_stems.add(part)

    for pat in _IMPORT_PATTERNS[2:]:
        for match in pat.finditer(source):
            raw_mod = match.group(1).strip()
            leaf = raw_mod.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
            stem = leaf.rsplit(".", 1)[0] if "." in leaf else leaf
            if stem:
                imported_stems.add(stem)

    for match in _CSHARP_USING_RE.finditer(source):
        imported_stems.update(part for part in match.group(1).split(".") if part)

    called_symbols = {m.group(1) for m in _CALL_TOKEN_RE.finditer(source)}
    # Java/C# static member calls name the changed type before ``.`` rather
    # than before ``(``. Treat that exact receiver token as a dependency too;
    # false positives can only widen the bounded scan cone, never hide a file.
    called_symbols.update(_MEMBER_CALL_OWNER_RE.findall(source))
    return imported_stems, defined_symbols, called_symbols


def compute_incremental_scan_cone(
    file_sources: dict[str, str],
    changed_files: list[str],
    *,
    max_depth: int | None = None,
) -> dict[str, Any]:
    """Pillar 6: Compute incremental call-cone of files transitively affected by changed_files."""
    if max_depth is not None and (
        not isinstance(max_depth, int) or isinstance(max_depth, bool) or not 0 <= max_depth <= 1_000
    ):
        raise ValueError("max_depth must be an integer between 0 and 1000")
    file_hashes: dict[str, str] = {}
    file_stems: dict[str, set[str]] = {}
    imported_by_file: dict[str, set[str]] = {}
    defined_by_file: dict[str, set[str]] = {}
    called_by_file: dict[str, set[str]] = {}
    importing_by_stem: dict[str, set[str]] = {}
    dependent_by_symbol: dict[str, set[str]] = {}

    for path, content in sorted((file_sources or {}).items()):
        text = str(content or "")
        file_hashes[path] = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
        file_stems[path] = _module_stems_for_path(path)
        imp_stems, def_syms, call_syms = _extract_file_dependencies(text)
        imported_by_file[path] = imp_stems
        defined_by_file[path] = def_syms
        called_by_file[path] = call_syms
        for stem in imp_stems:
            importing_by_stem.setdefault(stem, set()).add(path)
            dependent_by_symbol.setdefault(stem, set()).add(path)
        for symbol in call_syms:
            dependent_by_symbol.setdefault(symbol, set()).add(path)

    affected_cone: set[str] = set()
    queue: deque[tuple[str, int]] = deque()
    for changed in changed_files or []:
        if changed in file_sources and changed not in affected_cone:
            affected_cone.add(changed)
            queue.append((changed, 0))
        else:
            norm_changed = changed.replace("\\", "/").lstrip("./")
            for candidate in file_sources:
                norm_cand = candidate.replace("\\", "/").lstrip("./")
                if (norm_cand == norm_changed or norm_cand.endswith("/" + norm_changed)) and candidate not in affected_cone:
                    affected_cone.add(candidate)
                    queue.append((candidate, 0))

    depth_truncated = False
    max_depth_observed = 0
    while queue:
        current, depth = queue.popleft()
        max_depth_observed = max(max_depth_observed, depth)
        curr_stems = file_stems.get(current, set())
        curr_defs = defined_by_file.get(current, set())
        candidates: set[str] = set()
        for stem in curr_stems:
            candidates.update(importing_by_stem.get(stem, set()))
        for symbol in curr_defs:
            candidates.update(dependent_by_symbol.get(symbol, set()))
        unseen = candidates - affected_cone
        if max_depth is not None and depth >= max_depth:
            depth_truncated = depth_truncated or bool(unseen)
            continue
        for candidate in sorted(unseen):
            if candidate in affected_cone:
                continue
            affected_cone.add(candidate)
            queue.append((candidate, depth + 1))

    affected_cone_files = sorted(affected_cone)
    skipped_unchanged_files = sorted(set(file_sources.keys()) - affected_cone)
    total_files = max(1, len(file_sources))
    cone_reduction_ratio = 1.0 - (len(affected_cone_files) / total_files)

    return {
        "affected_cone_files": affected_cone_files,
        "skipped_unchanged_files": skipped_unchanged_files,
        "file_hashes": file_hashes,
        "cone_reduction_ratio": cone_reduction_ratio,
        "depth_truncated": depth_truncated,
        "max_depth_observed": max_depth_observed,
    }


def _normalize_api_path(raw_path: str) -> str:
    path = raw_path.strip().split("?", 1)[0].strip()
    path = re.sub(r"\$\{[^}]+\}", "{param}", path)
    path = re.sub(r"\{[^}]+\}", "{param}", path)
    path = re.sub(r"<[^>]+>", "{param}", path)
    path = re.sub(r":[A-Za-z_]\w*", "{param}", path)
    path = re.sub(r"(?<=/)\d+(?=/|$)", "{param}", path)
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    return path


def correlate_cross_language_api_flows(file_sources: dict[str, str]) -> list[dict[str, Any]]:
    """Pillar 6: Correlate frontend HTTP client calls with backend API route definitions."""
    frontend_calls: list[tuple[str, str, int]] = []
    backend_routes: list[tuple[str, str, int]] = []

    for file_path, content in sorted((file_sources or {}).items()):
        text = str(content or "")
        lower_path = file_path.lower()

        if lower_path.endswith(_FRONTEND_EXTS):
            for match in _FRONTEND_HTTP_RE.finditer(text):
                raw_url = match.group("fetch_url") or match.group("axios_url") or ""
                if raw_url:
                    line_no = text.count("\n", 0, match.start()) + 1
                    frontend_calls.append((_normalize_api_path(raw_url), file_path, line_no))

        if lower_path.endswith(_BACKEND_EXTS):
            for match in _BACKEND_ROUTE_RE.finditer(text):
                raw_url = (
                    match.group("py_url")
                    or match.group("router_url")
                    or match.group("java_url")
                    or ""
                )
                if raw_url:
                    line_no = text.count("\n", 0, match.start()) + 1
                    backend_routes.append((_normalize_api_path(raw_url), file_path, line_no))

    flows: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int, str, int]] = set()
    for fe_norm, fe_file, fe_line in frontend_calls:
        for be_norm, be_file, be_line in backend_routes:
            if fe_norm == be_norm and (fe_file != be_file or fe_line != be_line):
                key = (fe_norm, fe_file, fe_line, be_file, be_line)
                if key not in seen:
                    seen.add(key)
                    flows.append({
                        "api_path": fe_norm,
                        "frontend_file": fe_file,
                        "frontend_line": fe_line,
                        "backend_file": be_file,
                        "backend_line": be_line,
                    })

    flows.sort(key=lambda item: (
        item["api_path"],
        item["frontend_file"],
        item["frontend_line"],
        item["backend_file"],
        item["backend_line"],
    ))
    return flows


def build_enterprise_enriched_sarif(
    audit: dict[str, Any],
    *,
    include_fixes: bool = True,
    include_attack_graph: bool = True,
) -> dict[str, Any]:
    """Wave-7 Item #7: SARIF v2.1.0 çıktısını codeFlows, fixes ve çok-adımlı saldırı grafiği ile zenginleştir."""
    sarif = render_project_audit_sarif(audit)
    findings = _active_findings(audit)
    runs = sarif.get("runs") or []
    if not runs:
        return sarif
    run0 = runs[0]
    results = run0.get("results") or []
    for result, finding in zip(results, findings):
        uri = str(finding.get("file") or audit.get("project_name") or "project").strip() or "project"
        try:
            start_line = max(1, int(finding.get("line") or 1))
        except (TypeError, ValueError):
            start_line = 1
        if "codeFlows" not in result:
            result["codeFlows"] = [
                {
                    "threadFlows": [
                        {
                            "locations": [
                                {
                                    "location": _sarif_location(
                                        uri,
                                        start_line,
                                        f"Doğrulanan kaynak/hedef: {str(finding.get('title') or '')[:100]}",
                                    )
                                }
                            ]
                        }
                    ]
                }
            ]
        if include_fixes:
            rec_text = str(finding.get("recommendation") or "Sniper otomatik güvenlik yaması uygula")[:200]
            result["fixes"] = [
                {
                    "description": {"text": rec_text},
                    "artifactChanges": [
                        {
                            "artifactLocation": {"uri": uri},
                            "replacements": [
                                {
                                    "deletedRegion": {"startLine": start_line},
                                    "insertedContent": {"text": str(finding.get("recommendation") or "")[:200]},
                                }
                            ],
                        }
                    ],
                }
            ]
    if include_attack_graph:
        try:
            import attack_path_correlator

            run0.setdefault("properties", {})["attackGraph"] = (
                attack_path_correlator.synthesize_multi_hop_exploit_chains(findings)
            )
        except Exception:  # noqa: BLE001
            pass
    return sarif


