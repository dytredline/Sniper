"""Pure report renderers shared by the HTTP server and command-line tools.

This module intentionally has no dependency on the server, storage, database,
network, or filesystem layers.  Renderers only transform supplied dictionaries
into deterministic HTML, CSV, and SARIF values.
"""

from __future__ import annotations

import csv
import html
import io


def render_sarif(scan: dict) -> dict:
    findings = scan.get("findings", [])
    level_map = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    rules = []
    results = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        rule_id = f"SNIPER-{finding.get('id', 'finding')}"
        rules.append({
            "id": rule_id,
            "shortDescription": {"text": str(finding.get("title", "Sniper bulgusu"))},
            "fullDescription": {"text": str(finding.get("description", ""))},
            "help": {"text": str(finding.get("recommendation", ""))},
            "properties": {
                "category": finding.get("category"),
                "reference": finding.get("reference"),
                "severity": finding.get("severity"),
                "owasp": finding.get("owasp"),
                "cwe": finding.get("cwe"),
                "confidence": finding.get("confidence"),
                "detection": finding.get("detection"),
            },
        })
        results.append({
            "ruleId": rule_id,
            "level": level_map.get(finding.get("severity", "info"), "note"),
            "message": {"text": str(finding.get("description") or finding.get("title") or "Sniper bulgusu")},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": scan.get("target_url", "")}}}],
            "fingerprints": {"sniper/v1": str(finding.get("id", ""))},
            "properties": {
                "evidence": finding.get("evidence"),
                "recommendation": finding.get("recommendation"),
                "reference": finding.get("reference"),
                "severity": finding.get("severity"),
                "owasp": finding.get("owasp"),
                "cwe": finding.get("cwe"),
                "confidence": finding.get("confidence"),
                "detection": finding.get("detection"),
            },
        })
    return {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Sniper",
                "version": "1.0",
                "informationUri": "https://owasp.org/www-project-web-security-testing-guide/",
                "rules": rules,
            }},
            "automationDetails": {"id": f"sniper/{scan.get('target_hostname', 'target')}/{scan.get('id', 'scan')}"},
            "invocations": [{"executionSuccessful": scan.get("status") == "completed", "properties": {
                "scanId": scan.get("id"), "score": scan.get("score"), "grade": scan.get("grade"),
            }}],
            "results": results,
        }],
    }


def _combined_engagement_findings(engagement: dict) -> list[dict]:
    automated = (engagement.get("latest_scan") or {}).get("findings", [])
    return [
        {
            **finding,
            "source": "manual",
            "affected_asset": finding.get("affected_asset") or engagement.get("target_url", ""),
            "owasp": finding.get("owasp_category", ""),
            "cwe": finding.get("cwe_id", ""),
        }
        for finding in engagement.get("findings", [])
        if isinstance(finding, dict)
    ] + [
        {
            **finding,
            "source": "automatic",
            "affected_asset": engagement.get("target_url", ""),
        }
        for finding in automated
        if isinstance(finding, dict)
    ]


def render_engagement_csv(engagement: dict) -> str:
    output = io.StringIO(newline="")
    fields = [
        "source", "id", "severity", "status", "title", "affected_asset", "owasp", "cwe",
        "cvss_score", "cvss_vector", "remediation_owner", "due_date", "description", "impact",
        "evidence", "recommendation", "resolution_notes", "resolved_at", "last_retested_at",
    ]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore", lineterminator="\r\n")
    writer.writeheader()
    for finding in _combined_engagement_findings(engagement):
        writer.writerow({field: _csv_safe(finding.get(field, "")) for field in fields})
    return output.getvalue()


DIFF_CSV_FIELDS = ["change", "id", "severity", "title", "affected_asset", "category", "description", "recommendation"]


def render_diff_csv(diff: dict) -> str:
    """Scan Diff sonucunu tek tabloda dışa aktarır; hücreler manuel denetim CSV'siyle aynı formül-nötrlemeden geçer."""
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=DIFF_CSV_FIELDS, extrasaction="ignore", lineterminator="\r\n")
    writer.writeheader()
    for change, key in (("new", "new_findings"), ("resolved", "resolved_findings"), ("persistent", "persistent_findings")):
        for finding in diff.get(key, []) or []:
            if not isinstance(finding, dict):
                continue
            row = {field: _csv_safe(finding.get(field, "")) for field in DIFF_CSV_FIELDS if field != "change"}
            row["change"] = change
            writer.writerow(row)
    return output.getvalue()


def _csv_safe(value) -> str | int | float:
    if value is None:
        return ""
    if isinstance(value, (int, float)):
        return value
    rendered = str(value)
    if rendered and rendered[0] in ("\t", "\r", "\n", "\x00"):
        return "'" + rendered
    if rendered.lstrip().startswith(("=", "+", "-", "@", "＝", "＋", "－", "＠")):
        return "'" + rendered
    return rendered


def render_engagement_sarif(engagement: dict) -> dict:
    level_map = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    rules: list[dict] = []
    results: list[dict] = []
    seen_rules: set[str] = set()
    for finding in _combined_engagement_findings(engagement):
        finding_id = str(finding.get("id") or "finding")
        rule_id = f"SNIPER-{finding.get('source', 'finding').upper()}-{finding_id}"
        if rule_id not in seen_rules:
            rules.append({
                "id": rule_id,
                "shortDescription": {"text": str(finding.get("title") or "Sniper bulgusu")},
                "fullDescription": {"text": str(finding.get("description") or "")},
                "help": {"text": str(finding.get("recommendation") or "")},
                "properties": {
                    "source": finding.get("source"), "severity": finding.get("severity"),
                    "owasp": finding.get("owasp"), "cwe": finding.get("cwe"),
                },
            })
            seen_rules.add(rule_id)
        results.append({
            "ruleId": rule_id,
            "level": level_map.get(finding.get("severity", "info"), "note"),
            "message": {"text": str(finding.get("description") or finding.get("title") or "Sniper bulgusu")},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": str(finding.get("affected_asset") or engagement.get("target_url", ""))}}}],
            "fingerprints": {"sniper/engagement/v1": finding_id},
            "properties": {
                "source": finding.get("source"), "status": finding.get("status"),
                "severity": finding.get("severity"), "owasp": finding.get("owasp"), "cwe": finding.get("cwe"),
                "cvssScore": finding.get("cvss_score"), "cvssVector": finding.get("cvss_vector"),
                "remediationOwner": finding.get("remediation_owner"), "dueDate": finding.get("due_date"),
                "resolutionNotes": finding.get("resolution_notes"),
            },
        })
    return {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Sniper", "version": "1.1",
                "informationUri": "https://owasp.org/www-project-web-security-testing-guide/",
                "rules": rules,
            }},
            "automationDetails": {"id": f"sniper/engagement/{engagement.get('id', 'assessment')}"},
            "invocations": [{"executionSuccessful": True, "properties": {
                "engagementId": engagement.get("id"), "target": engagement.get("target_url"),
                "coveragePercent": (engagement.get("coverage") or {}).get("percent"),
            }}],
            "results": results,
        }],
    }


def render_report(scan: dict) -> str:
    esc = lambda value: html.escape(str(value) if value is not None else "")
    findings = scan.get("findings", [])
    finding_html = "".join(
        f"""
        <article class="finding {esc(finding.get('severity'))}">
          <div class="finding-head"><span>{esc(finding.get('severity', '').upper())}</span><b>{esc(finding.get('title'))}</b></div>
          <p>{esc(finding.get('description'))}</p>
          <dl><dt>Kanıt</dt><dd><code>{esc(finding.get('evidence'))}</code></dd>
              <dt>Öneri</dt><dd>{esc(finding.get('recommendation'))}</dd>
              <dt>Sınıflandırma</dt><dd>{esc(' · '.join(value for value in (finding.get('owasp'), finding.get('cwe')) if value) or 'OWASP WSTG')}</dd>
              <dt>Tespit</dt><dd>{esc(finding.get('detection', 'passive'))} · güven: {esc(finding.get('confidence', 'high'))}</dd>
              <dt>Referans</dt><dd>{esc(finding.get('reference'))}</dd></dl>
        </article>"""
        for finding in findings
    ) or "<p>Bu profilde bulgu tespit edilmedi.</p>"
    counts = scan.get("counts", {})
    comparison = scan.get("comparison") or {}
    if comparison.get("baseline"):
        comparison_html = '<section class="delta"><b>İlk ölçüm</b><span>Sonraki taramalarda değişimler karşılaştırılacaktır.</span></section>'
    elif comparison:
        score_delta = comparison.get("score_delta")
        score_delta_text = f"{score_delta:+d}" if isinstance(score_delta, int) else "—"
        comparison_html = f"""<section class="counts">
        <div class="card"><small>Önceki puan</small><b>{esc(comparison.get('previous_score', '—'))}</b></div>
        <div class="card"><small>Puan değişimi</small><b>{esc(score_delta_text)}</b></div>
        <div class="card"><small>Yeni bulgu</small><b>{esc(comparison.get('new_count', 0))}</b></div>
        <div class="card"><small>Giderilen</small><b>{esc(comparison.get('resolved_count', 0))}</b></div>
        </section>"""
    else:
        comparison_html = ""
    return f"""<!doctype html><html lang="tr"><head><meta charset="utf-8"><title>Sniper denetim raporu</title>
    <style>
    :root{{--ink:#13231e;--muted:#5d6d67;--line:#dce5df;--paper:#fff;--bg:#f3f6f4;--green:#0e7a54;--red:#bd3b45;--amber:#b8780e}}
    *{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:14px/1.55 Inter,Arial,sans-serif}}
    main{{max-width:920px;margin:40px auto;background:var(--paper);padding:52px;border:1px solid var(--line)}}
    header{{display:flex;justify-content:space-between;gap:24px;border-bottom:2px solid var(--ink);padding-bottom:24px}}
    h1{{font-size:27px;margin:0 0 6px}}h2{{margin-top:42px}}.brand{{letter-spacing:.15em;font-weight:800;color:var(--green)}}
    .score{{font-size:44px;font-weight:800;line-height:1}}.score small{{font-size:15px;color:var(--muted)}}
    .meta,.counts{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:24px 0}}.card{{padding:14px;border:1px solid var(--line);background:#f9fbfa}}
    .card small,dt{{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.08em}}.card b{{display:block;font-size:17px}}
    .finding{{border:1px solid var(--line);border-left:5px solid #789;padding:20px;margin:14px 0;break-inside:avoid}}
    .finding.high,.finding.critical{{border-left-color:var(--red)}}.finding.medium{{border-left-color:var(--amber)}}.finding.low{{border-left-color:#3b7f9b}}
    .finding-head{{display:flex;gap:12px;align-items:center}}.finding-head span{{font-size:10px;font-weight:800;letter-spacing:.08em}}
    .delta{{display:flex;gap:12px;margin:20px 0;padding:14px;background:#e8f3f6;color:#315d6d}}.delta span{{color:var(--muted)}}
    dl{{display:grid;grid-template-columns:90px 1fr;gap:8px 14px}}dd{{margin:0}}code{{white-space:pre-wrap;overflow-wrap:anywhere}}
    footer{{margin-top:38px;padding-top:18px;border-top:1px solid var(--line);color:var(--muted);font-size:12px}}
    @media print{{body{{background:white}}main{{border:0;margin:0;max-width:none;padding:20px}}}}@media(max-width:700px){{main{{margin:0;padding:25px}}.meta,.counts{{grid-template-columns:1fr 1fr}}header{{display:block}}}}
    </style></head><body><main>
    <header><div><div class="brand">SNIPER / BAĞIMSIZ DENETİM</div><h1>Web güvenliği temel değerlendirmesi</h1><div>{esc(scan.get('target_url'))}</div></div>
    <div class="score">{esc(scan.get('score', '—'))}<small>/100 · {esc(scan.get('grade', '—'))}</small></div></header>
    <section class="meta"><div class="card"><small>Tarama kimliği</small><b>{esc(scan.get('id'))}</b></div><div class="card"><small>Durum</small><b>{esc(scan.get('status'))}</b></div><div class="card"><small>Başlangıç</small><b>{esc(scan.get('started_at'))}</b></div><div class="card"><small>Bitiş</small><b>{esc(scan.get('finished_at'))}</b></div></section>
    <section class="counts"><div class="card"><small>Kritik</small><b>{esc(counts.get('critical', 0))}</b></div><div class="card"><small>Yüksek</small><b>{esc(counts.get('high', 0))}</b></div><div class="card"><small>Orta</small><b>{esc(counts.get('medium', 0))}</b></div><div class="card"><small>Düşük</small><b>{esc(counts.get('low', 0))}</b></div></section>
    {comparison_html}<h2>Bulgular</h2>{finding_html}
    <footer>Profil: safe-baseline-v2 · Kayıtlı hedefte düşük etkili GET kontrolleri ve yalnız dönen içerik üzerinde pasif analiz çalıştırılmıştır. Bu otomatik çıktı, kapsamlı manuel sızma testinin veya uyumluluk sertifikasının yerine geçmez.</footer>
    </main></body></html>"""


REPORT_STYLE = """
    :root{--ink:#13231e;--muted:#5d6d67;--line:#dce5df;--paper:#fff;--bg:#f3f6f4;--green:#0e7a54;--red:#bd3b45;--amber:#b8780e}
    *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.55 Inter,Arial,sans-serif}
    main{max-width:920px;margin:40px auto;background:var(--paper);padding:52px;border:1px solid var(--line)}
    header{display:flex;justify-content:space-between;gap:24px;border-bottom:2px solid var(--ink);padding-bottom:24px}
    h1{font-size:27px;margin:0 0 6px}h2{margin-top:42px}.brand{letter-spacing:.15em;font-weight:800;color:var(--green)}
    .score{font-size:44px;font-weight:800;line-height:1}.score small{font-size:15px;color:var(--muted)}
    .meta,.counts{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:24px 0}.card{padding:14px;border:1px solid var(--line);background:#f9fbfa}
    .card small,dt{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.08em}.card b{display:block;font-size:17px}
    .finding{border:1px solid var(--line);border-left:5px solid #789;padding:20px;margin:14px 0;break-inside:avoid}
    .finding.high,.finding.critical{border-left-color:var(--red)}.finding.medium{border-left-color:var(--amber)}.finding.low{border-left-color:#3b7f9b}
    .finding-head{display:flex;gap:12px;align-items:center}.finding-head span{font-size:10px;font-weight:800;letter-spacing:.08em}
    .delta{display:flex;gap:12px;margin:20px 0;padding:14px;background:#e8f3f6;color:#315d6d}.delta span{color:var(--muted)}
    dl{display:grid;grid-template-columns:90px 1fr;gap:8px 14px}dd{margin:0}code{white-space:pre-wrap;overflow-wrap:anywhere}
    footer{margin-top:38px;padding-top:18px;border-top:1px solid var(--line);color:var(--muted);font-size:12px}
    @media print{body{background:white}main{border:0;margin:0;max-width:none;padding:20px}}@media(max-width:700px){main{margin:0;padding:25px}.meta,.counts{grid-template-columns:1fr 1fr}header{display:block}}
"""


def render_diff_report(diff: dict, scan_1: dict, scan_2: dict) -> str:
    """İki tarama arasındaki farkı, tekil tarama raporuyla aynı stilde yazdırılabilir HTML olarak üretir."""
    esc = lambda value: html.escape(str(value if value is not None else ""))
    summary = diff.get("summary", {})

    def finding_cards(findings: list, empty_text: str) -> str:
        cards = "".join(
            f"""
        <article class="finding {esc(finding.get('severity'))}">
          <div class="finding-head"><span>{esc(str(finding.get('severity') or 'info').upper())}</span><b>{esc(finding.get('title') or finding.get('id') or 'Bulgu')}</b></div>
          <p>{esc(finding.get('description'))}</p>
          <dl><dt>Öneri</dt><dd>{esc(finding.get('recommendation'))}</dd>
              <dt>Varlık</dt><dd>{esc(finding.get('affected_asset') or scan_2.get('target_url'))}</dd>
              <dt>Kimlik</dt><dd><code>{esc(finding.get('id'))}</code></dd></dl>
        </article>"""
            for finding in findings if isinstance(finding, dict)
        )
        return cards or f"<p>{esc(empty_text)}</p>"

    def severity_row(label: str, counts: dict) -> str:
        counts = counts or {}
        return (
            f"<tr><th>{esc(label)}</th>"
            + "".join(f"<td>{esc(counts.get(key, 0))}</td>" for key in ("critical", "high", "medium", "low", "info"))
            + "</tr>"
        )

    score_delta = summary.get("score_delta")
    score_delta_text = f"{score_delta:+d}" if isinstance(score_delta, int) else "—"
    return f"""<!doctype html><html lang="tr"><head><meta charset="utf-8"><title>Sniper tarama karşılaştırması</title>
    <style>{REPORT_STYLE}
    table{{width:100%;border-collapse:collapse;margin:16px 0}}th,td{{border:1px solid var(--line);padding:8px 10px;text-align:left}}th{{background:#f9fbfa;font-weight:600}}
    </style></head><body><main>
    <header><div><div class="brand">SNIPER / TARAMA KARŞILAŞTIRMASI</div><h1>İki tarama arasındaki değişim</h1><div>{esc(scan_2.get('target_url'))}</div></div>
    <div class="score">{esc(score_delta_text)}<small> puan · {esc(summary.get('scan_1_score', '—'))} → {esc(summary.get('scan_2_score', '—'))}</small></div></header>
    <section class="meta">
      <div class="card"><small>Önceki tarama</small><b>{esc(summary.get('scan_1_id'))}</b>{esc(summary.get('scan_1_finished_at'))}</div>
      <div class="card"><small>Sonraki tarama</small><b>{esc(summary.get('scan_2_id'))}</b>{esc(summary.get('scan_2_finished_at'))}</div>
      <div class="card"><small>Önceki puan</small><b>{esc(summary.get('scan_1_score', '—'))}/100 · {esc(scan_1.get('grade', '—'))}</b></div>
      <div class="card"><small>Sonraki puan</small><b>{esc(summary.get('scan_2_score', '—'))}/100 · {esc(scan_2.get('grade', '—'))}</b></div>
    </section>
    <section class="counts">
      <div class="card"><small>Yeni bulgu</small><b>{esc(summary.get('new_count', 0))}</b></div>
      <div class="card"><small>Giderilen</small><b>{esc(summary.get('resolved_count', 0))}</b></div>
      <div class="card"><small>Devam eden</small><b>{esc(summary.get('persistent_count', 0))}</b></div>
      <div class="card"><small>Hedef</small><b>{esc(scan_2.get('target_hostname'))}</b></div>
    </section>
    <table><thead><tr><th>Önem dağılımı</th><th>Kritik</th><th>Yüksek</th><th>Orta</th><th>Düşük</th><th>Bilgi</th></tr></thead>
    <tbody>{severity_row('Yeni', summary.get('new_by_severity'))}{severity_row('Giderilen', summary.get('resolved_by_severity'))}{severity_row('Devam eden', summary.get('persistent_by_severity'))}</tbody></table>
    <h2>Yeni bulgular</h2>{finding_cards(diff.get('new_findings', []), 'Yeni bulgu yok.')}
    <h2>Giderilen bulgular</h2>{finding_cards(diff.get('resolved_findings', []), 'Giderilen bulgu yok.')}
    <h2>Devam eden bulgular</h2>{finding_cards(diff.get('persistent_findings', []), 'Devam eden bulgu yok.')}
    <footer>Karşılaştırma yalnız aynı hedefe ait iki tamamlanmış otomatik taramayı kapsar; bulgular kimlik veya içerik parmak iziyle eşleştirilir. Bu çıktı manuel sızma testinin yerine geçmez.</footer>
    </main></body></html>"""


def render_engagement_report(engagement: dict) -> str:
    esc = lambda value: html.escape(str(value) if value is not None else "")
    findings = engagement.get("findings", [])
    scan = engagement.get("latest_scan") or {}
    automated_findings = scan.get("findings", [])
    coverage = engagement.get("coverage", {})
    remediation = engagement.get("remediation", {})
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    combined = [
        {**finding, "source": "Manuel", "affected_asset": finding.get("affected_asset", engagement.get("target_url"))}
        for finding in findings
    ] + [
        {**finding, "source": "Otomatik temel tarama", "affected_asset": engagement.get("target_url")}
        for finding in automated_findings
    ]
    combined.sort(key=lambda item: severity_order.get(item.get("severity", "info"), 5))
    counts = {severity: sum(1 for item in combined if item.get("severity") == severity) for severity in severity_order}
    finding_rows = "".join(
        f"""
        <article class="finding {esc(item.get('severity'))}">
          <div class="finding-head"><span>{esc(item.get('severity', '').upper())}</span><b>{esc(item.get('title'))}</b><small>{esc(item.get('source'))}</small></div>
          <p>{esc(item.get('description'))}</p>
          <dl><dt>Etkilenen varlık</dt><dd>{esc(item.get('affected_asset'))}</dd>
              <dt>İyileştirme durumu</dt><dd>{esc(finding_status_label(item.get('status', 'open')))}</dd>
              <dt>Sınıflandırma</dt><dd>{esc(' · '.join(value for value in (item.get('owasp_category') or item.get('owasp'), item.get('cwe_id') or item.get('cwe')) if value) or '—')}</dd>
              <dt>CVSS 3.1</dt><dd>{esc(f"{item.get('cvss_score'):.1f} · {item.get('cvss_vector')}" if item.get('cvss_score') is not None else '—')}</dd>
              <dt>Etki</dt><dd>{esc(item.get('impact', 'Otomatik bulgu; manuel etki değerlendirmesi önerilir.'))}</dd>
              <dt>Kanıt</dt><dd><code>{esc(item.get('evidence'))}</code></dd>
              <dt>Öneri</dt><dd>{esc(item.get('recommendation'))}</dd>
              <dt>Sorumlu / hedef</dt><dd>{esc(' · '.join(value for value in (item.get('remediation_owner'), item.get('due_date')) if value) or '—')}</dd>
              <dt>Çözüm / yeniden test</dt><dd>{esc(item.get('resolution_notes') or '—')}</dd>
              <dt>Zaman damgası</dt><dd>{esc(' · '.join(value for value in (item.get('resolved_at'), item.get('last_retested_at')) if value) or '—')}</dd></dl>
        </article>"""
        for item in combined
    ) or "<p>Kaydedilmiş açık bulgu bulunmuyor.</p>"
    category_rows = "".join(
        f"<tr><td>{esc(category['title'])}</td><td>{esc(category['completed'])} / {esc(category['total'])}</td><td>{esc(category['percent'])}%</td><td>{esc(category['reference'])}</td></tr>"
        for category in engagement.get("categories", [])
    )
    test_rows = "".join(
        f"<tr><td><code>{esc(test['control_id'])}</code></td><td>{esc(test['category_title'])}</td><td>{esc(test['title'])}</td><td>{esc(test_status_label(test['status']))}</td><td>{esc(test.get('notes'))}</td></tr>"
        for test in engagement.get("tests", [])
    )
    approvals = engagement.get("special_approvals", {})
    approval_text = ", ".join(
        label for key, label in (
            ("controlled_lockout", "Kontrollü hesap kilitlenme doğrulaması"),
            ("staging_capacity", "Staging kapasite testi gözlemi"),
            ("redacted_data_proof", "Maskeli veri sızıntısı kanıtı"),
        ) if approvals.get(key)
    ) or "Özel onaylı doğrulama yok"
    return f"""<!doctype html><html lang="tr"><head><meta charset="utf-8"><title>Sniper manuel sızma testi raporu</title>
    <style>
    :root{{--ink:#13231e;--muted:#61716b;--line:#dce5df;--paper:#fff;--bg:#f3f6f4;--green:#0e7a54;--red:#bd3b45;--amber:#b8780e;--blue:#2f7088}}
    *{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:14px/1.55 Inter,Arial,sans-serif}}main{{max-width:980px;margin:35px auto;background:var(--paper);padding:50px;border:1px solid var(--line)}}
    header{{display:flex;justify-content:space-between;gap:24px;border-bottom:2px solid var(--ink);padding-bottom:25px}}h1{{font-size:29px;margin:0 0 7px}}h2{{margin:40px 0 14px;font-size:21px}}h3{{font-size:15px}}.brand{{letter-spacing:.15em;font-weight:800;color:var(--green)}}
    .coverage{{font-size:42px;font-weight:800;line-height:1;text-align:right}}.coverage small{{display:block;font-size:10px;color:var(--muted);margin-top:6px}}.meta,.counts{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:23px 0}}.card{{padding:13px;border:1px solid var(--line);background:#f9fbfa}}.card small,dt{{color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.07em}}.card b{{display:block;font-size:15px;overflow-wrap:anywhere}}
    .scope{{display:grid;grid-template-columns:1fr 1fr;gap:14px}}.scope>div{{border:1px solid var(--line);padding:16px}}.scope p{{white-space:pre-wrap}}table{{width:100%;border-collapse:collapse;font-size:11px}}th,td{{border:1px solid var(--line);padding:8px;text-align:left;vertical-align:top}}th{{background:#f4f7f5;color:var(--muted);text-transform:uppercase;font-size:9px;letter-spacing:.06em}}
    .finding{{border:1px solid var(--line);border-left:5px solid var(--blue);padding:18px;margin:12px 0;break-inside:avoid}}.finding.high,.finding.critical{{border-left-color:var(--red)}}.finding.medium{{border-left-color:var(--amber)}}.finding-head{{display:flex;gap:11px;align-items:center}}.finding-head span{{font-size:9px;font-weight:900}}.finding-head small{{margin-left:auto;color:var(--muted)}}dl{{display:grid;grid-template-columns:115px 1fr;gap:7px 13px}}dd{{margin:0}}code{{white-space:pre-wrap;overflow-wrap:anywhere}}
    .summary{{white-space:pre-wrap;border-left:4px solid var(--green);padding:4px 0 4px 16px}}footer{{margin-top:40px;padding-top:16px;border-top:1px solid var(--line);color:var(--muted);font-size:11px}}
    @media print{{body{{background:white}}main{{border:0;margin:0;max-width:none;padding:18px}}h2{{break-after:avoid}}table,.finding{{break-inside:avoid}}}}@media(max-width:700px){{main{{margin:0;padding:24px}}header{{display:block}}.coverage{{text-align:left;margin-top:15px}}.meta,.counts,.scope{{grid-template-columns:1fr 1fr}}}}
    </style></head><body><main>
    <header><div><div class="brand">SNIPER / MANUEL SIZMA TESTİ</div><h1>{esc(engagement.get('name'))}</h1><div>{esc(engagement.get('target_url'))}</div></div><div class="coverage">{esc(coverage.get('percent', 0))}%<small>METODOLOJİ KAPSAMI</small></div></header>
    <section class="meta"><div class="card"><small>Denetim kimliği</small><b>{esc(engagement.get('id'))}</b></div><div class="card"><small>Durum</small><b>{esc(engagement.get('status'))}</b></div><div class="card"><small>Yetki referansı</small><b>{esc(engagement.get('authorization_ref') or 'Belirtilmedi')}</b></div><div class="card"><small>Test penceresi</small><b>{esc(engagement.get('test_window') or 'Belirtilmedi')}</b></div></section>
    <section class="counts"><div class="card"><small>Kritik</small><b>{counts['critical']}</b></div><div class="card"><small>Yüksek</small><b>{counts['high']}</b></div><div class="card"><small>Orta</small><b>{counts['medium']}</b></div><div class="card"><small>Düşük</small><b>{counts['low']}</b></div></section>
    <section class="counts"><div class="card"><small>Etkin bulgu</small><b>{esc(remediation.get('active', 0))}</b></div><div class="card"><small>Geciken</small><b>{esc(remediation.get('overdue', 0))}</b></div><div class="card"><small>Yeniden test</small><b>{esc(remediation.get('retest', 0))}</b></div><div class="card"><small>Çözülen</small><b>{esc(remediation.get('resolved', 0))}</b></div></section>
    <h2>Yönetici özeti</h2><p class="summary">{esc(engagement.get('executive_summary') or 'Yönetici özeti henüz yazılmadı.')}</p>
    <h2>Kapsam ve çalışma kuralları</h2><section class="scope"><div><h3>Kapsam içi</h3><p>{esc(engagement.get('scope_notes') or 'Belirtilmedi')}</p></div><div><h3>Kapsam dışı</h3><p>{esc(engagement.get('out_of_scope') or 'Belirtilmedi')}</p></div></section><p><b>Özel onaylar:</b> {esc(approval_text)}</p>
    <h2>Bulgular</h2>{finding_rows}
    <h2>Metodoloji kapsamı</h2><table><thead><tr><th>Kategori</th><th>Tamamlanan</th><th>Kapsam</th><th>Referans</th></tr></thead><tbody>{category_rows}</tbody></table>
    <h2>Test günlüğü</h2><table><thead><tr><th>Kontrol</th><th>Kategori</th><th>Test</th><th>Durum</th><th>Not</th></tr></thead><tbody>{test_rows}</tbody></table>
    <footer>Sniper yerel denetim kaydı · Otomatik temel tarama ve manuel test kanıtlarını birleştirir. Özel onaylı doğrulamalar trafik üretmez; yalnızca yetkili test uzmanının güvenli kanıtını kaydeder.</footer>
    </main></body></html>"""


def test_status_label(status: str) -> str:
    return {
        "not_tested": "Test edilmedi", "passed": "Geçti", "failed": "Bulgu var",
        "needs_review": "İnceleme gerekli", "not_applicable": "Uygulanamaz",
    }.get(status, status)


def finding_status_label(status: str) -> str:
    return {
        "open": "Açık", "in_progress": "Üzerinde çalışılıyor",
        "retest_required": "Yeniden test bekliyor", "resolved": "Çözüldü",
        "reopened": "Yeniden açıldı", "risk_accepted": "Risk kabulü",
    }.get(status, status)

