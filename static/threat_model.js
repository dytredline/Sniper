// Tehdit modeli paneli (STRIDE + veri akış diyagramı) ve bağımlılık erişilebilirliği tablosu.
// Diyagram sunucuda bağımlılıksız SVG olarak üretilir (tüm metinler kaçışlı); burada yalnız yerleştirilir.
(function () {
  "use strict";

  const STATUS_CLASS = { finding: "threat-finding", review: "threat-review" };

  function esc(value) {
    return String(value ?? "").replace(/[&<>"']/g, ch => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]));
  }

  function findingLabel(findings, index) {
    const f = findings[index];
    if (!f) return `#${index}`;
    return `${f.file || "?"}${f.line ? `:${f.line}` : ""} — ${f.title || ""}`;
  }

  function threatRows(model, findings) {
    return (model.threats || []).map(t => {
      const refs = (t.finding_refs || []).slice(0, 3).map(i => `<li>${esc(findingLabel(findings, i))}</li>`).join("");
      const extra = t.finding_count > 3 ? `<li>… +${t.finding_count - 3}</li>` : "";
      const detail = refs ? `<ul class="threat-refs">${refs}${extra}</ul>` : `<small>${esc(t.note || t.hint || "")}</small>`;
      return `<tr class="${STATUS_CLASS[t.status] || ""}"><td>${esc(t.id)}</td><td><b>${esc(t.stride)}</b> <small>${esc(t.stride_label)}</small></td>`
        + `<td>${esc(t.title)}</td><td>${esc(t.status_label)}${t.finding_count ? ` (${Number(t.finding_count)})` : ""}</td><td>${detail}</td></tr>`;
    }).join("");
  }

  // Yetki envanteriyle eşleşen rotalarda koruma bilgisi (eşleşme yoksa boş).
  function protectionCell(r) {
    if (r.protected === undefined) return "—";
    const idor = r.idor_candidate ? " · IDOR adayı" : "";
    return r.protected ? `${esc(r.protection || "korumalı")}${idor}` : `<b>korumasız</b>${idor}`;
  }

  function routeRows(model) {
    return (model.routes || []).slice(0, 200).map(r =>
      `<tr><td>${esc(r.method)}</td><td><code>${esc(r.path)}</code></td><td>${esc(r.handler)}</td><td>${protectionCell(r)}</td><td><code>${esc(r.file)}:${Number(r.line) || 0}</code></td></tr>`
    ).join("");
  }

  function strideSummary(model) {
    const counts = model.stride_counts || {};
    return Object.keys(counts).map(key => {
      const c = counts[key] || {};
      return `<span class="threat-chip${c.finding ? " has-finding" : ""}">${esc(key)}: ${Number(c.finding || 0)} bulgu · ${Number(c.review || 0)} gözden geçirme</span>`;
    }).join("");
  }

  async function renderThreatModel(audit) {
    const detail = document.getElementById("project-audit-detail");
    if (!detail || !audit || !audit.id) return;
    let panel = detail.querySelector(".threat-model-panel");
    if (!panel) {
      panel = document.createElement("section");
      panel.id = "threat-model-panel";
      panel.className = "threat-model-panel";
      const anchor = detail.querySelector(".project-finding-summary");
      if (anchor) detail.insertBefore(panel, anchor); else detail.appendChild(panel);
    }
    panel.dataset.auditId = audit.id;
    panel.innerHTML = `<p class="muted">Tehdit modeli yükleniyor…</p>`;
    let data;
    try {
      const response = await fetch(`/api/project-audits/${encodeURIComponent(audit.id)}/threat-model`);
      data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || "Tehdit modeli alınamadı.");
    } catch (error) {
      if (panel.dataset.auditId === audit.id) panel.innerHTML = `<p class="muted">${esc(error.message)}</p>`;
      return;
    }
    if (panel.dataset.auditId !== audit.id) return; // başka analiz açıldı
    const model = data.threat_model || {};
    const findings = Array.isArray(audit.findings) ? audit.findings : [];
    const routes = routeRows(model);
    panel.innerHTML = /* sniper-reviewed: html-safe (metinler esc ile; SVG sunucuda html.escape ile üretildi) */ `
      <details open><summary><b>Tehdit modeli (STRIDE)</b> <small>${Number(model.route_count || 0)} rota · ${(model.threats || []).length} tehdit${model.partial ? " · kısmi tarama" : ""}${data.rebuilt_from_disk ? " · klasörden yeniden çıkarıldı" : ""}</small></summary>
        <div class="threat-chips">${strideSummary(model)}</div>
        <div class="threat-dfd-wrap">${data.svg || ""}</div>
        <table class="threat-table"><thead><tr><th>No</th><th>STRIDE</th><th>Tehdit</th><th>Durum</th><th>Ayrıntı</th></tr></thead><tbody>${threatRows(model, findings)}</tbody></table>
        <details><summary>Rota envanteri (${Number(model.route_count || 0)})</summary>${routes
          ? `<table class="threat-table"><thead><tr><th>Yöntem</th><th>Yol</th><th>İşleyici</th><th>Koruma</th><th>Konum</th></tr></thead><tbody>${routes}</tbody></table>`
          : "<p>Rota bulunamadı.</p>"}</details>
        <ul class="threat-notes">${(model.notes || []).map(n => `<li>${esc(n)}</li>`).join("")}</ul>
      </details>`;
  }

  const VERDICT_CLASS = { reachable: "reach-yes", unknown: "reach-unknown", imported_not_called: "reach-imported", not_imported: "reach-no" };

  function renderReachabilitySummary(res, el) {
    if (!el || !res || res.format !== "sniper-vulnerability-reachability-v1" || !Array.isArray(res.items)) return;
    const sa = res.symbol_analysis || {};
    const counts = sa.verdict_counts || {};
    const labels = sa.verdict_labels || {};
    const order = { reachable: 0, unknown: 1, imported_not_called: 2, not_imported: 3 };
    const sevRank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const items = res.items.slice().sort((a, b) => {
      // 20. tur: öncelik puanı varsa "önce bunları düzelt" sırası; yoksa eski önem + erişilebilirlik sırası
      const pa = (a.priority || {}).score, pb = (b.priority || {}).score;
      if (typeof pa === "number" && typeof pb === "number" && pa !== pb) return pb - pa;
      const ra = a.reachability || {}, rb = b.reachability || {};
      return (sevRank[ra.effective_severity] ?? 5) - (sevRank[rb.effective_severity] ?? 5) || (order[ra.verdict] ?? 9) - (order[rb.verdict] ?? 9);
    });
    const rows = items.slice(0, 200).map(item => {
      const r = item.reachability || {};
      const base = r.effective_severity !== r.base_severity
        ? `${esc(r.effective_severity)} <small>(${esc(r.base_severity)}'dan düşürüldü)</small>` : esc(r.effective_severity || item.severity || "");
      const p = item.priority || {};
      const sev = p.tier ? `<span class="prio-chip prio-${esc(String(p.tier).replace(/[^a-z_]/g, ""))}">${esc(p.tier_label || p.tier)}</span> `
        + `<small>${Number(p.score || 0)}</small><br>${base}${item.usage ? `<br><small>${esc(item.usage.label || "")}</small>` : ""}` : base;
      const where = (r.evidence || []).slice(0, 2).map(s => `${s.file}:${s.line}`).join(", ");
      return `<tr class="${VERDICT_CLASS[r.verdict] || ""}"><td>${esc(item.package_name)}</td><td>${esc(item.vulnerability_id || item.id || "")}</td>`
        + `<td>${sev}</td><td>${esc(r.label || "")}<br><small>${esc(r.priority_reason || "")}</small></td>`
        + `<td><small>${esc((r.matched_symbols || []).join(", ") || (r.symbols || []).slice(0, 4).join(", "))}${r.symbol_source ? ` · ${esc(r.symbol_source)}` : ""}</small></td>`
        + `<td><code>${esc(where)}</code></td></tr>`;
    }).join("");
    const chips = Object.keys(labels).map(k => `<span class="threat-chip">${esc(labels[k])}: ${Number(counts[k] || 0)}</span>`).join("");
    const box = document.createElement("div");
    box.className = "reachability-summary";
    box.innerHTML = /* sniper-reviewed: html-safe (tüm hücreler esc ile) */ `<div class="threat-chips">${chips}</div>`
      + `<table class="threat-table"><thead><tr><th>Paket</th><th>Danışma</th><th>Öncelik</th><th>Erişilebilirlik</th><th>Semboller</th><th>Konum</th></tr></thead><tbody>${rows}</tbody></table>`;
    el.appendChild(box);
  }

  globalThis.renderThreatModel = renderThreatModel;
  globalThis.renderReachabilitySummary = renderReachabilitySummary;
})();
