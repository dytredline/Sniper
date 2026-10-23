// Portföy ve SLA (17. tur): projeler arası pano, SLA uyumu, MTTR, haftalık eğilim, SLA politikası (yönetici)
// ve DefectDojo/Jira/CSV dışa aktarımı (analist). Görünüm bölümü bu betikte oluşturulur (index.html'e yalnız
// gezinme öğesi + betik/stil etiketi eklenir). Sunucudan gelen metinler esc() ile kaçışlanır; satır içi stil yok
// (CSP style-src 'self'): grafik SVG öznitelikleriyle çizilir.
(function () {
  "use strict";
  const SEVERITIES = ["critical", "high", "medium", "low", "info"];
  const SEVERITY_LABELS = { critical: "Kritik", high: "Yüksek", medium: "Orta", low: "Düşük", info: "Bilgi" };
  const FORMATS = { defectdojo: "DefectDojo (Generic Findings JSON)", jira: "Jira (CSV içe aktarma)", csv: "Düz CSV" };
  const STATUS_FILTERS = { active: "Etkin bulgular", fixed: "Düzelenler", suppressed: "Bastırılanlar", all: "Tümü" };
  const esc = value => String(value ?? "").replace(/[&<>"']/g, ch => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch]);
  const num = value => (value === null || value === undefined || value === "" ? "—" : esc(value));
  const request = (path, options = {}) => (typeof globalThis.api === "function" ? globalThis.api(path, options) : fetch(path, options).then(async response => {
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || `İstek tamamlanamadı (${response.status})`);
    return data;
  }));
  const notify = (message, type) => (typeof globalThis.toast === "function" ? globalThis.toast(message, type) : undefined);
  const state = { data: null, policy: null, role: null, authEnabled: false, loading: false, filter: { group: "", root: "" } };

  // -- yetki (sunucu ayrıca denetler) ----------------------------------------------------------------
  function canExport() { return !state.authEnabled || state.role === "analyst" || state.role === "admin"; }
  function canEditPolicy() { return !state.authEnabled || state.role === "admin"; }

  // -- görünüm iskeleti -------------------------------------------------------------------------------
  function ensureView() {
    let section = document.querySelector('[data-view="portfolio"]');
    if (section) return section;
    section = document.createElement("section");
    section.className = "view";
    section.dataset.view = "portfolio";
    section.id = "portfolio-view";
    section.innerHTML = /* sniper-reviewed: html-safe (sabit iskelet; dinamik veri yok) */ `<section class="panel"><div class="panel-head"><div><p class="eyebrow">PROJELER ARASI</p><h2>Portföy ve SLA</h2></div>` +
      `<button class="button" type="button" data-portfolio-refresh>Yenile</button></div>` +
      `<p class="muted">Bulgu takibindeki tüm projelerin özeti: etkin bulgular, SLA ihlalleri, ortalama düzeltme süresi (MTTR) ve haftalık eğilim. Risk puanı etkin bulguların önem ağırlıklarından ve SLA ihlallerinden hesaplanır.</p>` +
      `<div id="portfolio-body"><p class="muted">Yükleniyor…</p></div></section>` +
      `<section class="panel"><div class="panel-head"><div><p class="eyebrow">KURAL</p><h2>SLA politikası</h2></div></div><div id="portfolio-policy"></div></section>` +
      `<section class="panel"><div class="panel-head"><div><p class="eyebrow">DOSYA</p><h2>Dışa aktarım</h2></div></div><div id="portfolio-export"></div></section>`;
    const anchor = document.getElementById("tracking-view");
    if (anchor && anchor.parentNode) anchor.parentNode.insertBefore(section, anchor.nextSibling);
    else (document.querySelector("main") || document.body).appendChild(section);
    if (location.hash === "#portfolio") section.classList.add("active");
    return section;
  }

  // -- süzgeç (25. tur): toplu tarama grubu ve kök dizin ------------------------------------------------
  function filterBar(data) {
    const groups = data.bulk_groups || [];
    const current = data.filter || {};
    if (!groups.length && !current.group && !current.root) return "";
    const options = [`<option value="">Tüm projeler</option>`].concat(groups.map(g =>
      `<option value="${esc(g.name)}"${g.name === current.group ? " selected" : ""}>${esc(g.name)} (${Number(g.project_count || 0)} proje)</option>`));
    return `<form class="portfolio-filter" id="portfolio-filter-form"><label>Toplu tarama grubu <select name="group">${options.join("")}</select></label>` +
      `<label>Kök dizin <input name="root" maxlength="1024" placeholder="/home/community-user/projeler" value="${esc(current.root || "")}"></label>` +
      `<button class="button" type="submit">Süz</button></form>`;
  }

  function portfolioUrl() {
    const params = new URLSearchParams({ weeks: "12" });
    if (state.filter.group) params.set("group", state.filter.group);
    if (state.filter.root) params.set("root", state.filter.root);
    return `/api/portfolio?${params.toString()}`;
  }

  // -- hesap kartları -------------------------------------------------------------------------------
  function cards(data) {
    const t = data.totals || {};
    const sla = data.sla || {};
    const mttr = (data.mttr && data.mttr.overall) || {};
    const ratio = sla.fixed_within_sla_ratio == null ? "—" : String(Math.round(Number(sla.fixed_within_sla_ratio) * 100));
    const items = [
      ["Etkin bulgu", num(t.active), ""],
      ["SLA ihlali", num(t.sla_breached), Number(t.sla_breached) > 0 ? " bad" : ""],
      ["Son tarihi geçen", num(t.overdue), Number(t.overdue) > 0 ? " bad" : ""],
      [`Son ${Number(data.recent_days || 30)} günde yeni`, num(t.new_recent), ""],
      [`Son ${Number(data.recent_days || 30)} günde düzelen`, num(t.fixed_recent), " good"],
      ["Ortalama düzeltme (gün)", num(mttr.mean_days), ""],
      ["SLA içinde düzelme (%)", esc(ratio), ""],
      ["Sorumlusuz etkin", num(t.unassigned_active), ""],
    ];
    return `<div class="portfolio-cards">${items.map(([label, value, cls]) => `<div class="portfolio-card${cls}"><b>${value}</b><span>${esc(label)}</span></div>`).join("")}</div>`;
  }

  function severityLine(bySeverity) {
    return `<p class="portfolio-sev">${SEVERITIES.map(s => `<span class="sev-pill sev-${s}">${esc(SEVERITY_LABELS[s])}: ${Number((bySeverity || {})[s] || 0)}</span>`).join(" ")}</p>`;
  }

  // -- eğilim grafiği (SVG; satır içi stil yok) ----------------------------------------------------------
  function trendChart(trend) {
    if (!Array.isArray(trend) || !trend.length) return `<p class="muted">Eğilim için veri yok.</p>`;
    const width = 640, height = 180, pad = 28;
    const max = Math.max(1, ...trend.map(w => Math.max(Number(w.active) || 0, Number(w.new) || 0, Number(w.fixed) || 0)));
    const step = (width - 2 * pad) / trend.length;
    const y = value => height - pad - (Number(value) || 0) / max * (height - 2 * pad);
    const bars = trend.map((w, i) => {
      const x = pad + i * step;
      const bw = Math.max(2, step / 3 - 2);
      return `<rect class="bar-new" x="${(x + 2).toFixed(1)}" y="${y(w.new).toFixed(1)}" width="${bw.toFixed(1)}" height="${(height - pad - y(w.new)).toFixed(1)}"><title>${esc(w.week_end)} · yeni ${Number(w.new)}</title></rect>` +
        `<rect class="bar-fixed" x="${(x + 2 + bw + 1).toFixed(1)}" y="${y(w.fixed).toFixed(1)}" width="${bw.toFixed(1)}" height="${(height - pad - y(w.fixed)).toFixed(1)}"><title>${esc(w.week_end)} · düzelen ${Number(w.fixed)}</title></rect>`;
    }).join("");
    const points = trend.map((w, i) => `${(pad + i * step + step / 2).toFixed(1)},${y(w.active).toFixed(1)}`).join(" ");
    const labels = trend.map((w, i) => (i % 2 === 0 ? `<text x="${(pad + i * step + step / 2).toFixed(1)}" y="${height - 8}" text-anchor="middle">${esc(String(w.week_end).slice(5))}</text>` : "")).join("");
    const summary = `Son ${trend.length} hafta: etkin ${Number(trend[0].active)} → ${Number(trend[trend.length - 1].active)}`;
    return `<figure class="portfolio-trend"><svg viewBox="0 0 ${width} ${height}" role="img" aria-label="${esc(summary)}">` +
      `<line class="axis" x1="${pad}" y1="${height - pad}" x2="${width - pad}" y2="${height - pad}"></line>${bars}` +
      `<polyline class="line-active" points="${points}"></polyline>${labels}</svg>` +
      `<figcaption><span class="key key-active"></span>Etkin (hafta sonu) <span class="key key-new"></span>Yeni <span class="key key-fixed"></span>Düzelen · en yüksek ${max}</figcaption></figure>`;
  }

  // -- tablolar -----------------------------------------------------------------------------------------
  function projectTable(projects) {
    if (!projects || !projects.length) return `<p class="muted">Takip edilen proje yok. Proje analizi yapıldıkça bulgu takibi ve portföy dolar.</p>`;
    const rows = projects.map(p => {
      const sev = p.active_by_severity || {};
      return `<tr><td><b>${esc(p.project_name)}</b><br><small class="muted">${esc(p.project_path)}</small></td>` +
        `<td class="num"><b>${Number(p.risk_score || 0)}</b></td>` +
        SEVERITIES.slice(0, 4).map(s => `<td class="num sev-${s}">${Number(sev[s] || 0)}</td>`).join("") +
        `<td class="num${p.sla_breached ? " bad" : ""}">${Number(p.sla_breached || 0)}</td><td class="num${p.overdue ? " bad" : ""}">${Number(p.overdue || 0)}</td>` +
        `<td class="num">${Number(p.unassigned_active || 0)}</td><td class="num">${Number(p.new_recent || 0)} / ${Number(p.fixed_recent || 0)}</td>` +
        `<td class="num">${num(p.mttr_days)}</td><td class="num${(p.dependencies || {}).fix_first ? " bad" : ""}">${Number((p.dependencies || {}).fix_first || 0)}</td>` +
        `<td><small>${esc(p.last_audit_at || "—")}${p.grade ? ` · ${esc(p.grade)}` : ""}</small></td>` +
        `<td><button type="button" class="mini-button" data-portfolio-open="${esc(p.project_path)}">Takipte aç</button></td></tr>`;
    }).join("");
    return `<div class="table-scroll"><table class="portfolio-table"><thead><tr><th>Proje</th><th>Risk puanı</th><th>Kritik</th><th>Yüksek</th><th>Orta</th><th>Düşük</th>` +
      `<th>SLA ihlali</th><th>Gecikmiş</th><th>Sorumlusuz</th><th>Yeni / düzelen (30 gün)</th><th>MTTR (gün)</th><th>Bağımlılık: önce düzelt</th><th>Son analiz</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }

  // 21. tur: alanlara göre etkin bulgular (yönetici özetiyle aynı sınıflandırma; bağımlılık = proje bulguları + SCA)
  const SECTION_COLUMNS = [["code", "Kod"], ["dependencies", "Bağımlılık"], ["iac", "IaC"], ["container", "Konteyner"]];
  function sectionTable(projects) {
    const withSections = (projects || []).filter(p => p.by_section);
    if (!withSections.length) return "";
    const other = s => Number(s.license || 0) + Number(s.api || 0) + Number(s.supply_chain || 0);
    const body = withSections.map(p => {
      const s = p.by_section || {};
      return `<tr><td><b>${esc(p.project_name)}</b><br><small class="muted">${esc(p.project_path)}</small></td>` +
        SECTION_COLUMNS.map(([key]) => `<td class="num">${Number(s[key] || 0)}</td>`).join("") +
        `<td class="num">${other(s)}</td></tr>`;
    }).join("");
    return `<h3>Alanlara göre etkin bulgular</h3><div class="table-scroll"><table class="portfolio-table compact"><thead><tr><th>Proje</th>` +
      SECTION_COLUMNS.map(([, label]) => `<th>${esc(label)}</th>`).join("") +
      `<th>Lisans / API / tedarik zinciri</th></tr></thead><tbody>${body}</tbody></table></div>`;
  }

  // 20. tur: bağımlılık açıkları (SCA) proje başına öncelik katmanı ve kullanım durumu
  function dependencyTable(rows) {
    if (!rows || !rows.length) return "";
    const body = rows.map(d => `<tr><td><b>${esc(d.project_name)}</b><br><small class="muted">${esc(d.project_path)}</small></td>` +
      `<td class="num${d.fix_first ? " bad" : ""}">${Number(d.fix_first || 0)}</td><td class="num">${Number(d.plan || 0)}</td>` +
      `<td class="num">${Number(d.monitor || 0)}</td><td class="num">${Number(d.unscored || 0)}</td><td class="num">${Number(d.active || 0)}</td>` +
      `<td class="num">${Number(d.used || 0)} / ${Number(d.unused || 0)} / ${Number(d.transitive_only || 0)}</td></tr>`).join("");
    return `<h3>Bağımlılık açıkları: önce bunları düzelt</h3><div class="table-scroll"><table class="portfolio-table compact"><thead><tr><th>Proje</th>` +
      `<th>Önce düzelt</th><th>Planla</th><th>İzle</th><th>Puanlanmamış</th><th>Etkin</th><th>Kullanılan / kullanılmayan / geçişli</th></tr></thead><tbody>${body}</tbody></table></div>`;
  }

  function mttrTable(mttr, sla) {
    if (!mttr) return "";
    const by = mttr.by_severity || {};
    const recent = (mttr.recent && mttr.recent.by_severity) || {};
    const slaBy = (sla && sla.by_severity) || {};
    const rows = SEVERITIES.map(s => `<tr><td>${esc(SEVERITY_LABELS[s])}</td><td class="num">${num(by[s] && by[s].mean_days)}</td><td class="num">${num(by[s] && by[s].median_days)}</td>` +
      `<td class="num">${Number((by[s] && by[s].count) || 0)}</td><td class="num">${num(recent[s] && recent[s].mean_days)}</td>` +
      `<td class="num">${Number((slaBy[s] && slaBy[s].active_breached) || 0)}</td><td class="num">${Number((slaBy[s] && slaBy[s].active_due_soon) || 0)}</td>` +
      `<td class="num">${Number((slaBy[s] && slaBy[s].fixed_in_sla) || 0)} / ${Number((slaBy[s] && slaBy[s].fixed_late) || 0)}</td></tr>`).join("");
    return `<h3>Önem başına düzeltme süresi ve SLA</h3><div class="table-scroll"><table class="portfolio-table compact"><thead><tr><th>Önem</th><th>MTTR ort. (gün)</th><th>MTTR ortanca</th><th>Düzelen</th>` +
      `<th>Son ${Number((mttr.recent && mttr.recent.window_days) || 90)} gün ort.</th><th>SLA ihlali</th><th>Yaklaşan</th><th>SLA içinde / geç</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }

  // -- SLA politikası --------------------------------------------------------------------------------
  function policyForm(payload) {
    const policy = (payload && payload.policy) || { days: {}, auto_due_date: false, risk_acceptance_days: 0 };
    const disabled = canEditPolicy() ? "" : " disabled";
    const fields = SEVERITIES.map(s => `<label><span>${esc(SEVERITY_LABELS[s])} <small>(gün)</small></span><input type="number" min="1" max="3650" name="days_${s}" value="${policy.days[s] == null ? "" : Number(policy.days[s])}" placeholder="SLA yok"${disabled}></label>`).join("");
    return `<form id="portfolio-policy-form" class="portfolio-policy">${fields}` +
      `<label class="check"><input type="checkbox" name="auto_due_date"${policy.auto_due_date ? " checked" : ""}${disabled}> Yeni bulgulara SLA'ya göre otomatik son tarih yaz</label>` +
      `<label>Risk kabulü varsayılan süresi (gün; 0 = süresiz)<input type="number" min="0" max="1825" name="risk_acceptance_days" value="${Number(policy.risk_acceptance_days || 0)}"${disabled}></label>` +
      `<div class="portfolio-actions"><button class="button primary" type="submit"${disabled}>Politikayı kaydet</button>` +
      `<button class="button" type="button" data-portfolio-reset${disabled}>Varsayılana dön</button>` +
      `<button class="button" type="button" data-portfolio-apply${disabled}>Son tarihi olmayan etkin bulgulara uygula</button></div>` +
      `<p class="muted">${payload && payload.customized ? "Özelleştirilmiş politika." : "Varsayılan politika."} Boş gün = bu önemde SLA yok. ` +
      `Son tarihi geçen bulgular için hatırlatma, süresi dolan risk kabulleri için yeniden açma saatlik yapılır (bildirim ayarları: SLA ihlali, risk kabulü süresi doldu).` +
      `${canEditPolicy() ? "" : " Politikayı yalnız yönetici değiştirebilir."}</p></form>`;
  }

  function policyFromForm(form) {
    const data = new FormData(form);
    const days = {};
    for (const s of SEVERITIES) {
      const raw = String(data.get(`days_${s}`) || "").trim();
      days[s] = raw === "" ? null : Number.parseInt(raw, 10);
    }
    return { days, auto_due_date: data.get("auto_due_date") === "on", risk_acceptance_days: Number.parseInt(String(data.get("risk_acceptance_days") || "0"), 10) || 0 };
  }

  // -- dışa aktarım ----------------------------------------------------------------------------------
  function exportForm(projects) {
    const disabled = canExport() ? "" : " disabled";
    const projectOptions = [`<option value="">Tüm projeler</option>`].concat((projects || []).map(p => `<option value="${esc(p.project_path)}">${esc(p.project_name)}</option>`)).join("");
    return `<form id="portfolio-export-form" class="portfolio-export"><label>Biçim<select name="format">${Object.entries(FORMATS).map(([k, v]) => `<option value="${k}">${esc(v)}</option>`).join("")}</select></label>` +
      `<label>Proje<select name="project_path">${projectOptions}</select></label>` +
      `<label>Durum<select name="status">${Object.entries(STATUS_FILTERS).map(([k, v]) => `<option value="${k}">${esc(v)}</option>`).join("")}</select></label>` +
      `<button class="button primary" type="submit"${disabled}>İndir</button></form>` +
      `<p class="muted">Dosya yerelde üretilir; Sniper hiçbir dış sisteme bağlanmaz. CSV hücreleri formül enjeksiyonuna karşı kaçışlanır. Her dışa aktarım işlem geçmişine yazılır.${canExport() ? "" : " Dışa aktarım için analist ya da yönetici rolü gerekir."}</p>`;
  }

  function exportUrl(values) {
    const params = new URLSearchParams({ format: values.format || "csv", status: values.status || "active" });
    if (values.project_path) params.set("project_path", values.project_path);
    return `/api/portfolio/export?${params.toString()}`;
  }

  async function download(form) {
    const values = Object.fromEntries(new FormData(form).entries());
    const button = form.querySelector("button[type=submit]");
    if (button) button.disabled = true;
    try {
      const response = await fetch(exportUrl(values), { credentials: "same-origin" });
      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new Error(data.error || `Dışa aktarım başarısız (${response.status})`);
      }
      const disposition = response.headers.get("Content-Disposition") || "";
      const match = /filename="([^"]+)"/.exec(disposition);
      const blob = await response.blob();
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = match ? match[1] : "sniper-bulgular";
      document.body.appendChild(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(link.href), 5000);
      notify("Dışa aktarım dosyası indirildi.");
    } catch (error) {
      notify(error.message, "error");
    } finally {
      if (button) button.disabled = !canExport();
    }
  }

  // -- yükleme ----------------------------------------------------------------------------------------
  async function loadRole() {
    try {
      const status = await request("/api/auth/status");
      state.authEnabled = Boolean(status && status.enabled);
      state.role = status && status.user ? status.user.role : null;
    } catch (_error) {
      state.authEnabled = false;
      state.role = null;
    }
  }

  function render() {
    const body = document.getElementById("portfolio-body");
    if (!body || !state.data) return;
    const data = state.data;
    body.innerHTML = /* sniper-reviewed: html-safe (filterBar/cards/trendChart/projectTable/dependencyTable/mttrTable tüm sunucu metnini esc ile, sayıları Number ile yazar) */ filterBar(data) + cards(data) + severityLine((data.totals || {}).active_by_severity) + trendChart(data.trend) +
      projectTable(data.projects) + sectionTable(data.projects) + dependencyTable(data.dependency_projects) + mttrTable(data.mttr, data.sla);
    const policy = document.getElementById("portfolio-policy");
    if (policy) policy.innerHTML = policyForm(state.policy); // sniper-reviewed: html-safe (politika değerleri Number; etiketler sabit)
    const exp = document.getElementById("portfolio-export");
    if (exp) exp.innerHTML = exportForm(data.projects); // sniper-reviewed: html-safe (proje adı/yolu esc ile)
  }

  async function load() {
    ensureView();
    if (state.loading) return;
    state.loading = true;
    const body = document.getElementById("portfolio-body");
    try {
      await loadRole();
      const [data, policy] = await Promise.all([request(portfolioUrl()), request("/api/portfolio/sla-policy")]);
      state.data = data;
      state.policy = policy;
      render();
    } catch (error) {
      if (body) body.innerHTML = `<p class="muted">${esc(error.message)}</p>`; // sniper-reviewed: html-safe (esc)
    } finally {
      state.loading = false;
    }
  }

  async function postPolicy(body, message) {
    try {
      state.policy = await request("/api/portfolio/sla-policy", { method: "POST", body: JSON.stringify({ confirm: true, ...body }) });
      notify(message);
      await load();
    } catch (error) {
      notify(error.message, "error");
    }
  }

  // -- olaylar ----------------------------------------------------------------------------------------
  document.addEventListener("click", event => {
    if (event.target.closest("[data-portfolio-refresh]")) { load(); return; }
    if (event.target.closest("[data-portfolio-reset]")) {
      if (globalThis.confirm && !globalThis.confirm("SLA politikası varsayılana dönsün mü?")) return;
      postPolicy({ reset: true }, "SLA politikası varsayılana döndü.");
      return;
    }
    if (event.target.closest("[data-portfolio-apply]")) {
      if (globalThis.confirm && !globalThis.confirm("Son tarihi olmayan tüm etkin bulgulara SLA son tarihi yazılsın mı? (Geçmişte kalan tarihler hemen gecikmiş görünür.)")) return;
      request("/api/portfolio/sla-policy/apply", { method: "POST", body: JSON.stringify({ confirm: true }) })
        .then(result => { notify(`${Number(result.updated || 0)} bulguya SLA son tarihi yazıldı.`); load(); })
        .catch(error => notify(error.message, "error"));
      return;
    }
    const open = event.target.closest("[data-portfolio-open]");
    if (open) {
      const select = document.getElementById("tracking-project");
      if (select) {
        const value = open.dataset.portfolioOpen;
        if (![...select.options].some(option => option.value === value)) select.add(new Option(value, value));
        select.value = value;
        select.dispatchEvent(new Event("change", { bubbles: true }));
      }
      location.hash = "#tracking";
    }
  });
  document.addEventListener("submit", event => {
    if (event.target.id === "portfolio-policy-form") {
      event.preventDefault();
      postPolicy({ policy: policyFromForm(event.target) }, "SLA politikası kaydedildi.");
    } else if (event.target.id === "portfolio-filter-form") {
      event.preventDefault();
      state.filter = { group: event.target.elements.group.value, root: event.target.elements.root.value.trim() };
      load();
    } else if (event.target.id === "portfolio-export-form") {
      event.preventDefault();
      download(event.target);
    }
  });

  globalThis.sniperLoadPortfolio = load;
  if (typeof document !== "undefined" && document.readyState !== "loading") ensureView();
  else if (typeof document !== "undefined") document.addEventListener("DOMContentLoaded", ensureView);
  if (typeof location !== "undefined" && location.hash === "#portfolio") load();
  if (typeof module !== "undefined") module.exports = { filterBar, portfolioUrl, cards, trendChart, projectTable, sectionTable, mttrTable, policyForm, policyFromForm, exportForm, exportUrl, esc, state };
})();
