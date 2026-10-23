// Saklama ve yedekler (17. tur, W3-OPS): salt okunur yedek listesi, onaylı "şimdi yedek al", saklama politikası ve
// kuru çalıştırma önizlemesi; silme yalnız politika açıkken, önizlenen planla (plan_id) ve onayla. Geri yükleme
// arayüzden yapılamaz (yalnız CLI: update.py --restore-db). Kart "Sistem sağlığı" panelinin ardına eklenir;
// görünür olunca yüklenir. Yalnız textContent kullanılır; yönetici değilse yalnız bilgi notu gösterilir.
(() => {
  const scope = typeof window !== "undefined" ? window : globalThis;
  const byId = id => (typeof document !== "undefined" ? document.getElementById(id) : null);
  const CATEGORY_ORDER = ["backups", "project_audits", "notifications", "jobs", "temp", "caches"];
  const state = { plan: null, policy: null };

  function el(tag, text, className) {
    const node = document.createElement(tag);
    if (text != null) node.textContent = String(text);
    if (className) node.className = className;
    return node;
  }

  function mb(bytes) {
    const value = Number(bytes || 0) / (1024 * 1024);
    return `${value < 10 ? value.toFixed(1) : Math.round(value)} MB`;
  }

  function dateText(iso) {
    return typeof iso === "string" ? iso.replace("T", " ").replace(/\.\d+/, "").replace("Z", " UTC") : "—";
  }

  async function call(path, body) {
    const options = body === undefined ? { headers: { Accept: "application/json" } }
      : { method: "POST", headers: { "Content-Type": "application/json", Accept: "application/json" }, body: JSON.stringify(body) };
    const response = await scope.fetch(path, options);
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const error = new Error(data.error || `İstek başarısız (${response.status})`);
      error.status = response.status;
      throw error;
    }
    return data;
  }

  function build() {
    const section = el("section", null, "panel data-retention-panel");
    section.id = "data-retention-panel";
    const head = el("div", null, "panel-head");
    const title = el("div");
    title.append(el("p", "SİSTEM", "eyebrow"), el("h2", "Saklama ve yedekler"));
    const actions = el("div", null, "button-row");
    const backup = el("button", "Şimdi yedek al", "mini-button");
    backup.type = "button";
    backup.dataset.retentionBackup = "1";
    const preview = el("button", "Önizle", "mini-button");
    preview.type = "button";
    preview.dataset.retentionPreview = "1";
    actions.append(backup, preview);
    head.append(title, actions);
    const intro = el("p", "Veritabanı yedekleri salt okunur listelenir; geri yükleme yalnız komut satırından yapılır. "
      + "Saklama politikası varsayılan olarak kapalıdır; önizleme hiçbir şeyi silmez. Denetim kaydı ve bulgu takibi asla silinmez.", "muted");
    const status = el("p", "", "muted data-retention-status");
    status.setAttribute?.("aria-live", "polite");
    const backupsWrap = el("div", null, "table-wrap");
    const backupsTable = el("table", null, "ops-table");
    const thead = el("thead");
    const headRow = el("tr");
    for (const label of ["Yedek", "Tür", "Tarih", "Etiket", "Boyut", "İzin"]) headRow.append(el("th", label));
    thead.append(headRow);
    const backupsBody = el("tbody");
    backupsTable.append(thead, backupsBody);
    backupsWrap.append(backupsTable);
    const restoreLabel = el("p", "Geri yükleme (yalnız komut satırı):", "muted");
    const restore = el("pre", "", "system-version-command");
    const form = el("form", null, "form-grid data-retention-form");
    const planWrap = el("div", null, "table-wrap");
    const planTable = el("table", null, "ops-table");
    const planHead = el("thead");
    const planHeadRow = el("tr");
    for (const label of ["Kategori", "Silinecek", "Boyut"]) planHeadRow.append(el("th", label));
    planHead.append(planHeadRow);
    const planBody = el("tbody");
    planTable.append(planHead, planBody);
    planWrap.append(planTable);
    const runRow = el("div", null, "button-row");
    const run = el("button", "Planı yürüt", "button");
    run.type = "button";
    run.dataset.retentionRun = "1";
    run.disabled = true;
    const runNote = el("small", "", "muted");
    runRow.append(run, runNote);
    section.append(head, intro, status, backupsWrap, restoreLabel, restore, form, planWrap, runRow);
    return { section, backup, preview, status, backupsBody, restore, form, planBody, run, runNote };
  }

  function renderBackups(ui, data) {
    ui.backupsBody.replaceChildren();
    for (const item of data.db_backups || []) {
      const row = el("tr", null, item.world_readable ? "health-warn" : "");
      row.append(el("td", item.name), el("td", item.kind === "auth" ? "giriş" : "veritabanı"), el("td", dateText(item.created_at)),
        el("td", item.named ? `${item.label} (korunur)` : (item.label || "—")), el("td", mb(item.bytes)),
        el("td", item.world_readable ? `${item.mode} — başkalarınca okunabilir` : item.mode));
      ui.backupsBody.append(row);
    }
    const summary = data.summary || {};
    ui.status.textContent = `${Number(summary.count || 0)} yedek · ${mb(summary.bytes)} · ${Number(summary.named || 0)} etiketli · `
      + `${(data.update_backups || []).length} güncelleme yedeği`;
    const commands = data.restore_commands || {};
    ui.restore.textContent = `${commands.db || ""}\n${commands.update || ""}`;
  }

  const FIELDS = [
    ["enabled", null, "Saklama politikası açık", "checkbox"],
    ["auto_daily", null, "Günlük otomatik yürüt", "checkbox"],
    ["backups", "keep_last", "Son N yedek", "number"],
    ["backups", "keep_daily", "Günlük yedek (gün)", "number"],
    ["backups", "keep_weekly", "Haftalık yedek (hafta)", "number"],
    ["backups", "include_named", "Etiketli (elle alınmış) yedekleri de kapsa", "checkbox"],
    ["project_audits", "enabled", "Eski proje analizlerini sil", "checkbox"],
    ["project_audits", "older_than_days", "Analiz yaşı (gün)", "number"],
    ["project_audits", "keep_per_project", "Proje başına saklanacak analiz", "number"],
    ["notifications", "enabled", "Okunmuş eski bildirimleri sil", "checkbox"],
    ["notifications", "read_older_than_days", "Bildirim yaşı (gün)", "number"],
    ["jobs", "enabled", "Bitmiş eski iş kayıtlarını sil", "checkbox"],
    ["jobs", "older_than_days", "İş kaydı yaşı (gün)", "number"],
    ["temp", "enabled", "Geçici dosya ve önbelleği temizle", "checkbox"],
    ["temp", "older_than_days", "Geçici dosya yaşı (gün)", "number"],
    ["caches", "enabled", "Önbellekleri temizle (eski arşiv dizinleri, PDF iş dizinleri, LSP)", "checkbox"],
    ["caches", "older_than_days", "Önbellek yaşı (gün)", "number"],
  ];

  function fieldName(group, key) { return key ? `${group}.${key}` : group; }

  function renderPolicy(ui, policy) {
    ui.form.replaceChildren();
    for (const [group, key, label, type] of FIELDS) {
      if (key && (!policy[group] || typeof policy[group] !== "object")) continue;  // eski sunucu: grup yok
      const value = key ? policy[group][key] : policy[group];
      const wrap = el("label", type === "checkbox" ? null : label);
      const input = el("input");
      input.type = type;
      input.name = fieldName(group, key);
      if (type === "checkbox") {
        input.checked = Boolean(value);
        wrap.append(input, el("span", ` ${label}`));
      } else {
        input.value = String(value);
        input.min = "0";
        wrap.append(input);
      }
      ui.form.append(wrap);
    }
    const row = el("div", null, "button-row");
    const save = el("button", "Politikayı kaydet", "button primary");
    save.type = "submit";
    row.append(save);
    ui.form.append(row);
  }

  function readPolicy(form) {
    const policy = JSON.parse(JSON.stringify(state.policy));
    for (const [group, key, , type] of FIELDS) {
      const input = form.elements ? form.elements[fieldName(group, key)] : null;
      if (!input || (key && !policy[group])) continue;
      const value = type === "checkbox" ? Boolean(input.checked) : Number.parseInt(input.value, 10);
      if (key) policy[group][key] = value; else policy[group] = value;
    }
    return policy;
  }

  function renderPlan(ui, payload) {
    const plan = payload.plan || {};
    state.plan = plan;
    state.policy = payload.policy;
    ui.planBody.replaceChildren();
    for (const name of CATEGORY_ORDER) {
      if (plan.summary && !plan.summary[name]) continue;  // sunucu bu kategoriyi bildirmiyor
      const summary = (plan.summary || {})[name] || {};
      const row = el("tr");
      row.append(el("td", summary.label || name), el("td", String(Number(summary.count || 0))), el("td", mb(summary.bytes)));
      ui.planBody.append(row);
    }
    const total = plan.total || { count: 0, bytes: 0 };
    ui.run.disabled = !plan.enabled || !total.count;
    ui.runNote.textContent = !plan.enabled
      ? `Önizleme: ${total.count} öğe (${mb(total.bytes)}). Politika kapalı — yürütmek için önce açıp kaydedin.`
      : `Önizleme: ${total.count} öğe (${mb(total.bytes)}) silinecek.`;
  }

  async function loadAll(ui) {
    try {
      renderBackups(ui, await call("/api/system/backups"));
      const payload = await call("/api/system/retention");
      renderPolicy(ui, payload.policy);
      renderPlan(ui, payload);
    } catch (error) {
      ui.status.textContent = error.status === 403 ? "Saklama ve yedek yönetimi yalnız yöneticiye açıktır."
        : (error.message || "Yedek bilgisi alınamadı");
      ui.backup.disabled = true;
      ui.preview.disabled = true;
    }
  }

  function wire(ui) {
    ui.preview.addEventListener("click", async () => {
      try { renderPlan(ui, await call("/api/system/retention")); } catch (error) { ui.status.textContent = error.message; }
    });
    ui.backup.addEventListener("click", async () => {
      if (typeof scope.confirm === "function" && !scope.confirm("Veritabanının tutarlı bir yedeği alınsın mı?")) return;
      ui.backup.disabled = true;
      try {
        const data = await call("/api/system/backups", { confirm: true });
        renderBackups(ui, data);
        ui.status.textContent = `Yedek alındı: ${(data.created || []).map(item => item.name).join(", ")}`;
      } catch (error) {
        ui.status.textContent = error.message;
      } finally {
        ui.backup.disabled = false;
      }
    });
    ui.form.addEventListener("submit", async event => {
      event.preventDefault?.();
      try {
        const payload = await call("/api/system/retention/policy", { confirm: true, policy: readPolicy(ui.form) });
        renderPolicy(ui, payload.policy);
        renderPlan(ui, payload);
        ui.status.textContent = "Saklama politikası kaydedildi.";
      } catch (error) {
        ui.status.textContent = error.message;
      }
    });
    ui.run.addEventListener("click", async () => {
      const plan = state.plan;
      if (!plan || !plan.plan_id) return;
      const question = `Önizlenen plan yürütülsün mü? ${plan.total.count} öğe (${mb(plan.total.bytes)}) kalıcı olarak silinecek.`;
      if (typeof scope.confirm === "function" && !scope.confirm(question)) return;
      ui.run.disabled = true;
      try {
        const result = await call("/api/system/retention/run", { confirm: true, plan_id: plan.plan_id });
        renderPlan(ui, result);
        renderBackups(ui, await call("/api/system/backups"));
        ui.status.textContent = `Plan yürütüldü: ${mb(result.freed_bytes)} boşaltıldı.`;
      } catch (error) {
        ui.status.textContent = error.message;
        try { renderPlan(ui, await call("/api/system/retention")); } catch (_e) { /* önizleme yenilenemedi */ }
      }
    });
  }

  function start() {
    const anchor = byId("system-health-panel");
    if (!anchor || byId("data-retention-panel")) return null;
    const ui = build();
    if (typeof anchor.insertAdjacentElement === "function") anchor.insertAdjacentElement("afterend", ui.section);
    else if (anchor.parentNode) anchor.parentNode.insertBefore(ui.section, anchor.nextSibling || null);
    wire(ui);
    if (typeof IntersectionObserver === "function") {
      const observer = new IntersectionObserver(entries => {
        if (entries.some(entry => entry.isIntersecting)) {
          observer.disconnect();
          loadAll(ui);
        }
      });
      observer.observe(ui.section);
    } else {
      loadAll(ui);
    }
    return ui;
  }

  scope.SniperDataRetention = { start, readPolicy, renderPlan, renderBackups, mb, FIELDS };
  if (typeof document !== "undefined") {
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start);
    else start();
  }
})();
