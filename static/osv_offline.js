// Çevrimdışı OSV (18. tur): tüm ekosistemlerde (PyPI, Go, Maven, RubyGems, crates.io, Packagist, NuGet, npm …)
// kilit dosyalarını yerel OSV veritabanıyla eşleme ve ekosistem başına veritabanı durumu.
// Bağımlılık paneline bir form, araç matrisindeki hazırlık bölümüne bir durum tablosu ekler. Yalnız DOM API/textContent.
(() => {
  const scope = typeof window !== "undefined" ? window : globalThis;
  const STATUS = { ok: "Güncel", stale: "Bayat (7 günden eski)", missing: "Yok", untrusted: "Doğrulanamadı" };

  function el(tag, text, className) {
    const node = document.createElement(tag);
    if (text != null) node.textContent = String(text);
    if (className) node.className = className;
    return node;
  }

  function sizeText(bytes) {
    const n = Number(bytes || 0);
    if (!n) return "—";
    if (n >= 1048576) return `${(n / 1048576).toFixed(1)} MB`;
    return `${Math.max(1, Math.round(n / 1024))} KB`;
  }

  function dateText(value) {
    if (!value) return "—";
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? String(value) : d.toLocaleString("tr-TR");
  }

  async function getJson(path) {
    const response = await fetch(path, { credentials: "same-origin" });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || `İstek başarısız (${response.status}).`);
    return data;
  }

  async function postJson(path, body) {
    const response = await fetch(path, {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || `İstek başarısız (${response.status}).`);
    return data;
  }

  function renderStatus(container, data) {
    container.replaceChildren();
    const rows = Array.isArray(data && data.databases) ? data.databases : [];
    container.append(el("h3", "Çevrimdışı OSV veritabanları"));
    if (!rows.length) {
      container.append(el("p", "Veritabanı bilgisi yok.", "muted"));
      return;
    }
    const wrap = el("div", null, "responsive-table");
    const table = el("table", null, "osv-offline-table");
    const thead = el("thead");
    const head = el("tr");
    for (const title of ["Ekosistem", "Durum", "Veri tarihi", "Boyut", "Kayıt"]) head.append(el("th", title));
    thead.append(head);
    const tbody = el("tbody");
    for (const row of rows) {
      const tr = el("tr");
      tr.append(el("td", row.ecosystem), el("td", STATUS[row.status] || row.status, `osv-offline-${row.status}`),
        el("td", dateText(row.retrieved_utc)), el("td", sizeText(row.bytes)),
        el("td", row.records != null ? Number(row.records).toLocaleString("tr-TR") : "—"));
      tbody.append(tr);
    }
    table.append(thead, tbody);
    wrap.append(table);
    container.append(wrap, el("p", "Güncelleme: python3 scripts/osv_refresh.py (zamanlayıcı: sniper-osv-refresh.timer).", "muted"));
  }

  function mountStatus() {
    const anchor = document.getElementById("taint-engine-status");
    if (!anchor || document.querySelector("[data-osv-offline-status]")) return;
    const container = el("div", null, "osv-offline-status");
    container.dataset.osvOfflineStatus = "1";
    anchor.after(container);
    let loaded = false;
    const load = () => {
      if (loaded) return;
      loaded = true;
      getJson("/api/dependency-security/offline-db")
        .then(data => renderStatus(container, data))
        .catch(error => { container.replaceChildren(el("p", error.message, "muted")); loaded = false; });
    };
    if (typeof IntersectionObserver === "function") {
      const observer = new IntersectionObserver(entries => {
        if (entries.some(entry => entry.isIntersecting)) { observer.disconnect(); load(); }
      });
      observer.observe(container);
    } else {
      load();
    }
  }

  function coverageText(result) {
    const parts = (result.coverage || []).map(item => {
      if (item.status === "unavailable") return `${item.ecosystem}: veritabanı yok`;
      return `${item.ecosystem}: ${Number(item.components || 0)} bileşen, ${Number(item.vulnerabilities || 0)} açık`;
    });
    return parts.join(" · ");
  }

  // 20. tur: "Önce bunları düzelt" — puan: önem × erişilebilirlik × düzeltme varlığı × doğrudan/dolaylı.
  const TIER_LABELS = { fix_first: "Önce düzelt", plan: "Planla", monitor: "İzle" };
  const USAGE_LABELS = { used: "kodda kullanılıyor", unused: "bildirilmiş, kullanılmıyor",
    transitive_only: "yalnız geçişli", unknown: "kullanım bilinmiyor" };

  function renderPriority(container, priority) {
    container.replaceChildren();
    const order = (priority && Array.isArray(priority.order)) ? priority.order : [];
    if (!order.length) return;
    const tiers = priority.tiers || {};
    container.append(el("h4", "Önce bunları düzelt"));
    container.append(el("p", `Önce düzelt: ${Number(tiers.fix_first || 0)} · Planla: ${Number(tiers.plan || 0)} · İzle: ${Number(tiers.monitor || 0)}`, "muted"));
    const list = el("ol", null, "osv-priority-list");
    for (const item of order.slice(0, 10)) {
      const row = el("li");
      row.append(el("span", TIER_LABELS[item.tier] || String(item.tier || ""), `prio-chip prio-${String(item.tier || "").replace(/[^a-z_]/g, "")}`));
      row.append(el("b", ` ${item.package_name || ""}@${item.installed_version || ""} `));
      row.append(el("span", `${item.vulnerability_id || ""} · puan ${Number(item.score || 0)} · ${USAGE_LABELS[item.usage] || item.usage || ""}`));
      if (item.fixed_version) row.append(el("span", ` · düzeltme: ${item.fixed_version}`));
      const ev = (item.evidence || [])[0];
      if (ev && ev.file) row.append(el("small", ` (${ev.file}:${Number(ev.line || 0)})`, "muted"));
      list.append(row);
    }
    container.append(list);
  }

  function mountForm() {
    const actions = document.querySelector(".dependency-panel .dependency-actions");
    if (!actions || actions.querySelector("form[data-osv-offline-form]")) return;
    const form = el("form");
    form.id = "dependency-osv-offline-form";
    form.dataset.osvOfflineForm = "1";
    const label = el("label", "Proje yolu (çevrimdışı OSV)");
    const input = el("input");
    input.name = "project_path";
    input.maxLength = 1024;
    input.required = true;
    const sibling = document.querySelector("#dependency-import-form input[name=project_path]");
    input.value = sibling ? sibling.value : "";
    label.append(input);
    const button = el("button", "Çevrimdışı OSV ile tara (tüm ekosistemler)", "button secondary");
    button.type = "submit";
    const result = el("p", null, "muted osv-offline-result");
    result.setAttribute("role", "status");
    result.setAttribute("aria-live", "polite");
    const prio = el("div", null, "osv-priority");
    form.append(label, button, result, prio);
    form.addEventListener("submit", async event => {
      event.preventDefault();
      button.disabled = true;
      result.textContent = "Kilit dosyaları yerel OSV veritabanıyla eşleniyor…";
      try {
        const data = await postJson("/api/dependency-security/offline-scan",
          { project_path: input.value.trim(), confirm_local: true });
        const head = data.deduplicated ? "Bu sonuç daha önce kaydedilmiş." : `${Number(data.finding_count || 0)} bağımlılık bulgusu kaydedildi.`;
        const warn = (data.warnings || []).length ? ` Uyarı: ${data.warnings.join(" ")}` : "";
        result.textContent = `${head} ${coverageText(data)}${warn}`;
        renderPriority(prio, data.priority);
        await scope.loadAll?.();
      } catch (error) {
        result.textContent = error.message;
      } finally {
        button.disabled = false;
      }
    });
    actions.append(form);
  }

  function mount() {
    mountForm();
    mountStatus();
  }

  scope.SniperOsvOffline = { renderStatus, coverageText, sizeText, renderPriority, mount };
  if (typeof document !== "undefined" && typeof document.addEventListener === "function") {
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", mount);
    else mount();
  }
})();
