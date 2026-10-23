// İşletim: zamanlanmış taramalar ve bildirimler. Yalnız DOM API ve textContent kullanır (HTML enjeksiyonu yok).
(() => {
  // 21. tur: bağımlılık güvenliği / konteyner / lisans / OSV tazeliği olayları (aç/kapat kutuları)
  const EXTRA_EVENTS = ["malicious_package", "sca_fix_first", "container_critical", "license_forbidden", "osv_db_stale"];
  const scope = typeof window !== "undefined" ? window : globalThis;
  const byId = id => (typeof document !== "undefined" ? document.getElementById(id) : null);
  const BADGE_MS = 30000;
  const STATUS_LABELS = {
    submitted: "Kuyruğa alındı", queued: "Sırada", running: "Çalışıyor", succeeded: "Tamamlandı", failed: "Başarısız",
    expired: "Süre aşımı", cancelled: "İptal", interrupted: "Yarıda kaldı", skipped_overlap: "Atlandı (önceki iş sürüyor)",
    skipped_duplicate: "Atlandı (aynı hedefte iş var)", submit_failed: "Kuyruğa alınamadı", invalid_frequency: "Geçersiz sıklık",
  };
  let scanTypes = [];

  async function request(path, options = {}) {
    const config = { ...options, headers: { ...(options.body ? { "Content-Type": "application/json" } : {}) } };
    const response = await fetch(path, config);
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || `İstek tamamlanamadı (${response.status})`);
    return data;
  }

  function toast(message, type = "success") {
    if (typeof scope.toast === "function") scope.toast(message, type);
  }

  function el(tag, text, className) {
    const node = document.createElement(tag);
    if (text != null) node.textContent = String(text);
    if (className) node.className = className;
    return node;
  }

  function when(value) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value);
    return new Intl.DateTimeFormat("tr-TR", { dateStyle: "short", timeStyle: "short" }).format(date);
  }

  // -- Zamanlanmış taramalar -------------------------------------------------
  function renderScanTypes() {
    const select = byId("ops-scan-type");
    if (!select || select.options.length) return;
    for (const item of scanTypes) select.add(new Option(item.label, item.key));
    syncTypeFields();
  }

  function syncTypeFields() {
    const select = byId("ops-scan-type");
    const item = scanTypes.find(type => type.key === select?.value) || {};
    byId("ops-scope-field")?.classList.toggle("hidden", !item.uses_scope);
    byId("ops-base-ref-field")?.classList.toggle("hidden", !item.base_ref);
    // 21. tur: konteyner imajı / SBOM planlarında hedef bir dosya ya da rootfs dizinidir (alan adı aynı kalır).
    const input = byId("ops-schedule-form")?.elements?.project_path;
    const text = input?.parentElement?.firstChild;
    if (text && text.nodeType === 3) text.nodeValue = item.target_label || "Yerel proje yolu";
    if (input) input.placeholder = item.target_placeholder || "/home/community-user/proje";
  }

  async function scheduleAction(body) {
    const data = await request("/api/schedules", { method: "POST", body: JSON.stringify({ confirm: true, ...body }) });
    if (data.schedules) renderSchedules(data);
    return data;
  }

  function renderSchedules(data) {
    scanTypes = data.scan_types || scanTypes;
    renderScanTypes();
    const tz = document.querySelector("#ops-timezone-form input[name=timezone]");
    if (tz && document.activeElement !== tz) tz.value = data.timezone || "Europe/Istanbul";
    const body = byId("ops-schedule-body");
    if (!body) return;
    const schedules = data.schedules || [];
    body.replaceChildren();
    byId("ops-schedule-empty")?.classList.toggle("hidden", schedules.length > 0);
    const count = byId("ops-schedule-count");
    if (count) count.textContent = `${schedules.length} / ${data.max_schedules || 50} plan · ${data.timezone || ""}`;
    const labels = Object.fromEntries(scanTypes.map(type => [type.key, type.label]));
    for (const item of schedules) {
      const row = document.createElement("tr");
      row.append(el("td", item.name || item.id), el("td", item.project_path), el("td", labels[item.scan_type] || item.scan_type),
        el("td", item.frequency), el("td", item.enabled ? when(item.next_run_at) : "Devre dışı"),
        el("td", item.last_run_at ? `${when(item.last_run_at)} · ${item.run_count || 0} kez` : "—"),
        el("td", STATUS_LABELS[item.last_status] || item.last_status || "—"));
      const actions = el("td");
      const group = el("div", null, "button-row");
      const button = (label, handler) => {
        const node = el("button", label, "mini-button");
        node.type = "button";
        node.addEventListener("click", async () => {
          node.disabled = true;
          try { await handler(); } catch (error) { toast(error.message, "error"); } finally { node.disabled = false; }
        });
        group.append(node);
      };
      button("Şimdi çalıştır", async () => {
        const outcome = await request("/api/schedules", { method: "POST", body: JSON.stringify({ confirm: true, action: "run-now", id: item.id }) });
        toast(STATUS_LABELS[outcome.status] || outcome.status);
        loadSchedules();
      });
      button(item.enabled ? "Devre dışı bırak" : "Etkinleştir", () => scheduleAction({ action: item.enabled ? "disable" : "enable", id: item.id }));
      button("Sil", async () => {
        if (typeof confirm === "function" && !confirm(`“${item.name || item.id}” planı silinsin mi?`)) return;
        await scheduleAction({ action: "delete", id: item.id });
      });
      actions.append(group);
      row.append(actions);
      body.append(row);
    }
  }

  async function loadSchedules() {
    try { renderSchedules(await request("/api/schedules")); } catch (error) { toast(error.message, "error"); }
  }

  // -- Bildirimler -------------------------------------------------------------
  function renderNotifications(data) {
    const list = byId("ops-notification-list");
    if (!list) return;
    list.replaceChildren();
    const items = data.items || [];
    byId("ops-notification-empty")?.classList.toggle("hidden", items.length > 0);
    const count = byId("ops-unread-count");
    if (count) count.textContent = `${data.unread || 0} okunmamış`;
    renderBadge(data.unread || 0);
    for (const item of items) {
      const card = el("article", null, `ops-notification ${item.severity || ""} ${item.read ? "" : "unread"}`);
      card.append(el("b", item.title), el("p", item.message));
      if ((item.details || []).length) {
        const ul = el("ul");
        for (const line of item.details) ul.append(el("li", line));
        card.append(ul);
      }
      const channels = Object.entries(item.channels || {}).map(([name, state]) => `${name}: ${state}`).join(" · ");
      card.append(el("small", `${when(item.created_at)} · ${channels}`));
      list.append(card);
    }
  }

  function renderBadge(unread) {
    const badge = byId("ops-unread-badge");
    if (!badge) return;
    badge.textContent = unread > 99 ? "99+" : String(unread);
    badge.classList.toggle("hidden", !unread);
  }

  async function loadNotifications() {
    try { renderNotifications(await request("/api/notifications?limit=100")); } catch (error) { toast(error.message, "error"); }
  }

  async function refreshBadge() {
    try { renderBadge((await request("/api/notifications?unread=1&limit=1")).unread || 0); } catch (_error) { /* sessiz */ }
  }

  function fillSettings(settings) {
    const form = byId("ops-settings-form");
    if (!form) return;
    const f = form.elements;
    const events = settings.events || {};
    const channels = settings.channels || {};
    const smtp = channels.smtp || {};
    const quiet = settings.quiet_hours || {};
    f.new_findings.checked = Boolean(events.new_findings?.enabled);
    f.min_severity.value = events.new_findings?.min_severity || "high";
    f.fixed_findings.checked = Boolean(events.fixed_findings?.enabled);
    f.scan_failed.checked = Boolean(events.scan_failed?.enabled);
    if (f.system_health) f.system_health.checked = events.system_health?.enabled !== false;
    if (f.finding_assigned) f.finding_assigned.checked = events.finding_assigned?.enabled !== false;
    if (f.finding_due) f.finding_due.checked = events.finding_due?.enabled !== false;
    if (f.due_days_before) f.due_days_before.value = events.finding_due?.days_before ?? 2;
    for (const name of EXTRA_EVENTS) if (f[name]) f[name].checked = events[name]?.enabled !== false;
    f.desktop.checked = Boolean(channels.desktop?.enabled);
    const note = byId("ops-desktop-note");
    if (note) note.textContent = settings.desktop_available ? "(kullanılabilir)" : "(bu oturumda notify-send/masaüstü yok; sessizce atlanır)";
    f.smtp.checked = Boolean(smtp.enabled);
    f.smtp_host.value = smtp.host || "";
    f.smtp_port.value = smtp.port || 587;
    f.smtp_security.value = smtp.security || "starttls";
    f.smtp_username.value = smtp.username || "";
    f.smtp_password.value = "";
    f.smtp_password.placeholder = smtp.password_set ? "kayıtlı (değiştirmek için yazın)" : "kayıtlı parola yok";
    f.smtp_password_clear.checked = false;
    f.smtp_from.value = smtp.from_addr || "";
    f.smtp_to.value = (smtp.to || []).join(", ");
    f.webhook.checked = Boolean(channels.webhook?.enabled);
    f.webhook_url.value = channels.webhook?.url || "";
    f.quiet.checked = Boolean(quiet.enabled);
    f.quiet_start.value = quiet.start || "22:00";
    f.quiet_end.value = quiet.end || "08:00";
    f.quiet_allow_critical.checked = quiet.allow_critical !== false;
    f.confirm.checked = false;
  }

  function settingsFromForm(form) {
    const f = form.elements;
    return {
      events: {
        new_findings: { enabled: f.new_findings.checked, min_severity: f.min_severity.value },
        fixed_findings: { enabled: f.fixed_findings.checked },
        scan_failed: { enabled: f.scan_failed.checked },
        ...(f.system_health ? { system_health: { enabled: f.system_health.checked } } : {}),
        ...(f.finding_assigned ? { finding_assigned: { enabled: f.finding_assigned.checked } } : {}),
        ...(f.finding_due ? { finding_due: { enabled: f.finding_due.checked, days_before: Math.max(0, Math.min(30, Number(f.due_days_before?.value || 0) | 0)) } } : {}),
        ...Object.fromEntries(EXTRA_EVENTS.filter(name => f[name]).map(name => [name, { enabled: f[name].checked }])),
      },
      channels: {
        desktop: { enabled: f.desktop.checked },
        smtp: {
          enabled: f.smtp.checked, host: f.smtp_host.value.trim(), port: Number(f.smtp_port.value || 587),
          security: f.smtp_security.value, username: f.smtp_username.value.trim(), from_addr: f.smtp_from.value.trim(),
          to: f.smtp_to.value.split(",").map(item => item.trim()).filter(Boolean),
        },
        webhook: { enabled: f.webhook.checked, url: f.webhook_url.value.trim() },
      },
      quiet_hours: { enabled: f.quiet.checked, start: f.quiet_start.value, end: f.quiet_end.value, allow_critical: f.quiet_allow_critical.checked },
    };
  }

  async function loadSettings() {
    try { fillSettings(await request("/api/notification-settings")); } catch (error) { toast(error.message, "error"); }
  }

  // -- Olaylar -------------------------------------------------------------------
  function bind() {
    byId("ops-scan-type")?.addEventListener("change", syncTypeFields);
    byId("ops-schedule-form")?.addEventListener("submit", async event => {
      event.preventDefault();
      const form = event.currentTarget;
      const data = new FormData(form);
      const type = scanTypes.find(item => item.key === data.get("scan_type")) || {};
      const schedule = { name: data.get("name") || "", scan_type: data.get("scan_type"), project_path: data.get("project_path"), frequency: data.get("frequency") };
      if (type.uses_scope && data.get("scope") === "all") schedule.scope = { preset: "all" };
      if (type.base_ref) schedule.base_ref = data.get("base_ref") || "HEAD~1";
      try {
        await scheduleAction({ action: "create", schedule });
        form.reset();
        syncTypeFields();
        toast("Plan kaydedildi.");
      } catch (error) { toast(error.message, "error"); }
    });
    byId("ops-timezone-form")?.addEventListener("submit", async event => {
      event.preventDefault();
      try {
        await scheduleAction({ action: "timezone", timezone: new FormData(event.currentTarget).get("timezone") });
        event.currentTarget.elements.confirm.checked = false;
        toast("Saat dilimi kaydedildi.");
      } catch (error) { toast(error.message, "error"); }
    });
    byId("ops-mark-all")?.addEventListener("click", async () => {
      try {
        await request("/api/notifications", { method: "POST", body: JSON.stringify({ action: "mark-read", ids: "all" }) });
        loadNotifications();
      } catch (error) { toast(error.message, "error"); }
    });
    byId("ops-settings-form")?.addEventListener("submit", async event => {
      event.preventDefault();
      const form = event.currentTarget;
      const body = { confirm: true, action: "save", settings: settingsFromForm(form) };
      if (form.elements.smtp_password_clear.checked) body.smtp_password = "";
      else if (form.elements.smtp_password.value) body.smtp_password = form.elements.smtp_password.value;
      try {
        fillSettings(await request("/api/notification-settings", { method: "POST", body: JSON.stringify(body) }));
        toast("Bildirim ayarları kaydedildi.");
      } catch (error) { toast(error.message, "error"); }
    });
    byId("ops-send-test")?.addEventListener("click", async () => {
      try {
        const item = await request("/api/notification-settings", { method: "POST", body: JSON.stringify({ confirm: true, action: "test" }) });
        toast("Test: " + Object.entries(item.channels || {}).map(([name, state]) => `${name} ${state}`).join(", "));
        loadNotifications();
      } catch (error) { toast(error.message, "error"); }
    });
  }

  function show(view) {
    if (view === "schedules") loadSchedules();
    if (view === "notifications") { loadNotifications(); loadSettings(); }
  }

  scope.SniperOps = { show, loadSchedules, loadNotifications, refreshBadge, renderSchedules, renderNotifications, settingsFromForm, fillSettings };
  if (typeof document !== "undefined" && document.getElementById("ops-schedule-form")) {
    bind();
    refreshBadge();
    setInterval(refreshBadge, BADGE_MS);
    const view = (location.hash || "").slice(1);
    if (view === "schedules" || view === "notifications") show(view);
  }
})();
