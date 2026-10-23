// Bulgu takibi: analiz detayında durum rozetleri/durum değiştirme, "Bulgu takibi" görünümü ve iş birliği
// (sorumlu, son tarih, yorumlar, "Bana atananlar"). Yorum metni yalnız textContent ile yazılır.
(function () {
  "use strict";
  const STATUS_LABELS = { open: "Açık", in_progress: "Üzerinde çalışılıyor", fixed: "Düzeldi", risk_accepted: "Risk kabulü", false_positive: "Yanlış alarm", reopened: "Yeniden açıldı" };
  const SEVERITY_LABELS = { critical: "Kritik", high: "Yüksek", medium: "Orta", low: "Düşük", info: "Bilgi" };
  const FILTERS = { active: "open,in_progress,reopened", fixed: "fixed", suppressed: "risk_accepted,false_positive", all: "" };
  const NAME_KEY = "sniper.tracking.assignee";
  const esc = value => String(value ?? "").replace(/[&<>"']/g, ch => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch]);
  const request = (path, options = {}) => (typeof globalThis.api === "function" ? globalThis.api(path, options) : fetch(path, options).then(async response => {
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || `İstek tamamlanamadı (${response.status})`);
    return data;
  }));
  const notify = (message, type) => (typeof globalThis.toast === "function" ? globalThis.toast(message, type) : undefined);
  const post = (path, body) => request(path, { method: "POST", body: JSON.stringify({ confirm: true, ...body }) });
  const view = {
    project: "", filter: "active", mode: "project",
    assigned: { assignee: "", status: "active", severity: "", overdue: false },
    unified: { source: "", status: "active", severity: "", offset: 0 },
    ctx: { authEnabled: false, me: null, users: [], names: [] },
  };

  function storedName() {
    try { return globalThis.localStorage?.getItem(NAME_KEY) || ""; } catch (_error) { return ""; }
  }
  function rememberName(name) {
    try { globalThis.localStorage?.setItem(NAME_KEY, name); } catch (_error) { /* gizli pencere: yok say */ }
  }

  // -- yetki yardımcıları (sunucu ayrıca denetler) ------------------------------------------------
  function canEdit(ctx) {
    return !ctx.authEnabled || (ctx.me && ctx.me.role !== "reader");
  }
  function canDeleteComment(comment, ctx) {
    if (!ctx.authEnabled) return true;
    if (!ctx.me || ctx.me.role === "reader") return false;
    return ctx.me.role === "admin" || (comment.author_id && comment.author_id === ctx.me.id);
  }

  function dueChip(item) {
    if (!item || !item.due_date) return "";
    const late = item.overdue ? " overdue" : "";
    return `<span class="track-chip due${late}" title="Son tarih">son tarih ${esc(item.due_date)}${item.overdue ? " · gecikmiş" : ""}</span>`;
  }

  function ownerCell(item) {
    const who = item.assignee_name ? `<span class="track-owner">${esc(item.assignee_name)}</span>` : `<span class="muted">atanmamış</span>`;
    return `${who}${item.due_date ? `<br>${dueChip(item)}` : ""}`;
  }

  function badge(finding) {
    const track = finding && finding.tracking;
    if (!track) return "";
    const fresh = track.is_new ? `<span class="track-chip new">yeni</span>` : `<span class="track-chip seen" title="İlk görülme: ${esc(track.first_seen_at)}">${Number(track.seen_count || 1)}. kez</span>`;
    const owner = track.assignee_name ? `<span class="track-chip owner" title="Sorumlu">${esc(track.assignee_name)}</span>` : "";
    return `<span class="track-badges">${fresh}<span class="track-chip status-${esc(track.status)}">${esc(track.status_label || STATUS_LABELS[track.status] || track.status)}</span>${owner}${dueChip(track)}` +
      (track.status === "fixed" ? "" : `<button type="button" class="mini-button" data-track-edit="${esc(track.id)}" data-track-status="${esc(track.status)}">Durum</button>`) + `</span>`;
  }

  function statusForm(id, current) {
    const options = ["open", "in_progress", "risk_accepted", "false_positive"]
      .map(status => `<option value="${status}"${status === current ? " selected" : ""}>${STATUS_LABELS[status]}</option>`).join("");
    return `<form class="track-status-form" data-track-form="${esc(id)}"><select name="status" aria-label="Yeni durum">${options}</select>` +
      `<input name="note" maxlength="2000" placeholder="Not (isteğe bağlı)" aria-label="Not">` +
      `<input type="date" name="expires_at" title="Risk kabulü bitiş tarihi (isteğe bağlı; yalnız risk kabulünde)" aria-label="Risk kabulü bitiş tarihi">` +
      `<button class="mini-button accent" type="submit">Onayla</button>` +
      `<button class="mini-button" type="button" data-track-cancel>Vazgeç</button></form>`;
  }

  // -- sorgu ----------------------------------------------------------------------------------------
  function assignedQuery(filters, ctx) {
    const params = [];
    const assignee = filters.assignee || (ctx.authEnabled ? "me" : "all");
    params.push(`assignee=${encodeURIComponent(assignee)}`);
    if (filters.status === "active") params.push(`status=${FILTERS.active}`);
    if (filters.severity) params.push(`severity=${encodeURIComponent(filters.severity)}`);
    if (filters.overdue) params.push("overdue=1");
    return `/api/finding-tracking/assigned?${params.join("&")}`;
  }

  function unifiedQuery(filters) {
    const params = [];
    if (filters.source) params.push(`source=${encodeURIComponent(filters.source)}`);
    if (filters.status === "active") params.push(`status=${encodeURIComponent(FILTERS.active)}`);
    else if (filters.status && filters.status !== "all") params.push(`status=${encodeURIComponent(filters.status)}`);
    if (filters.severity) params.push(`severity=${encodeURIComponent(filters.severity)}`);
    params.push("limit=500");
    if (filters.offset) params.push(`offset=${Number(filters.offset)}`);
    return `/api/findings/unified?${params.join("&")}`;
  }

  // -- yorumlar (DOM + textContent; innerHTML yok) --------------------------------------------------
  function renderComments(container, comments, ctx, trackedId) {
    const doc = container.ownerDocument || globalThis.document;
    while (container.firstChild) container.removeChild(container.firstChild);
    if (!comments.length) {
      const empty = doc.createElement("p");
      empty.className = "muted";
      empty.textContent = "Henüz yorum yok.";
      container.appendChild(empty);
      return container;
    }
    for (const comment of comments) {
      const box = doc.createElement("div");
      box.className = "track-comment";
      const meta = doc.createElement("div");
      meta.className = "track-comment-meta";
      meta.textContent = `${comment.author_name || "yerel kullanıcı"} · ${comment.created_at || ""}`;
      if (canDeleteComment(comment, ctx)) {
        const remove = doc.createElement("button");
        remove.type = "button";
        remove.className = "mini-button";
        remove.textContent = "Sil";
        remove.setAttribute("data-track-comment-delete", String(comment.id));
        remove.setAttribute("data-track-id", String(trackedId));
        meta.appendChild(remove);
      }
      const body = doc.createElement("p");
      body.className = "track-comment-body";
      body.textContent = comment.body || "";
      box.appendChild(meta);
      box.appendChild(body);
      container.appendChild(box);
    }
    return container;
  }

  function detailHtml(item, ctx) {
    const id = esc(item.id);
    const edit = canEdit(ctx);
    let assign = "";
    if (edit && ctx.authEnabled) {
      const options = [`<option value="">— atanmamış —</option>`].concat((ctx.users || []).map(user =>
        `<option value="${esc(user.id)}"${user.id === item.assignee_id ? " selected" : ""}>${esc(user.username)} (${esc(user.role_label || user.role)})</option>`)).join("");
      assign = `<form class="track-inline-form" data-track-assign="${id}"><label>Sorumlu<select name="assignee_id">${options}</select></label><button class="mini-button accent" type="submit">Ata</button></form>`;
    } else if (edit) {
      const names = (ctx.names || []).map(name => `<option value="${esc(name)}"></option>`).join("");
      assign = `<form class="track-inline-form" data-track-assign="${id}"><label>Sorumlu<input name="assignee_name" maxlength="80" value="${esc(item.assignee_name)}" list="track-names-${id}" placeholder="Ad (boş: atamayı kaldır)"></label><datalist id="track-names-${id}">${names}</datalist><button class="mini-button accent" type="submit">Ata</button></form>`;
    }
    const due = edit ? `<form class="track-inline-form" data-track-due="${id}"><label>Son tarih<input type="date" name="due_date" value="${esc(item.due_date)}"></label><button class="mini-button accent" type="submit">Kaydet</button>${item.due_date ? `<button class="mini-button" type="button" data-track-due-clear="${id}">Tarihi kaldır</button>` : ""}</form>` : "";
    const owner = `<p class="muted">Sorumlu: ${item.assignee_name ? esc(item.assignee_name) : "atanmamış"}${item.assigned_at ? ` (${esc(item.assigned_at)})` : ""}${item.due_date ? ` · ${dueChip(item)}` : ""}</p>`;
    const form = edit ? `<form class="track-comment-form" data-track-comment="${id}"><textarea name="body" rows="3" maxlength="4000" placeholder="Yorum yaz (düz metin, en çok 4000 karakter)" aria-label="Yorum"></textarea><button class="mini-button accent" type="submit">Yorum ekle</button></form>` : "";
    return `<div class="track-detail">${owner}<div class="track-detail-forms">${assign}${due}</div><h4>Yorumlar</h4><div class="track-comments" data-track-comments="${id}"></div>${form}</div>`;
  }

  async function openDetail(id, row) {
    const open = row.nextElementSibling;
    if (open && open.dataset && open.dataset.trackDetailRow === id) {
      open.remove();  // ikinci tıklama kapatır
      return;
    }
    try {
      const item = await request(`/api/finding-tracking/${encodeURIComponent(id)}`);
      row.insertAdjacentHTML("afterend", `<tr class="track-detail-row" data-track-detail-row="${esc(id)}"><td colspan="5"></td></tr>`);
      const detailRow = row.nextElementSibling;
      const cell = detailRow.querySelector("td");
      cell.innerHTML = detailHtml(item, view.ctx); // sniper-reviewed: html-safe (detailHtml tüm alanları esc ile; yorumlar ayrıca textContent)
      renderComments(cell.querySelector("[data-track-comments]"), item.comments || [], view.ctx, item.id);
    } catch (error) {
      notify(error.message, "error");
    }
  }

  async function refreshAfterChange(id) {
    await loadCurrent();
    const selector = globalThis.CSS && globalThis.CSS.escape ? globalThis.CSS.escape(id) : String(id).replace(/["\\]/g, "");
    const row = document.querySelector(`[data-track-row="${selector}"]`);
    if (row) await openDetail(id, row);
  }

  async function submitStatus(form) {
    const id = form.dataset.trackForm;
    const data = new FormData(form);
    form.querySelector("button[type=submit]").disabled = true;
    try {
      const body = { status: data.get("status"), note: data.get("note") || "" };
      // 17. tur: risk kabulüne bitiş tarihi (boşsa SLA politikasındaki varsayılan süre uygulanır).
      if (body.status === "risk_accepted" && data.get("expires_at")) body.expires_at = data.get("expires_at");
      await post(`/api/finding-tracking/${encodeURIComponent(id)}/status`, body);
      notify("Bulgu durumu güncellendi; sonraki analizlere de taşınır.");
      const detail = document.querySelector("#project-audit-detail .project-detail-head .eyebrow");
      if (detail && typeof globalThis.openProjectAudit === "function" && form.closest("#project-audit-detail")) await globalThis.openProjectAudit(detail.textContent);
      if (form.closest("#tracking-view")) await loadCurrent();
    } catch (error) {
      notify(error.message, "error");
      form.querySelector("button[type=submit]").disabled = false;
    }
  }

  async function submitCollab(form) {
    const data = new FormData(form);
    const button = form.querySelector("button[type=submit]");
    if (button) button.disabled = true;
    try {
      let id;
      if (form.dataset.trackAssign) {
        id = form.dataset.trackAssign;
        const body = view.ctx.authEnabled ? { assignee_id: data.get("assignee_id") || null } : { assignee_name: (data.get("assignee_name") || "").trim() || null };
        await post(`/api/finding-tracking/${encodeURIComponent(id)}/assign`, body);
        notify("Sorumlu güncellendi.");
      } else if (form.dataset.trackDue) {
        id = form.dataset.trackDue;
        await post(`/api/finding-tracking/${encodeURIComponent(id)}/due`, { due_date: data.get("due_date") || null });
        notify("Son tarih güncellendi.");
      } else {
        id = form.dataset.trackComment;
        const text = String(data.get("body") || "").trim();
        if (!text) throw new Error("Yorum boş olamaz.");
        await post(`/api/finding-tracking/${encodeURIComponent(id)}/comments`, { body: text });
        notify("Yorum eklendi.");
      }
      await loadContext();
      await refreshAfterChange(id);
    } catch (error) {
      notify(error.message, "error");
      if (button) button.disabled = false;
    }
  }

  async function clickAction(id, path, body, message) {
    try {
      await post(path, body);
      notify(message);
      await refreshAfterChange(id);
    } catch (error) {
      notify(error.message, "error");
    }
  }

  document.addEventListener("click", event => {
    const networkEdit = event.target.closest("[data-network-edit]");
    if (networkEdit) {
      const status = globalThis.prompt?.("Durum: open, in_progress, fixed, risk_accepted, false_positive, reopened", networkEdit.dataset.status || "open");
      if (status == null) return;
      const assignee_name = globalThis.prompt?.("Sorumlu adı (isteğe bağlı)", networkEdit.dataset.assignee || "") ?? "";
      const due_date = globalThis.prompt?.("Son tarih YYYY-MM-DD (isteğe bağlı)", networkEdit.dataset.due || "") ?? "";
      clickAction(networkEdit.dataset.networkEdit,
        `/api/findings/unified/network/${encodeURIComponent(networkEdit.dataset.networkEdit)}`,
        { status, assignee_name, due_date }, "Ağ bulgusu güncellendi.");
      return;
    }
    const page = event.target.closest("[data-unified-offset]");
    if (page) { view.unified.offset = Number(page.dataset.unifiedOffset) || 0; loadCurrent(); return; }
    const edit = event.target.closest("[data-track-edit]");
    if (edit) {
      const holder = edit.closest(".track-badges") || edit.parentElement;
      if (!holder.querySelector("[data-track-form]")) holder.insertAdjacentHTML("beforeend", statusForm(edit.dataset.trackEdit, edit.dataset.trackStatus));
      return;
    }
    if (event.target.closest("[data-track-cancel]")) {
      event.target.closest("[data-track-form]")?.remove();
      return;
    }
    const detail = event.target.closest("[data-track-detail]");
    if (detail) {
      openDetail(detail.dataset.trackDetail, detail.closest("tr"));
      return;
    }
    const remove = event.target.closest("[data-track-comment-delete]");
    if (remove) {
      const id = remove.dataset.trackId;
      clickAction(id, `/api/finding-tracking/${encodeURIComponent(id)}/comments/${encodeURIComponent(remove.dataset.trackCommentDelete)}/delete`, {}, "Yorum silindi.");
      return;
    }
    const clear = event.target.closest("[data-track-due-clear]");
    if (clear) {
      const id = clear.dataset.trackDueClear;
      clickAction(id, `/api/finding-tracking/${encodeURIComponent(id)}/due`, { due_date: null }, "Son tarih kaldırıldı.");
      return;
    }
    const mode = event.target.closest("[data-track-mode]");
    if (mode) {
      view.mode = ["project", "assigned", "unified"].includes(mode.dataset.trackMode) ? mode.dataset.trackMode : "project";
      loadCurrent();
      return;
    }
    const filter = event.target.closest("[data-track-filter]");
    if (filter) {
      view.filter = filter.dataset.trackFilter;
      loadCurrent();
    }
  });
  document.addEventListener("submit", event => {
    const status = event.target.closest("[data-track-form]");
    if (status) {
      event.preventDefault();
      submitStatus(status);
      return;
    }
    const collab = event.target.closest("[data-track-assign], [data-track-due], [data-track-comment]");
    if (!collab) return;
    event.preventDefault();
    submitCollab(collab);
  });
  document.addEventListener("change", event => {
    const target = event.target;
    if (target.id === "tracking-project") {
      view.project = target.value;
      loadCurrent();
      return;
    }
    const filters = view.assigned;
    if (target.id === "track-assignee-filter") filters.assignee = target.value;
    else if (target.id === "track-assignee-name") { filters.assignee = target.value.trim(); rememberName(filters.assignee); }
    else if (target.id === "track-assigned-status") filters.status = target.value;
    else if (target.id === "track-assigned-severity") filters.severity = target.value;
    else if (target.id === "track-assigned-overdue") filters.overdue = Boolean(target.checked);
    else {
      const unified = view.unified;
      if (target.id === "track-unified-source") unified.source = target.value;
      else if (target.id === "track-unified-status") unified.status = target.value;
      else if (target.id === "track-unified-severity") unified.severity = target.value;
      else return;
      unified.offset = 0;
    }
    loadCurrent();
  });

  function trendHtml(trend) {
    if (!trend.length) return "<p class=\"muted\">Henüz analiz yok.</p>";
    const rows = trend.map(row => `<tr><td>${esc(row.created_at)}</td><td>${row.mode === "supplement" ? "ek tarama" : "tam"}</td><td>${Number(row.score)} (${esc(row.grade)})</td><td>${Number(row.new)}</td><td>${Number(row.fixed)}</td><td>${Number(row.reopened)}</td><td>${Number(row.not_rescanned)}</td></tr>`).join("");
    return `<table class="track-table"><thead><tr><th>Analiz</th><th>Tür</th><th>Puan</th><th>Yeni</th><th>Düzelen</th><th>Yeniden açılan</th><th>Doğrulanamayan</th></tr></thead><tbody>${rows}</tbody></table>`;
  }

  // 25. tur: AI/ajan önerisi rozeti (ai_triage.js) ve yerel model açıksa satır düğmesi.
  function aiCell(item) {
    const chip = typeof globalThis.sniperAiChip === "function" ? globalThis.sniperAiChip(item.ai) : "";
    const run = globalThis.sniperAiLocalEnabled && item.status !== "fixed" ? `<button type="button" class="mini-button" data-ai-run="${esc(item.id)}" title="Yerel modelle triyaj önerisi al">AI</button>` : "";
    return chip + run;
  }

  function rowHtml(item, showProject) {
    const where = `<code>${esc(item.file)}${item.line ? `:${Number(item.line)}` : ""}</code> · ${esc(item.reference)}`;
    const project = showProject ? ` · ${esc(String(item.project_path || "").split("/").pop())}` : "";
    return `<tr class="sev-${esc(item.severity)}${item.overdue ? " track-overdue" : ""}" data-track-row="${esc(item.id)}"><td>${esc(SEVERITY_LABELS[item.severity] || item.severity)}</td><td>${esc(item.title)}<br><small>${where}${project}</small></td>` +
      `<td><span class="track-badges"><span class="track-chip status-${esc(item.status)}">${esc(item.status_label)}</span>${item.risk_expires_at ? `<span class="track-chip due" title="Risk kabulü bitiş tarihi">bitiş ${esc(item.risk_expires_at)}</span>` : ""}${item.status === "fixed" ? "" : `<button type="button" class="mini-button" data-track-edit="${esc(item.id)}" data-track-status="${esc(item.status)}">Durum</button>`}${aiCell(item)}</span></td>` +
      `<td>${ownerCell(item)}</td>` +
      `<td><small>${esc(item.first_seen_at)}${item.fixed_at ? `<br>düzeldi: ${esc(item.fixed_at)}` : ""}</small><br><button type="button" class="mini-button" data-track-detail="${esc(item.id)}">Ayrıntı</button></td></tr>`;
  }

  function tableHtml(items, showProject) {
    const rows = items.map(item => rowHtml(item, showProject)).join("");
    return `<table class="track-table"><thead><tr><th>Önem</th><th>Bulgu</th><th>Durum</th><th>Sorumlu</th><th>Tarih</th></tr></thead><tbody>${rows || `<tr><td colspan="5" class="muted">Bu filtrede bulgu yok.</td></tr>`}</tbody></table>`;
  }

  function modesHtml() {
    return `<div class="button-row track-modes">` +
      [["project", "Proje"], ["unified", "Tüm kaynaklar"], ["assigned", view.ctx.authEnabled ? "Bana atananlar" : "Atananlar"]].map(([key, label]) =>
        `<button type="button" class="mini-button${view.mode === key ? " accent" : ""}" data-track-mode="${key}">${label}</button>`).join("") + `</div>`;
  }

  function unifiedFiltersHtml() {
    const f = view.unified;
    const options = (rows, current) => rows.map(([value, label]) => `<option value="${value}"${value === current ? " selected" : ""}>${label}</option>`).join("");
    return `<div class="button-row track-assigned-filters">` +
      `<label>Kaynak<select id="track-unified-source">${options([["", "Tümü"], ["project", "Proje analizi"], ["manual", "Elle"], ["network", "Ağ taraması"], ["dependency", "Bağımlılık"]], f.source)}</select></label>` +
      `<label>Durum<select id="track-unified-status">${options([["active", "Açık"], ["all", "Tümü"], ["fixed", "Düzelen"], ["risk_accepted", "Risk kabulü"], ["false_positive", "Yanlış alarm"]], f.status)}</select></label>` +
      `<label>Önem<select id="track-unified-severity">${options([["", "Tümü"], ...Object.entries(SEVERITY_LABELS)], f.severity)}</select></label></div>`;
  }

  function unifiedTableHtml(items) {
    const sourceLabels = { project: "Proje", manual: "Elle", network: "Ağ", dependency: "Bağımlılık" };
    const rows = items.map(item => {
      const location = item.location && item.location.file ? `${item.location.file}${item.location.line ? `:${Number(item.location.line)}` : ""}` :
        (item.location && item.location.asset ? item.location.asset : "—");
      const owner = item.assignee && item.assignee.name ? esc(item.assignee.name) : `<span class="muted">atanmamış</span>`;
      const triage = item.triage ? `<br><small>öneri: ${esc(item.triage.verdict)} · ${(Number(item.triage.confidence) * 100).toFixed(0)}%</small>` : "";
      return `<tr class="sev-${esc(item.severity)}${item.overdue ? " track-overdue" : ""}"><td>${esc(sourceLabels[item.source] || item.source)}</td>` +
        `<td>${esc(SEVERITY_LABELS[item.severity] || item.severity)}</td><td>${esc(item.title)}<br><small><code>${esc(location)}</code> · ${esc(item.reference || "—")} · ${esc((item.scope || {}).name || "—")}</small></td>` +
        `<td><span class="track-chip status-${esc(item.status)}">${esc(STATUS_LABELS[item.status] || item.status)}</span>${triage}` +
        `${item.source === "network" && canEdit(view.ctx) ? `<br><button type="button" class="mini-button" data-network-edit="${esc(item.source_id)}" data-status="${esc(item.status)}" data-assignee="${esc((item.assignee || {}).name || "")}" data-due="${esc(item.due_date || "")}">Düzenle</button>` : ""}</td>` +
        `<td>${owner}${item.due_date ? `<br>${dueChip(item)}` : ""}</td><td><small>${esc(item.updated_at || item.first_seen_at || "")}</small></td></tr>`;
    }).join("");
    return `<table class="track-table"><thead><tr><th>Kaynak</th><th>Önem</th><th>Bulgu</th><th>Durum</th><th>Sorumlu</th><th>Güncelleme</th></tr></thead><tbody>${rows || `<tr><td colspan="6" class="muted">Bu filtrede bulgu yok.</td></tr>`}</tbody></table>`;
  }

  function assignedFiltersHtml() {
    const f = view.assigned;
    const ctx = view.ctx;
    let who;
    if (ctx.authEnabled) {
      const current = f.assignee || "me";
      const options = [["me", "Bana atananlar"], ["all", "Tüm atananlar"]].concat((ctx.users || []).map(user => [user.id, user.username]))
        .map(([value, label]) => `<option value="${esc(value)}"${value === current ? " selected" : ""}>${esc(label)}</option>`).join("");
      who = `<label>Sorumlu<select id="track-assignee-filter">${options}</select></label>`;
    } else {
      const names = (ctx.names || []).map(name => `<option value="${esc(name)}"></option>`).join("");
      who = `<label>Sorumlu<input id="track-assignee-name" maxlength="80" value="${esc(f.assignee)}" list="track-assignee-names" placeholder="Ad (boş: tüm atananlar)"></label><datalist id="track-assignee-names">${names}</datalist>`;
    }
    const sev = [["", "Tümü"]].concat(Object.entries(SEVERITY_LABELS)).map(([value, label]) => `<option value="${value}"${value === f.severity ? " selected" : ""}>${label}</option>`).join("");
    return `<div class="button-row track-assigned-filters">${who}` +
      `<label>Durum<select id="track-assigned-status"><option value="active"${f.status === "active" ? " selected" : ""}>Açık</option><option value="all"${f.status === "all" ? " selected" : ""}>Tümü</option></select></label>` +
      `<label>Önem<select id="track-assigned-severity">${sev}</select></label>` +
      `<label class="track-check"><input type="checkbox" id="track-assigned-overdue"${f.overdue ? " checked" : ""}> Yalnız gecikenler</label></div>`;
  }

  async function loadAssigned(root) {
    const data = await request(assignedQuery(view.assigned, view.ctx));
    const items = data.findings || [];
    root.innerHTML = /* sniper-reviewed: html-safe (alt parçalar esc ile; sayılar Number) */ `${modesHtml()}<div class="project-audit-summary track-summary">
        <div><b>${items.length}</b><span>atanmış bulgu</span></div>
        <div><b>${Number(data.overdue || 0)}</b><span>gecikmiş</span></div></div>
      ${assignedFiltersHtml()}${tableHtml(items, true)}`;
  }

  async function loadUnified(root) {
    const data = await request(unifiedQuery(view.unified));
    const counts = data.counts || {};
    const bySource = counts.by_source || {};
    root.innerHTML = /* sniper-reviewed: html-safe (dinamik metinler unifiedTableHtml içinde esc ile) */ `${modesHtml()}` +
      `<div class="project-audit-summary track-summary"><div><b>${Number(data.total || 0)}</b><span>eşleşen bulgu</span></div>` +
      `<div><b>${Number(bySource.project || 0)} / ${Number(bySource.manual || 0)} / ${Number(bySource.network || 0)} / ${Number(bySource.dependency || 0)}</b><span>proje / elle / ağ / bağımlılık</span></div>` +
      `<div><b>${Number(data.returned || 0)}</b><span>gösterilen${data.truncated ? " · sınırlandı" : ""}</span></div></div>` +
      `${unifiedFiltersHtml()}${unifiedTableHtml(data.items || [])}` +
      `<div class="button-row"><button type="button" class="mini-button" data-unified-offset="${Math.max(0, Number(data.offset || 0) - 500)}"${Number(data.offset || 0) ? "" : " disabled"}>Önceki</button>` +
      `<button type="button" class="mini-button" data-unified-offset="${Number(data.next_offset || 0)}"${data.next_offset == null ? " disabled" : ""}>Sonraki</button></div>`;
  }

  async function loadProject(root) {
    const query = `project_path=${encodeURIComponent(view.project)}`;
    const [summary, list] = await Promise.all([
      request(`/api/finding-tracking/summary?${query}`),
      request(`/api/finding-tracking?${query}${FILTERS[view.filter] ? `&status=${FILTERS[view.filter]}` : ""}`),
    ]);
    const sev = summary.active_by_severity || {};
    const own = summary.ownership || {};
    const mttf = summary.mean_time_to_fix_hours == null ? "—" : summary.mean_time_to_fix_hours < 48 ? `${summary.mean_time_to_fix_hours} sa` : `${(summary.mean_time_to_fix_hours / 24).toFixed(1)} gün`;
    const tabs = [["active", "Açık"], ["fixed", "Düzelen"], ["suppressed", "Bastırılan"], ["all", "Tümü"]]
      .map(([key, label]) => `<button type="button" class="mini-button${view.filter === key ? " accent" : ""}" data-track-filter="${key}">${label}</button>`).join("");
    root.innerHTML = `${modesHtml()}<div class="project-audit-summary track-summary">
        <div><b>${Number(summary.active)}</b><span>açık bulgu</span></div>
        <div><b>${Number(sev.critical || 0)} / ${Number(sev.high || 0)}</b><span>kritik / yüksek</span></div>
        <div><b>${Number(summary.fixed_total)}</b><span>düzelen · ort. ${esc(mttf)}</span></div>
        <div><b>${Number(summary.suppressed)}</b><span>bastırılan</span></div>
        <div><b>${Number(own.assigned_active || 0)} / ${Number(own.overdue || 0)}</b><span>atanmış / gecikmiş</span></div></div>
      <h3>Trend</h3>${trendHtml(summary.trend || [])}
      <div class="button-row">${tabs}</div>${tableHtml(list.findings || [], false)}`;
  }

  async function loadCurrent() {
    const root = document.querySelector("#tracking-body");
    if (!root) return;
    const label = document.querySelector(".track-project-label");
    if (label) label.hidden = view.mode !== "project";
    try {
      if (view.mode === "assigned") return await loadAssigned(root);
      if (view.mode === "unified") return await loadUnified(root);
      if (view.project) await loadProject(root);
    } catch (error) {
      root.innerHTML = `${modesHtml()}<p class="muted">${esc(error.message)}</p>`;
    }
  }

  async function loadContext() {
    const [status, people] = await Promise.all([
      request("/api/auth/status").catch(() => ({})),
      request("/api/finding-tracking/assignees").catch(() => ({})),
    ]);
    view.ctx = {
      authEnabled: Boolean(status.enabled), me: status.user || null,
      users: people.users || [], names: people.names || [],
    };
    if (!view.ctx.authEnabled && !view.assigned.assignee) view.assigned.assignee = storedName();
    return view.ctx;
  }

  async function loadTracking() {
    const select = document.querySelector("#tracking-project");
    if (!select) return;
    try {
      await loadContext();
      const data = await request("/api/finding-tracking/projects");
      const projects = data.projects || [];
      if (!projects.length) {
        select.innerHTML = "";
        view.mode = "unified";
      } else {
        if (!projects.some(item => item.project_path === view.project)) view.project = projects[0].project_path;
        select.innerHTML = projects.map(item => `<option value="${esc(item.project_path)}"${item.project_path === view.project ? " selected" : ""}>${esc(item.project_name)} · ${Number(item.active)} açık</option>`).join("");
      }
      await loadCurrent();
    } catch (error) {
      notify(error.message, "error");
    }
  }

  globalThis.sniperTrackingBadge = badge;
  globalThis.sniperLoadTracking = loadTracking;
  if (typeof module !== "undefined") module.exports = { badge, statusForm, STATUS_LABELS };
  globalThis.sniperTrackingInternals = { ownerCell, dueChip, assignedQuery, unifiedQuery, unifiedTableHtml,
    renderComments, detailHtml, canDeleteComment, canEdit, rowHtml, view };
})();
