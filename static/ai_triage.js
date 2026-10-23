// AI/ajan triyajı (25. tur): "Bulgu takibi" görünümünde öneri paneli. Öneriler (Claude Code, Codex, yerel model)
// bulgu durumunu değiştirmez; analist kabul/ret eder. Ajan metni (gerekçe, düzeltme önerisi) yalnız textContent ile
// yazılır; hiçbir zaman HTML olarak basılmaz ya da çalıştırılmaz.
(function () {
  "use strict";
  const VERDICT_LABELS = { likely_true: "Muhtemelen gerçek", likely_false: "Muhtemelen yanlış alarm", uncertain: "Belirsiz" };
  const DECISION_LABELS = { pending: "Karar bekliyor", accepted: "Kabul edildi", rejected: "Reddedildi", auto_applied: "Otomatik uygulandı", reverted: "Geri alındı" };
  const esc = value => String(value ?? "").replace(/[&<>"']/g, ch => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch]);
  const request = (path, options = {}) => (typeof globalThis.api === "function" ? globalThis.api(path, options) : fetch(path, options).then(async response => {
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || `İstek tamamlanamadı (${response.status})`);
    return data;
  }));
  const post = (path, body) => request(path, { method: "POST", body: JSON.stringify({ confirm: true, ...body }) });
  const notify = (message, type) => (typeof globalThis.toast === "function" ? globalThis.toast(message, type) : undefined);
  const state = { project: "", settings: null, suggestions: [], role: { admin: true, analyst: true }, filter: "pending" };

  function roleFrom(status) {
    if (!status || !status.enabled) return { admin: true, analyst: true };
    const role = status.user && status.user.role;
    return { admin: role === "admin", analyst: role === "admin" || role === "analyst" };
  }

  // Bulgu takibi satırındaki küçük AI rozeti (finding_tracking.js rowHtml çağırır).
  function chipHtml(ai) {
    if (!ai || !VERDICT_LABELS[ai.verdict]) return "";
    const conf = Number(ai.confidence || 0).toFixed(2);
    const decided = ai.decision && ai.decision !== "pending" ? ` · ${esc(DECISION_LABELS[ai.decision] || ai.decision)}` : "";
    return `<span class="track-chip ai-chip ai-${esc(ai.verdict)}" title="AI önerisi (öneridir; analist kararı değildir) · ${esc(ai.agent)}">AI: ${esc(VERDICT_LABELS[ai.verdict])} ${conf}${decided}</span>`;
  }

  function cardHtml() {
    const s = state.settings || { policy: { auto_apply: {} }, local: {} };
    const allowed = Boolean(s.project_external_allowed);
    const auto = s.policy.auto_apply || {};
    const local = s.local || {};
    const admin = state.role.admin;
    const filters = [["pending", "Karar bekleyen"], ["all", "Tümü"]].map(([key, label]) =>
      `<button type="button" class="mini-button${state.filter === key ? " accent" : ""}" data-ai-filter="${key}">${label}</button>`).join("");
    const localForm = admin ? `<form id="ai-local-form" class="ai-local-form">
        <label class="track-check"><input type="checkbox" name="enabled"${local.enabled ? " checked" : ""}> Yerel model triyajı</label>
        <label>Uç (yalnız loopback)<input name="endpoint" maxlength="300" value="${esc(local.endpoint)}" spellcheck="false"></label>
        <label>Model<input name="model" maxlength="120" value="${esc(local.model)}" spellcheck="false"></label>
        <label>Günlük bütçe<input name="daily_budget" type="number" min="0" max="10000" value="${Number(local.daily_budget || 0)}"></label>
        <button type="submit" class="mini-button">Kaydet</button><button type="button" class="mini-button" data-ai-local-test="1">Bağlantıyı sına</button></form>` :
      `<p class="muted">Yerel model triyajı: ${local.enabled ? "açık" : "kapalı"}.</p>`;
    // 26. tur: ajan başına otomatik uygulama eşiği (Claude 0,90 / Codex 0,99 varsayılan) ve uzlaşı modu
    const perAgent = auto.per_agent || {};
    const agentRows = Object.keys(perAgent).sort().map(key => {
      const entry = perAgent[key] || {};
      const on = entry.enabled !== false;
      const conf = Number(entry.min_confidence || 0.9).toFixed(2);
      return admin
        ? `<tr><td><code>${esc(key)}</code></td><td><label class="track-check"><input type="checkbox" name="agent-enabled" data-agent="${esc(key)}"${on ? " checked" : ""}> Açık</label></td><td><input type="number" name="agent-conf" data-agent="${esc(key)}" min="0.5" max="1" step="0.01" value="${conf}"></td></tr>`
        : `<tr><td><code>${esc(key)}</code></td><td>${on ? "Açık" : "Kapalı"}</td><td>${conf}</td></tr>`;
    }).join("");
    // Uzlaşı modu üç değerli: "auto" (varsayılan; projede ≥2 etkin ajan varsa) | true | false
    const consensusKey = auto.require_consensus === true ? "on" : auto.require_consensus === false ? "off" : "auto";
    const consensusLabels = { auto: "Otomatik (en az iki ajan varsa)", on: "Her zaman uzlaşı", off: "Tek ajan (ajan başına eşik)" };
    const consensusLabel = consensusLabels[consensusKey];
    const consensusConf = Number(auto.consensus_min_confidence || 0.7).toFixed(2);
    const consensusOptions = Object.entries(consensusLabels).map(([key, label]) =>
      `<option value="${key}"${key === consensusKey ? " selected" : ""}>${label}</option>`).join("");
    const agentTable = `<table class="track-table ai-agent-table"><thead><tr><th>Ajan</th><th>Durum</th><th>Eşik</th></tr></thead><tbody>${agentRows}</tbody></table>`;
    const agentBlock = admin ? `<form id="ai-agent-form" class="ai-local-form"><p><b>Ajan başına eşik</b></p>${agentTable}
        <label>Yeni ajan<input name="new-agent" maxlength="32" pattern="[a-z0-9_-]{1,32}" spellcheck="false"></label>
        <label>Eşik<input name="new-agent-conf" type="number" min="0.5" max="1" step="0.01" value="0.90"></label>
        <label>Uzlaşı modu<select name="require_consensus">${consensusOptions}</select></label>
        <label>Uzlaşı eşiği<input name="consensus_min_confidence" type="number" min="0.5" max="1" step="0.01" value="${consensusConf}"></label>
        <button type="submit" class="mini-button">Eşikleri kaydet</button></form>` :
      `<p><b>Ajan başına eşik</b></p>${agentTable}<p><b>Uzlaşı modu:</b> ${consensusLabel}</p><p><b>Uzlaşı eşiği:</b> ${consensusConf}</p>`;
    return `<section class="panel ai-triage-panel" id="ai-triage-panel">
      <div class="panel-head"><div><p class="eyebrow">AJAN DESTEKLİ</p><h2>AI triyaj önerileri</h2></div></div>
      <p class="muted">Claude Code, Codex gibi kodlama ajanları bulguları MCP sunucusu (<code>scripts/sniper-mcp</code>) ya da dosya paketiyle (<code>cli_reports.py triage export</code>) inceleyip öneri gönderir. Öneriler bulgu durumunu değiştirmez; kabul ettiğinizde bulgu takibine ve denetim kaydına "AI önerisiyle" notuyla yazılır. Bağlama: docs/AI-TRIYAJ.md.</p>
      <div class="ai-policy">
        <p><b>Dış ajana izin (bu proje):</b> <span class="track-chip ${allowed ? "status-open" : "status-fixed"}">${allowed ? "açık" : "kapalı"}</span>
        ${admin ? `<button type="button" class="mini-button" data-ai-consent="${allowed ? "off" : "on"}">${allowed ? "İzni kaldır" : "İzin ver"}</button>` : ""}</p>
        <p class="muted">Uyarı: dış ajan kullanıldığında kod parçaları ajanın model sağlayıcısına gönderilir; bu, Sniper'ın çevrimdışı ilkesinin dışındadır. İzin proje başınadır ve varsayılan kapalıdır.</p>
        <p><b>Otomatik uygulama:</b> ${auto.enabled ? `açık (güven ≥ ${Number(auto.min_confidence || 0.9).toFixed(2)} olan "muhtemelen yanlış alarm" önerileri yanlış alarm yapılır; geri alınabilir)` : "kapalı (her öneri analist kararı bekler)"}
        ${admin ? `<button type="button" class="mini-button" data-ai-auto="${auto.enabled ? "off" : "on"}">${auto.enabled ? "Kapat" : "Aç"}</button>` : ""}</p>
        ${agentBlock}
        ${localForm}
        ${local.enabled && state.role.analyst ? `<p><button type="button" class="mini-button" data-ai-batch="1">Önerisi olmayan açık bulguları yerel modelle triyajla (en çok 10)</button></p>` : ""}
      </div>
      <div class="button-row">${filters}</div>
      <div id="ai-suggestion-list"></div>
    </section>`;
  }

  // Öneri listesi: ajan metni textContent ile.
  function renderList(root) {
    const list = root.querySelector("#ai-suggestion-list");
    if (!list) return;
    list.textContent = "";
    const items = state.suggestions;
    if (!items.length) {
      const empty = document.createElement("p");
      empty.className = "muted";
      empty.textContent = state.filter === "pending" ? "Karar bekleyen öneri yok." : "Bu projede henüz öneri yok.";
      list.appendChild(empty);
      return;
    }
    const table = document.createElement("table");
    table.className = "track-table ai-table";
    table.innerHTML = "<thead><tr><th>Bulgu</th><th>AI önerisi</th><th>Gerekçe</th><th>Karar</th></tr></thead><tbody></tbody>";
    const body = table.querySelector("tbody");
    for (const item of items) {
      const row = document.createElement("tr");
      row.dataset.aiSuggestion = item.id;
      const finding = document.createElement("td");
      finding.textContent = item.finding_title || item.tracked_id;
      const where = document.createElement("small");
      where.textContent = ` ${item.finding_file || ""}${item.finding_line ? `:${Number(item.finding_line)}` : ""}`;
      finding.appendChild(document.createElement("br"));
      finding.appendChild(where);
      const verdict = document.createElement("td");
      verdict.textContent = `${VERDICT_LABELS[item.verdict] || item.verdict} (${Number(item.confidence || 0).toFixed(2)})`;
      const who = document.createElement("small");
      who.textContent = ` ${item.agent || item.source}${item.model ? ` / ${item.model}` : ""}`;
      verdict.appendChild(document.createElement("br"));
      verdict.appendChild(who);
      const why = document.createElement("td");
      why.textContent = item.rationale || "";
      if (item.fix_suggestion) {
        const fix = document.createElement("small");
        fix.className = "ai-fix";
        fix.textContent = `Düzeltme önerisi: ${item.fix_suggestion}`;
        why.appendChild(document.createElement("br"));
        why.appendChild(fix);
      }
      const decision = document.createElement("td");
      decision.textContent = DECISION_LABELS[item.decision] || item.decision;
      if (state.role.analyst) {
        const actions = [];
        if (item.decision === "pending") {
          if (item.verdict !== "uncertain") actions.push(["accept", "Kabul et"]);
          actions.push(["reject", "Reddet"]);
        } else if (item.decision === "accepted" || item.decision === "auto_applied") {
          actions.push(["revert", "Geri al"]);
        }
        for (const [action, label] of actions) {
          const button = document.createElement("button");
          button.type = "button";
          button.className = "mini-button";
          button.dataset.aiDecision = action;
          button.dataset.aiTracked = item.tracked_id;
          button.dataset.aiId = item.id;
          button.textContent = label;
          decision.appendChild(document.createElement("br"));
          decision.appendChild(button);
        }
      }
      row.append(finding, verdict, why, decision);
      body.appendChild(row);
    }
    list.appendChild(table);
  }

  async function load() {
    const view = document.querySelector("#tracking-view");
    const select = document.querySelector("#tracking-project");
    if (!view || !select) return;
    state.project = select.value || "";
    let root = document.querySelector("#ai-triage-panel");
    if (!state.project) { if (root) root.remove(); return; }
    try {
      const query = `project_path=${encodeURIComponent(state.project)}`;
      const [status, settings, list] = await Promise.all([
        request("/api/auth/status").catch(() => ({})),
        request(`/api/ai-triage/settings?${query}`),
        request(`/api/ai-triage/suggestions?${query}${state.filter === "pending" ? "&decision=pending" : ""}`),
      ]);
      state.role = roleFrom(status);
      state.settings = settings;
      state.suggestions = list.suggestions || [];
      globalThis.sniperAiLocalEnabled = Boolean(settings.local && settings.local.enabled) && state.role.analyst;
      const wrapper = document.createElement("div");
      wrapper.innerHTML = /* sniper-reviewed: html-safe (yalnız esc'li ayar alanları; ajan metni renderList'te textContent) */ cardHtml();
      const fresh = wrapper.firstElementChild;
      if (root) root.replaceWith(fresh); else view.appendChild(fresh);
      root = fresh;
      renderList(root);
    } catch (error) {
      notify(error.message, "error");
    }
  }

  async function act(fn, message) {
    try {
      await fn();
      if (message) notify(message, "success");
    } catch (error) {
      notify(error.message, "error");
    }
    // Karar bulgu durumunu değiştirmiş olabilir: takip tablosu ve panel birlikte yenilenir.
    if (originalLoad) await wrappedLoad(); else await load();
  }

  document.addEventListener("click", event => {
    const target = event.target instanceof Element ? event.target : null;
    if (!target) return;
    const filter = target.closest("[data-ai-filter]");
    if (filter) { state.filter = filter.dataset.aiFilter; load(); return; }
    const decision = target.closest("[data-ai-decision]");
    if (decision) {
      const { aiDecision, aiTracked, aiId } = decision.dataset;
      act(() => post(`/api/finding-tracking/${encodeURIComponent(aiTracked)}/ai/${encodeURIComponent(aiId)}/decision`, { decision: aiDecision }),
        aiDecision === "accept" ? "Öneri kabul edildi (AI önerisiyle)." : aiDecision === "reject" ? "Öneri reddedildi." : "Geri alındı.");
      return;
    }
    const consent = target.closest("[data-ai-consent]");
    if (consent) {
      const on = consent.dataset.aiConsent === "on";
      if (on && typeof globalThis.confirm === "function" && !globalThis.confirm("Dış ajana izin verirseniz bu projenin kod parçaları ajanın model sağlayıcısına gönderilebilir (çevrimdışı ilke dışı). Devam edilsin mi?")) return;
      act(() => post("/api/ai-triage/consent", { project_path: state.project, enabled: on }), on ? "Dış ajana izin verildi." : "Dış ajan izni kaldırıldı.");
      return;
    }
    const auto = target.closest("[data-ai-auto]");
    if (auto) {
      act(() => post("/api/ai-triage/auto-apply", { enabled: auto.dataset.aiAuto === "on" }), "Otomatik uygulama politikası kaydedildi.");
      return;
    }
    if (target.closest("[data-ai-local-test]")) {
      post("/api/ai-triage/local/test", {}).then(result => notify(result.ok ? `Bağlantı başarılı (${(result.models || []).length} model).` : `Bağlantı kurulamadı: ${result.error}`, result.ok ? "success" : "error"))
        .catch(error => notify(error.message, "error"));
      return;
    }
    const run = target.closest("[data-ai-run]");
    if (run) {
      run.disabled = true;
      act(() => post(`/api/finding-tracking/${encodeURIComponent(run.dataset.aiRun)}/ai/run`, {}), "Yerel model önerisi kaydedildi.");
      return;
    }
    if (target.closest("[data-ai-batch]")) {
      act(async () => {
        const list = await request(`/api/finding-tracking?project_path=${encodeURIComponent(state.project)}&status=open,in_progress,reopened`);
        const todo = (list.findings || []).filter(item => !item.ai).slice(0, 10);
        for (const item of todo) await post(`/api/finding-tracking/${encodeURIComponent(item.id)}/ai/run`, {}); // eşzamanlılık 1
      }, "Toplu yerel triyaj tamamlandı.");
    }
  });

  // Ajan başına eşik formu: per_agent + uzlaşı modu; genel anahtar (enabled) olduğu gibi gönderilir.
  function agentPayload(form) {
    const auto = (state.settings && state.settings.policy && state.settings.policy.auto_apply) || {};
    const perAgent = {};
    for (const input of form.querySelectorAll("[name=agent-conf]")) {
      const key = input.dataset.agent;
      const box = Array.from(form.querySelectorAll("[name=agent-enabled]")).find(item => item.dataset.agent === key);
      perAgent[key] = { enabled: box ? Boolean(box.checked) : true, min_confidence: Number(input.value) };
    }
    const extra = form.querySelector("[name=new-agent]");
    const name = extra ? String(extra.value || "").trim().toLowerCase() : "";
    if (name) perAgent[name] = { enabled: true, min_confidence: Number((form.querySelector("[name=new-agent-conf]") || {}).value || 0.9) };
    const consensus = form.querySelector("[name=require_consensus]");
    const mode = consensus ? String(consensus.value || "auto") : "auto";
    const payload = { enabled: Boolean(auto.enabled), per_agent: perAgent,
      require_consensus: mode === "on" ? true : mode === "off" ? false : "auto" };
    const consensusConf = form.querySelector("[name=consensus_min_confidence]");
    if (consensusConf && String(consensusConf.value || "") !== "") payload.consensus_min_confidence = Number(consensusConf.value);
    return payload;
  }

  document.addEventListener("submit", event => {
    const form = event.target;
    if (form instanceof Element && form.id === "ai-agent-form") {
      event.preventDefault();
      act(() => post("/api/ai-triage/auto-apply", agentPayload(form)), "Ajan eşikleri kaydedildi.");
      return;
    }
    if (!(form instanceof Element) || form.id !== "ai-local-form") return;
    event.preventDefault();
    const data = new FormData(form);
    const settings = {
      enabled: form.querySelector("[name=enabled]").checked,
      endpoint: String(data.get("endpoint") || ""),
      model: String(data.get("model") || ""),
      daily_budget: Number(data.get("daily_budget") || 0),
    };
    act(() => post("/api/ai-triage/local", { settings }), "Yerel model ayarları kaydedildi.");
  });

  document.addEventListener("change", event => {
    if (event.target instanceof Element && event.target.id === "tracking-project") setTimeout(load, 0);
  });

  // Bulgu takibi görünümü yüklendiğinde panel de yüklenir.
  let originalLoad = null;
  async function wrappedLoad() {
    if (originalLoad) await originalLoad();
    await load();
  }
  function hook() {
    if (typeof globalThis.sniperLoadTracking === "function" && globalThis.sniperLoadTracking !== wrappedLoad) {
      originalLoad = globalThis.sniperLoadTracking;
      globalThis.sniperLoadTracking = wrappedLoad;
    }
  }
  hook();
  if (typeof document.addEventListener === "function") document.addEventListener("DOMContentLoaded", hook);

  globalThis.sniperAiChip = chipHtml;
  const internals = { chipHtml, cardHtml, renderList, roleFrom, agentPayload, state, VERDICT_LABELS, DECISION_LABELS };
  globalThis.sniperAiTriageInternals = internals;
  if (typeof module !== "undefined") module.exports = internals;
})();
