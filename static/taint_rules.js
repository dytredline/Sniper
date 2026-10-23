// Araç Matrisi > Özel taint kuralları: işletmeci tanımlı kaynak/hedef/arındırıcı kuralları
// (YAML/JSON). Listeleme, kaydetme (açık onay), silme, örnek koda karşı deneme, Opengrep dışa aktarma.
// Yalnız DOM API ve textContent kullanır.
(() => {
  const scope = typeof window !== "undefined" ? window : globalThis;
  const byId = id => (typeof document !== "undefined" ? document.getElementById(id) : null);

  async function call(path, body) {
    const options = body === undefined ? {} : { method: "POST", body: JSON.stringify(body) };
    if (typeof scope.api === "function") return scope.api(path, options);
    const response = await scope.fetch(path, { ...options, headers: body === undefined ? undefined : { "Content-Type": "application/json" }, credentials: "same-origin" });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(typeof data.error === "string" ? data.error : `İstek ${response.status} durum koduyla başarısız oldu.`);
    return data;
  }

  function el(tag, text, className) {
    const node = document.createElement(tag);
    if (text !== undefined && text !== null) node.textContent = String(text);
    if (className) node.className = className;
    return node;
  }

  function message(text, isError = false) {
    const target = byId("taint-rules-message");
    if (!target) return;
    target.textContent = text;
    target.className = isError ? "error-message" : "muted";
  }

  function renderStatus(data) {
    const body = byId("taint-rules-body");
    const state = byId("taint-rules-state");
    if (state) state.textContent = data.available === false ? (data.message || "Özel kurallar kullanılamıyor.") : (data.activation || "");
    if (!body) return;
    body.replaceChildren();
    for (const rule of data.rules || []) {
      const row = document.createElement("tr");
      row.append(el("td", rule.name), el("td", rule.language), el("td", (rule.sink_kinds || []).join(", ") || "—"),
        el("td", Object.entries(rule.counts || {}).map(([k, v]) => `${k}: ${v}`).join(" · ")), el("td", rule.stored_at || ""));
      const cell = el("td");
      const button = el("button", "Sil", "button secondary");
      button.type = "button";
      button.addEventListener("click", () => remove(rule.name));
      cell.append(button);
      row.append(cell);
      body.append(row);
    }
    const empty = byId("taint-rules-empty");
    if (empty) empty.classList.toggle("hidden", (data.rules || []).length > 0);
  }

  async function refresh() {
    try {
      const data = await call("/api/taint-rules");
      renderStatus(data);
      return data;
    } catch (error) {
      message(`Kurallar alınamadı: ${error.message}`, true);
      return null;
    }
  }

  async function save() {
    const content = byId("taint-rules-content")?.value || "";
    if (!byId("taint-rules-confirm")?.checked) {
      message("Kaydetmek için onay kutusunu işaretleyin.", true);
      return null;
    }
    try {
      const saved = await call("/api/taint-rules", { content, confirm_custom_rules: true });
      message(`Kural kaydedildi: ${saved.name} (${saved.language}).`);
      await refresh();
      return saved;
    } catch (error) {
      message(`Kural kaydedilemedi: ${error.message}`, true);
      return null;
    }
  }

  async function remove(name) {
    if (!byId("taint-rules-confirm")?.checked) {
      message("Silmek için onay kutusunu işaretleyin.", true);
      return null;
    }
    try {
      await call(`/api/taint-rules/${encodeURIComponent(name)}/delete`, { confirm_custom_rules: true });
      message(`Kural silindi: ${name}.`);
      return refresh();
    } catch (error) {
      message(`Kural silinemedi: ${error.message}`, true);
      return null;
    }
  }

  function renderTrial(data) {
    const out = byId("taint-rules-trial");
    if (!out) return;
    out.replaceChildren();
    const fresh = data.new_flows || [];
    out.append(el("p", `Kuralla eklenen akış: ${fresh.length} · kaldırılan: ${(data.removed_flows || []).length} · toplam: ${(data.flows || []).length}`, "autofix-head"));
    if (data.note) out.append(el("p", data.note, "muted"));
    const list = el("ul");
    for (const flow of fresh) {
      list.append(el("li", `${flow.source} (satır ${flow.source_line}) → ${flow.sink} [${flow.sink_kind}] (satır ${flow.sink_line})`));
    }
    out.append(list);
    out.classList.remove("hidden");
  }

  async function tryRule() {
    const content = byId("taint-rules-content")?.value || "";
    const code = byId("taint-rules-code")?.value || "";
    const filename = byId("taint-rules-filename")?.value || "";
    try {
      const data = await call("/api/taint-rules/try", { content, code, filename });
      renderTrial(data);
      message("Deneme tamamlandı (kural kaydedilmedi).");
      return data;
    } catch (error) {
      message(`Deneme başarısız: ${error.message}`, true);
      return null;
    }
  }

  function init() {
    const panel = byId("taint-rules-panel");
    if (!panel || panel.dataset.ready === "1") return;
    panel.dataset.ready = "1";
    byId("taint-rules-save")?.addEventListener("click", save);
    byId("taint-rules-try")?.addEventListener("click", tryRule);
    byId("taint-rules-refresh")?.addEventListener("click", refresh);
    refresh();
  }

  scope.SniperTaintRules = Object.freeze({ refresh, save, remove, tryRule, renderStatus, renderTrial, init });
  if (typeof document !== "undefined" && document.readyState !== "loading") init();
  else if (typeof document !== "undefined") document.addEventListener("DOMContentLoaded", init);
})();
