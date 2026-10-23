(function () {
  "use strict";

  const modalId = "siem-ecs-preview-modal";
  const route = "/api/tool-reports/siem-ecs-ndjson/summary";
  const kinds = ["alert", "asset", "enrichment", "event", "metric", "state", "pipeline_error", "signal"];
  const get = suffix => document.getElementById(`siem-ecs-${suffix}`);
  const form = get("preview-form");
  const paste = get("paste");
  const file = get("file");
  const error = get("preview-error");
  const result = get("preview-result");
  const submit = form.querySelector('button[type="submit"]');
  const fields = ["record-count", "kind-counts", "report-sha256"];
  let generation = 0;
  let busy = false;

  function clear() {
    generation += 1;
    busy = false;
    submit.disabled = false;
    paste.value = "";
    file.value = "";
    if (Array.isArray(file.files)) file.files = [];
    error.textContent = "";
    error.classList.add("hidden");
    result.classList.add("hidden");
    fields.forEach(name => { get(name).textContent = ""; });
  }

  globalThis.clearSiemEcsPreview = clear;
  if (typeof window !== "undefined") window.clearSiemEcsPreview = clear;

  function reject() {
    result.classList.add("hidden");
    fields.forEach(name => { get(name).textContent = ""; });
    error.textContent = "Geçersiz veya sınırı aşan ECS JSONL kanıtı.";
    error.classList.remove("hidden");
  }

  function validSummary(data) {
    if (!data || typeof data !== "object" || Array.isArray(data) ||
        Object.keys(data).length !== 4 || data.format !== "ecs-ndjson" ||
        !Number.isSafeInteger(data.record_count) || data.record_count < 1 || data.record_count > 500) return false;
    const counts = data.kind_counts;
    if (!counts || typeof counts !== "object" || Array.isArray(counts) ||
        Object.keys(counts).length !== kinds.length ||
        !kinds.every(kind => Number.isSafeInteger(counts[kind]) && counts[kind] >= 0 && counts[kind] <= 500)) return false;
    if (kinds.reduce((sum, kind) => sum + counts[kind], 0) !== data.record_count) return false;
    return typeof data.report_sha256 === "string" && /^[0-9a-f]{64}$/.test(data.report_sha256);
  }

  document.addEventListener("click", event => {
    const opener = event.target.closest?.('[data-action="open-siem-ecs-preview"]');
    if (opener) {
      event.preventDefault();
      clear();
      showModal(modalId, true);
      return;
    }
    const close = event.target.closest?.(`[data-close="${modalId}"]`);
    if (close || event.target.id === modalId) {
      event.preventDefault();
      clear();
      showModal(modalId, false);
    }
  });

  document.addEventListener("submit", async event => {
    if (event.target.id !== "siem-ecs-preview-form") return;
    event.preventDefault();
    if (busy) return;
    generation += 1;
    const current = generation;
    busy = true;
    submit.disabled = true;
    error.textContent = "";
    error.classList.add("hidden");
    result.classList.add("hidden");
    fields.forEach(name => { get(name).textContent = ""; });
    try {
      let raw = paste.value;
      if (!raw.trim() && file.files?.[0]) {
        if (file.files[0].size > 60000) throw new Error("size");
        raw = await file.files[0].text();
      }
      if (generation !== current) return;
      if (!raw.trim() || new TextEncoder().encode(raw).length > 60000) throw new Error("size");
      const payload = JSON.stringify({ report: raw });
      if (new TextEncoder().encode(payload).length > 65536) throw new Error("size");
      const data = await api(route, { method: "POST", body: payload });
      if (generation !== current) return;
      if (!validSummary(data)) throw new Error("response");
      get("record-count").textContent = String(data.record_count);
      get("kind-counts").textContent = kinds.map(kind => `${kind}:${data.kind_counts[kind]}`).join(" ");
      get("report-sha256").textContent = data.report_sha256;
      result.classList.remove("hidden");
      paste.value = "";
      file.value = "";
      if (Array.isArray(file.files)) file.files = [];
    } catch (_) {
      if (generation === current) reject();
    } finally {
      if (generation === current) {
        busy = false;
        submit.disabled = false;
      }
    }
  });
})();
