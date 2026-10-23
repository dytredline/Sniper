(function () {
  "use strict";
  const modalId = "playwright-json-preview-modal";
  const route = "/api/tool-reports/playwright-json/summary";
  const get = suffix => document.getElementById(`playwright-json-${suffix}`);
  const form = get("preview-form"), paste = get("paste"), file = get("file");
  const error = get("preview-error"), result = get("preview-result");
  const submit = form.querySelector(`button[type="submit"]`);
  const fields = ["file-count", "test-count", "outcomes", "report-sha256"];
  let generation = 0, busy = false;
  function clear() {
    generation += 1; busy = false; submit.disabled = false;
    paste.value = ""; file.value = ""; error.textContent = "";
    error.classList.add("hidden"); result.classList.add("hidden");
    fields.forEach(name => { get(name).textContent = ""; });
  }
  function invalidateForInputEdit() {
    generation += 1; busy = false; submit.disabled = false;
    error.textContent = ""; error.classList.add("hidden");
    result.classList.add("hidden");
    fields.forEach(name => { get(name).textContent = ""; });
  }
  function reject() {
    result.classList.add("hidden");
    fields.forEach(name => { get(name).textContent = ""; });
    error.textContent = "Geçersiz veya sınırı aşan Playwright JSON raporu.";
    error.classList.remove("hidden");
  }
  function validSummary(data) {
    const bounded = value => Number.isSafeInteger(value) && value >= 0 && value <= 1000;
    if (!data || data.format !== "playwright-json" || !bounded(data.file_count) ||
        data.file_count < 1 || data.file_count > 50 || !bounded(data.test_count) ||
        data.test_count < 1) return false;
    const counts = data.outcome_counts, keys = ["expected", "skipped", "unexpected", "flaky"];
    if (!counts || typeof counts !== "object" || Array.isArray(counts) ||
        Object.keys(counts).length !== keys.length || !keys.every(key => bounded(counts[key]))) return false;
    return keys.reduce((sum, key) => sum + counts[key], 0) === data.test_count &&
      typeof data.report_sha256 === "string" && /^[0-9a-f]{64}$/.test(data.report_sha256);
  }
  document.addEventListener("click", event => {
    const opener = event.target.closest?.(`[data-action="open-playwright-json-preview"]`);
    if (opener) { event.preventDefault(); clear(); showModal(modalId, true); return; }
    const close = event.target.closest?.(`[data-close="${modalId}"]`);
    if (close || event.target.id === modalId) {
      event.preventDefault(); clear(); showModal(modalId, false);
    }
  });
  // The shared modal close path emits this before hiding the dialog, including Escape.
  document.getElementById(modalId).addEventListener("sniper:playwright-json-preview-close", clear);
  for (const eventName of ["input", "change"]) {
    document.addEventListener(eventName, event => {
      if (event.target === paste || event.target === file) invalidateForInputEdit();
    });
  }
  document.addEventListener("submit", async event => {
    if (event.target.id !== "playwright-json-preview-form") return;
    event.preventDefault(); if (busy) return;
    const current = generation;
    const submittedPaste = paste.value, submittedFile = file.files?.[0] || null;
    const isCurrent = () => generation === current && paste.value === submittedPaste &&
      (file.files?.[0] || null) === submittedFile;
    busy = true; submit.disabled = true;
    error.textContent = ""; error.classList.add("hidden"); result.classList.add("hidden");
    try {
      let raw = paste.value;
      if (!raw.trim() && file.files?.[0]) {
        if (file.files[0].size > 60000) throw new Error("size");
        raw = await file.files[0].text();
      }
      if (!isCurrent()) return;
      if (!raw.trim() || new TextEncoder().encode(raw).length > 60000) throw new Error("size");
      const report = JSON.parse(raw);
      if (!report || typeof report !== "object" || Array.isArray(report)) throw new Error("shape");
      const body = JSON.stringify({ report });
      if (new TextEncoder().encode(body).length > 65536) throw new Error("size");
      const data = await api(route, { method: "POST", body });
      if (!isCurrent()) return;
      if (!validSummary(data)) throw new Error("response");
      get("file-count").textContent = String(data.file_count);
      get("test-count").textContent = String(data.test_count);
      get("outcomes").textContent = `beklenen:${data.outcome_counts.expected} atlandı:${data.outcome_counts.skipped} beklenmeyen:${data.outcome_counts.unexpected} kararsız:${data.outcome_counts.flaky}`;
      get("report-sha256").textContent = data.report_sha256;
      result.classList.remove("hidden"); paste.value = ""; file.value = "";
    } catch (_) {
      if (isCurrent()) reject();
    } finally {
      if (generation === current) { busy = false; submit.disabled = false; }
    }
  });
})();
