(function () {
  "use strict";

  const modalId = "schemathesis-junit-preview-modal";
  const route = "/api/tool-reports/schemathesis-junit/summary";
  const get = suffix => document.getElementById(`schemathesis-junit-${suffix}`);
  const form = get("preview-form");
  const paste = get("paste");
  const file = get("file");
  const error = get("preview-error");
  const result = get("preview-result");
  const copyButton = get("copy-sha256");
  const copyStatus = get("copy-status");
  const submit = form.querySelector('button[type="submit"]');
  const fields = ["suite-count", "testcase-count", "outcomes", "report-sha256"];
  let generation = 0;
  let busy = false;
  let activeDigest = "";
  let activeSyncEvent = null;
  let inFlightCopy = null;

  function resetCopyState() {
    activeDigest = "";
    if (copyButton) {
      if (!copyButton.textContent) copyButton.textContent = "SHA-256 kopyala";
      copyButton.disabled = true;
      copyButton.hidden = true;
      copyButton.classList.add("hidden");
    }
    if (copyStatus) {
      copyStatus.textContent = "";
      copyStatus.hidden = true;
      copyStatus.classList.add("hidden");
    }
  }

  function showCopyStatus(message) {
    if (!copyStatus) return;
    copyStatus.textContent = message;
    copyStatus.hidden = false;
    copyStatus.classList.remove("hidden");
  }

  function getClipboard() {
    return (
      (typeof navigator !== "undefined" && navigator?.clipboard) ||
      (typeof window !== "undefined" && window?.navigator?.clipboard) ||
      document?.defaultView?.navigator?.clipboard ||
      globalThis?.navigator?.clipboard ||
      globalThis?.clipboard ||
      null
    );
  }

  async function handleCopyClick(event) {
    if (event && activeSyncEvent === event) return inFlightCopy;
    activeSyncEvent = event || null;
    inFlightCopy = (async () => {
      event?.preventDefault?.();
      if (busy || !copyButton || copyButton.disabled || result.classList.contains("hidden")) return;
      const displayed = get("report-sha256")?.textContent || "";
      if (!activeDigest || displayed !== activeDigest || !/^[0-9a-f]{64}$/.test(displayed)) {
        showCopyStatus("Pano erişimi başarısız; SHA-256 kopyalanamadı.");
        return;
      }
      const current = generation;
      try {
        const clipboard = getClipboard();
        if (!clipboard || typeof clipboard.writeText !== "function") {
          throw new Error("clipboard");
        }
        await clipboard.writeText(displayed);
        if (generation === current && !busy && activeDigest === displayed && !result.classList.contains("hidden")) {
          showCopyStatus("SHA-256 panoya kopyalandı.");
        }
      } catch (_) {
        if (generation === current && !busy && activeDigest === displayed && !result.classList.contains("hidden")) {
          showCopyStatus("Pano erişimi başarısız; SHA-256 kopyalanamadı.");
        }
      }
    })();
    try {
      return await inFlightCopy;
    } finally {
      activeSyncEvent = null;
      inFlightCopy = null;
    }
  }

  function clear() {
    generation += 1;
    busy = false;
    submit.disabled = false;
    activeSyncEvent = null;
    inFlightCopy = null;
    paste.value = "";
    file.value = "";
    if (Array.isArray(file.files)) file.files = [];
    error.textContent = "";
    error.classList.add("hidden");
    result.classList.add("hidden");
    fields.forEach(name => { get(name).textContent = ""; });
    resetCopyState();
  }

  globalThis.clearSchemathesisJunitPreview = clear;
  if (typeof window !== "undefined") window.clearSchemathesisJunitPreview = clear;

  function reject(message) {
    result.classList.add("hidden");
    fields.forEach(name => { get(name).textContent = ""; });
    resetCopyState();
    error.textContent = message;
    error.classList.remove("hidden");
  }

  function validSummary(data) {
    if (!data || data.format !== "schemathesis-junit-xml") return false;
    const bounded = (value, limit) => Number.isSafeInteger(value) && value >= 0 && value <= limit;
    if (!bounded(data.suite_count, 20) || data.suite_count < 1 ||
        !bounded(data.testcase_count, 500)) return false;
    const counts = data.outcome_counts;
    const keys = ["passed", "failed", "errors", "skipped"];
    if (!counts || typeof counts !== "object" || Array.isArray(counts) ||
        Object.keys(counts).length !== keys.length ||
        !keys.every(key => bounded(counts[key], 500))) return false;
    if (keys.reduce((sum, key) => sum + counts[key], 0) !== data.testcase_count) return false;
    return typeof data.report_sha256 === "string" && /^[0-9a-f]{64}$/.test(data.report_sha256);
  }

  resetCopyState();

  document.addEventListener("click", event => {
    const opener = event.target?.closest?.('[data-action="open-schemathesis-junit-preview"]');
    if (opener) {
      event.preventDefault();
      clear();
      showModal(modalId, true);
      return;
    }
    const close = event.target?.closest?.(`[data-close="${modalId}"]`);
    if (close || event.target?.id === modalId) {
      event.preventDefault();
      clear();
      showModal(modalId, false);
      return;
    }
    const copyTrigger = event.target?.id === "schemathesis-junit-copy-sha256"
      ? event.target
      : event.target?.closest?.("#schemathesis-junit-copy-sha256");
    if (copyTrigger) {
      return handleCopyClick(event);
    }
  });

  document.addEventListener("submit", async event => {
    if (event.target?.id !== "schemathesis-junit-preview-form") return;
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
    resetCopyState();
    try {
      let raw = paste.value;
      if (!raw.trim() && file.files?.[0]) {
        if (file.files[0].size > 60000) throw new Error("large");
        raw = await file.files[0].text();
      }
      if (generation !== current) return;
      if (!raw.trim() || new TextEncoder().encode(raw).length > 60000) throw new Error("size");
      const payload = JSON.stringify({ report: raw });
      if (new TextEncoder().encode(payload).length > 65536) throw new Error("size");
      const data = await api(route, { method: "POST", body: payload });
      if (generation !== current) return;
      if (!validSummary(data)) throw new Error("response");
      busy = false;
      submit.disabled = false;
      get("suite-count").textContent = String(data.suite_count);
      get("testcase-count").textContent = String(data.testcase_count);
      get("outcomes").textContent = `geçti:${data.outcome_counts.passed} başarısız:${data.outcome_counts.failed} hata:${data.outcome_counts.errors} atlandı:${data.outcome_counts.skipped}`;
      get("report-sha256").textContent = data.report_sha256;
      activeDigest = data.report_sha256;
      if (copyButton) {
        if (!copyButton.textContent) copyButton.textContent = "SHA-256 kopyala";
        copyButton.disabled = false;
        copyButton.hidden = false;
        copyButton.classList.remove("hidden");
      }
      result.classList.remove("hidden");
      paste.value = "";
      file.value = "";
      if (Array.isArray(file.files)) file.files = [];
    } catch (_) {
      if (generation === current) reject("Geçersiz veya sınırı aşan JUnit XML raporu.");
    } finally {
      if (generation === current) {
        busy = false;
        submit.disabled = false;
      }
    }
  });
})();
