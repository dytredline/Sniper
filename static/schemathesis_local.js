(function () {
  "use strict";

  const modalId = "schemathesis-local-modal";
  const route = "/api/tool-runs/schemathesis-local";
  const readinessRoute = "/api/tooling/readiness";
  const openers = document.querySelectorAll('[data-action="open-schemathesis-local"]');
  const get = suffix => document.getElementById(`schemathesis-local-${suffix}`);
  const form = get("form");
  const schemaInput = get("schema");
  const consent = get("consent");
  const error = get("error");
  const result = get("result");
  const submit = form.querySelector('button[type="submit"]');
  const fields = ["suite-count", "testcase-count", "outcomes", "report-sha256"];
  let generation = 0;
  let configured = false;
  let busy = false;

  function setConfigured(ready) {
    configured = ready;
    openers.forEach(opener => {
      opener.disabled = !ready;
      opener.title = ready ? "" : "Sentetik yerel testin çalışma zamanı hazır değil.";
    });
    if (!busy) submit.disabled = !ready;
  }

  function readyProfile(payload) {
    const tools = payload && Array.isArray(payload.tools) ? payload.tools : [];
    const tool = tools.find(item => item && item.id === "schemathesis");
    const profiles = tool && Array.isArray(tool.profiles) ? tool.profiles : [];
    const profile = profiles.find(item => item && item.route === route);
    return !!(profile && profile.runtime === "precheck_passed" &&
      profile.action === "local_input_required");
  }

  async function loadReadiness() {
    setConfigured(false);
    try {
      setConfigured(readyProfile(await api(readinessRoute)));
    } catch (_) {
      setConfigured(false);
    }
  }
  void loadReadiness();

  function clear() {
    generation += 1;
    busy = false;
    submit.disabled = !configured;
    schemaInput.value = "";
    consent.checked = false;
    error.textContent = "";
    error.classList.add("hidden");
    result.classList.add("hidden");
    fields.forEach(name => { get(name).textContent = ""; });
  }

  function reject(unavailable = false) {
    result.classList.add("hidden");
    fields.forEach(name => { get(name).textContent = ""; });
    error.textContent = unavailable
      ? "Sentetik yerel test şu anda kullanılamıyor veya meşgul. Sunucu yapılandırmasını ve çalışma durumunu denetleyip yeniden deneyin."
      : "Yerel sentetik test çalıştırılamadı. Girdi, kurulum veya sınırları denetleyin.";
    error.classList.remove("hidden");
  }

  function validSummary(data) {
    if (!data || data.status !== "completed" || data.scope !== "synthetic-fixture-only" ||
        data.format !== "schemathesis-junit-xml") return false;
    const bounded = (value, max) => Number.isSafeInteger(value) && value >= 0 && value <= max;
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

  document.addEventListener("click", event => {
    const opener = event.target.closest?.('[data-action="open-schemathesis-local"]');
    if (opener) {
      event.preventDefault();
      if (!configured || opener.disabled) return;
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
    if (event.target.id !== "schemathesis-local-form") return;
    event.preventDefault();
    if (busy) return;
    if (!configured) { reject(); return; }
    if (!consent.checked) { reject(); return; }
    const current = generation;
    busy = true;
    submit.disabled = true;
    error.textContent = "";
    error.classList.add("hidden");
    result.classList.add("hidden");
    try {
      const raw = schemaInput.value;
      if (!raw.trim() || new TextEncoder().encode(raw).length > 64000) throw new Error("schema");
      const schema = JSON.parse(raw);
      if (!schema || typeof schema !== "object" || Array.isArray(schema)) throw new Error("schema");
      const body = JSON.stringify({ confirm_local: true, schema });
      if (new TextEncoder().encode(body).length > 65536) throw new Error("size");
      const data = await api(route, { method: "POST", body });
      if (generation !== current) return;
      if (!validSummary(data)) throw new Error("response");
      get("suite-count").textContent = String(data.suite_count);
      get("testcase-count").textContent = String(data.testcase_count);
      get("outcomes").textContent = `geçti:${data.outcome_counts.passed} başarısız:${data.outcome_counts.failed} hata:${data.outcome_counts.errors} atlandı:${data.outcome_counts.skipped}`;
      get("report-sha256").textContent = data.report_sha256;
      result.classList.remove("hidden");
      schemaInput.value = "";
      consent.checked = false;
    } catch (cause) {
      if (generation === current) reject(cause?.status === 503);
    } finally {
      if (generation === current) {
        busy = false;
        submit.disabled = !configured;
      }
    }
  });
})();
