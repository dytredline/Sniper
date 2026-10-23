(function () {
  "use strict";

  const route = "/api/tool-runs/schemathesis-loopback";
  const readinessRoute = "/api/tooling/readiness";
  const modalId = "schemathesis-loopback-modal";
  const get = suffix => document.getElementById(`schemathesis-loopback-${suffix}`);
  const form = get("form");
  const portInput = get("port");
  const schemaInput = get("schema");
  const consent = get("consent");
  const availability = get("availability");
  const error = get("error");
  const result = get("result");
  const submit = form.querySelector('button[type="submit"]');
  const fields = ["request-count", "suite-count", "testcase-count", "outcomes", "report-sha256"];
  let generation = 0;
  let configured = false;
  let busy = false;

  function clearPrivate() {
    portInput.value = "";
    schemaInput.value = "";
    consent.checked = false;
  }

  function clear() {
    generation += 1;
    configured = false;
    busy = false;
    submit.disabled = true;
    clearPrivate();
    availability.textContent = "";
    error.textContent = "";
    error.classList.add("hidden");
    result.classList.add("hidden");
    fields.forEach(name => { get(name).textContent = ""; });
  }

  function reject(message = "Onaylı yerel API testi çalıştırılamadı. Girdi ve çalışma sınırlarını denetleyin.") {
    result.classList.add("hidden");
    fields.forEach(name => { get(name).textContent = ""; });
    error.textContent = message;
    error.classList.remove("hidden");
  }

  function readyProfile(payload) {
    const tools = payload && Array.isArray(payload.tools) ? payload.tools : [];
    const tool = tools.find(item => item && item.id === "schemathesis");
    const profiles = tool && Array.isArray(tool.profiles) ? tool.profiles : [];
    const profile = profiles.find(item => item && item.route === route);
    return !!(profile && profile.runtime === "precheck_passed" &&
      profile.action === "local_input_required");
  }

  function bounded(value, minimum, maximum) {
    return Number.isSafeInteger(value) && value >= minimum && value <= maximum;
  }

  function validSummary(data) {
    if (!data || data.status !== "completed" || data.scope !== "approved-loopback" ||
        data.format !== "schemathesis-junit-xml" ||
        !bounded(data.request_count, 1, 24) || !bounded(data.suite_count, 1, 20) ||
        !bounded(data.testcase_count, 0, 500)) return false;
    const counts = data.outcome_counts;
    const keys = ["passed", "failed", "errors", "skipped"];
    if (!counts || typeof counts !== "object" || Array.isArray(counts) ||
        Object.keys(counts).length !== keys.length ||
        !keys.every(key => bounded(counts[key], 0, 500))) return false;
    if (keys.reduce((sum, key) => sum + counts[key], 0) !== data.testcase_count) return false;
    return typeof data.report_sha256 === "string" && /^[0-9a-f]{64}$/.test(data.report_sha256);
  }

  document.addEventListener("click", async event => {
    const opener = event.target.closest?.('[data-action="open-schemathesis-loopback"]');
    if (opener) {
      event.preventDefault();
      clear();
      showModal(modalId, true);
      const current = generation;
      availability.textContent = "Operatör izin listesi ve çalışma zamanı denetleniyor…";
      try {
        const payload = await api(readinessRoute);
        if (generation !== current) return;
        configured = readyProfile(payload);
        availability.textContent = configured
          ? "Yerel ön koşullar bulundu. Yalnız operatörün izin verdiği 127.0.0.1 portu kullanılabilir."
          : "Bu profil kullanılamıyor: operatör izin listesi veya sabitlenmiş çalışma zamanı hazır değil.";
        submit.disabled = !configured;
      } catch (_) {
        if (generation !== current) return;
        availability.textContent = "Yapılandırma doğrulanamadı; yerel test kullanılamıyor.";
        submit.disabled = true;
      }
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
    if (event.target.id !== "schemathesis-loopback-form") return;
    event.preventDefault();
    if (busy) return;
    if (!configured) { reject("Bu profil yapılandırılmamış veya kullanılamıyor."); return; }
    if (!consent.checked) { reject("Yerel API testini açıkça onaylayın."); return; }
    const current = generation;
    busy = true;
    submit.disabled = true;
    error.textContent = "";
    error.classList.add("hidden");
    result.classList.add("hidden");
    fields.forEach(name => { get(name).textContent = ""; });
    try {
      const port = portInput.value.trim();
      if (!/^[1-9][0-9]{0,4}$/.test(port) || Number(port) > 65535) throw new Error("port");
      const raw = schemaInput.value;
      if (!raw.trim() || new TextEncoder().encode(raw).length > 32768) throw new Error("schema");
      const schema = JSON.parse(raw);
      if (!schema || typeof schema !== "object" || Array.isArray(schema)) throw new Error("schema");
      const body = JSON.stringify({ confirm_local: true, target_url: `http://127.0.0.1:${port}`, schema });
      if (new TextEncoder().encode(body).length > 65536) throw new Error("size");
      const data = await api(route, { method: "POST", headers: { "Content-Type": "application/json" }, body });
      if (generation !== current) return;
      if (!validSummary(data)) throw new Error("response");
      get("request-count").textContent = String(data.request_count);
      get("suite-count").textContent = String(data.suite_count);
      get("testcase-count").textContent = String(data.testcase_count);
      get("outcomes").textContent = `geçti:${data.outcome_counts.passed} başarısız:${data.outcome_counts.failed} hata:${data.outcome_counts.errors} atlandı:${data.outcome_counts.skipped}`;
      get("report-sha256").textContent = data.report_sha256;
      result.classList.remove("hidden");
      clearPrivate();
    } catch (_) {
      if (generation === current) reject();
    } finally {
      if (generation === current) {
        busy = false;
        submit.disabled = !configured;
      }
    }
  });
})();
