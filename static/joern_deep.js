// Joern derin analiz paneli (C/C++, Java, Kotlin, PHP, Go, Ruby, C#; isteğe bağlı JS/TS ve Python): proje yolu + onay
// (+ JS/TS-Python seçeneği ve süre bütçesi) → iş kuyruğunda POST /api/tool-runs/joern-deep; bulgular yalnız textContent
// ile, SARIF indirilebilir. Süre/bellek sınırında kısmi sonuç uyarısı gösterilir.
(() => {
  const scope = typeof window !== "undefined" ? window : globalThis;
  const ROUTE = "/api/tool-runs/joern-deep";
  const SEVERITY = Object.freeze({ critical: "KRİTİK", high: "YÜKSEK", medium: "ORTA", low: "DÜŞÜK", info: "BİLGİ" });
  let lastSarif = null;

  const byId = id => (typeof document !== "undefined" ? document.getElementById(id) : null);

  function cell(row, text) {
    const td = document.createElement("td");
    td.textContent = text == null ? "" : String(text);
    row.append(td);
  }

  function renderResult(result) {
    const summary = byId("joern-deep-summary");
    const body = byId("joern-deep-body");
    const download = byId("joern-deep-sarif");
    if (summary) {
      const languages = Object.entries(result.languages || {}).map(([lang, count]) => `${lang}: ${count} dosya`).join(", ");
      const fast = result.fast_engine ? ` · hızlı motorla eşleşen: ${result.fast_engine.matched_findings ?? 0}, yalnız Joern: ${result.fast_engine.joern_only_findings ?? 0}` : "";
      const hybrid = result.scripting_fast_engine && result.scripting_fast_engine.available !== false
        ? ` · JS/Python: proje analizinde de var ${result.scripting_fast_engine.matched ?? 0}, olasıyı doğrulayan ${result.scripting_fast_engine.confirmed_uncertain ?? 0}, çelişen ${result.scripting_fast_engine.conflicting ?? 0}, yalnız Joern ${result.scripting_fast_engine.joern_only ?? 0}`
        : "";
      const partial = result.partial ? " · KISMİ SONUÇ" : "";
      summary.textContent = `Bulgu: ${result.finding_count ?? 0}${result.findings_truncated ? " (kırpıldı)" : ""} · ${languages} · ${result.duration_seconds ?? "?"} sn · Joern ${result.engine?.version || ""}${fast}${hybrid}${partial}`;
    }
    const warnings = byId("joern-deep-warnings");
    if (warnings) {
      const list = Array.isArray(result.warnings) ? result.warnings.map(String) : [];
      warnings.textContent = list.join(" ");
      if (list.length) warnings.classList?.remove("hidden");
      else warnings.classList?.add("hidden");
    }
    if (body) {
      body.replaceChildren();
      for (const finding of Array.isArray(result.findings) ? result.findings : []) {
        const row = document.createElement("tr");
        cell(row, SEVERITY[finding.severity] || finding.severity);
        cell(row, finding.title);
        cell(row, `${finding.file}:${finding.line}`);
        cell(row, finding.fast_engine_match ? `${finding.evidence} [Proje analizinde de doğrulandı (hızlı motor)]`
          : finding.joern_only ? `${finding.evidence} [Yalnız Joern]` : finding.evidence);
        body.append(row);
      }
    }
    lastSarif = result.sarif || null;
    if (download) download.disabled = !lastSarif;
  }

  function downloadSarif() {
    if (!lastSarif || typeof Blob === "undefined" || typeof document === "undefined") return false;
    const blob = new Blob([JSON.stringify(lastSarif, null, 2)], { type: "application/sarif+json" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "sniper-joern.sarif";
    link.click();
    setTimeout(() => URL.revokeObjectURL(link.href), 1000);
    return true;
  }

  async function submit() {
    const pathInput = byId("joern-deep-path");
    const confirm = byId("joern-deep-confirm");
    const status = byId("joern-deep-status");
    const error = byId("joern-deep-error");
    if (error) { error.textContent = ""; error.classList?.add("hidden"); }
    const projectPath = (pathInput?.value || "").trim();
    try {
      if (!projectPath) throw new Error("Proje klasörü yolu girin.");
      if (!confirm?.checked) throw new Error("Yerel analiz onayını işaretleyin.");
      if (!scope.SniperJobs) throw new Error("İş kuyruğu istemcisi yüklenmedi.");
      const payload = { confirm_local: true, project_path: projectPath };
      if (byId("joern-deep-scripting")?.checked) payload.include_scripting = true;
      const budgetText = String(byId("joern-deep-budget")?.value ?? "").trim();
      if (budgetText) {
        const minutes = Number(budgetText);
        if (!Number.isInteger(minutes) || minutes < 1 || minutes > 60) throw new Error("Süre bütçesi 1–60 dakika arasında bir tam sayı olmalı.");
        payload.time_budget_seconds = minutes * 60;
      }
      const job = await scope.SniperJobs.run(ROUTE, payload, status);
      scope.SniperJobsPanel?.refresh?.();
      if (job.state !== "succeeded") throw new Error(job.error || scope.SniperJobs.stateLabel(job.state));
      renderResult(job.result || {});
      return job.result;
    } catch (failure) {
      if (error) { error.textContent = failure.message; error.classList?.remove("hidden"); }
      return null;
    }
  }

  function init() {
    const form = byId("joern-deep-form");
    if (!form || form.dataset.ready === "1") return;
    form.dataset.ready = "1";
    form.addEventListener("submit", event => { event.preventDefault(); submit(); });
    byId("joern-deep-sarif")?.addEventListener("click", downloadSarif);
  }

  scope.SniperJoernDeep = Object.freeze({ ROUTE, submit, renderResult, downloadSarif, init });
  if (typeof document !== "undefined" && document.readyState !== "loading") init();
  else if (typeof document !== "undefined") document.addEventListener("DOMContentLoaded", init);
})();
