// Araç Matrisi > İşler: arka plan iş kuyruğundaki işleri listeler ve iptal ettirir.
// Yalnız DOM API ve textContent kullanır (HTML enjeksiyonu yok).
(() => {
  const scope = typeof window !== "undefined" ? window : globalThis;
  const REFRESH_MS = 5000;
  let timer = null;

  const byId = id => (typeof document !== "undefined" ? document.getElementById(id) : null);

  function cell(row, text) {
    const td = document.createElement("td");
    td.textContent = text == null ? "" : String(text);
    row.append(td);
    return td;
  }

  function render(jobs) {
    const body = byId("jobs-panel-body");
    const empty = byId("jobs-panel-empty");
    if (!body) return;
    body.replaceChildren();
    if (empty) empty.classList.toggle("hidden", jobs.length > 0);
    for (const job of jobs) {
      const row = document.createElement("tr");
      cell(row, job.id);
      cell(row, job.route);
      cell(row, scope.SniperJobs ? scope.SniperJobs.stateLabel(job.state) : job.state);
      cell(row, job.created_at || "");
      cell(row, job.http_status || job.error || "");
      const action = cell(row, "");
      if (job.state === "queued" || job.state === "running") {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "button secondary";
        button.textContent = job.cancel_requested ? "İptal istendi" : "İptal et";
        button.disabled = Boolean(job.cancel_requested);
        button.addEventListener("click", async () => {
          button.disabled = true;
          try { await scope.SniperJobs.cancel(job.id); } catch (_error) { /* liste yenilenince görünür */ }
          refresh();
        });
        action.append(button);
      }
      body.append(row);
    }
  }

  async function refresh() {
    if (!scope.SniperJobs) return [];
    const error = byId("jobs-panel-error");
    try {
      const jobs = await scope.SniperJobs.list();
      if (error) { error.textContent = ""; error.classList.add("hidden"); }
      render(jobs);
      return jobs;
    } catch (failure) {
      if (error) { error.textContent = `İş listesi alınamadı: ${failure.message}`; error.classList.remove("hidden"); }
      return [];
    }
  }

  function init() {
    const panel = byId("jobs-panel");
    if (!panel || panel.dataset.ready === "1") return;
    panel.dataset.ready = "1";
    byId("jobs-panel-refresh")?.addEventListener("click", refresh);
    refresh();
    timer = scope.setInterval(() => {
      if (typeof document === "undefined" || document.visibilityState !== "hidden") refresh();
    }, REFRESH_MS);
  }

  scope.SniperJobsPanel = Object.freeze({ refresh, render, init, stop: () => scope.clearInterval(timer) });
  if (typeof document !== "undefined" && document.readyState !== "loading") init();
  else if (typeof document !== "undefined") document.addEventListener("DOMContentLoaded", init);
})();
