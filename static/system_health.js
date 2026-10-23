// Sniper öz sağlık panosu (salt okunur): /api/system/health-report. Hiçbir şeyi silmez ya da düzeltmez;
// yalnız durum ve öneri gösterir. Pahalı denetimler sunucuda önbelleklidir; kart görünür olunca yüklenir.
(() => {
  const scope = typeof window !== "undefined" ? window : globalThis;
  const byId = id => (typeof document !== "undefined" ? document.getElementById(id) : null);
  const CLASS = { ok: "health-ok", info: "health-info", unknown: "health-unknown", warn: "health-warn", fail: "health-fail" };

  function el(tag, text, className) {
    const node = document.createElement(tag);
    if (text != null) node.textContent = String(text);
    if (className) node.className = className;
    return node;
  }

  function overallText(report) {
    const counts = report.counts || {};
    return `Genel durum: ${report.overall_label || report.overall} · ${Number(counts.fail || 0)} sorun · ${Number(counts.warn || 0)} uyarı`;
  }

  function render(report) {
    const overall = byId("system-health-overall");
    if (overall) {
      overall.textContent = overallText(report);
      overall.className = `system-health-overall ${CLASS[report.overall] || ""}`;
    }
    const body = byId("system-health-checks");
    if (!body) return;
    body.replaceChildren();
    for (const check of report.checks || []) {
      const row = el("tr", null, CLASS[check.status] || "");
      const advice = el("td");
      if (check.detail) advice.append(el("div", check.detail));
      if (check.recommendation) advice.append(el("strong", check.recommendation));
      row.append(el("td", check.label), el("td", check.status_label || check.status, "health-status"), el("td", check.value), advice);
      body.append(row);
    }
  }

  async function load(refresh = false) {
    const overall = byId("system-health-overall");
    if (!byId("system-health-checks")) return;
    if (overall) overall.textContent = "Denetleniyor…";
    try {
      const response = await fetch(`/api/system/health-report${refresh ? "?refresh=1" : ""}`, { headers: { Accept: "application/json" } });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || `Sağlık raporu alınamadı (${response.status})`);
      render(data);
    } catch (error) {
      if (overall) overall.textContent = error.message || "Sağlık raporu alınamadı";
    }
  }

  function start() {
    const panel = byId("system-health-panel");
    if (!panel) return;
    byId("system-health-refresh")?.addEventListener("click", () => load(true));
    if (typeof IntersectionObserver === "function") {
      const observer = new IntersectionObserver(entries => {
        if (entries.some(entry => entry.isIntersecting)) {
          observer.disconnect();
          load(false);
        }
      });
      observer.observe(panel);
    } else {
      load(false);
    }
  }

  scope.SniperSystemHealth = { render, load, overallText };
  if (typeof document !== "undefined") {
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start);
    else start();
  }
})();
