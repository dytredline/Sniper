// İlk açılış ön yüklemesi (17. tur W3-UI). auth.js'ten hemen sonra yüklenir; onun fetch sarmalayıcısını sarar.
// 1) /api/bootstrap tek istekle arayüzün açılışta istediği salt okunur GET'leri getirir (ui_assets.BOOTSTRAP_PATHS);
//    bu yollar için açılış penceresinde ağ yerine paketteki yanıt verilir.
// 2) Açılış penceresinde aynı adrese yinelenen GET'ler tek ağ isteğinde birleştirilir (yanıt klonlanır).
// Pencere: paket geldikten sonra kısa süre; GET dışı ilk istek (durum değişikliği) pencereyi hemen kapatır.
// Paket alınamazsa (eski sunucu, hata, zaman aşımı) her şey eskisi gibi ağdan istenir.
(function () {
  "use strict";
  const BOOT_PATHS = [
    "/api/scan-scope", "/api/dashboard", "/api/targets", "/api/scans?limit=200", "/api/engagements", "/api/lab-runs",
    "/api/project-audits", "/api/tooling", "/api/dependency-security", "/api/jobs",
    "/api/notifications?unread=1&limit=1", "/api/taint-rules", "/api/eval/latest", "/api/eval/history",
    "/api/eval/rule-false-positives", "/api/system/version",
  ];
  const WINDOW_MS = 3000;
  const TIMEOUT_MS = 6000;
  const baseFetch = window.fetch;
  if (typeof baseFetch !== "function") return;
  const bootSet = new Set(BOOT_PATHS);
  const shared = new Map();
  let active = true;
  let deadline = Infinity;

  function apiKey(input) {
    try {
      const url = new URL(typeof input === "string" ? input : input.url, location.href);
      if (url.origin !== location.origin || !url.pathname.startsWith("/api/") || url.hash) return null;
      return url.pathname + url.search;
    } catch (error) { return null; }
  }

  function stop() {
    active = false;
    shared.clear();
  }

  const controller = typeof AbortController === "function" ? new AbortController() : null;
  const timer = setTimeout(() => { if (controller) controller.abort(); }, TIMEOUT_MS);
  const bootPromise = baseFetch("/api/bootstrap", { credentials: "same-origin", signal: controller ? controller.signal : undefined })
    .then(response => (response.ok ? response.json() : null))
    .catch(() => null)
    .then(data => {
      clearTimeout(timer);
      const responses = data && data.format === 1 && data.responses && typeof data.responses === "object" ? data.responses : null;
      if (!responses) stop();
      else deadline = performance.now() + WINDOW_MS;
      return responses;
    });

  function cached(key, input, init) {
    return bootPromise.then(responses => {
      const entry = responses && responses[key];
      if (active && performance.now() <= deadline && entry && entry.status === 200 && "body" in entry) {
        return new Response(JSON.stringify(entry.body), { status: 200, headers: { "Content-Type": "application/json; charset=utf-8" } });
      }
      return baseFetch(input, init);
    });
  }

  window.fetch = function (input, init) {
    const method = String((init && init.method) || (input && typeof input === "object" && input.method) || "GET").toUpperCase();
    if (method !== "GET" && method !== "HEAD") {
      if (active) stop();
      return baseFetch(input, init);
    }
    if (!active || performance.now() > deadline || (init && (init.body || init.signal)) || method === "HEAD") {
      return baseFetch(input, init);
    }
    const key = apiKey(input);
    if (!key) return baseFetch(input, init);
    let promise = shared.get(key);
    if (!promise) {
      promise = bootSet.has(key) ? cached(key, input, init) : baseFetch(input, init);
      shared.set(key, promise);
      promise.catch(() => shared.delete(key));
    }
    return promise.then(response => response.clone());
  };
})();
