// Proje analizini arka plan iş kuyruğunda çalıştırır: ilerleme (aşama + yüzde), iptal, sayfa yenilense/kapansa da
// sürer (iş kimliği tarayıcıda saklanır, sayfa açılınca izlemeye devam edilir). Sonuç eşzamanlı API ile aynı
// kayıtlı analiz nesnesidir. Ayrıca analiz ayrıntısına monorepo alt proje özetini ekler.
// Yalnız DOM API ve textContent kullanılır.
// Kullanım: await window.SniperProjectJobs.start(body, form) → kayıtlı analiz (id, project_name …)
(() => {
  const scope = typeof window !== "undefined" ? window : globalThis;
  const ROUTE = "/api/project-audits";
  const STORAGE_KEY = "sniper.projectJob";
  const BOX_ID = "project-job-status";  // dinamik oluşturulur (index.html'de yok)
  const FINAL = new Set(["succeeded", "failed", "cancelled", "expired", "interrupted"]);
  const POLL_MS = 1000;
  const MAX_POLL_MS = 5000;
  const MAX_POLLS = 20000;
  const STATE_TEXT = Object.freeze({
    queued: "Sırada bekliyor",
    running: "Çalışıyor",
    succeeded: "Tamamlandı",
    failed: "Başarısız",
    cancelled: "İptal edildi",
    expired: "Süre sınırı aşıldı",
    interrupted: "Yeniden başlatmada yarıda kaldı",
  });
  const wait = ms => new Promise(resolve => scope.setTimeout(resolve, ms));

  function remember(jobId) {
    try {
      if (jobId) scope.localStorage.setItem(STORAGE_KEY, jobId);
      else scope.localStorage.removeItem(STORAGE_KEY);
    } catch (_error) { /* tarayıcı depolaması kapalı: izleme yalnız bu sayfada sürer */ }
  }

  function remembered() {
    try {
      const value = scope.localStorage.getItem(STORAGE_KEY);
      return typeof value === "string" && /^job_[0-9a-f]{24}$/.test(value) ? value : null;
    } catch (_error) {
      return null;
    }
  }

  async function request(path, options = {}) {
    const response = await scope.fetch(path, {
      method: options.method || "GET",
      headers: options.body ? { "Content-Type": "application/json" } : undefined,
      body: options.body ? JSON.stringify(options.body) : undefined,
      credentials: "same-origin",
    });
    let data = {};
    try { data = await response.json(); } catch (_error) { data = {}; }
    if (!response.ok) {
      const error = new Error(typeof data.error === "string" ? data.error : `İstek ${response.status} durum koduyla başarısız oldu.`);
      error.status = response.status;
      throw error;
    }
    return data;
  }

  function el(tag, text, className) {
    const node = document.createElement(tag);
    if (text != null) node.textContent = String(text);
    if (className) node.className = className;
    return node;
  }

  // Durum kutusu: aşama etiketi, dosya sayısı, yüzde, ilerleme çubuğu ve iptal düğmesi (proje formunun altında).
  function statusBox(anchor) {
    let box = document.getElementById(BOX_ID);
    if (!box) {
      box = el("div", null, "project-limitations project-job-status");
      box.id = BOX_ID;
      box.setAttribute("role", "status");
      box.setAttribute("aria-live", "polite");
      const head = el("p");
      head.append(el("strong", "Proje analizi arka planda çalışıyor"), el("span", "", "project-job-name"));
      const bar = el("progress");
      bar.max = 100;
      bar.value = 0;
      bar.className = "project-job-bar";
      const line = el("p");
      line.append(el("span", "", "project-job-stage"), el("span", "", "project-job-count"), el("span", "", "project-job-percent"));
      const cancel = el("button", "İptal et", "mini-button project-job-cancel");
      cancel.type = "button";
      const note = el("small", "Sayfayı kapatsanız da analiz sürer; bitince bildirim merkezinde görünür.", "muted");
      box.append(head, bar, line, cancel, note);
      const target = anchor || document.getElementById("project-audit-form");
      if (target && target.parentNode) target.parentNode.insertBefore(box, target.nextSibling);
      else document.body.append(box);
    }
    box.classList.remove("hidden");
    return box;
  }

  function render(box, job) {
    if (!box || !job) return;
    const progress = job.progress || {};
    const percent = job.state === "succeeded" ? 100 : Math.max(0, Math.min(100, Number(progress.percent || 0)));
    const bar = box.querySelector(".project-job-bar");
    if (bar) bar.value = percent;
    const name = box.querySelector(".project-job-name");
    if (name) name.textContent = job.label ? ` · ${job.label}` : "";
    const stage = box.querySelector(".project-job-stage");
    if (stage) {
      stage.textContent = job.state === "running" && progress.label ? progress.label : (STATE_TEXT[job.state] || "Bilinmiyor");
    }
    const count = box.querySelector(".project-job-count");
    if (count) {
      count.textContent = job.state === "queued" && job.queue_position
        ? ` · sıra ${Number(job.queue_position)}`
        : (Number.isInteger(progress.total) && progress.total > 0 ? ` · ${Number(progress.done || 0)}/${Number(progress.total)} dosya` : "");
    }
    const pct = box.querySelector(".project-job-percent");
    if (pct) pct.textContent = ` · %${Math.round(percent)}`;
    const cancel = box.querySelector(".project-job-cancel");
    if (cancel) cancel.disabled = FINAL.has(job.state) || job.cancel_requested === true;
    box.dataset.jobId = job.id || "";
    box.dataset.jobState = job.state || "";
  }

  async function poll(jobId, box) {
    let delay = POLL_MS;
    for (let index = 0; index < MAX_POLLS; index += 1) {
      let job;
      try {
        job = await request(`/api/jobs/${encodeURIComponent(jobId)}`);
      } catch (error) {
        if (error.status === 404) {
          remember(null);
          throw new Error("Arka plan işi bulunamadı (süresi dolmuş ya da sunucu yeniden başlamış olabilir).");
        }
        await wait(Math.min(MAX_POLL_MS, delay * 2));
        continue;
      }
      render(box, job);
      if (FINAL.has(job.state)) {
        remember(null);
        return job;
      }
      // Kuyrukta beklerken daha seyrek, çalışırken saniyede bir yoklanır (hız sınırının çok altında).
      delay = job.state === "queued" ? Math.min(MAX_POLL_MS, delay + 1000) : POLL_MS;
      await wait(delay);
    }
    throw new Error("İş durumu çok uzun süre değişmedi; İşler panelinden kontrol edin.");
  }

  function bindCancel(box, jobId) {
    const button = box.querySelector(".project-job-cancel");
    if (!button) return;
    button.onclick = async () => {
      button.disabled = true;
      try {
        await request(`/api/jobs/${encodeURIComponent(jobId)}/cancel`, { method: "POST", body: {} });
      } catch (error) {
        button.disabled = false;
        scope.toast?.(error.message, "error");
      }
    };
  }

  function outcome(job) {
    if (job.state === "succeeded") {
      const result = job.result || {};
      if (!result.id) throw new Error("Analiz tamamlandı ancak kayıt kimliği alınamadı; Proje analizleri listesini yenileyin.");
      return result;
    }
    throw new Error(job.error || STATE_TEXT[job.state] || "İş tamamlanamadı.");
  }

  async function start(body, form) {
    const box = statusBox(form);
    render(box, { state: "queued", progress: { percent: 0 } });
    let job;
    try {
      job = await request("/api/jobs", { method: "POST", body: { route: ROUTE, payload: body || {} } });
    } catch (error) {
      box.classList.add("hidden");
      throw error;
    }
    remember(job.id);
    bindCancel(box, job.id);
    render(box, job);
    scope.SniperJobsPanel?.refresh?.();
    const final = await poll(job.id, box);
    scope.SniperJobsPanel?.refresh?.();
    if (final.state === "succeeded") box.classList.add("hidden");
    return outcome(final);
  }

  // Sayfa açılınca: önceki oturumda başlatılmış ve hâlâ süren analiz varsa izlemeye devam et.
  async function resume() {
    const jobId = remembered();
    if (!jobId) return null;
    let job;
    try {
      job = await request(`/api/jobs/${encodeURIComponent(jobId)}`);
    } catch (_error) {
      remember(null);
      return null;
    }
    if (job.route !== ROUTE) {
      remember(null);
      return null;
    }
    const box = statusBox(null);
    bindCancel(box, jobId);
    render(box, job);
    try {
      const final = FINAL.has(job.state) ? job : await poll(jobId, box);
      remember(null);
      const audit = outcome(final);
      box.classList.add("hidden");
      await scope.loadAll?.();
      await scope.openProjectAudit?.(audit.id);
      scope.toast?.(`${audit.project_name || "Proje"} analizi tamamlandı.`);
      return audit;
    } catch (error) {
      scope.toast?.(error.message, "error");
      return null;
    }
  }

  // --- Monorepo alt proje özeti (analiz ayrıntısı) ---
  function severityText(counts) {
    const c = counts || {};
    return `${Number(c.critical || 0)} kritik · ${Number(c.high || 0)} yüksek · ${Number(c.medium || 0)} orta · ${Number(c.low || 0)} düşük`;
  }

  function dependencyText(dep) {
    if (!dep) return "—";
    const parts = Object.entries(dep.by_ecosystem || {}).map(([eco, count]) => `${eco} ${Number(count)}`);
    const total = Number(dep.component_count || 0);
    return parts.length ? `${total} bileşen (${parts.join(", ")})` : `${total} bileşen`;
  }

  function renderSubprojects(audit, detail) {
    if (!detail || !audit || typeof document === "undefined") return;
    detail.querySelector(".subproject-panel")?.remove();
    const data = audit.subprojects;
    if (!data || !Array.isArray(data.subprojects) || !data.subprojects.length) return;
    const panel = el("section", null, "subproject-panel license-panel");
    const head = el("details");
    head.open = data.subprojects.length <= 12;
    const title = el("summary");
    title.append(el("b", "Alt projeler (monorepo)"),
      el("small", ` ${Number(data.count || data.subprojects.length)} alt proje · ${data.declared ? "çalışma alanı bildirimi" : "örtük (birden çok bağımlılık bildirimi)"}`));
    head.append(title);
    const table = el("table", null, "threat-table subproject-table");
    const thead = el("thead");
    const hr = el("tr");
    for (const name of ["Alt proje", "Tür", "Dosya", "Diller", "Bulgular", "Bağımlılıklar"]) hr.append(el("th", name));
    thead.append(hr);
    const tbody = el("tbody");
    const rows = [...data.subprojects];
    if (data.root && (data.root.file_count || data.root.finding_count)) rows.push(data.root);
    for (const row of rows) {
      const tr = el("tr");
      const languages = Object.entries(row.languages || {}).map(([lang, count]) => `${lang} ${Number(count)}`).join(", ");
      [row.path === "." ? "(kök)" : row.path, row.kind, Number(row.file_count || 0), languages || "—",
        severityText(row.finding_counts), row.path === "." ? "—" : dependencyText(row.dependencies)]
        .forEach(value => tr.append(el("td", value)));
      tbody.append(tr);
    }
    table.append(thead, tbody);
    head.append(table);
    if (data.truncated) head.append(el("p", "Alt proje listesi kısaltıldı (ilk 200).", "muted"));
    panel.append(head);
    const anchor = detail.querySelector(".project-finding-summary");
    if (anchor) detail.insertBefore(panel, anchor); else detail.append(panel);
  }

  // app.js ayrıntı görünümü lisans kancasını çağırır; tüm betikler yüklendikten sonra o kancaya alt proje
  // özetini zincirleriz (app.js'e ek çağrı gerekmez).
  function installDetailHook() {
    const previous = scope.renderLicenseSummary;
    if (previous && previous.__subprojects) return;
    const chained = function chainedRender(audit, detail) {
      const result = typeof previous === "function" ? previous(audit, detail) : undefined;
      try { renderSubprojects(audit, detail); } catch (_error) { /* özet gösterilemezse ayrıntı yine açılır */ }
      return result;
    };
    chained.__subprojects = true;
    scope.renderLicenseSummary = chained;
  }

  if (typeof document !== "undefined") {
    document.addEventListener("DOMContentLoaded", () => {
      installDetailHook();
      resume();
    });
  }

  scope.SniperProjectJobs = Object.freeze({ start, resume, poll, render, renderSubprojects, installDetailHook });
})();
