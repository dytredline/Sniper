// Toplu depo taraması (25. tur). "Uygulama analizi" görünümüne tek bir panel ekler: kök dizindeki git depolarını /
// proje köklerini keşfet (önizleme), seçilenleri tek işte tara (proje analizi + çevrimdışı SCA, isteğe bağlı konteyner
// imajı), ilerlemeyi izle ve iptal et. Her depo ayrı proje olarak bulgu takibine ve portföye girer (grup adıyla).
// Yalnız DOM API ve textContent kullanılır; sunucu her istekte confirm ve CSRF'yi ayrıca denetler.
(() => {
  const scope = typeof window !== "undefined" ? window : globalThis;
  const ROUTE = "/api/bulk-scans";
  const PANEL_ID = "bulk-scan-launcher";
  const FINAL = new Set(["succeeded", "failed", "cancelled", "interrupted"]);
  const STATUS_LABELS = {
    pending: "Bekliyor", running: "Taranıyor", succeeded: "Tamamlandı", skipped: "Atlandı (commit değişmedi)",
    failed: "Hata", cancelled: "İptal edildi", queued: "Sırada", interrupted: "Yarıda kaldı",
  };
  const state = { found: null, rows: [], run: null, timer: null, ui: null };

  function el(tag, attrs = {}, text) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) {
      if (key === "className") node.className = value;
      else node.setAttribute(key, value);
    }
    if (text !== undefined) node.textContent = text;
    return node;
  }

  async function call(path, body) {
    const options = body === undefined ? {} : {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ confirm: true, ...body }),
    };
    const response = await scope.fetch(path, options);
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || `İstek tamamlanamadı (${response.status})`);
    return data;
  }

  function formatSize(bytes) {
    const value = Number(bytes || 0);
    if (value >= 1e9) return `${(value / 1e9).toFixed(1)} GB`;
    if (value >= 1e6) return `${(value / 1e6).toFixed(1)} MB`;
    return `${Math.max(1, Math.round(value / 1e3))} KB`;
  }

  // Aday kartı satırı: ad, göreli yol, uzak addan türetilen ad, son commit, diller, boyut ve uyarılar.
  function candidateDetails(item) {
    const parts = [];
    if (item.remote && item.remote.name) parts.push(`${item.remote.host ? `${item.remote.host}/` : ""}${item.remote.name}`);
    if (item.commit) parts.push(`${String(item.commit).slice(0, 8)}${item.committed_at ? ` · ${String(item.committed_at).slice(0, 10)}` : ""}`);
    else if (item.kind === "git") parts.push(item.git_error || "commit yok");
    else parts.push("git deposu değil (bildirim dosyası)");
    const langs = (item.languages || []).map(lang => `${lang.name} ${Number(lang.files || 0)}`).join(", ");
    if (langs) parts.push(langs);
    parts.push(`${Number(item.file_count || 0)} dosya · ${formatSize(item.size_bytes)}${item.estimate_truncated ? "+" : ""}`);
    if (item.monorepo) parts.push(`monorepo: ${Number(item.monorepo.subprojects || 0)} alt proje`);
    const flags = [];
    if (item.unchanged) flags.push("son taramadan beri commit değişmedi");
    if ((item.too_large || []).length) flags.push("boyut sınırını aşıyor");
    if (Number(item.image_count || 0)) flags.push(`${Number(item.image_count)} konteyner imajı`);
    return { text: parts.join(" · "), flags };
  }

  function renderPreview(found) {
    const ui = state.ui;
    state.found = found;
    state.rows = [];
    ui.list.textContent = "";
    const candidates = found.candidates || [];
    const notes = [];
    if ((found.truncated || []).length) notes.push(`sınıra ulaşıldı: ${found.truncated.join(", ")}`);
    const skipped = found.skipped || {};
    if (skipped.symlink) notes.push(`${Number(skipped.symlink)} sembolik bağ izlenmedi`);
    if (skipped.depth) notes.push(`${Number(skipped.depth)} dizin derinlik sınırının ötesinde`);
    ui.summary.textContent = `${candidates.length} depo bulundu (${found.root})${notes.length ? ` — ${notes.join("; ")}` : ""}.`;
    for (const item of candidates) {
      const row = el("li", { className: "bulk-scan-candidate" });
      const label = el("label", { className: "check" });
      const box = el("input", { type: "checkbox", name: "bulk_repo" });
      box.checked = Boolean(item.selected);
      const title = el("b", {}, item.rel === "." ? item.name : item.rel);
      label.append(box, title);
      const info = candidateDetails(item);
      const details = el("small", {}, info.text);
      row.append(label, details);
      for (const flag of info.flags) row.append(el("span", { className: "pill" }, flag));
      ui.list.append(row);
      state.rows.push({ item, box });
    }
    ui.start.disabled = candidates.length === 0;
  }

  function selectedPaths() {
    return state.rows.filter(row => row.box.checked).map(row => row.item.path);
  }

  function collectOptions() {
    const ui = state.ui;
    return {
      sca: Boolean(ui.sca.checked), container: Boolean(ui.container.checked),
      skip_unchanged: Boolean(ui.skipUnchanged.checked), changed_files: Boolean(ui.changedFiles.checked),
      parallel: Math.min(4, Math.max(1, Number(ui.parallel.value) || 1)),
    };
  }

  function renderRun(run) {
    const ui = state.ui;
    state.run = run;
    const totals = run.totals || {};
    const progress = run.progress || {};
    const label = STATUS_LABELS[run.status] || run.status;
    ui.runStatus.textContent = `${label}: ${Number(totals.succeeded || 0)} tamamlandı, ${Number(totals.skipped || 0)} atlandı, `
      + `${Number(totals.failed || 0)} hata, ${Number(totals.cancelled || 0)} iptal / ${Number(totals.total || 0)} depo`
      + `${progress.detail && !FINAL.has(run.status) ? ` — şu an: ${progress.detail}` : ""}.`;
    ui.runList.textContent = "";
    for (const item of run.items || []) {
      const severity = item.severity_counts || {};
      const counts = ["critical", "high", "medium"].filter(key => severity[key]).map(key => `${key} ${Number(severity[key])}`);
      const parts = [STATUS_LABELS[item.status] || item.status];
      if (item.finding_count !== undefined && item.finding_count !== null) parts.push(`${Number(item.finding_count)} bulgu${counts.length ? ` (${counts.join(", ")})` : ""}`);
      if (item.mode === "changed") parts.push("yalnız değişen dosyalar");
      if (item.sca && item.sca.status === "succeeded") parts.push(`SCA ${Number(item.sca.finding_count || 0)} açık`);
      else if (item.sca && item.sca.status) parts.push(`SCA: ${item.sca.error || item.sca.status}`);
      if (item.error) parts.push(item.error);
      const row = el("li", { className: `bulk-scan-item ${item.status || ""}` });
      row.append(el("b", {}, item.rel === "." ? item.name : (item.rel || item.name)), el("small", {}, parts.join(" · ")));
      ui.runList.append(row);
    }
    ui.cancel.hidden = FINAL.has(run.status);
  }

  async function poll(id) {
    clearTimeout(state.timer);
    try {
      const run = await call(`${ROUTE}/${encodeURIComponent(id)}`);
      renderRun(run);
      if (!FINAL.has(run.status)) {
        state.timer = setTimeout(() => poll(id), 2000);
      } else if (typeof scope.loadAll === "function") {
        await scope.loadAll();
      }
    } catch (error) {
      state.ui.runStatus.textContent = error.message;
    }
  }

  function buildPanel() {
    const section = el("section", { className: "panel project-audit-launcher bulk-scan-launcher", id: PANEL_ID });
    const intro = el("div");
    intro.append(el("span", { className: "project-audit-icon", "aria-hidden": "true" }, "⧉"));
    const text = el("p");
    text.append(el("b", {}, "Bir klasördeki tüm depoları tara"));
    text.append(el("small", {}, "Kök dizindeki git depoları ve proje kökleri bulunur (sembolik bağ izlenmez, ağa çıkılmaz). "
      + "Seçilenler sırayla taranır: proje analizi + çevrimdışı bağımlılık açıkları; her depo ayrı proje olarak portföye girer."));
    intro.append(text);

    const form = el("form", { className: "bulk-scan-form", id: "bulk-scan-form" });
    const rootLabel = el("label", {}, "Kök dizin");
    const root = el("input", { name: "root", id: "bulk-scan-root", maxlength: "1024", autocomplete: "off", spellcheck: "false",
      required: "", placeholder: "~/projeler" });
    rootLabel.append(root);
    const depthLabel = el("label", {}, "En çok derinlik");
    const depth = el("input", { name: "max_depth", type: "number", min: "0", max: "8", value: "4" });
    depth.value = "4";
    depthLabel.append(depth);
    const find = el("button", { className: "button", type: "submit" }, "Depoları bul");
    form.append(rootLabel, depthLabel, find);

    const summary = el("p", { className: "muted bulk-scan-summary", role: "status", "aria-live": "polite" });
    const list = el("ul", { className: "bulk-scan-candidates" });

    const options = el("fieldset", { className: "bulk-scan-options" });
    options.append(el("legend", {}, "Tarama seçenekleri"));
    const check = (name, label, checked) => {
      const wrap = el("label", { className: "check" });
      const box = el("input", { type: "checkbox", name });
      box.checked = checked;
      wrap.append(box, el("span", {}, label));
      options.append(wrap);
      return box;
    };
    const sca = check("sca", "Çevrimdışı bağımlılık açıkları (OSV)", true);
    const container = check("container", "Depodaki konteyner imajı arşivleri", false);
    const skipUnchanged = check("skip_unchanged", "Commit değişmediyse atla", true);
    const changedFiles = check("changed_files", "Yalnız değişen dosyalar (son taranan commit'e göre, git)", false);
    const parallelLabel = el("label", {}, "Aynı anda");
    const parallel = el("select", { name: "parallel" });
    for (const value of ["1", "2", "3", "4"]) parallel.append(el("option", { value }, value));
    parallel.value = "1";
    parallelLabel.append(parallel);
    const groupLabel = el("label", {}, "Portföy grubu");
    const group = el("input", { name: "group", maxlength: "60", autocomplete: "off", placeholder: "kök dizinin adı" });
    groupLabel.append(group);
    options.append(parallelLabel, groupLabel);

    const start = el("button", { className: "button primary", type: "button" }, "Seçilenleri tara");
    start.disabled = true;
    const cancel = el("button", { className: "button", type: "button" }, "Toplu taramayı iptal et");
    cancel.hidden = true;
    const runStatus = el("p", { className: "muted bulk-scan-run-status", role: "status", "aria-live": "polite" });
    const runList = el("ul", { className: "bulk-scan-items" });
    section.append(intro, form, summary, list, options, start, cancel, runStatus, runList);
    state.ui = { section, root, depth, find, summary, list, sca, container, skipUnchanged, changedFiles, parallel, group,
                 start, cancel, runStatus, runList };

    form.addEventListener("submit", async event => {
      event.preventDefault();
      const value = root.value.trim();
      if (!value) return;
      find.disabled = true;
      summary.textContent = "Depolar aranıyor…";
      try {
        renderPreview(await call(`${ROUTE}/discover`, { root: value, max_depth: Math.min(8, Math.max(0, Number(depth.value) || 0)) }));
      } catch (error) {
        summary.textContent = error.message;
      } finally {
        find.disabled = false;
      }
    });
    start.addEventListener("click", async () => {
      const paths = selectedPaths();
      if (!paths.length || !state.found) {
        runStatus.textContent = "Taranacak depo seçin.";
        return;
      }
      if (scope.confirm && !scope.confirm(`${paths.length} depo taransın mı? (Her depo ayrı proje olarak kaydedilir.)`)) return;
      start.disabled = true;
      try {
        const body = { root: state.found.root, paths, options: collectOptions() };
        if (group.value.trim()) body.group = group.value.trim();
        const result = await call(ROUTE, body);
        renderRun(result.bulk);
        poll(result.bulk.id);
      } catch (error) {
        runStatus.textContent = error.message;
      } finally {
        start.disabled = false;
      }
    });
    cancel.addEventListener("click", async () => {
      if (!state.run) return;
      if (scope.confirm && !scope.confirm("Toplu tarama iptal edilsin mi? Çalışan depo taraması durdurulur.")) return;
      try {
        await call(`${ROUTE}/${encodeURIComponent(state.run.id)}/cancel`, {});
        poll(state.run.id);
      } catch (error) {
        runStatus.textContent = error.message;
      }
    });
    return section;
  }

  function mount() {
    if (document.getElementById(PANEL_ID)) return;
    const anchor = document.querySelector('[data-view="projects"] .container-scan-launcher')
      || document.querySelector('[data-view="projects"] .project-audit-launcher');
    if (!anchor) return;
    anchor.after(buildPanel());
  }

  scope.SniperBulkScan = { buildPanel, mount, renderPreview, renderRun, selectedPaths, collectOptions, candidateDetails, formatSize, state };
  if (typeof document !== "undefined" && typeof document.addEventListener === "function") {
    // konteyner paneli (container_scan.js) önce bağlansın diye yükleme sonrası
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", () => setTimeout(mount, 0));
    else setTimeout(mount, 0);
  }
})();
