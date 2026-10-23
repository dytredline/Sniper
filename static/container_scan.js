// Konteyner imajı / rootfs işletim sistemi paket taraması (18. tur). "Uygulama analizi" görünümüne ikinci bir
// başlatıcı ekler (docker save tar'ı, OCI düzeni ya da açılmış rootfs yolu) ve konteyner analizlerinin ayrıntısına
// imaj özeti + CycloneDX SBOM indirme bağlantısı koyar. Sonuç proje analizi olarak kaydedilir (bulgu takibi,
// portföy, raporlar aynı yoldan çalışır). Yalnız DOM API ve textContent kullanılır.
(() => {
  const scope = typeof window !== "undefined" ? window : globalThis;
  const ROUTE = "/api/container-images";
  const PANEL_ID = "container-scan-launcher";
  const SUMMARY_ID = "container-scan-summary";

  function el(tag, attrs = {}, text) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) {
      if (key === "className") node.className = value;
      else node.setAttribute(key, value);
    }
    if (text !== undefined) node.textContent = text;
    return node;
  }

  async function postScan(body) {
    const response = await scope.fetch(ROUTE, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || `İstek tamamlanamadı (${response.status})`);
    return data;
  }

  function buildPanel() {
    const section = el("section", { className: "panel project-audit-launcher container-scan-launcher", id: PANEL_ID });
    const intro = el("div");
    intro.append(el("span", { className: "project-audit-icon", "aria-hidden": "true" }, "▣"));
    const text = el("p");
    text.append(el("b", {}, "Konteyner imajını yerelde incele"));
    text.append(el("small", {}, "docker save arşivi, OCI düzeni ya da açılmış rootfs: işletim sistemi paketleri (dpkg, apk, rpm) "
      + "çevrimdışı OSV veritabanıyla eşlenir. Docker gerekmez, imaj diske açılmaz."));
    intro.append(text);
    const form = el("form", { className: "container-scan-form", id: "container-scan-form" });
    const pathLabel = el("label", {}, "İmaj ya da rootfs yolu");
    const input = el("input", { name: "image_path", id: "container-image-path", maxlength: "1024", autocomplete: "off",
      spellcheck: "false", required: "", placeholder: "~/imajlar/uygulama.tar" });
    pathLabel.append(input);
    const dockerfileLabel = el("label", {}, "Dockerfile yolu (isteğe bağlı)");
    const dockerfileInput = el("input", { name: "dockerfile_path", id: "container-dockerfile-path", maxlength: "1024",
      autocomplete: "off", spellcheck: "false", placeholder: "~/projeler/uygulama/Dockerfile" });
    dockerfileLabel.append(dockerfileInput);
    const check = el("label", { className: "check" });
    const box = el("input", { type: "checkbox", name: "ignore_unfixed", id: "container-ignore-unfixed" });
    check.append(box, el("span", {}, "Düzeltmesi olmayanları gizle"));
    const button = el("button", { className: "button primary", type: "submit" }, "Taramayı başlat");
    const status = el("p", { className: "muted container-scan-status", role: "status", "aria-live": "polite" });
    form.append(pathLabel, dockerfileLabel, check, button);
    section.append(intro, form, status);
    form.addEventListener("submit", async event => {
      event.preventDefault();
      const value = input.value.trim();
      if (!value) return;
      button.disabled = true;
      status.textContent = "Taranıyor…";
      try {
        const body = { image_path: value, ignore_unfixed: box.checked };
        const dockerfile = dockerfileInput.value.trim();
        if (dockerfile) body.dockerfile_path = dockerfile;
        const saved = await postScan(body);
        const info = saved.container || {};
        const os = info.os || {};
        status.textContent = `${saved.project_name}: ${os.pretty_name || os.id || "?"}, ${info.package_count || 0} paket, `
          + `${(saved.findings || []).length} bulgu (düzeltmesi olan ${info.fixable_findings || 0}).`;
        if (typeof scope.loadAll === "function") await scope.loadAll();
        if (typeof scope.openProjectAudit === "function") await scope.openProjectAudit(saved.id);
      } catch (error) {
        status.textContent = error.message;
      } finally {
        button.disabled = false;
      }
    });
    return section;
  }

  function mount() {
    if (document.getElementById(PANEL_ID)) return;
    const launcher = document.querySelector('[data-view="projects"] .project-audit-launcher');
    if (!launcher) return;
    launcher.after(buildPanel());
  }

  function renderContainerSummary(audit, host) {
    const container = host && typeof host.querySelector === "function" ? host : document.getElementById("project-audit-detail");
    if (!container) return;
    container.querySelector(`#${SUMMARY_ID}`)?.remove();
    if (!audit || audit.audit_kind !== "container" || !audit.container) return;
    const info = audit.container;
    const os = info.os || {};
    const image = info.image || {};
    const osv = info.osv || {};
    const build = info.build_context || {};
    const zstd = info.zstd_readiness || {};
    const box = el("section", { className: "container-scan-summary", id: SUMMARY_ID });
    box.append(el("h3", {}, "Konteyner imajı"));
    const list = el("dl");
    const rows = [
      ["Biçim", `${image.format || "?"} · ${Number(image.layers || 0)} katman${(image.tags || []).length ? ` · ${image.tags.join(", ")}` : ""}`],
      ["İşletim sistemi", `${os.pretty_name || os.id || "?"} → OSV ${os.ecosystem || "—"}`],
      ["Paketler", `${Number(info.package_count || 0)} (${Object.entries(info.package_types || {}).map(([k, v]) => `${k} ${v}`).join(", ") || "—"})`],
      ["Düzeltmesi olan bulgu", String(Number(info.fixable_findings || 0))],
      ["OSV veritabanı", osv.status === "missing" ? "yok" : `${osv.retrieved_utc || "?"}${osv.cached ? " (dizin önbellekten)" : ""}`],
      ["Dil paketleri", `${Number(info.language_components || 0)} (${info.language_matching === "matched" ? "eşlendi" : "OSV çok ekosistem eşleyicisi bekleniyor"})`],
      ["Zstd katman", zstd.available ? "yerel decoder hazır" : `hazır değil: ${zstd.reason || "decoder yok"}`],
    ];
    if (build.format) {
      rows.push(["Dockerfile son aşama", `${build.final_stage || "?"}: ${(build.matched_packages || []).length}/`
        + `${(build.declared_packages || []).length} bildirilen paket imaj envanterinde`]);
    }
    for (const [label, value] of rows) {
      list.append(el("dt", {}, label), el("dd", {}, value));
    }
    box.append(list);
    const link = el("a", { className: "button", href: `${ROUTE}/${encodeURIComponent(audit.id)}/sbom`, download: "" }, "CycloneDX SBOM indir");
    box.append(link);
    const anchor = container.querySelector(".project-audit-summary") || container.firstElementChild;
    if (anchor) anchor.after(box);
    else container.append(box);
  }

  scope.renderContainerSummary = renderContainerSummary;

  function chain() {
    // Analiz ayrıntısı her açıldığında app.js renderLicenseSummary'yi çağırır: konteyner özeti de aynı anda.
    const previous = scope.renderLicenseSummary;
    if (previous && previous.__containerChained) return;
    const wrapped = function (audit, host) {
      const result = typeof previous === "function" ? previous.apply(this, arguments) : undefined;
      try { renderContainerSummary(audit, host); } catch (_error) { /* özet hatası ayrıntıyı bozmaz */ }
      return result;
    };
    wrapped.__containerChained = true;
    scope.renderLicenseSummary = wrapped;
  }

  scope.SniperContainerScan = { renderContainerSummary, buildPanel, mount, chain };
  if (typeof document !== "undefined" && typeof document.addEventListener === "function") {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", () => { mount(); chain(); });
    } else {
      mount();
      chain();
    }
  }
})();
