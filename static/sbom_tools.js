// SBOM araçları (20. tur): kayıtlı SBOM'lar için SPDX 2.3 indirme bağlantısı ve dış SBOM dosyasını
// (CycloneDX JSON/XML, SPDX JSON/tag-value) çevrimdışı OSV ile tarama formu + VEX indirme. Yalnız DOM API/textContent.
(() => {
  const scope = typeof window !== "undefined" ? window : globalThis;

  function el(tag, text, className) {
    const node = document.createElement(tag);
    if (text != null) node.textContent = String(text);
    if (className) node.className = className;
    return node;
  }

  function spdxHref(href) {
    const value = String(href || "");
    if (!/^\/api\/(dependency-sboms\/[A-Za-z0-9_-]+|container-images\/prj_[0-9a-f]+\/sbom)$/.test(value)) return "";
    return `${value}?format=spdx`;
  }

  function vexHref(auditId, format) {
    if (!/^prj_[0-9a-f]{12,32}$/.test(String(auditId || ""))) return "";
    const fmt = format === "cyclonedx" ? "cyclonedx" : "openvex";
    return `/api/dependency-security/sbom-scans/${auditId}/vex?format=${fmt}`;
  }

  function link(href, text) {
    const a = el("a", text, "mini-button");
    a.setAttribute("href", href);
    a.setAttribute("download", "");
    return a;
  }

  // app.js'in yazdığı "SBOM" bağlantılarının yanına SPDX karşılığını ekler (bir kez).
  function decorateSources(container) {
    if (!container || typeof container.querySelectorAll !== "function") return 0;
    let added = 0;
    for (const anchor of container.querySelectorAll("a[href^='/api/dependency-sboms/']")) {
      if (anchor.dataset && anchor.dataset.spdxDecorated) continue;
      const href = spdxHref(anchor.getAttribute("href"));
      if (!href) continue;
      if (anchor.dataset) anchor.dataset.spdxDecorated = "1";
      const extra = link(href, "SPDX");
      extra.setAttribute("title", "Aynı SBOM'u SPDX 2.3 JSON olarak indir");
      anchor.after(extra);
      added += 1;
    }
    return added;
  }

  function renderScanResult(container, audit) {
    container.replaceChildren();
    const info = (audit && audit.sbom) || {};
    const counts = (audit && audit.finding_counts) || {};
    const name = audit && audit.project_name ? audit.project_name : "—";
    const fmt = info.source_format || "?";
    const spec = info.spec_version || "";
    const total = Number(info.component_count || 0);
    const matched = Number(info.matched_components || 0);
    const found = Array.isArray(audit && audit.findings) ? audit.findings.length : 0;
    const critical = Number(counts.critical || 0);
    const high = Number(counts.high || 0);
    const score = Number(audit && audit.score || 0);
    container.append(el("p", `SBOM: ${name} · ${fmt} ${spec} · bileşen ${total} · eşlenen ${matched} · bulgu ${found} (kritik ${critical}, yüksek ${high}) · puan ${score}`));
    for (const warning of (audit && audit.warnings) || []) container.append(el("p", warning, "muted"));
    const row = el("div", null, "button-row");
    const openvex = vexHref(audit && audit.id, "openvex");
    if (openvex) {
      row.append(link(openvex, "OpenVEX indir"), link(vexHref(audit.id, "cyclonedx"), "CycloneDX VEX indir"));
      container.append(row);
    }
    const list = el("ul", null, "sbom-scan-findings");
    for (const finding of ((audit && audit.findings) || []).slice(0, 20)) {
      const pkg = finding.package || {};
      list.append(el("li", `[${String(finding.severity || "").toUpperCase()}] ${finding.reference || ""} — ` +
        `${pkg.source || ""} ${pkg.installed_version || ""} → ${finding.fixed_version || "düzeltme yok"}`));
    }
    if (list.children.length) container.append(list);
    return container;
  }

  async function postJson(path, body) {
    const response = await fetch(path, {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || `İstek başarısız (${response.status}).`);
    return data;
  }

  function mount() {
    const actions = document.querySelector(".dependency-panel .dependency-actions");
    if (actions && !actions.querySelector("form[data-sbom-scan-form]")) {
      const form = el("form");
      form.setAttribute("data-sbom-scan-form", "");
      const label = el("label", "Dış SBOM dosyası (CycloneDX / SPDX)");
      const input = el("input");
      input.name = "sbom_path";
      input.setAttribute("maxlength", "1024");
      input.setAttribute("placeholder", "~/Downloads/bom.json");
      input.required = true;
      label.append(input);
      const confirmLabel = el("label", "Yerel dosyayı çevrimdışı taramayı onaylıyorum", "check");
      const confirm = el("input");
      confirm.type = "checkbox";
      confirm.name = "confirm";
      confirmLabel.prepend(confirm);
      const button = el("button", "SBOM'u tara", "button secondary");
      button.type = "submit";
      const result = el("div", null, "sbom-scan-result");
      result.setAttribute("role", "status");
      result.setAttribute("aria-live", "polite");
      form.append(label, confirmLabel, button);
      actions.append(form);
      actions.after(result);
      form.addEventListener("submit", async (event) => {
        event.preventDefault();
        result.replaceChildren(el("p", "SBOM taranıyor…", "muted"));
        try {
          if (!confirm.checked) throw new Error("Taramayı onaylayın.");
          const audit = await postJson("/api/dependency-security/sbom-scan", { sbom_path: input.value.trim(), confirm: true });
          renderScanResult(result, audit);
          await scope.loadAll?.();
        } catch (error) {
          result.replaceChildren(el("p", error.message || String(error), "error"));
        }
      });
    }
    const sources = document.querySelector("#dependency-sources");
    if (sources) {
      decorateSources(sources);
      if (typeof MutationObserver === "function" && !sources.dataset.spdxObserved) {
        sources.dataset.spdxObserved = "1";
        new MutationObserver(() => decorateSources(sources)).observe(sources, { childList: true });
      }
    }
  }

  scope.SniperSbomTools = { spdxHref, vexHref, decorateSources, renderScanResult, mount };
  if (typeof document !== "undefined" && typeof document.addEventListener === "function") {
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", mount);
    else mount();
  }
})();
