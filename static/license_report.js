// Bağımlılık lisans uyumu: proje analizi ayrıntısında lisans bölümü ve lisans politikası düzenleyicisi.
// Veri sunucuda yerel dosyalardan çıkarılır (ağ yok). Yalnız DOM API ve textContent kullanılır.
(() => {
  const scope = typeof window !== "undefined" ? window : globalThis;
  const LABELS = { allowed: "İzinli", caution: "Dikkat", review: "İnceleme", denied: "Yasak" };
  const ORDER = ["denied", "caution", "review", "allowed"];

  function el(tag, text, className) {
    const node = document.createElement(tag);
    if (text != null) node.textContent = String(text);
    if (className) node.className = className;
    return node;
  }

  function licenseText(item) {
    return item.expression || item.raw || "belirlenemedi";
  }

  function summaryLine(report) {
    const cats = report.by_category || {};
    return ORDER.map(key => `${LABELS[key]} ${Number(cats[key] || 0)}`).join(" · ");
  }

  function rows(report) {
    return (report.items || []).slice(0, 150).map(item => [
      item.name + (item.version ? `@${item.version}` : ""),
      licenseText(item),
      LABELS[item.category] || item.category,
      `${item.ecosystem}${item.dev ? " · geliştirme" : ""}${item.heuristic ? " · metin sezgisi" : ""}`,
      item.source || "",
    ]);
  }

  function policyLines(value) {
    return String(value || "").split(/[\n,]+/).map(item => item.trim()).filter(Boolean);
  }

  function policyEditor(container) {
    const details = el("details", null, "license-policy");
    details.append(el("summary", "Lisans politikası (izinli / dikkat / yasak)"));
    const form = el("form", null, "form-grid license-policy-form");
    const fields = {};
    for (const [name, label] of [["denied", "Yasak"], ["caution", "Dikkat"], ["allowed", "İzinli"]]) {
      const wrap = el("label", null, "full");
      wrap.append(el("span", `${label} (SPDX kimlikleri; joker *, satır ya da virgülle ayırın)`));
      const area = document.createElement("textarea");
      area.name = name;
      area.rows = name === "allowed" ? 5 : 3;
      fields[name] = area;
      wrap.append(area);
      form.append(wrap);
    }
    const confirmLabel = el("label", null, "full");
    const confirm = document.createElement("input");
    confirm.type = "checkbox";
    confirm.name = "confirm";
    confirmLabel.append(confirm, el("span", " Politikayı değiştirmeyi onaylıyorum (sonraki analizlerde uygulanır; yönetici yetkisi gerekir)"));
    form.append(confirmLabel);
    const buttons = el("div", null, "button-row full");
    const save = el("button", "Kaydet", "mini-button accent");
    save.type = "submit";
    const reset = el("button", "Varsayılana dön", "mini-button");
    reset.type = "button";
    buttons.append(save, reset);
    form.append(buttons);
    const status = el("p", "", "muted");
    details.append(form, status);

    function fill(data) {
      const policy = data.policy || {};
      for (const name of Object.keys(fields)) fields[name].value = (policy[name] || []).join("\n");
      status.textContent = data.customized ? "Özelleştirilmiş politika etkin." : "Varsayılan politika etkin.";
    }

    async function send(body) {
      if (!confirm.checked) {
        status.textContent = "Önce onay kutusunu işaretleyin.";
        return;
      }
      try {
        const response = await fetch("/api/license-policy", {
          method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ confirm: true, ...body }),
        });
        const data = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(data.error || `Politika kaydedilemedi (${response.status})`);
        fill(data);
        confirm.checked = false;
        status.textContent = "Kaydedildi; yeni politika sonraki analizde uygulanır.";
      } catch (error) {
        status.textContent = error.message || "Politika kaydedilemedi";
      }
    }

    details.addEventListener("toggle", async () => {
      if (!details.open || details.dataset.loaded) return;
      details.dataset.loaded = "1";
      try {
        const response = await fetch("/api/license-policy", { headers: { Accept: "application/json" } });
        const data = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(data.error || `Politika alınamadı (${response.status})`);
        fill(data);
      } catch (error) {
        status.textContent = error.message || "Politika alınamadı";
      }
    });
    form.addEventListener("submit", event => {
      event.preventDefault();
      send({ policy: { denied: policyLines(fields.denied.value), caution: policyLines(fields.caution.value), allowed: policyLines(fields.allowed.value) } });
    });
    reset.addEventListener("click", () => send({ reset: true }));
    container.append(details);
  }

  function renderLicenseSummary(audit, detail) {
    if (!detail || !audit || typeof document === "undefined") return;
    detail.querySelector(".license-panel")?.remove();
    const report = audit.licenses;
    const panel = el("section", null, "license-panel");
    const head = el("details");
    head.open = Boolean(report && ((report.by_category || {}).denied || (report.by_category || {}).caution));
    const title = el("summary");
    title.append(el("b", "Bağımlılık lisansları"), el("small", report ? ` ${Number(report.component_count || 0)} bileşen · ${summaryLine(report)}` : " lisans bilgisi bulunamadı"));
    head.append(title);
    if (report) {
      const project = report.project_license;
      head.append(el("p", `Proje lisansı: ${project ? `${licenseText(project)} (${project.source}${project.heuristic ? ", metin sezgisi" : ""})` : "belirlenemedi"}`));
      const chips = el("div", null, "threat-chips");
      for (const entry of (report.by_license || []).slice(0, 12)) {
        chips.append(el("span", `${entry.license}: ${Number(entry.count)} · ${LABELS[entry.category] || entry.category}`, `threat-chip license-${entry.category}`));
      }
      head.append(chips);
      const list = rows(report);
      if (list.length) {
        const table = el("table", null, "threat-table license-table");
        const thead = el("thead");
        const hr = el("tr");
        for (const name of ["Paket", "Lisans", "Durum", "Ekosistem", "Kaynak"]) hr.append(el("th", name));
        thead.append(hr);
        const tbody = el("tbody");
        for (const cells of list) {
          const tr = el("tr");
          cells.forEach((value, index) => tr.append(el("td", value, index === 2 ? "license-status" : null)));
          tbody.append(tr);
        }
        table.append(thead, tbody);
        head.append(table);
        if (report.truncated) head.append(el("p", "Liste kısaltıldı (ilk 300).", "muted"));
      } else {
        head.append(el("p", "Politikaya göre dikkat/yasak/inceleme gerektiren bileşen yok.", "muted"));
      }
      const notes = el("ul", null, "threat-notes");
      for (const note of report.notes || []) notes.append(el("li", note));
      head.append(notes);
    } else {
      head.append(el("p", "Bağımlılık bildirimi ya da yerel paket üst verisi bulunamadı; kısmi taramada lisans denetimi yapılmaz.", "muted"));
    }
    policyEditor(head);
    panel.append(head);
    const anchor = detail.querySelector(".project-finding-summary");
    if (anchor) detail.insertBefore(panel, anchor); else detail.append(panel);
  }

  scope.renderLicenseSummary = renderLicenseSummary;
  scope.SniperLicense = { renderLicenseSummary, summaryLine, rows, policyLines };
})();
