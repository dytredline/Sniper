// VEX (17. tur): bağımlılık açıkları için CycloneDX VEX / OpenVEX üretimi, analist kararı ve tedarikçi VEX'i içe aktarma.
// Bağımlılık panelindeki ".dependency-actions" alanına bir form ekler. Yalnız DOM API ve textContent kullanılır.
(() => {
  const scope = typeof window !== "undefined" ? window : globalThis;
  const STATUS_LABELS = { not_affected: "Etkilenmiyor", affected: "Etkileniyor", fixed: "Düzeltildi", under_investigation: "İnceleniyor" };
  const BASIS_LABELS = { auto: "otomatik", analyst: "analist kararı", imported: "içe aktarılan VEX", scanner: "tarayıcı", policy: "politika" };
  const JUSTIFICATIONS = {
    component_not_present: "Bileşen üründe yok",
    vulnerable_code_not_present: "Açıklı kod üründe yok",
    vulnerable_code_not_in_execute_path: "Açıklı kod çalışma yolunda değil",
    vulnerable_code_cannot_be_controlled_by_adversary: "Açıklı kod saldırgan tarafından denetlenemez",
    inline_mitigations_already_exist: "Kod içi önlem mevcut",
  };

  function el(tag, text, className) {
    const node = document.createElement(tag);
    if (text != null) node.textContent = String(text);
    if (className) node.className = className;
    return node;
  }

  function option(value, label, selected) {
    const node = el("option", label);
    node.value = value;
    if (selected) node.selected = true;
    return node;
  }

  async function post(path, body) {
    const response = await fetch(path, {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || `İstek başarısız (${response.status}).`);
    return { data, response };
  }

  function summaryText(summary) {
    const s = (summary && summary.statuses) || {};
    return Object.keys(STATUS_LABELS).map(key => `${STATUS_LABELS[key]} ${Number(s[key] || 0)}`).join(" · ");
  }

  // Tek bulgu için analist kararı formu (satırın altına açılır).
  function decisionForm(statement, onSaved) {
    const form = el("form", null, "vex-decision-form");
    const status = el("select");
    status.name = "status";
    status.setAttribute("aria-label", "VEX kararı");
    for (const key of Object.keys(STATUS_LABELS)) status.append(option(key, STATUS_LABELS[key], key === statement.status));
    const justification = el("select");
    justification.name = "justification";
    justification.setAttribute("aria-label", "Gerekçe");
    justification.append(option("", "Gerekçe seçin"));
    for (const key of Object.keys(JUSTIFICATIONS)) justification.append(option(key, JUSTIFICATIONS[key], key === statement.justification));
    const impact = el("textarea");
    impact.name = "impact_statement";
    impact.maxLength = 2000;
    impact.placeholder = "Neden etkilenmiyor? (en az 10 karakter)";
    impact.value = statement.basis === "analyst" ? statement.impact_statement || "" : "";
    const action = el("input");
    action.name = "action_statement";
    action.maxLength = 2000;
    action.placeholder = "Yapılacak eylem (Etkileniyor için zorunlu)";
    action.value = statement.basis === "analyst" ? statement.action_statement || "" : "";
    const sync = () => {
      const notAffected = status.value === "not_affected";
      justification.hidden = !notAffected;
      impact.hidden = !notAffected;
      action.hidden = status.value !== "affected";
    };
    status.addEventListener("change", sync);
    sync();
    const save = el("button", "Kararı kaydet", "mini-button accent");
    save.type = "submit";
    const message = el("small", "", "muted");
    form.append(status, justification, impact, action, save);
    if (statement.basis === "analyst" || statement.basis === "imported") {
      const clear = el("button", "Kararı kaldır", "mini-button");
      clear.type = "button";
      clear.addEventListener("click", async () => {
        try {
          await post("/api/dependency-security/vex-decisions", { confirm: true, finding_id: statement.finding_id, clear: true });
          onSaved();
        } catch (error) { message.textContent = error.message; }
      });
      form.append(clear);
    }
    form.append(message);
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const body = { confirm: true, finding_id: statement.finding_id, status: status.value };
      if (status.value === "not_affected") Object.assign(body, { justification: justification.value, impact_statement: impact.value });
      if (status.value === "affected") body.action_statement = action.value;
      try {
        await post("/api/dependency-security/vex-decisions", body);
        onSaved();
      } catch (error) { message.textContent = error.message; }
    });
    return form;
  }

  function renderResult(container, result, reload) {
    container.replaceChildren();
    container.append(el("p", `${result.summary.total} ifade · ${summaryText(result.summary)}`, "vex-summary"));
    const NOTE = "Otomatik 'Etkilenmiyor' yalnız paket tam kilit dosyasında hiç yoksa verilir; açıklı fonksiyonun kaynakta çağrılmaması tek başına yeterli sayılmaz (başka bir bağımlılık çağırabilir). Diğer kararlar analist ya da içe aktarılan VEX ile verilir.";
    container.append(el("p", NOTE, "muted"));
    const wrap = el("div", null, "responsive-table");
    const table = el("table", null, "vex-table");
    const head = el("tr");
    for (const name of ["Zafiyet", "Paket / sürüm", "Karar", "Dayanak", "Açıklama", ""]) head.append(el("th", name));
    const thead = el("thead");
    thead.append(head);
    const tbody = el("tbody");
    for (const st of result.statements || []) {
      const tr = el("tr");
      tr.append(el("td", st.vulnerability_id), el("td", `${st.package}${st.version ? "@" + st.version : ""}`));
      const decision = el("td", STATUS_LABELS[st.status] || st.status, `vex-status vex-${st.status}`);
      if (st.justification) decision.append(el("small", ` · ${JUSTIFICATIONS[st.justification] || st.justification}`));
      tr.append(decision, el("td", BASIS_LABELS[st.basis] || st.basis));
      tr.append(el("td", [st.impact_statement, st.action_statement, st.status_notes].filter(Boolean).join(" ")));
      const cell = el("td");
      if (st.finding_id) {
        const edit = el("button", "Karar ver", "mini-button");
        edit.type = "button";
        edit.addEventListener("click", () => {
          const next = tr.nextSibling;
          if (next && next.className === "vex-decision-row") { next.remove(); return; }
          const row = el("tr", null, "vex-decision-row");
          const td = el("td");
          td.colSpan = 6;
          td.append(decisionForm(st, reload));
          row.append(td);
          tr.after(row);
        });
        cell.append(edit);
      }
      tr.append(cell);
      tbody.append(tr);
    }
    table.append(thead, tbody);
    wrap.append(table);
    container.append(wrap);
  }

  function filenameFrom(response, fallback) {
    const header = response.headers.get("Content-Disposition") || "";
    const match = /filename="([^"]+)"/.exec(header);
    return match ? match[1] : fallback;
  }

  function mount() {
    const actions = document.querySelector(".dependency-panel .dependency-actions");
    if (!actions || actions.querySelector("form[data-vex-form]")) return;
    const form = el("form");
    form.id = "dependency-vex-form";
    form.dataset.vexForm = "1";
    const pathLabel = el("label", "Proje yolu (VEX)");
    const pathInput = el("input");
    pathInput.name = "project_path";
    pathInput.maxLength = 1024;
    pathInput.required = true;
    const sibling = document.querySelector("#dependency-import-form input[name=project_path]");
    pathInput.value = sibling ? sibling.value : "";
    pathLabel.append(pathInput);
    const formatLabel = el("label", "VEX biçimi");
    const format = el("select");
    format.name = "format";
    format.append(option("openvex", "OpenVEX 0.2.0", true), option("cyclonedx", "CycloneDX 1.5 VEX"));
    formatLabel.append(format);
    const devLabel = el("label", null, "vex-dev-option");
    const dev = el("input");
    dev.type = "checkbox";
    dev.name = "dev_as_not_affected";
    devLabel.append(dev, el("span", "Geliştirme bağımlılıklarını 'Etkilenmiyor' say"));
    const preview = el("button", "VEX önizle", "button secondary");
    preview.type = "submit";
    const download = el("button", "VEX indir", "button secondary");
    download.type = "button";
    const importLabel = el("label", "Tedarikçi VEX'i içe aktar (JSON)");
    const file = el("input");
    file.type = "file";
    file.accept = ".json,application/json";
    importLabel.append(file);
    form.append(pathLabel, formatLabel, devLabel, preview, download, importLabel);
    const result = el("div", null, "vex-result");
    result.id = "dependency-vex-result";
    result.setAttribute("aria-live", "polite");
    actions.append(form, result);

    const body = () => ({ confirm_local: true, project_path: pathInput.value.trim(), format: format.value,
      dev_as_not_affected: Boolean(dev.checked) });
    const load = async () => {
      result.replaceChildren(el("p", "VEX hazırlanıyor…", "muted"));
      try {
        const { data } = await post("/api/dependency-security/vex", body());
        renderResult(result, data, load);
      } catch (error) { result.replaceChildren(el("p", error.message, "vex-error")); }
    };
    form.addEventListener("submit", (event) => { event.preventDefault(); load(); });
    download.addEventListener("click", async () => {
      try {
        const { data, response } = await post("/api/dependency-security/vex", { ...body(), download: true });
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
        const anchor = el("a");
        anchor.href = URL.createObjectURL(blob);
        anchor.download = filenameFrom(response, `sniper-${format.value}-vex.json`);
        document.body.append(anchor);
        anchor.click();
        anchor.remove();
        setTimeout(() => URL.revokeObjectURL(anchor.href), 1000);
      } catch (error) { result.replaceChildren(el("p", error.message, "vex-error")); }
    });
    file.addEventListener("change", async () => {
      const chosen = file.files && file.files[0];
      if (!chosen) return;
      try {
        if (chosen.size > 5_000_000) throw new Error("VEX dosyası çok büyük (en çok 5 MB).");
        const document_ = JSON.parse(await chosen.text());
        const { data } = await post("/api/dependency-security/vex-import",
          { confirm: true, project_path: pathInput.value.trim(), document: document_ });
        const line = `İçe aktarıldı: ${data.applied} karar uygulandı, ${data.skipped_analyst} analist kararı korundu, ${data.unmatched} ifade eşleşmedi (kaynak: ${data.source}).`;
        result.replaceChildren(el("p", line, "vex-summary"));
      } catch (error) {
        result.replaceChildren(el("p", error instanceof SyntaxError ? "Dosya geçerli JSON değil." : error.message, "vex-error"));
      } finally { file.value = ""; }
    });
  }

  scope.SniperVex = { mount, renderResult, decisionForm, summaryText, STATUS_LABELS, JUSTIFICATIONS };
  if (typeof document !== "undefined" && document.addEventListener) {
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", mount);
    else mount();
  }
})();
