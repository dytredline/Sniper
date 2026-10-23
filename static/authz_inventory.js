// Rota yetki envanteri: proje analizi raporunda rotalar, koruma türü ve IDOR adayları (yalnız textContent ile).
// 17. tur: API sözleşmesi ↔ rota uyumu bölümü (gölge uç noktalar, kodda olmayan işlemler, kimlik doğrulama uyuşmazlığı).
(() => {
  const scope = typeof window !== "undefined" ? window : globalThis;
  const PROTECTION = Object.freeze({
    router: "yönlendirici", "router.use": "yönlendirici ara katmanı", mounted: "bağlandığı yerde ara katman",
    inline: "satır içi denetim", dependency: "bağımlılık (Depends)", mixin: "mixin", inherited: "taban sınıf",
    urlconf: "URL yapılandırması", global: "genel ayar", delegated: "korumalı fonksiyona devrediyor",
    permission_classes: "permission_classes", guard: "guard", "global-guard": "genel guard", decorator: "dekoratör",
    method_decorator: "yöntem dekoratörü", get_permissions: "get_permissions",
  });

  function label(protection) {
    if (!protection) return "korumasız";
    const [kind, name] = String(protection).split(":");
    const base = PROTECTION[kind] || kind;
    return name ? `${base}: ${name}` : base;
  }

  function el(tag, text, className) {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = String(text);
    if (className) node.className = className;
    return node;
  }

  function render(audit, container) {
    if (typeof document === "undefined" || !container) return null;
    const previousContract = container.querySelector(".api-contract-report");
    if (previousContract) previousContract.remove();
    const contract = renderContract(audit);
    const routes = renderRoutes(audit, container);
    if (contract) {
      const anchor = container.querySelector(".project-finding-summary");
      if (routes && routes.nextSibling) container.insertBefore(contract, routes.nextSibling);
      else if (anchor) container.insertBefore(contract, anchor);
      else container.append(contract);
    }
    return routes || contract;
  }

  function contractTable(titles, rows) {
    const table = el("table", undefined, "route-inventory-table");
    const header = el("tr");
    for (const title of titles) header.append(el("th", title));
    table.append(header);
    for (const cells of rows) {
      const row = el("tr");
      for (const cell of cells) row.append(el("td", cell));
      table.append(row);
    }
    return table;
  }

  function renderContract(audit) {
    const report = audit && audit.api_contract;
    if (!report || !report.summary || !report.summary.specs) return null;
    const s = report.summary;
    const section = el("details", undefined, "api-contract-report route-inventory-contract project-limitations");
    const head = el("summary");
    head.append(el("strong", "API sözleşmesi ↔ rotalar: "));
    head.append(document.createTextNode(
      `${s.specs} sözleşme · ${s.spec_operations} işlem · ${s.matched_operations} eşleşti · ${s.shadow_routes} gölge uç nokta · ${s.missing_in_code} kodda yok · ${s.auth_mismatch} kimlik uyuşmazlığı`,
    ));
    section.append(head);
    section.append(el("p", "Statik karşılaştırma: sözleşmedeki yollar koddaki rota envanteriyle (bağlama öneki bilinmiyorsa sonek eşleşmesiyle) ya da operationId ile eşlenir. Rota envanteri desteklenmeyen dillerdeki (ör. Java, Go) işlemler eşleşmez; bu durumda gölge/eksik uç nokta raporlanmaz."));
    section.append(contractTable(["Sözleşme", "Biçim", "İşlem", "Eşleşen", "operationId ile", "Kapsama"], (report.specs || []).map(spec => [
      spec.file, spec.format, spec.operations, spec.matched, spec.matched_by_operation_id, `${Math.round(Number(spec.coverage || 0) * 100)} %`,
    ])));
    if ((report.shadow || []).length) {
      section.append(el("h4", "Belgelenmemiş (gölge) uç noktalar"));
      section.append(contractTable(["Yöntem", "Yol", "Konum", "Koruma"], report.shadow.map(route => [
        route.method, route.path, `${route.file}:${Number(route.line) || 0}`, route.protected ? "korumalı" : "korumasız",
      ])));
    }
    if ((report.auth_mismatch || []).length) {
      section.append(el("h4", "Sözleşme kimlik doğrulama istiyor, kodda denetim yok"));
      section.append(contractTable(["Yöntem", "Yol", "Konum"], report.auth_mismatch.map(item => [
        item.method, item.path, `${item.file}:${Number(item.line) || 0}`,
      ])));
    }
    if ((report.missing || []).length) {
      section.append(el("h4", "Sözleşmede olup kodda bulunmayan işlemler"));
      section.append(contractTable(["Sözleşme", "Yöntem", "Yol"], report.missing.map(item => [item.spec, item.method, item.path])));
    }
    return section;
  }

  function renderRoutes(audit, container) {
    const previous = container.querySelector(".route-inventory:not(.route-inventory-contract)");
    if (previous) previous.remove();
    const inventory = audit && audit.route_inventory;
    if (!inventory || !inventory.summary || !inventory.summary.total) return null;
    const summary = inventory.summary;
    const section = el("details", undefined, "route-inventory project-limitations");
    const head = el("summary");
    head.append(el("strong", "Rota yetki envanteri: "));
    head.append(document.createTextNode(
      `${summary.total} rota · ${summary.protected} korumalı · ${summary.unprotected_sensitive} korumasız hassas · ${summary.idor_candidates} IDOR adayı`
      + (summary.truncated ? " (ilk 300 rota gösteriliyor)" : ""),
    ));
    section.append(head);
    section.append(el("p", "Statik tahmin: koruma; dekoratör, ara katman, guard, permission_classes, URL yapılandırması ya da satır içi denetimden çıkarılır. Ağ geçidi/proxy düzeyindeki kimlik doğrulama görünmez."));
    const table = el("table", undefined, "route-inventory-table");
    const header = el("tr");
    for (const title of ["Yöntem", "Yol", "Konum", "Koruma", "Not"]) header.append(el("th", title));
    table.append(header);
    for (const route of inventory.routes || []) {
      const row = el("tr", undefined, route.protection ? "protected" : "unprotected");
      row.append(el("td", (route.methods || []).join("/")));
      row.append(el("td", route.path || route.handler || "—"));
      row.append(el("td", `${route.file}:${Number(route.line) || 0}`));
      row.append(el("td", route.public ? "bilerek açık" : label(route.protection)));
      row.append(el("td", route.idor_candidate ? "IDOR adayı" : ""));
      table.append(row);
    }
    section.append(table);
    const anchor = container.querySelector(".project-finding-summary");
    if (anchor) container.insertBefore(section, anchor); else container.append(section);
    return section;
  }

  scope.renderRouteInventory = render;
  scope.renderApiContract = renderContract;
})();
