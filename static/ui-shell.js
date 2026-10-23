/* Görsel kabuk: ikonlar, pencere boyutu ve dar ekran menüsü. Ağ isteği yapmaz. */
(() => {
  "use strict";
  const glyphs = new Map([["◎", "target"], ["⌘", "layers"], ["!", "warning"], ["↻", "history"],
    ["</>", "code"], ["✓", "check"], ["◫", "flask"], ["◇", "layers"], ["↗", "activity"], ["⌁", "shield"], ["#", "report"]]);
  const paintIcons = root => {
    for (const icon of root.querySelectorAll(".metric-icon, .empty-icon, .project-audit-icon, .lab-scenario-icon, .safe-note > span, .pentest-banner > span, .lab-guard > span")) {
      if (icon.dataset.uiGlyph) continue;
      const name = glyphs.get(icon.textContent.trim());
      if (!name) continue;
      const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
      const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
      use.setAttribute("href", `/static/ui-icons.svg#${name}`);
      svg.setAttribute("class", "ui-symbol");
      svg.setAttribute("aria-hidden", "true");
      svg.append(use);
      icon.dataset.uiGlyph = name;
      icon.setAttribute("aria-hidden", "true");
      icon.replaceChildren(svg);
    }
  };
  paintIcons(document);
  for (const host of document.querySelectorAll(".metric-grid, .target-rows, #dependency-report-findings")) {
    new MutationObserver(() => paintIcons(host)).observe(host, { childList: true });
  }
  const windowIcon = name => {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
    svg.setAttribute("class", "ui-symbol");
    svg.setAttribute("aria-hidden", "true");
    use.setAttribute("href", `/static/ui-icons.svg#${name}`);
    svg.append(use);
    return svg;
  };
  for (const panel of document.querySelectorAll(".modal, .drawer, .workspace")) {
    const closeButton = panel.querySelector(".modal-close[data-close]");
    if (!closeButton) continue;
    panel.classList.add("ui-window");
    closeButton.classList.add("ui-window-control", "ui-window-close");
    closeButton.setAttribute("title", "Kapat");
    if (closeButton.textContent.trim() === "×") closeButton.replaceChildren(windowIcon("close"));
    // Workspace zaten ekranı kaplar; mevcut kapatma davranışına dokunulmaz.
    if (panel.classList.contains("workspace")) continue;
    const resizeButton = document.createElement("button");
    resizeButton.type = "button";
    resizeButton.className = "ui-window-control ui-window-resize";
    const syncSize = () => {
      const expanded = panel.classList.contains("ui-window-expanded");
      const label = expanded ? "Önceki boyuta dön" : "Pencereyi büyüt";
      resizeButton.setAttribute("aria-label", label);
      resizeButton.setAttribute("title", label);
      resizeButton.setAttribute("aria-pressed", String(expanded));
      resizeButton.replaceChildren(windowIcon(expanded ? "restore" : "expand"));
    };
    resizeButton.addEventListener("click", () => {
      panel.classList.toggle("ui-window-expanded");
      syncSize();
    });
    closeButton.after(resizeButton);
    syncSize();
    const backdrop = panel.closest(".modal-backdrop, .drawer-backdrop");
    if (backdrop) new MutationObserver(() => {
      if (backdrop.classList.contains("hidden") && panel.classList.contains("ui-window-expanded")) {
        panel.classList.remove("ui-window-expanded");
        syncSize();
      }
    }).observe(backdrop, { attributes: true, attributeFilter: ["class"] });
  }
  const sidebar = document.querySelector(".sidebar");
  const menu = document.getElementById("mobile-menu");
  const main = document.querySelector(".main");
  const scrim = document.querySelector(".ui-nav-scrim");
  if (!sidebar || !menu || !main || !scrim) return;
  const mobile = matchMedia("(max-width: 900px)");
  let wasOpen = false;
  let previousInert = main.inert;
  const close = () => sidebar.classList.remove("open");
  const sync = () => {
    const open = mobile.matches && sidebar.classList.contains("open");
    menu.setAttribute("aria-expanded", String(open));
    scrim.classList.toggle("is-visible", open);
    document.body.classList.toggle("ui-nav-open", open);
    if (open && !wasOpen) {
      previousInert = main.inert;
      main.inert = true;
      sidebar.querySelector(".nav-item.active, .sidebar-close")?.focus();
    } else if (!open && wasOpen) {
      main.inert = previousInert;
      if (mobile.matches) menu.focus();
    }
    sidebar.inert = mobile.matches && !open;
    wasOpen = open;
  };
  sidebar.querySelector(".sidebar-close")?.addEventListener("click", close);
  scrim.addEventListener("click", close);
  document.addEventListener("keydown", event => {
    if (!wasOpen) return;
    if (event.key === "Escape") { event.preventDefault(); close(); }
    if (event.key === "Tab") {
      const items = [...sidebar.querySelectorAll("a[href], button:not(:disabled), select")].filter(item => item.getClientRects().length);
      const first = items[0], last = items.at(-1);
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
    }
  });
  new MutationObserver(sync).observe(sidebar, { attributes: true, attributeFilter: ["class"] });
  mobile.addEventListener("change", () => { close(); sync(); });
  for (const item of sidebar.querySelectorAll(".nav-item")) {
    item.setAttribute("title", item.textContent.trim());
    item.setAttribute("aria-label", item.textContent.trim());
  }
  sync();
})();
