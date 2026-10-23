import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";

const app = readFileSync(new URL("../static/app.js", import.meta.url), "utf8");
const html = readFileSync(new URL("../static/index.html", import.meta.url), "utf8");
const refreshCss = readFileSync(new URL("../static/ui-refresh.css", import.meta.url), "utf8");
const iconSprite = readFileSync(new URL("../static/ui-icons.svg", import.meta.url), "utf8");
const start = app.indexOf("const TOOL_CARD_DESTINATIONS = Object.freeze({");
const end = app.indexOf("\nfunction labScenarioLabel(", start);
assert.ok(start >= 0 && end > start);
const renderSource = app.slice(start, end);

function classList(initial = []) {
  const values = new Set(initial);
  return {
    contains(value) { return values.has(value); },
    toggle(value, force) {
      if (force === undefined ? !values.has(value) : force) values.add(value);
      else values.delete(value);
    },
  };
}

test("tool-specific panels follow readiness changes while shared built-in panels remain", () => {
  const nodes = new Map();
  const panelNodes = new Map([
    ["trivy-secret-panel", { classList: classList(["hidden"]) }],
    ["completed-backlog-panel", { classList: classList() }],
    ["advanced-tool-panel", { classList: classList() }],
  ]);
  const $ = selector => {
    if (!nodes.has(selector)) nodes.set(selector, { innerHTML: "", textContent: "" });
    return nodes.get(selector);
  };
  const esc = value => String(value).replace(/[&<>'"]/g, character =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[character]);
  const state = {
    tooling: {
      summary: { control_count: 1, category_count: 1 },
      policy: { native: "Yerleşik", external: "Harici", completion: "Uzman doğrular" },
      categories: [{ title: "Kod", reference: "WSTG", control_count: 1, coverage: "Kısmi", required_input: "Kaynak", tool_ids: ["trivy", "codeql"] }],
      tools: [
        { id: "trivy", name: "Trivy", kind: "SCA", license: "Açık", summary: "Yerel ve rapor", formats: ["JSON"], url: "https://example.test/trivy", workflows: [
          { mode: "local", label: "Yerel sır profili", routes: ["/api/tool-runs/trivy-secret"] },
          { mode: "report_import", label: "Kayıtlı rapor", routes: ["/api/tool-reports/trivy-native-json/summary"] },
        ] },
        { id: "codeql", name: "CodeQL", kind: "SAST", license: "GitHub", summary: "Harici", formats: ["SARIF"], url: "https://example.test/codeql", workflows: [
          { mode: "external", label: "Harici analiz", routes: [] },
        ] },
      ],
    },
    toolingReadiness: { tools: [
      { id: "trivy", profiles: [
        { label: "Yerel sır profili", route: "/api/tool-runs/trivy-secret", runtime: "unavailable", action: "local_input_required" },
        { label: "Kayıtlı rapor", route: "/api/tool-reports/trivy-native-json/summary", runtime: "not_applicable", action: "report_only" },
      ] },
      { id: "codeql", profiles: [
        { label: "Harici analiz", route: null, runtime: "not_applicable", action: "external_only" },
      ] },
    ] },
  };
  const document = {
    addEventListener() {},
    getElementById(id) { return panelNodes.get(id) || null; },
  };
  const context = vm.createContext({ state, $, esc, document });
  vm.runInContext(`${renderSource}\nrenderTooling();`, context);

  assert.equal(panelNodes.get("trivy-secret-panel").classList.contains("hidden"), true);
  assert.equal(panelNodes.get("completed-backlog-panel").classList.contains("hidden"), false);
  assert.equal(panelNodes.get("advanced-tool-panel").classList.contains("hidden"), false);
  assert.doesNotMatch(nodes.get("#tool-card-grid").innerHTML, /Yerel sır profili/);
  assert.match(nodes.get("#tool-card-grid").innerHTML, /Kayıtlı rapor/);
  assert.doesNotMatch(nodes.get("#tool-card-grid").innerHTML, /CodeQL|Harici analiz/);
  assert.doesNotMatch(nodes.get("#tool-matrix-body").innerHTML, /CodeQL/);

  state.toolingReadiness.tools[0].profiles[0].runtime = "precheck_passed";
  vm.runInContext("renderTooling();", context);
  assert.equal(panelNodes.get("trivy-secret-panel").classList.contains("hidden"), false);
  assert.match(nodes.get("#tool-card-grid").innerHTML, /Yerel sır profili/);
});

test("tool-specific static panels start hidden without hiding shared panels", () => {
  assert.match(html, /<section class="panel hidden" id="trivy-secret-panel"/);
  assert.match(html, /<section class="panel hidden" id="joern-deep-panel"/);
  assert.match(html, /<section class="panel" id="completed-backlog-panel"/);
  assert.match(html, /<section class="panel" id="advanced-tool-panel"/);
});

test("missing readiness exposes only safe catalog fallbacks with a warning", () => {
  const nodes = new Map();
  const $ = selector => {
    if (!nodes.has(selector)) nodes.set(selector, { innerHTML: "", textContent: "" });
    return nodes.get(selector);
  };
  const esc = value => String(value).replace(/[&<>'"]/g, character =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[character]);
  const workflow = (mode, label, route) => ({ mode, label, routes: route ? [route] : [] });
  const tool = (id, name, workflows) => ({
    id, name, kind: "Test", license: "Test", summary: `${name} summary`, formats: ["JSON"],
    url: `https://example.test/${id}`, workflows,
  });
  const state = {
    tooling: {
      summary: { control_count: 1, category_count: 1 },
      policy: { native: "Yerleşik", external: "Harici", completion: "Uzman doğrular" },
      categories: [{
        title: "Kod", reference: "WSTG", control_count: 1, coverage: "Kısmi", required_input: "Kaynak",
        tool_ids: ["builtin", "report", "local", "authorized", "external", "manual"],
      }],
      tools: [
        tool("builtin", "Built-in", [workflow("built_in", "Yerleşik denetim", "/api/business-logic/audit")]),
        tool("report", "Report", [workflow("report_import", "Rapor içe aktar", "/api/tool-reports/sarif/summary")]),
        tool("local", "Local", [workflow("local", "Yerel çalıştır", "/api/tool-runs/trivy-secret")]),
        tool("authorized", "Authorized", [workflow("authorized", "Yetkili hedef", "/api/nmap/tcp-scan")]),
        tool("external", "External", [workflow("external", "Harici", null)]),
        tool("manual", "Manual", [workflow("manual", "Manuel", null)]),
      ],
    },
    toolingReadiness: null,
  };
  const completedPanel = { scrollIntoView() {}, querySelector() { return null; } };
  const reportOpener = { click() {} };
  const document = {
    addEventListener() {},
    getElementById(id) { return id === "completed-backlog-panel" ? completedPanel : null; },
    querySelector() { return reportOpener; },
  };
  const context = vm.createContext({ state, $, esc, document });
  vm.runInContext(`${renderSource}\nrenderTooling();`, context);

  assert.match(nodes.get("#tooling-policy").innerHTML, /uygunluk durumu alınamadı/i);
  assert.match(nodes.get("#tool-card-grid").innerHTML, /Built-in|Yerleşik denetim/);
  assert.match(nodes.get("#tool-card-grid").innerHTML, /Report|Rapor içe aktar/);
  assert.doesNotMatch(nodes.get("#tool-card-grid").innerHTML, /Local|Yerel çalıştır/);
  assert.doesNotMatch(nodes.get("#tool-card-grid").innerHTML, /Authorized|Yetkili hedef/);
  assert.doesNotMatch(nodes.get("#tool-card-grid").innerHTML, /External|Harici/);
  assert.doesNotMatch(nodes.get("#tool-card-grid").innerHTML, /Manual|Manuel/);
  assert.equal(nodes.get("#tool-count-label").textContent, "2 kullanılabilir araç/yöntem");

  assert.equal(vm.runInContext('openToolCardRoute("/api/business-logic/audit")', context), true);
  assert.equal(vm.runInContext('openToolCardRoute("/api/tool-reports/sarif/summary")', context), true);
  assert.equal(vm.runInContext('openToolCardRoute("/api/tool-runs/trivy-secret")', context), false);
});

test("repeated built-in routes render as one readable capability and one action", () => {
  const nodes = new Map();
  const $ = selector => {
    if (!nodes.has(selector)) nodes.set(selector, { innerHTML: "", textContent: "" });
    return nodes.get(selector);
  };
  const esc = value => String(value).replace(/[&<>'"]/g, character =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[character]);
  const routes = [
    "/api/secret-intelligence/audit",
    "/api/privacy-dataflow/audit",
    "/api/business-logic/audit",
  ];
  const state = {
    tooling: {
      summary: { control_count: 3, category_count: 1 },
      policy: { native: "Yerleşik", external: "Harici", completion: "Uzman doğrular" },
      categories: [{
        title: "Kod", reference: "ASVS", control_count: 3, coverage: "Yerleşik",
        required_input: "Kaynak", tool_ids: ["sniper-auditors"],
      }],
      tools: [{
        id: "sniper-auditors", name: "Sniper Yerleşik Denetçiler", kind: "SAST", license: "Yerleşik",
        summary: "Yerel denetçiler", formats: ["JSON"], url: "https://example.test/auditors",
        workflows: [{ mode: "built_in", label: "Satır içi / proje kod denetçileri", routes }],
      }],
    },
    toolingReadiness: {
      tools: [{ id: "sniper-auditors", profiles: routes.map(route => ({
        label: "Satır içi / proje kod denetçileri", route,
        runtime: "precheck_passed", action: "native",
      })) }],
      binary_pins: [],
    },
  };
  const panel = { classList: classList(), scrollIntoView() {}, querySelector() { return null; } };
  const document = {
    addEventListener() {},
    getElementById(id) { return id === "completed-backlog-panel" ? panel : null; },
    querySelector() { return null; },
  };
  const context = vm.createContext({ state, $, esc, document });
  vm.runInContext(`${renderSource}\nrenderTooling();`, context);

  const card = nodes.get("#tool-card-grid").innerHTML;
  assert.equal((card.match(/Satır içi \/ proje kod denetçileri/g) || []).length, 1,
    "the capability label should appear once even when several routes implement it");
  assert.equal((card.match(/data-tool-route=/g) || []).length, 1);
  assert.match(nodes.get("#tooling-summary").innerHTML,
    /<small>KULLANILABİLİR AKIŞ<\/small><b>1<\/b>/);
});

test("npm audit saved-report capability is named once with distinct compact actions", () => {
  const nodes = new Map();
  const $ = selector => {
    if (!nodes.has(selector)) nodes.set(selector, { innerHTML: "", textContent: "" });
    return nodes.get(selector);
  };
  const esc = value => String(value).replace(/[&<>'"]/g, character =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[character]);
  const label = "Kaydedilmiş rapor ve salt-okunur düzeltme planı özeti";
  const routes = ["/api/tool-reports/npm-audit/summary", "/api/tool-reports/dependency-remediation-plan"];
  const state = {
    tooling: {
      summary: {}, policy: { native: "", external: "", completion: "" }, categories: [],
      tools: [{ id: "npm-audit", name: "npm audit", kind: "SCA", license: "npm", summary: "test",
        formats: ["JSON"], url: "https://example.test/npm", workflows: [] }],
    },
    toolingReadiness: { tools: [{ id: "npm-audit", profiles: routes.map(route => ({
      label, route, runtime: "not_applicable", action: "report_only",
    })) }], binary_pins: [] },
  };
  const document = { addEventListener() {}, getElementById() { return null; }, querySelector() { return null; } };
  const context = vm.createContext({ state, $, esc, document });
  vm.runInContext(`${renderSource}\nrenderTooling();`, context);
  const card = nodes.get("#tool-card-grid").innerHTML;
  assert.equal((card.match(new RegExp(label, "g")) || []).length, 1);
  assert.equal((card.match(/data-tool-route=/g) || []).length, 2);
  assert.match(card, /Rapor özeti/);
  assert.match(card, /Düzeltme planı/);
});

test("tool cards keep text on the pixel grid during hover", () => {
  const hoverRule = refreshCss.match(/\.tool-card:hover\s*\{([^}]*)\}/)?.[1] || "";
  assert.ok(hoverRule, "tool card hover rule must exist");
  assert.doesNotMatch(hoverRule, /transform\s*:/);
  const summaryRule = refreshCss.match(/\.tooling-summary article:hover[^\{]*\{([^}]*)\}/)?.[1] || "";
  assert.ok(summaryRule, "summary hover rule must exist");
  assert.doesNotMatch(summaryRule, /transform\s*:/);
  const actionRule = refreshCss.match(/\.tool-card \.button\s*\{([^}]*)\}/)?.[1] || "";
  assert.ok(actionRule, "tool card action rule must exist");
  assert.doesNotMatch(actionRule, /transition\s*:[^;]*transform/);
  const actionHoverRule = refreshCss.match(/\.tool-card \.button:hover:not\(:disabled\)[^\{]*\{([^}]*)\}/)?.[1] || "";
  assert.ok(actionHoverRule, "tool card action hover rule must exist");
  assert.match(actionHoverRule, /transform\s*:\s*none/);
});

test("all tooling buttons stay on the pixel grid and capability copy keeps full row width", () => {
  const toolingButtonRule = refreshCss.match(/\.view\[data-view=["']tooling["']\] \.button\s*\{([^}]*)\}/)?.[1] || "";
  assert.ok(toolingButtonRule, "tooling-wide button rule must exist");
  assert.doesNotMatch(toolingButtonRule, /transition\s*:[^;]*transform/);
  const toolingHoverRule = refreshCss.match(/\.view\[data-view=["']tooling["']\] \.button:hover:not\(:disabled\)[^\{]*\{([^}]*)\}/)?.[1] || "";
  assert.ok(toolingHoverRule, "tooling-wide hover rule must exist");
  assert.match(toolingHoverRule, /transform\s*:\s*none/);

  const capabilityRule = refreshCss.match(/\.tool-capability\s*\{([^}]*)\}/)?.[1] || "";
  assert.ok(capabilityRule, "tool capability layout rule must exist");
  assert.match(capabilityRule, /grid-template-columns\s*:\s*minmax\(0,1fr\)/);
  assert.doesNotMatch(capabilityRule, /grid-template-columns\s*:[^;]*\sauto/);
  const actionRowRule = refreshCss.match(/\.tool-capability \.tool-card-actions\s*\{([^}]*)\}/)?.[1] || "";
  assert.match(actionRowRule, /justify-content\s*:\s*flex-start/);
});

test("tool summaries do not stretch and push formats to the bottom of tall cards", () => {
  const summaryRule = refreshCss.match(/\.tool-card > p\s*\{([^}]*)\}/)?.[1] || "";
  assert.ok(summaryRule, "direct tool summary rule must exist");
  assert.match(summaryRule, /flex\s*:\s*0 0 auto/);
});

test("tool card note and official page stay together at the card bottom", () => {
  const footerRule = refreshCss.match(/\.tool-card > small\s*\{([^}]*)\}/)?.[1] || "";
  assert.ok(footerRule, "tool-card footer positioning rule must exist");
  assert.match(footerRule, /margin-top\s*:\s*auto/);
});

test("tooling controls animate the box surface without transforming text", () => {
  const miniRule = refreshCss.match(/\.view\[data-view=["']tooling["']\] \.mini-button\s*\{([^}]*)\}/)?.[1] || "";
  assert.ok(miniRule, "tooling mini-button stabilization rule must exist");
  assert.doesNotMatch(miniRule, /transition\s*:[^;]*transform/);
  assert.match(miniRule, /transform\s*:\s*none/);

  const surfaceRule = refreshCss.match(/\.view\[data-view=["']tooling["']\] :is\(\.button,\.mini-button\)::after\s*\{([^}]*)\}/)?.[1] || "";
  assert.ok(surfaceRule, "tooling button surface animation must exist");
  assert.match(surfaceRule, /transform\s*:\s*none/);
  assert.doesNotMatch(surfaceRule, /transition\s*:[^;]*transform/);
  const surfaceHoverRule = refreshCss.match(/\.view\[data-view=["']tooling["']\] :is\(\.button,\.mini-button\):hover:not\(:disabled\)::after\s*\{([^}]*)\}/)?.[1] || "";
  assert.doesNotMatch(surfaceHoverRule, /transform\s*:/);

  const surfaceHostRule = refreshCss.match(/\.view\[data-view=["']tooling["']\] :is\(\.button,\.mini-button\)\s*\{([^}]*)\}/)?.[1] || "";
  assert.match(surfaceHostRule, /background\s*:\s*transparent/);
  assert.match(surfaceHostRule, /isolation\s*:\s*isolate/);
  assert.match(surfaceHostRule, /top\s*:\s*0/);
  assert.match(surfaceHostRule, /transition\s*:[^;]*top\s+\.18s\s+steps\(2,end\)/);
  const hostHoverRule = refreshCss.match(/\.view\[data-view=["']tooling["']\] :is\(\.button,\.mini-button\):hover:not\(:disabled\),\s*\n?\.view\[data-view=["']tooling["']\] :is\(\.button,\.mini-button\):active:not\(:disabled\)\s*\{([^}]*)\}/)?.[1] || "";
  assert.match(hostHoverRule, /top\s*:\s*-2px/);
  assert.match(hostHoverRule, /transform\s*:\s*none/);

  const rowRule = refreshCss.match(/\.view\[data-view=["']tooling["']\] \.button-row > :is\(\.button,\.mini-button\)\s*\{([^}]*)\}/)?.[1] || "";
  assert.match(rowRule, /min-height\s*:\s*42px/);
  assert.match(rowRule, /align-self\s*:\s*stretch/);

  const rowLayoutRule = refreshCss.match(/\.view\[data-view=["']tooling["']\] \.button-row\s*\{([^}]*)\}/)?.[1] || "";
  assert.match(rowLayoutRule, /display\s*:\s*flex/);
  assert.match(rowLayoutRule, /align-items\s*:\s*stretch/);
});

test("view and card entrance animations do not translate text layers", () => {
  const viewFrames = refreshCss.match(/@keyframes ui-view-in\s*\{([^}]*(?:\}[^}]*)?)\}/)?.[0] || "";
  const cardFrames = refreshCss.match(/@keyframes ui-card-in\s*\{([^}]*(?:\}[^}]*)?)\}/)?.[0] || "";
  assert.ok(viewFrames, "view entrance keyframes must exist");
  assert.ok(cardFrames, "card entrance keyframes must exist");
  assert.doesNotMatch(viewFrames, /transform\s*:/);
  assert.doesNotMatch(cardFrames, /transform\s*:/);
});

test("application analysis launchers keep checkbox and form controls aligned", () => {
  assert.match(refreshCss, /\.project-audit-launcher input\[type=["']checkbox["']\]\s*\{/);
  const containerRule = refreshCss.match(/\.container-scan-launcher form\.container-scan-form\s*\{([^}]*)\}/)?.[1] || "";
  assert.ok(containerRule, "container launcher layout rule must exist");
  assert.match(containerRule, /grid-template-columns\s*:\s*minmax\(0,1\.2fr\)\s+minmax\(0,1fr\)/);
});

test("application analysis uses crisp SVG symbols inside green icon tiles", () => {
  assert.match(html, /class="project-audit-icon"[^>]*>\s*<svg class="ui-symbol"[^>]*><use href="\/static\/ui-icons\.svg#folder-code"/);
  assert.match(html, /id="project-audit-empty"[\s\S]*?class="empty-icon"[^>]*>\s*<svg class="ui-symbol"[^>]*><use href="\/static\/ui-icons\.svg#code"/);
  assert.match(html, /id="dependency-empty"[\s\S]*?class="empty-icon"[^>]*>\s*<svg class="ui-symbol"[^>]*><use href="\/static\/ui-icons\.svg#package"/);
  assert.match(iconSprite, /<symbol id="package"/);
  assert.match(iconSprite, /<symbol id="folder-code"/);
  assert.match(iconSprite, /<symbol id="container"/);
  assert.match(iconSprite, /<symbol id="repositories"/);
  assert.doesNotMatch(html, /class="project-audit-icon">&lt;\/&gt;/);
});

test("basic scan modal keeps its copy and scope rows in a compact top-aligned flow", () => {
  const modalCopyRule = refreshCss.match(/#scan-target-label\s*\{([^}]*)\}/)?.[1] || "";
  assert.ok(modalCopyRule, "basic scan target copy rule must exist");
  assert.match(modalCopyRule, /margin\s*:\s*8px 0 14px/);
  const scopeRule = refreshCss.match(/#scan-modal \.scope-list > div\s*\{([^}]*)\}/)?.[1] || "";
  assert.ok(scopeRule, "basic scan scope row rule must exist");
  assert.match(scopeRule, /align-items\s*:\s*flex-start/);
  const scopeIconRule = refreshCss.match(/#scan-modal \.scope-list > div > span\s*\{([^}]*)\}/)?.[1] || "";
  assert.match(scopeIconRule, /flex\s*:\s*0 0 22px/);
});

test("Community interface shows the v1 product identity", () => {
  assert.match(html, /SNIPER 1\.0/);
  assert.doesNotMatch(html, /SNIPER 2\.0|Sniper 2\.0/);
});
