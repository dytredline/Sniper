import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";

const app = readFileSync(new URL("../static/app.js", import.meta.url), "utf8");
const html = readFileSync(new URL("../static/index.html", import.meta.url), "utf8");
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
