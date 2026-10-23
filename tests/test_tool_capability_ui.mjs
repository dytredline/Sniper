import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";

const app = readFileSync(new URL("../static/app.js", import.meta.url), "utf8");
const start = app.indexOf("const TOOL_CARD_DESTINATIONS = Object.freeze({");
const end = app.indexOf("\nfunction labScenarioLabel(", start);
assert.ok(start >= 0 && end > start);
const renderSource = app.slice(start, end);

test("Community tool cards omit unavailable and external-only methods", () => {
  const nodes = new Map();
  const $ = selector => {
    if (!nodes.has(selector)) nodes.set(selector, { innerHTML: "", textContent: "" });
    return nodes.get(selector);
  };
  const esc = value => String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;").replaceAll('"', "&quot;");
  const state = {
    tooling: {
      summary: { control_count: 161, category_count: 19, tool_count: 3, integrated_workflow_tool_count: 2 },
      policy: { native: "Yerleşik", external: "Harici öneri tarama değildir", completion: "Uzman doğrular" },
      categories: [],
      tools: [
        { id: "trivy", name: "Trivy", kind: "SCA", license: "Açık kaynak", summary: "Yerel", formats: ["JSON"], url: "https://example.test/trivy", workflows: [{ mode: "local", label: "Yerel sır profili", routes: ["/api/tool-runs/trivy-secret"] }] },
        { id: "burp-suite", name: "Burp Suite", kind: "DAST", license: "Ticari", summary: "Rapor", formats: ["XML"], url: "https://example.test/burp", workflows: [{ mode: "report_import", label: "Kaydedilmiş rapor özeti", routes: ["/api/tool-reports/burp-sitemap/summary"] }] },
        { id: "codeql", name: "CodeQL", kind: "SAST", license: "GitHub", summary: "Harici", formats: ["SARIF"], url: "https://example.test/codeql", workflows: [{ mode: "external", label: "Harici araç önerisi", routes: [] }] },
      ],
    },
    toolingReadiness: { tools: [
      { id: "trivy", profiles: [{ label: "Yerel sır profili", route: "/api/tool-runs/trivy-secret", runtime: "unavailable", action: "local_input_required", reason_code: "binary_unavailable" }] },
      { id: "burp-suite", profiles: [{ label: "Kaydedilmiş rapor özeti", route: "/api/tool-reports/burp-sitemap/summary", runtime: "not_applicable", action: "report_only", reason_code: "no_local_scan" }] },
      { id: "codeql", profiles: [{ label: "Harici araç önerisi", route: null, runtime: "not_applicable", action: "external_only", reason_code: "no_local_scan" }] },
    ] },
  };
  vm.runInNewContext(`${renderSource}\nrenderTooling();`, { state, $, esc, document: { addEventListener() {} } });
  const html = nodes.get("#tool-card-grid").innerHTML;
  const cards = [...html.matchAll(/<article class="tool-card">([\s\S]*?)<\/article>/g)].map(match => match[1]);
  assert.equal(cards.length, 1);
  assert.match(cards[0], /Burp Suite/);
  assert.match(cards[0], /Kaydedilmiş rapor özeti/);
  assert.doesNotMatch(html, /Trivy|CodeQL|Ön koşul eksik|Harici araç önerisi/);
  assert.equal(nodes.get("#tool-count-label").textContent, "1 kullanılabilir araç/yöntem");
  assert.match(nodes.get("#tooling-summary").innerHTML, /COMMUNITY'DE GÖRÜNEN/);
});

test("Community hides the duplicate static tool launcher", () => {
  const html = readFileSync(new URL("../static/index.html", import.meta.url), "utf8");
  assert.match(html, /<details class="ui-tool-launcher" hidden>/);
});
