import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";

const app = readFileSync(new URL("../static/app.js", import.meta.url), "utf8");
const start = app.indexOf("const TOOL_CARD_DESTINATIONS = Object.freeze({");
const end = app.indexOf("\nfunction labScenarioLabel(", start);
assert.ok(start >= 0 && end > start);
const renderSource = app.slice(start, end);

test("tool cards distinguish runnable profiles from report-only and external methods", () => {
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
  };
  vm.runInNewContext(`${renderSource}\nrenderTooling();`, { state, $, esc, document: { addEventListener() {} } });
  const html = nodes.get("#tool-card-grid").innerHTML;
  const cards = [...html.matchAll(/<article class="tool-card">([\s\S]*?)<\/article>/g)].map(match => match[1]);
  assert.equal(cards.length, 3);
  assert.match(cards[0], /Yerel sır profili/);
  assert.match(cards[0], /\/api\/tool-runs\/trivy-secret/);
  assert.match(cards[0], /Çalıştırma için gerekli ikili, izin ve kapsam/);
  assert.match(cards[1], /Kaydedilmiş rapor özeti/);
  assert.match(cards[1], /Öneri veya rapor özeti taramayı başlatmaz/);
  assert.doesNotMatch(cards[1], /Çalıştırma için gerekli/);
  assert.match(cards[2], /Harici araç önerisi/);
  assert.match(cards[2], /Sniper içinde otomatik çalışmaz/);
  assert.match(nodes.get("#tooling-summary").innerHTML, /SNIPER'DA TANIMLI AKIŞ/);
  assert.match(nodes.get("#tooling-summary").innerHTML, />2<\/b>/);
});
