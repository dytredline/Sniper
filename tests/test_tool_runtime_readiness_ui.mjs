import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";

const app = readFileSync(new URL("../static/app.js", import.meta.url), "utf8");
const start = app.indexOf("const TOOL_CARD_DESTINATIONS = Object.freeze({");
const end = app.indexOf("\nfunction labScenarioLabel(", start);
assert.ok(start >= 0 && end > start);
const renderSource = app.slice(start, end);

test("tool cards show per-route prerequisite and authorization states without raw configuration", () => {
  const nodes = new Map();
  const $ = selector => {
    if (!nodes.has(selector)) nodes.set(selector, { innerHTML: "", textContent: "" });
    return nodes.get(selector);
  };
  const esc = value => String(value).replace(/[&<>'"]/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[char]);
  const state = {
    tooling: {
      summary: { control_count: 1, category_count: 0, tool_count: 2, integrated_workflow_tool_count: 2 },
      policy: { native: "Yerleşik", external: "Harici", completion: "Uzman doğrular" },
      categories: [],
      tools: [
        { id: "nmap", name: "Nmap", kind: "Ağ", license: "Açık", summary: "İzinli", formats: ["XML"], url: "https://example.test/nmap", workflows: [{ mode: "authorized", label: "İzinli profil", routes: ["/api/nmap/tcp-scan"] }] },
        { id: "burp-suite", name: "Burp", kind: "Web", license: "Ticari", summary: "Rapor", formats: ["XML"], url: "https://example.test/burp", workflows: [{ mode: "report_import", label: "Rapor", routes: ["/api/tool-reports/burp-sitemap/summary"] }] },
      ],
    },
    toolingReadiness: { tools: [
      { id: "nmap", profiles: [{ label: "İzinli profil", route: "/api/nmap/tcp-scan", runtime: "precheck_passed", action: "authorization_required", reason_code: "binary_found" }] },
      { id: "burp-suite", profiles: [{ label: "Rapor", route: "/api/tool-reports/burp-sitemap/summary", runtime: "not_applicable", action: "report_only", reason_code: "no_local_scan" }] },
    ] },
  };
  vm.runInNewContext(`${renderSource}\nrenderTooling();`, { state, $, esc, document: { addEventListener() {} } });
  const cards = [...nodes.get("#tool-card-grid").innerHTML.matchAll(/<article class="tool-card">([\s\S]*?)<\/article>/g)].map(match => match[1]);
  assert.match(cards[0], /Ön koşul bulundu · hedef izni gerekli/);
  assert.match(cards[1], /Yalnız rapor özeti/);
  assert.doesNotMatch(cards[1], /Ön koşul bulundu/);
  assert.doesNotMatch(nodes.get("#tool-card-grid").innerHTML, /SNIPER_NMAP_BINARY/);
});
