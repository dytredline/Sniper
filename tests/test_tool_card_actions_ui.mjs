import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";

const app = readFileSync(new URL("../static/app.js", import.meta.url), "utf8");
const html = readFileSync(new URL("../static/index.html", import.meta.url), "utf8");
const mapStart = app.indexOf("const TOOL_CARD_DESTINATIONS = Object.freeze({");
const renderStart = app.indexOf("function renderTooling() {");
const end = app.indexOf("\nfunction labScenarioLabel(", renderStart);
assert.ok(renderStart >= 0 && end > renderStart);
const source = app.slice(mapStart >= 0 ? mapStart : renderStart, end);

function setup(toolId, route, action, runtime = "precheck_passed") {
  const nodes = new Map();
  const clicks = [];
  const handlers = new Map();
  const panel = {
    scrollIntoView() { clicks.push("scroll"); },
    querySelector() { return { focus() { clicks.push("focus"); } }; },
  };
  const document = {
    addEventListener(type, handler) { handlers.set(type, handler); },
    querySelector(selector) {
      const match = selector.match(/\[data-action="([^"]+)"\]/);
      if (!match) return null;
      return html.includes(`data-action="${match[1]}"`)
        ? { click() { clicks.push(`open:${match[1]}`); } } : null;
    },
    getElementById(id) {
      return html.includes(`id="${id}"`) ? panel : null;
    },
  };
  const state = {
    tooling: {
      summary: {}, policy: { native: "", external: "", completion: "" }, categories: [],
      tools: [{ id: toolId, name: toolId, kind: "test", license: "test", summary: "test",
        formats: [], url: "https://example.test", workflows: [{ mode: "local", label: "Profil", routes: [route] }] }],
    },
    toolingReadiness: { tools: [{ id: toolId, profiles: [
      { route, action, runtime, label: "Profil", reason_code: "test" },
    ] }] },
  };
  const $ = selector => {
    if (!nodes.has(selector)) nodes.set(selector, { innerHTML: "", textContent: "" });
    return nodes.get(selector);
  };
  const esc = value => String(value).replace(/[&<>'"]/g, char =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[char]);
  const context = vm.createContext({ state, $, esc, document,
    navigate(view) { clicks.push(`view:${view}`); },
    api() { throw new Error("Opening a card must not make an API request"); },
    fetch() { throw new Error("Opening a card must not fetch"); },
  });
  vm.runInContext(`${source}\nrenderTooling();`, context);
  const card = nodes.get("#tool-card-grid").innerHTML;
  function click(cardRoute = route, disabled = false) {
    const button = { disabled, dataset: { toolRoute: cardRoute } };
    let prevented = false;
    handlers.get("click")?.({ target: { closest() { return button; } }, preventDefault() { prevented = true; } });
    return prevented;
  }
  return { card, click, clicks, context };
}

test("report-only card opens its existing import preview without a scan", () => {
  const ui = setup("dependabot", "/api/tool-reports/dependabot/summary", "report_only", "not_applicable");
  assert.match(ui.card, /Rapor önizlemesini aç/);
  assert.ok(ui.click());
  assert.deepEqual(ui.clicks, ["open:open-dependabot-alerts-preview"]);
});

test("CodeQL report-only card opens SARIF preview without starting analysis", () => {
  const ui = setup("codeql", "/api/tool-reports/sarif/summary", "report_only", "not_applicable");
  assert.match(ui.card, /Rapor önizlemesini aç/);
  assert.ok(ui.click());
  assert.deepEqual(ui.clicks, ["open:open-sarif-preview"]);
});

test("OSV-Scanner report-only card opens SARIF preview without starting analysis", () => {
  const ui = setup("osv-scanner", "/api/tool-reports/sarif/summary", "report_only", "not_applicable");
  assert.match(ui.card, /Rapor önizlemesini aç/);
  assert.ok(ui.click());
  assert.deepEqual(ui.clicks, ["open:open-sarif-preview"]);
});

test("Schemathesis report-only card opens JUnit preview without starting API tests", () => {
  const ui = setup("schemathesis", "/api/tool-reports/schemathesis-junit/summary", "report_only", "not_applicable");
  assert.match(ui.card, /Rapor önizlemesini aç/);
  assert.ok(ui.click());
  assert.deepEqual(ui.clicks, ["open:open-schemathesis-junit-preview"]);
});

test("SIEM saved evidence card opens local preview without log transport", () => {
  const ui = setup("siem-review", "/api/tool-reports/siem-ecs-ndjson/summary", "report_only", "not_applicable");
  assert.match(ui.card, /Rapor önizlemesini aç/);
  assert.ok(ui.click());
  assert.deepEqual(ui.clicks, ["open:open-siem-ecs-preview"]);
});

test("local card moves to the existing two-consent form without submitting it", () => {
  const ui = setup("npm-audit", "/api/tool-runs/npm-audit-local", "local_input_required");
  assert.match(ui.card, /data-tool-route="\/api\/tool-runs\/npm-audit-local"/);
  assert.ok(ui.click());
  assert.deepEqual(ui.clicks, ["scroll", "focus"]);
  assert.match(html, /id="npm-audit-active-local-consent"/);
  assert.match(html, /id="npm-audit-active-registry-consent"/);
});

test("authorized route opens consent form, while unknown and unavailable routes fail closed", () => {
  const ui = setup("nuclei", "/api/nuclei/http-scans", "authorization_required");
  assert.ok(ui.click());
  assert.deepEqual(ui.clicks, ["open:open-nuclei-http-scan"]);
  assert.equal(vm.runInContext('openToolCardRoute("/api/unknown")', ui.context), false);
  assert.deepEqual(ui.clicks, ["open:open-nuclei-http-scan"]);

  const unavailable = setup("gitleaks", "/api/tool-runs/gitleaks", "local_input_required", "unavailable");
  assert.doesNotMatch(unavailable.card, /data-tool-route=/);
  assert.doesNotMatch(unavailable.card, /gitleaks/);
  unavailable.click("/api/tool-runs/gitleaks", true);
  assert.deepEqual(unavailable.clicks, []);
});

test("external-only cards have no in-app scan action", () => {
  const ui = setup("codeql", "/api/unknown", "external_only", "not_applicable");
  assert.doesNotMatch(ui.card, /data-tool-route=/);
});
