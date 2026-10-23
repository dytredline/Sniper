import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";

const source = readFileSync(new URL("../static/playwright_json_preview.js", import.meta.url), "utf8");
function setup(reply) {
  const nodes = new Map(), listeners = new Map(), calls = [], modals = [];
  function node(id) {
    if (nodes.has(id)) return nodes.get(id);
    const classes = new Set(["hidden"]), nodeListeners = new Map();
    const result = { id, value: "", files: [], textContent: "", disabled: false,
      classList: { add(name) { classes.add(name); }, remove(name) { classes.delete(name); },
        contains(name) { return classes.has(name); } },
      addEventListener(name, callback) { const group = nodeListeners.get(name) || [];
        group.push(callback); nodeListeners.set(name, group); },
      dispatchEvent(event) { for (const callback of nodeListeners.get(event.type) || []) callback(event); },
      querySelector() { return node("submit-button"); } };
    nodes.set(id, result); return result;
  }
  const document = { getElementById: node,
    addEventListener(name, callback) { const group = listeners.get(name) || [];
      group.push(callback); listeners.set(name, group); } };
  vm.runInNewContext(source, { document, TextEncoder,
    showModal(id, visible) { modals.push([id, visible]); },
    async api(route, options) { calls.push([route, options]); return reply; } });
  async function dispatch(name, target) { for (const callback of listeners.get(name) || [])
    await callback({ target, preventDefault() {} }); }
  return { node, calls, modals, dispatch };
}

test("saved Playwright JSON renders only aggregate runtime outcomes", async () => {
  const app = setup({ format: "playwright-json", file_count: 1, test_count: 3,
    outcome_counts: { expected: 1, skipped: 0, unexpected: 1, flaky: 1 },
    report_sha256: "a".repeat(64), private_error: "SECRET traceback" });
  await app.dispatch("click", { closest(selector) { return selector.includes("data-action") ? this : null; }, id: "open" });
  assert.deepEqual(app.modals, [["playwright-json-preview-modal", true]]);
  const report = { config: {}, suites: [{ specs: [] }], errors: [{ message: "SECRET" }], stats: {} };
  app.node("playwright-json-paste").value = JSON.stringify(report);
  await app.dispatch("submit", app.node("playwright-json-preview-form"));
  assert.equal(app.calls.length, 1);
  assert.equal(app.calls[0][0], "/api/tool-reports/playwright-json/summary");
  assert.deepEqual(JSON.parse(app.calls[0][1].body), { report });
  assert.equal(app.node("playwright-json-test-count").textContent, "3");
  assert.match(app.node("playwright-json-outcomes").textContent, /beklenmeyen:1/);
  assert.equal(app.node("playwright-json-preview-result").classList.contains("hidden"), false);
  const displayed = ["file-count", "test-count", "outcomes", "report-sha256"].
    map(key => app.node(`playwright-json-${key}`).textContent).join(" ");
  assert.doesNotMatch(displayed, /SECRET|traceback/);
});

test("invalid aggregate and oversized input fail closed", async () => {
  const app = setup({ format: "playwright-json", file_count: 1, test_count: 2,
    outcome_counts: { expected: 1, skipped: 0, unexpected: 0, flaky: 0 },
    report_sha256: "a".repeat(64) });
  app.node("playwright-json-paste").value = "x".repeat(60001);
  await app.dispatch("submit", app.node("playwright-json-preview-form"));
  assert.equal(app.calls.length, 0);
  assert.equal(app.node("playwright-json-preview-error").classList.contains("hidden"), false);
  app.node("playwright-json-paste").value = "{}";
  await app.dispatch("submit", app.node("playwright-json-preview-form"));
  assert.equal(app.calls.length, 1);
  assert.equal(app.node("playwright-json-preview-result").classList.contains("hidden"), true);
  assert.equal(app.node("playwright-json-test-count").textContent, "");
});

test("catalog route opens the installed Playwright preview UI", () => {
  const html = readFileSync(new URL("../static/index.html", import.meta.url), "utf8");
  const app = readFileSync(new URL("../static/app.js", import.meta.url), "utf8");
  assert.match(html, /playwright_json_preview\.js/);
  assert.match(html, /data-action="open-playwright-json-preview"/);
  assert.match(app, /"\/api\/tool-reports\/playwright-json\/summary": \{ action: "open-playwright-json-preview" \}/);
});
