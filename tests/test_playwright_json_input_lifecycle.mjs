import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";

const source = readFileSync(new URL("../static/playwright_json_preview.js", import.meta.url), "utf8");
const report = count => JSON.stringify({ config: {}, suites: [{ specs: [{ title: `case-${count}` }] }], stats: {} });
const summary = count => ({ format: "playwright-json", file_count: 1, test_count: count,
  outcome_counts: { expected: count, skipped: 0, unexpected: 0, flaky: 0 },
  report_sha256: String(count).repeat(64) });
function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}
function setup(replies) {
  const nodes = new Map(), listeners = new Map(), calls = [], modals = [];
  function node(id) {
    if (nodes.has(id)) return nodes.get(id);
    const classes = new Set(["hidden"]);
    const events = new Map();
    const value = { id, value: "", files: [], textContent: "", disabled: false,
      classList: { add(name) { classes.add(name); }, remove(name) { classes.delete(name); },
        contains(name) { return classes.has(name); } },
      addEventListener(name, callback) { const group = events.get(name) || [];
        group.push(callback); events.set(name, group); },
      dispatchEvent(event) { for (const callback of events.get(event.type) || []) callback(event); },
      querySelector() { return node("submit-button"); } };
    nodes.set(id, value); return value;
  }
  const document = { getElementById: node,
    addEventListener(name, callback, options) { const group = listeners.get(name) || [];
      group.push({ callback, capture: options === true || Boolean(options?.capture) });
      listeners.set(name, group); } };
  function showModal(id, visible) {
    modals.push([id, visible]);
    if (!visible && id === "playwright-json-preview-modal") {
      node(id).dispatchEvent({ type: "sniper:playwright-json-preview-close" });
    }
    node(id).classList[visible ? "remove" : "add"]("hidden");
  }
  // The shared shell registers its capture Escape listener before this module.
  // Its stopImmediatePropagation blocks all later document keydown listeners.
  document.addEventListener("keydown", event => {
    if (event.key !== "Escape" || node("playwright-json-preview-modal").classList.contains("hidden")) return;
    event.stopImmediatePropagation();
    showModal("playwright-json-preview-modal", false);
  }, true);
  vm.runInNewContext(source, { document, TextEncoder, showModal,
    activeModal() { const modal = node("playwright-json-preview-modal");
      return modal.classList.contains("hidden") ? null : modal; },
    api(route, options) { calls.push([route, options]); return replies.shift().promise; } });
  async function dispatch(name, target, extra = {}) {
    let stopped = false;
    const event = { ...extra, target, preventDefault() {},
      stopImmediatePropagation() { stopped = true; } };
    const callbacks = [...(listeners.get(name) || [])].sort((a, b) => Number(b.capture) - Number(a.capture));
    const pending = [];
    for (const entry of callbacks) {
      pending.push(Promise.resolve(entry.callback(event)));
      if (stopped) break;
    }
    await Promise.all(pending);
  }
  const opener = { id: "open", closest(selector) { return selector.includes("data-action") ? this : null; } };
  const closer = { id: "close", closest(selector) { return selector.includes("data-close") ? this : null; } };
  return { node, calls, modals, dispatch, opener, closer };
}

test("normal Playwright JSON submission shows only its summary", async () => {
  const first = deferred(), app = setup([first]);
  await app.dispatch("click", app.opener);
  app.node("playwright-json-paste").value = report(1);
  const submission = app.dispatch("submit", app.node("playwright-json-preview-form"));
  assert.equal(app.calls.length, 1);
  assert.equal(app.calls[0][0], "/api/tool-reports/playwright-json/summary");
  first.resolve(summary(1)); await submission;
  assert.equal(app.node("playwright-json-test-count").textContent, "1");
  assert.equal(app.node("playwright-json-preview-result").classList.contains("hidden"), false);
  assert.equal(app.node("playwright-json-paste").value, "");
});

test("editing pasted input during a pending response permits a fresh submission", async () => {
  const first = deferred(), second = deferred(), app = setup([first, second]);
  await app.dispatch("click", app.opener);
  const paste = app.node("playwright-json-paste"), form = app.node("playwright-json-preview-form");
  paste.value = report(1);
  const oldSubmission = app.dispatch("submit", form);
  assert.equal(app.calls.length, 1);
  paste.value = report(2);
  await app.dispatch("input", paste);
  assert.equal(app.node("submit-button").disabled, false);
  const newSubmission = app.dispatch("submit", form);
  assert.equal(app.calls.length, 2);
  assert.equal(JSON.parse(app.calls[1][1].body).report.suites[0].specs[0].title, "case-2");
  first.resolve(summary(1)); await oldSubmission;
  assert.equal(paste.value, report(2));
  assert.equal(app.node("playwright-json-preview-result").classList.contains("hidden"), true);
  second.resolve(summary(2)); await newSubmission;
  assert.equal(app.node("playwright-json-test-count").textContent, "2");
  assert.equal(paste.value, "");
});

test("a silent input change cannot let an older response erase the new report", async () => {
  const first = deferred(), second = deferred(), app = setup([first, second]);
  await app.dispatch("click", app.opener);
  const paste = app.node("playwright-json-paste"), form = app.node("playwright-json-preview-form");
  paste.value = report(1);
  const oldSubmission = app.dispatch("submit", form);
  paste.value = report(3);
  first.resolve(summary(1)); await oldSubmission;
  assert.equal(paste.value, report(3));
  assert.equal(app.node("playwright-json-preview-result").classList.contains("hidden"), true);
  assert.equal(app.node("submit-button").disabled, false);
  const newSubmission = app.dispatch("submit", form);
  assert.equal(app.calls.length, 2);
  second.resolve(summary(3)); await newSubmission;
  assert.equal(app.node("playwright-json-test-count").textContent, "3");
});

test("closing the modal invalidates a pending response", async () => {
  const first = deferred(), app = setup([first]);
  await app.dispatch("click", app.opener);
  app.node("playwright-json-paste").value = report(1);
  const oldSubmission = app.dispatch("submit", app.node("playwright-json-preview-form"));
  await app.dispatch("click", app.closer);
  first.resolve(summary(1)); await oldSubmission;
  assert.equal(app.node("playwright-json-test-count").textContent, "");
  assert.equal(app.node("playwright-json-preview-result").classList.contains("hidden"), true);
  assert.equal(app.node("playwright-json-paste").value, "");
  assert.deepEqual(app.modals, [["playwright-json-preview-modal", true], ["playwright-json-preview-modal", false]]);
});

test("shared Escape close leaves a delayed result empty", async () => {
  const first = deferred(), app = setup([first]);
  await app.dispatch("click", app.opener);
  const paste = app.node("playwright-json-paste");
  paste.value = report(1);
  const submission = app.dispatch("submit", app.node("playwright-json-preview-form"));
  assert.equal(app.calls.length, 1);
  await app.dispatch("keydown", app.node("playwright-json-preview-modal"), { key: "Escape" });
  assert.equal(app.node("playwright-json-preview-modal").classList.contains("hidden"), true);
  first.resolve(summary(1)); await submission;
  assert.equal(app.node("playwright-json-test-count").textContent, "");
  assert.equal(app.node("playwright-json-preview-result").classList.contains("hidden"), true);
  assert.equal(paste.value, "");
});
