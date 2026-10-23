import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";

const htmlSource = readFileSync(new URL("../static/index.html", import.meta.url), "utf8");
const source = readFileSync(new URL("../static/schemathesis_junit_preview.js", import.meta.url), "utf8");

function setup(reply, options = {}) {
  const nodes = new Map();
  const listeners = new Map();
  const calls = [];
  const modals = [];
  const clipboardWrites = [];
  const writeTextImpl = options.writeText || (async text => {
    clipboardWrites.push(text);
  });
  function node(id) {
    if (nodes.has(id)) return nodes.get(id);
    const classes = new Set(["hidden"]);
    const value = {
      id, value: "", files: [], textContent: "", disabled: false, hidden: true,
      classList: {
        add(name) { classes.add(name); },
        remove(name) { classes.delete(name); },
        contains(name) { return classes.has(name); },
      },
      querySelector() { return node("submit-button"); },
      __listeners: new Map(),
      addEventListener(name, callback) {
        const group = this.__listeners.get(name) || [];
        group.push(callback);
        this.__listeners.set(name, group);
      },
    };
    nodes.set(id, value);
    return value;
  }
  const document = {
    getElementById: node,
    addEventListener(name, callback) {
      const group = listeners.get(name) || [];
      group.push(callback);
      listeners.set(name, group);
    },
  };
  const navigator = options.omitClipboard
    ? {}
    : { clipboard: { writeText: text => writeTextImpl(text) } };
  vm.runInNewContext(source, {
    document,
    navigator,
    window: { navigator },
    TextEncoder,
    showModal(id, visible) { modals.push([id, visible]); },
    async api(route, reqOptions) {
      calls.push([route, reqOptions]);
      if (typeof reply === "function") return reply(route, reqOptions, calls.length);
      return reply;
    },
  });
  async function dispatch(name, target) {
    const event = { target, preventDefault() {} };
    // A real button click invokes its own handlers before bubbling to document.
    for (const callback of target?.__listeners?.get(name) || []) {
      await callback(event);
    }
    for (const callback of listeners.get(name) || []) {
      await callback(event);
    }
  }
  return { node, dispatch, calls, modals, clipboardWrites };
}

test("saved JUnit preview renders aggregate response and never echoes failure text", async () => {
  const app = setup({
    format: "schemathesis-junit-xml", suite_count: 1, testcase_count: 2,
    outcome_counts: { passed: 1, failed: 1, errors: 0, skipped: 0 },
    report_sha256: "a".repeat(64),
    leaked_detail: "private failure text",
  });
  await app.dispatch("click", {
    closest(selector) { return selector.includes("data-action") ? this : null; },
    id: "opener",
  });
  assert.deepEqual(app.modals, [["schemathesis-junit-preview-modal", true]]);
  const report = '<testsuite><testcase name="private"><failure>secret body</failure></testcase><testcase/></testsuite>';
  app.node("schemathesis-junit-paste").value = report;
  await app.dispatch("submit", app.node("schemathesis-junit-preview-form"));
  assert.equal(app.calls.length, 1);
  assert.equal(app.calls[0][0], "/api/tool-reports/schemathesis-junit/summary");
  assert.deepEqual(JSON.parse(app.calls[0][1].body), { report });
  assert.equal(app.node("schemathesis-junit-testcase-count").textContent, "2");
  assert.match(app.node("schemathesis-junit-outcomes").textContent, /başarısız:1/);
  assert.equal(app.node("schemathesis-junit-preview-result").classList.contains("hidden"), false);
  const displayed = [...["suite-count", "testcase-count", "outcomes", "report-sha256"]]
    .map(key => app.node(`schemathesis-junit-${key}`).textContent).join(" ");
  assert.doesNotMatch(displayed, /private|secret|body/);
});

test("large input and invalid aggregate reply fail closed without stale results", async () => {
  const invalid = setup({ format: "schemathesis-junit-xml", suite_count: 1, testcase_count: 2,
    outcome_counts: { passed: 1, failed: 0, errors: 0, skipped: 0 }, report_sha256: "a".repeat(64) });
  invalid.node("schemathesis-junit-paste").value = "x".repeat(60001);
  await invalid.dispatch("submit", invalid.node("schemathesis-junit-preview-form"));
  assert.equal(invalid.calls.length, 0);
  assert.equal(invalid.node("schemathesis-junit-preview-error").classList.contains("hidden"), false);
  invalid.node("schemathesis-junit-paste").value = "<testsuite/>";
  await invalid.dispatch("submit", invalid.node("schemathesis-junit-preview-form"));
  assert.equal(invalid.calls.length, 1);
  assert.equal(invalid.node("schemathesis-junit-preview-result").classList.contains("hidden"), true);
  assert.equal(invalid.node("schemathesis-junit-testcase-count").textContent, "");
});

test("copy button is present in index.html and copies only the validated 64-char SHA-256 digest without extra API calls", async () => {
  assert.match(
    htmlSource,
    /id="schemathesis-junit-copy-sha256"[^>]*>[^<]*kopyala/i,
    "Expected #schemathesis-junit-copy-sha256 button with Turkish label in static/index.html"
  );
  assert.match(
    htmlSource,
    /id="schemathesis-junit-copy-status"/,
    "Expected #schemathesis-junit-copy-status live status element in static/index.html"
  );

  const digest = "0123456789abcdef".repeat(4);
  const app = setup({
    format: "schemathesis-junit-xml",
    suite_count: 1,
    testcase_count: 2,
    outcome_counts: { passed: 1, failed: 1, errors: 0, skipped: 0 },
    report_sha256: digest,
  });

  const copyBtn = app.node("schemathesis-junit-copy-sha256");
  const copyStatus = app.node("schemathesis-junit-copy-status");

  // Before valid result, button must be disabled/hidden and clicking must not write to clipboard
  assert.equal(copyBtn.disabled, true);
  assert.equal(copyBtn.classList.contains("hidden"), true);
  await app.dispatch("click", copyBtn);
  assert.equal(app.clipboardWrites.length, 0);
  assert.equal(app.calls.length, 0);

  const report = '<testsuite name="https://internal.example/api"><testcase name="GET /secret"><failure>raw_failure_payload</failure></testcase><testcase name="GET /health"/></testsuite>';
  app.node("schemathesis-junit-paste").value = report;
  await app.dispatch("submit", app.node("schemathesis-junit-preview-form"));

  assert.equal(app.calls.length, 1);
  assert.equal(copyBtn.disabled, false);
  assert.equal(copyBtn.classList.contains("hidden"), false);
  assert.match(copyBtn.textContent, /kopyala/i);
  assert.equal(copyStatus.textContent, "");

  // Explicit click copies only the 64-char lowercase hex digest and makes no extra API request
  await app.dispatch("click", copyBtn);
  assert.equal(app.calls.length, 1);
  assert.deepEqual(app.clipboardWrites, [digest]);
  assert.equal(copyStatus.classList.contains("hidden"), false);
  assert.match(copyStatus.textContent, /kopyalandı/i);
  assert.doesNotMatch(copyStatus.textContent, /internal\.example|secret|raw_failure_payload/);
});

test("one bubbled user click writes the displayed digest exactly once", async () => {
  const digest = "0123456789abcdef".repeat(4);
  const app = setup({
    format: "schemathesis-junit-xml", suite_count: 1, testcase_count: 1,
    outcome_counts: { passed: 1, failed: 0, errors: 0, skipped: 0 },
    report_sha256: digest,
  });
  app.node("schemathesis-junit-paste").value = "<testsuite><testcase/></testsuite>";
  await app.dispatch("submit", app.node("schemathesis-junit-preview-form"));
  assert.equal(app.calls.length, 1);
  await app.dispatch("click", app.node("schemathesis-junit-copy-sha256"));
  assert.deepEqual(app.clipboardWrites, [digest]);
  assert.equal(app.calls.length, 1);
});

test("clipboard rejection reports failure without claiming success and leaves digest and aggregate intact", async () => {
  const digest = "fedcba9876543210".repeat(4);
  const app = setup(
    {
      format: "schemathesis-junit-xml",
      suite_count: 2,
      testcase_count: 3,
      outcome_counts: { passed: 2, failed: 1, errors: 0, skipped: 0 },
      report_sha256: digest,
    },
    {
      async writeText() {
        throw new Error("Clipboard write denied for sensitive <testsuite> input");
      },
    }
  );

  const report = '<testsuite><testcase name="secret-case"><failure>secret-body</failure></testcase></testsuite>';
  app.node("schemathesis-junit-paste").value = report;
  await app.dispatch("submit", app.node("schemathesis-junit-preview-form"));
  assert.equal(app.calls.length, 1);

  const copyBtn = app.node("schemathesis-junit-copy-sha256");
  const copyStatus = app.node("schemathesis-junit-copy-status");
  await app.dispatch("click", copyBtn);

  assert.equal(app.calls.length, 1);
  assert.equal(app.node("schemathesis-junit-preview-result").classList.contains("hidden"), false);
  assert.equal(app.node("schemathesis-junit-report-sha256").textContent, digest);
  assert.equal(app.node("schemathesis-junit-suite-count").textContent, "2");
  assert.equal(app.node("schemathesis-junit-testcase-count").textContent, "3");
  assert.equal(copyStatus.classList.contains("hidden"), false);
  assert.notEqual(copyStatus.textContent, "");
  assert.doesNotMatch(copyStatus.textContent, /kopyalandı/i);
  assert.doesNotMatch(copyStatus.textContent, /secret-case|secret-body|testsuite/);
});

test("close/reopen and invalid subsequent import reset copy button and status without copying stale digest", async () => {
  const digest = "abcdef0123456789".repeat(4);
  let shouldFailResponse = false;
  const app = setup(() => {
    if (shouldFailResponse) {
      return {
        format: "schemathesis-junit-xml",
        suite_count: 1,
        testcase_count: 5,
        outcome_counts: { passed: 1, failed: 0, errors: 0, skipped: 0 },
        report_sha256: digest,
      };
    }
    return {
      format: "schemathesis-junit-xml",
      suite_count: 1,
      testcase_count: 1,
      outcome_counts: { passed: 1, failed: 0, errors: 0, skipped: 0 },
      report_sha256: digest,
    };
  });

  app.node("schemathesis-junit-paste").value = "<testsuite><testcase/></testsuite>";
  await app.dispatch("submit", app.node("schemathesis-junit-preview-form"));
  const copyBtn = app.node("schemathesis-junit-copy-sha256");
  const copyStatus = app.node("schemathesis-junit-copy-status");
  await app.dispatch("click", copyBtn);
  assert.equal(app.clipboardWrites.length, 1);
  assert.notEqual(copyStatus.textContent, "");

  // Close modal -> resets copy button and status
  await app.dispatch("click", {
    id: "schemathesis-junit-preview-modal",
    closest() { return null; },
  });
  assert.equal(copyBtn.disabled, true);
  assert.equal(copyBtn.classList.contains("hidden"), true);
  assert.equal(copyStatus.textContent, "");
  assert.equal(copyStatus.classList.contains("hidden"), true);
  await app.dispatch("click", copyBtn);
  assert.equal(app.clipboardWrites.length, 1);

  // Reopen modal -> still disabled/hidden
  await app.dispatch("click", {
    id: "opener",
    closest(selector) { return selector.includes("data-action") ? this : null; },
  });
  assert.equal(copyBtn.disabled, true);
  assert.equal(copyBtn.classList.contains("hidden"), true);
  assert.equal(copyStatus.textContent, "");

  // Valid import followed by invalid response resets copy button and status
  app.node("schemathesis-junit-paste").value = "<testsuite><testcase/></testsuite>";
  await app.dispatch("submit", app.node("schemathesis-junit-preview-form"));
  await app.dispatch("click", copyBtn);
  assert.equal(app.clipboardWrites.length, 2);

  shouldFailResponse = true;
  app.node("schemathesis-junit-paste").value = "<testsuite><testcase/></testsuite>";
  await app.dispatch("submit", app.node("schemathesis-junit-preview-form"));
  assert.equal(copyBtn.disabled, true);
  assert.equal(copyBtn.classList.contains("hidden"), true);
  assert.equal(copyStatus.textContent, "");
  assert.equal(copyStatus.classList.contains("hidden"), true);
  await app.dispatch("click", copyBtn);
  assert.equal(app.clipboardWrites.length, 2);
});

