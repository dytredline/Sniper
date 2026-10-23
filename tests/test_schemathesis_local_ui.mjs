import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";

const source = readFileSync(new URL("../static/schemathesis_local.js", import.meta.url), "utf8");
const html = readFileSync(new URL("../static/index.html", import.meta.url), "utf8");
const appSource = readFileSync(new URL("../static/app.js", import.meta.url), "utf8");

function setup(
  reply,
  {
    runtime = "precheck_passed",
    action = "local_input_required",
    readinessFailure = false,
    profileRoute = "/api/tool-runs/schemathesis-local",
    profiles = null,
  } = {},
) {
  const nodes = new Map();
  const listeners = new Map();
  const calls = [];
  const modals = [];
  const opener = {
    id: "schemathesis-top-action", disabled: false, title: "",
    closest(selector) { return selector.includes("open-schemathesis-local") ? this : null; },
  };
  function node(id) {
    if (nodes.has(id)) return nodes.get(id);
    const classes = new Set(["hidden"]);
    const value = {
      id, value: "", checked: false, textContent: "", disabled: false,
      classList: {
        add(name) { classes.add(name); },
        remove(name) { classes.delete(name); },
        contains(name) { return classes.has(name); },
      },
      querySelector() { return node("submit-button"); },
    };
    nodes.set(id, value);
    return value;
  }
  const document = {
    getElementById: node,
    querySelectorAll(selector) {
      return selector === '[data-action="open-schemathesis-local"]' ? [opener] : [];
    },
    addEventListener(name, callback) {
      const group = listeners.get(name) || [];
      group.push(callback);
      listeners.set(name, group);
    },
  };
  vm.runInNewContext(source, {
    document, TextEncoder,
    showModal(id, visible) { modals.push([id, visible]); },
    async api(route, options) {
      calls.push([route, options]);
      if (route === "/api/tooling/readiness") {
        if (readinessFailure) throw new Error("private readiness failure");
        return {
          tools: [{
            id: "schemathesis",
            profiles: profiles ?? [{
              route: profileRoute,
              runtime,
              action,
            }],
          }],
        };
      }
      if (reply instanceof Error) throw reply;
      return reply;
    },
  });
  async function dispatch(name, target) {
    for (const callback of listeners.get(name) || []) {
      await callback({ target, preventDefault() {} });
    }
  }
  return {
    node, dispatch, calls, modals, opener,
    posts() { return calls.filter(([route]) => route === "/api/tool-runs/schemathesis-local"); },
    async ready() { await new Promise(resolve => setImmediate(resolve)); },
  };
}

const aggregate = {
  status: "completed", scope: "synthetic-fixture-only", format: "schemathesis-junit-xml",
  suite_count: 1, testcase_count: 1,
  outcome_counts: { passed: 1, failed: 0, errors: 0, skipped: 0 },
  report_sha256: "a".repeat(64),
  private_url: "https://secret.invalid/",
};

test("separate local form opens without a request and needs explicit consent", async () => {
  const ui = setup(aggregate);
  await ui.ready();
  await ui.dispatch("click", ui.opener);
  assert.deepEqual(ui.modals, [["schemathesis-local-modal", true]]);
  assert.equal(ui.posts().length, 0);
  ui.node("schemathesis-local-schema").value = '{"openapi":"3.0.3"}';
  await ui.dispatch("submit", ui.node("schemathesis-local-form"));
  assert.equal(ui.posts().length, 0);
  assert.equal(ui.node("schemathesis-local-error").classList.contains("hidden"), false);
  assert.match(html, /id="schemathesis-local-consent" type="checkbox"/);
  assert.match(html, /data-action="open-schemathesis-junit-preview"/);
  assert.match(html, /data-action="open-schemathesis-local"/);
  assert.match(appSource, /"\/api\/tool-runs\/schemathesis-local": \{ action: "open-schemathesis-local" \}/);
});

test("submit sends only consent and schema and renders allowlisted aggregate", async () => {
  const ui = setup(aggregate);
  await ui.ready();
  const schema = { openapi: "3.0.3", info: { title: "fixture", version: "1" },
    paths: { "/api/ping": { get: { responses: { "200": { description: "ok" } } } } } };
  ui.node("schemathesis-local-schema").value = JSON.stringify(schema);
  ui.node("schemathesis-local-consent").checked = true;
  await ui.dispatch("submit", ui.node("schemathesis-local-form"));
  assert.equal(ui.posts().length, 1);
  assert.equal(ui.posts()[0][0], "/api/tool-runs/schemathesis-local");
  assert.deepEqual(JSON.parse(ui.posts()[0][1].body), { confirm_local: true, schema });
  assert.equal(ui.node("schemathesis-local-testcase-count").textContent, "1");
  assert.match(ui.node("schemathesis-local-outcomes").textContent, /geçti:1/);
  assert.equal(ui.node("schemathesis-local-result").classList.contains("hidden"), false);
  const displayed = ["suite-count", "testcase-count", "outcomes", "report-sha256"]
    .map(key => ui.node(`schemathesis-local-${key}`).textContent).join(" ");
  assert.doesNotMatch(displayed, /secret\.invalid|private_url/);
  assert.equal(ui.node("schemathesis-local-consent").checked, false);
});

test("oversized input and invalid runtime aggregate fail closed", async () => {
  const ui = setup({ ...aggregate, outcome_counts: { passed: 0, failed: 0, errors: 0, skipped: 0 } });
  await ui.ready();
  ui.node("schemathesis-local-consent").checked = true;
  ui.node("schemathesis-local-schema").value = "x".repeat(64001);
  await ui.dispatch("submit", ui.node("schemathesis-local-form"));
  assert.equal(ui.posts().length, 0);
  ui.node("schemathesis-local-schema").value = '{"openapi":"3.0.3"}';
  await ui.dispatch("submit", ui.node("schemathesis-local-form"));
  assert.equal(ui.posts().length, 1);
  assert.equal(ui.node("schemathesis-local-result").classList.contains("hidden"), true);
  assert.equal(ui.node("schemathesis-local-error").classList.contains("hidden"), false);
  assert.equal(ui.node("schemathesis-local-testcase-count").textContent, "");
});

test("top synthetic-local action and submit fail closed when readiness is unavailable", async () => {
  const ui = setup(aggregate, { runtime: "unavailable" });
  await ui.ready();
  assert.equal(ui.calls.filter(([route]) => route === "/api/tooling/readiness").length, 1);
  assert.equal(ui.opener.disabled, true);
  assert.equal(ui.opener.title, "Sentetik yerel testin çalışma zamanı hazır değil.");
  await ui.dispatch("click", ui.opener);
  assert.equal(ui.modals.length, 0);
  ui.node("schemathesis-local-schema").value = '{"openapi":"3.0.3"}';
  ui.node("schemathesis-local-consent").checked = true;
  await ui.dispatch("submit", ui.node("schemathesis-local-form"));
  assert.equal(ui.posts().length, 0);
  assert.equal(ui.node("submit-button").disabled, true);
});

test("readiness failure keeps the top action and submit unavailable", async () => {
  const ui = setup(aggregate, { readinessFailure: true });
  await ui.ready();
  assert.equal(ui.opener.disabled, true);
  assert.equal(ui.opener.title, "Sentetik yerel testin çalışma zamanı hazır değil.");
  ui.node("schemathesis-local-schema").value = '{"openapi":"3.0.3"}';
  ui.node("schemathesis-local-consent").checked = true;
  await ui.dispatch("submit", ui.node("schemathesis-local-form"));
  assert.equal(ui.posts().length, 0);
  assert.doesNotMatch(ui.node("schemathesis-local-error").textContent, /private readiness failure/i);
});

test("ready top action opens the modal and posts only after explicit consent", async () => {
  const ui = setup(aggregate);
  await ui.ready();
  assert.equal(ui.calls.filter(([route]) => route === "/api/tooling/readiness").length, 1);
  assert.equal(ui.opener.disabled, false);
  assert.equal(ui.opener.title, "");
  await ui.dispatch("click", ui.opener);
  assert.deepEqual(ui.modals, [["schemathesis-local-modal", true]]);
  assert.equal(ui.posts().length, 0);
  ui.node("schemathesis-local-schema").value = '{"openapi":"3.0.3"}';
  ui.node("schemathesis-local-consent").checked = true;
  await ui.dispatch("submit", ui.node("schemathesis-local-form"));
  assert.equal(ui.posts().length, 1);
  assert.equal(ui.node("schemathesis-local-result").classList.contains("hidden"), false);
});

test("ready sibling, unknown, or missing profiles never enable the synthetic-local top action", async () => {
  for (const options of [
    { profileRoute: "/api/tool-runs/schemathesis-loopback" },
    { runtime: "unknown" },
    { action: "report_only" },
    { profiles: [] },
  ]) {
    const ui = setup(aggregate, options);
    await ui.ready();
    assert.equal(ui.opener.disabled, true);
    assert.equal(ui.opener.title, "Sentetik yerel testin çalışma zamanı hazır değil.");
    await ui.dispatch("click", ui.opener);
    assert.equal(ui.modals.length, 0);
    ui.node("schemathesis-local-schema").value = '{"openapi":"3.0.3"}';
    ui.node("schemathesis-local-consent").checked = true;
    await ui.dispatch("submit", ui.node("schemathesis-local-form"));
    assert.equal(ui.posts().length, 0);
  }
});

test("HTTP 503 renders bounded unavailable-or-busy guidance without server details", async () => {
  const unavailable = new Error("PRIVATE_URL=https://secret.invalid");
  unavailable.status = 503;
  const ui = setup(unavailable);
  await ui.ready();
  ui.node("schemathesis-local-schema").value = '{"openapi":"3.0.3"}';
  ui.node("schemathesis-local-consent").checked = true;
  await ui.dispatch("submit", ui.node("schemathesis-local-form"));
  const message = ui.node("schemathesis-local-error").textContent;
  assert.match(message, /kullanılamıyor veya meşgul/i);
  assert.doesNotMatch(message, /secret\.invalid|PRIVATE_URL/);
  assert.equal(ui.node("schemathesis-local-result").classList.contains("hidden"), true);
  assert.equal(ui.node("submit-button").disabled, false);
});

test("non-503 API failures retain the generic bounded error", async () => {
  const failed = new Error("PRIVATE_URL=https://secret.invalid");
  failed.status = 502;
  const ui = setup(failed);
  await ui.ready();
  ui.node("schemathesis-local-schema").value = '{"openapi":"3.0.3"}';
  ui.node("schemathesis-local-consent").checked = true;
  await ui.dispatch("submit", ui.node("schemathesis-local-form"));
  assert.equal(ui.node("schemathesis-local-error").textContent,
    "Yerel sentetik test çalıştırılamadı. Girdi, kurulum veya sınırları denetleyin.");
});
