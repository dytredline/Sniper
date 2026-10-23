import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";

const source = readFileSync(new URL("../static/siem_ecs_preview.js", import.meta.url), "utf8");
const kinds = ["alert", "asset", "enrichment", "event", "metric", "state", "pipeline_error", "signal"];

function setup(reply) {
  const nodes = new Map();
  const listeners = new Map();
  const calls = [];
  const modals = [];
  function node(id) {
    if (nodes.has(id)) return nodes.get(id);
    const classes = new Set(["hidden"]);
    const value = { id, value: "", files: [], textContent: "", disabled: false,
      classList: {
        add(name) { classes.add(name); }, remove(name) { classes.delete(name); },
        contains(name) { return classes.has(name); },
      },
      querySelector() { return node("siem-submit"); },
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
  vm.runInNewContext(source, { document, TextEncoder,
    showModal(id, visible) { modals.push([id, visible]); },
    async api(route, options) { calls.push([route, options]); return reply; },
  });
  async function dispatch(name, target) {
    for (const callback of listeners.get(name) || []) {
      await callback({ target, preventDefault() {} });
    }
  }
  return { node, dispatch, calls, modals };
}

test("saved ECS evidence preview posts locally and renders counts, never private fields", async () => {
  const counts = Object.fromEntries(kinds.map(kind => [kind, kind === "alert" ? 1 : 0]));
  const app = setup({ format: "ecs-ndjson", record_count: 1, kind_counts: counts,
    report_sha256: "a".repeat(64) });
  const raw = JSON.stringify({ "@timestamp": "2026-10-13T08:00:00Z",
    ecs: { version: "8.17.0" }, event: { kind: "alert" }, message: "private@example.test" });
  app.node("siem-ecs-paste").value = raw;
  await app.dispatch("submit", app.node("siem-ecs-preview-form"));
  assert.equal(app.calls.length, 1);
  assert.equal(app.calls[0][0], "/api/tool-reports/siem-ecs-ndjson/summary");
  assert.deepEqual(JSON.parse(app.calls[0][1].body), { report: raw });
  assert.equal(app.node("siem-ecs-record-count").textContent, "1");
  assert.match(app.node("siem-ecs-kind-counts").textContent, /alert:1/);
  assert.equal(app.node("siem-ecs-preview-result").classList.contains("hidden"), false);
  const displayed = ["record-count", "kind-counts", "report-sha256"]
    .map(key => app.node(`siem-ecs-${key}`).textContent).join(" ");
  assert.doesNotMatch(displayed, /private|example\.test|08:00:00/);
});

test("oversized input and inconsistent reply fail closed without stale result", async () => {
  const counts = Object.fromEntries(kinds.map(kind => [kind, kind === "alert" ? 1 : 0]));
  const app = setup({ format: "ecs-ndjson", record_count: 2, kind_counts: counts,
    report_sha256: "a".repeat(64) });
  app.node("siem-ecs-paste").value = "x".repeat(60001);
  await app.dispatch("submit", app.node("siem-ecs-preview-form"));
  assert.equal(app.calls.length, 0);
  app.node("siem-ecs-paste").value = "{}";
  await app.dispatch("submit", app.node("siem-ecs-preview-form"));
  assert.equal(app.calls.length, 1);
  assert.equal(app.node("siem-ecs-preview-result").classList.contains("hidden"), true);
  assert.equal(app.node("siem-ecs-record-count").textContent, "");
  assert.equal(app.node("siem-ecs-preview-error").classList.contains("hidden"), false);
});
