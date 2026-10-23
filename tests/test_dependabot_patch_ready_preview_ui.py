from __future__ import annotations

import json
import subprocess
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

import server
from server import SniperHandler
from storage import Store
from tool_report_dependabot import parse_dependabot_alerts_summary


PKG_MARKER = "SYNTHETIC_DEPENDABOT_PKG_Task16_DO_NOT_ECHO"
ADV_MARKER = "SYNTHETIC_DEPENDABOT_ADVISORY_Task16_DO_NOT_ECHO"
PATH_MARKER = "SYNTHETIC_DEPENDABOT_PATH_Task16_DO_NOT_ECHO"
PATCH_VER_MARKER = "2.9.1-PATCH-SECRET-Task16"
FIXED_VER_MARKER = "1.4.2-FIXED-SECRET-Task16"

MIXED_ALERTS_REPORT = {
    "alerts": [
        {
            "state": "open",
            "security_advisory": {"severity": "high", "summary": ADV_MARKER},
            "dependency": {
                "package": {"name": PKG_MARKER},
                "manifest_path": PATH_MARKER,
            },
            "security_vulnerability": {
                "first_patched_version": {"identifier": PATCH_VER_MARKER}
            },
        },
        {
            "state": "open",
            "security_advisory": {"severity": "medium", "summary": ADV_MARKER},
            "dependency": {
                "package": {"name": PKG_MARKER},
                "manifest_path": PATH_MARKER,
            },
            "security_vulnerability": {"first_patched_version": {}},
        },
        {
            "state": "fixed",
            "security_advisory": {"severity": "low", "summary": ADV_MARKER},
            "dependency": {
                "package": {"name": PKG_MARKER},
                "manifest_path": PATH_MARKER,
            },
            "security_vulnerability": {
                "first_patched_version": {"identifier": FIXED_VER_MARKER}
            },
        },
    ]
}

ZERO_PATCHABLE_REPORT = {
    "alerts": [
        {
            "state": "open",
            "security_advisory": {"severity": "critical", "summary": ADV_MARKER},
            "security_vulnerability": {
                "first_patched_version": {"identifier": "   "}
            },
        },
        {
            "state": "dismissed",
            "security_advisory": {"severity": "low", "summary": ADV_MARKER},
            "security_vulnerability": {
                "first_patched_version": {"identifier": FIXED_VER_MARKER}
            },
        },
    ]
}


NODE_HARNESS = r"""
const fs = require("node:fs");
const vm = require("node:vm");

const [appJsPath, indexHtmlPath, baseUrl, mode] = process.argv.slice(1);
const appJs = fs.readFileSync(appJsPath, "utf8");
const indexHtml = fs.readFileSync(indexHtmlPath, "utf8");

function buildDom() {
  const elements = new Map();
  const docListeners = new Map();
  const postRequests = [];
  let responseMutator = null;

  function makeElement(key) {
    if (elements.has(key)) return elements.get(key);
    const id = String(key).replace(/^#/, "");
    const classes = new Set();
    if (
      id.endsWith("-modal") ||
      id.endsWith("-result") ||
      id.endsWith("-error")
    ) {
      classes.add("hidden");
    }
    const el = {
      id,
      dataset: {},
      style: {},
      value: "",
      checked: false,
      disabled: false,
      files: [],
      innerHTML: "",
      textContent: "",
      handlers: new Map(),
      classList: {
        add(c) { classes.add(c); },
        remove(c) { classes.delete(c); },
        contains(c) { return classes.has(c); },
        toggle(c, force) {
          const next = force === undefined ? !classes.has(c) : Boolean(force);
          if (next) classes.add(c);
          else classes.delete(c);
        },
      },
      addEventListener(type, cb) {
        const list = this.handlers.get(type) || [];
        list.push(cb);
        this.handlers.set(type, list);
      },
      append() {},
      appendChild() {},
      remove() {},
      focus() {},
      reset() {},
      setSelectionRange() {},
      setAttribute() {},
      removeAttribute() {},
      querySelector(sel) { return makeElement(sel); },
      querySelectorAll() { return []; },
      closest(sel) {
        if (sel === "[data-action]" && this.dataset.action) return this;
        if (sel === "[data-close]" && this.dataset.close) return this;
        return null;
      },
    };
    elements.set(key, el);
    return el;
  }

  const document = {
    body: makeElement("body"),
    getElementById(id) { return makeElement("#" + id); },
    querySelector(sel) { return makeElement(sel); },
    querySelectorAll() { return []; },
    createElement(tag) { return makeElement("created:" + tag); },
    addEventListener(type, cb) {
      const list = docListeners.get(type) || [];
      list.push(cb);
      docListeners.set(type, list);
    },
  };

  const bootstrapRoutes = {
    "/api/dashboard": {},
    "/api/targets": { targets: [] },
    "/api/scans?limit=200": { scans: [] },
    "/api/engagements": { engagements: [] },
    "/api/lab-runs": { lab_runs: [] },
    "/api/project-audits": { project_audits: [], total: 0 },
    "/api/tooling": { tools: [], categories: [], summary: {}, policy: { native: "", external: "", completion: "" } },
    "/api/dependency-security": {},
  };

  async function customFetch(path, options = {}) {
    const method = (options.method || "GET").toUpperCase();
    if (method === "POST") {
      postRequests.push({ path, body: options.body });
      const res = await fetch(baseUrl + path, {
        method: "POST",
        headers: options.headers || { "Content-Type": "application/json" },
        body: options.body,
      });
      const data = await res.json();
      const finalData = responseMutator ? responseMutator(data) : data;
      return {
        ok: res.ok,
        status: res.status,
        json: async () => finalData,
      };
    }
    return {
      ok: true,
      status: 200,
      json: async () => bootstrapRoutes[path] || {},
    };
  }

  async function dispatch(type, target) {
    const list = docListeners.get(type) || [];
    const ev = {
      target,
      currentTarget: target,
      preventDefault() {},
      stopPropagation() {},
    };
    for (const cb of list) {
      await cb(ev);
    }
  }

  return {
    document,
    elements,
    makeElement,
    postRequests,
    dispatch,
    setResponseMutator(fn) { responseMutator = fn; },
  };
}

async function main() {
  const input = JSON.parse(fs.readFileSync(0, "utf8"));
  const dom = buildDom();
  const ctx = vm.createContext({
    document: dom.document,
    window: { addEventListener() {} },
    location: { hash: "" },
    history: { replaceState() {} },
    fetch: dom.customFetch || ((p, o) => dom.document),
    TextEncoder,
    URL,
    console,
    setTimeout: () => 0,
    clearTimeout() {},
    setInterval: () => 0,
  });

  // Wire customFetch properly
  const dom2 = buildDom();
  const context = vm.createContext({
    document: dom2.document,
    window: { addEventListener() {} },
    location: { hash: "" },
    history: { replaceState() {} },
    fetch: async (path, options = {}) => {
      const method = (options.method || "GET").toUpperCase();
      if (method === "POST") {
        dom2.postRequests.push({ path, body: options.body });
        const res = await fetch(baseUrl + path, {
          method: "POST",
          headers: options.headers || { "Content-Type": "application/json" },
          body: options.body,
        });
        const data = await res.json();
        const finalData = dom2._mutator ? dom2._mutator(data) : data;
        return {
          ok: res.ok,
          status: res.status,
          json: async () => finalData,
        };
      }
      return {
        ok: true,
        status: 200,
        json: async () => ({ tools: [], categories: [], summary: {}, policy: { native: "", external: "", completion: "" }, targets: [], scans: [], engagements: [], lab_runs: [], project_audits: [], total: 0 }),
      };
    },
    TextEncoder,
    URL,
    console,
    setTimeout: () => 0,
    clearTimeout() {},
    setInterval: () => 0,
  });

  vm.runInContext(appJs, context, { filename: appJsPath });
  await new Promise(r => setImmediate(r));

  const openBtn = dom2.makeElement("#open-dependabot-alerts-preview");
  openBtn.dataset.action = "open-dependabot-alerts-preview";
  const closeBtn = dom2.makeElement("#close-dependabot-preview");
  closeBtn.dataset.close = "dependabot-preview-modal";
  const form = dom2.makeElement("#dependabot-preview-form");
  const pasteInput = dom2.makeElement("#dependabot-paste");

  function snapshot() {
    const allTexts = [];
    for (const [, el] of dom2.elements.entries()) {
      if (el.textContent) allTexts.push(String(el.textContent));
      if (el.innerHTML) allTexts.push(String(el.innerHTML));
    }
    return {
      htmlHasOpenPatchableEl: indexHtml.includes('id="dependabot-open-patchable-count"'),
      postCount: dom2.postRequests.length,
      modalHidden: dom2.makeElement("#dependabot-preview-modal").classList.contains("hidden"),
      resultHidden: dom2.makeElement("#dependabot-preview-result").classList.contains("hidden"),
      errorHidden: dom2.makeElement("#dependabot-preview-error").classList.contains("hidden"),
      errorText: dom2.makeElement("#dependabot-preview-error").textContent,
      format: String(dom2.makeElement("#dependabot-format").textContent),
      alertCount: String(dom2.makeElement("#dependabot-alert-count").textContent),
      stateCounts: String(dom2.makeElement("#dependabot-state-counts").textContent),
      severityCounts: String(dom2.makeElement("#dependabot-severity-counts").textContent),
      openPatchableCount: String(dom2.makeElement("#dependabot-open-patchable-count").textContent),
      reportSha256: String(dom2.makeElement("#dependabot-report-sha256").textContent),
      pasteValue: pasteInput.value,
      allText: allTexts.join(" "),
    };
  }

  if (mode === "control") {
    await dom2.dispatch("click", openBtn);
    pasteInput.value = JSON.stringify(input.mixed_report);
    await dom2.dispatch("submit", form);
    const controlSnapshot = snapshot();
    process.stdout.write(JSON.stringify({ controlSnapshot }));
    return;
  }

  // Mode: patch_ready
  await dom2.dispatch("click", openBtn);
  pasteInput.value = JSON.stringify(input.mixed_report);
  await dom2.dispatch("submit", form);
  const mixedSnapshot = snapshot();

  // Zero patchable report
  pasteInput.value = JSON.stringify(input.zero_report);
  await dom2.dispatch("submit", form);
  const zeroSnapshot = snapshot();

  // Close clears openPatchableCount
  await dom2.dispatch("click", closeBtn);
  const afterCloseSnapshot = snapshot();

  // Seed again then reopen clears openPatchableCount
  pasteInput.value = JSON.stringify(input.mixed_report);
  await dom2.dispatch("submit", form);
  await dom2.dispatch("click", openBtn);
  const afterReopenSnapshot = snapshot();

  // Seed again then malformed client input clears stale result
  pasteInput.value = JSON.stringify(input.mixed_report);
  await dom2.dispatch("submit", form);
  pasteInput.value = "{bad json";
  await dom2.dispatch("submit", form);
  const afterMalformedClientInputSnapshot = snapshot();

  // Invalid response overrides (missing, negative, fractional, string, > open, > alert_count)
  const mutators = {
    missing: d => { const c = { ...d }; delete c.open_alerts_with_available_patched_version; return c; },
    negative: d => ({ ...d, open_alerts_with_available_patched_version: -1 }),
    fractional: d => ({ ...d, open_alerts_with_available_patched_version: 1.25 }),
    stringVal: d => ({ ...d, open_alerts_with_available_patched_version: "1" }),
    exceedsOpen: d => ({ ...d, open_alerts_with_available_patched_version: d.state_counts.open + 1 }),
    exceedsTotal: d => ({ ...d, state_counts: { ...d.state_counts, open: d.alert_count }, open_alerts_with_available_patched_version: d.alert_count + 1 }),
  };

  const invalidResponseSnapshots = {};
  for (const [name, fn] of Object.entries(mutators)) {
    dom2._mutator = null;
    pasteInput.value = JSON.stringify(input.mixed_report);
    await dom2.dispatch("submit", form);
    dom2._mutator = fn;
    pasteInput.value = JSON.stringify(input.mixed_report);
    await dom2.dispatch("submit", form);
    invalidResponseSnapshots[name] = snapshot();
  }

  process.stdout.write(JSON.stringify({
    mixedSnapshot,
    zeroSnapshot,
    afterCloseSnapshot,
    afterReopenSnapshot,
    afterMalformedClientInputSnapshot,
    invalidResponseSnapshots,
  }));
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
"""


class DependabotPatchReadyPreviewUiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "data" / "sniper-test.db"
        self.previous_store = server.STORE
        server.STORE = Store(self.db_path)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), SniperHandler)
        self.port = self.httpd.server_address[1]
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.server_thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.server_thread.start()

        self.app_dir = Path(__file__).resolve().parent.parent
        self.app_js = self.app_dir / "static" / "app.js"
        self.index_html = self.app_dir / "static" / "index.html"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.server_thread.join(timeout=5)
        server.STORE = self.previous_store
        self.tmp.cleanup()

    def _run_ui(self, mode: str) -> dict:
        payload = {
            "mixed_report": MIXED_ALERTS_REPORT,
            "zero_report": ZERO_PATCHABLE_REPORT,
        }
        proc = subprocess.run(
            ["node", "-e", NODE_HARNESS, str(self.app_js), str(self.index_html), self.base_url, mode],
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"Node harness failed ({proc.returncode}): {proc.stderr}")
        return json.loads(proc.stdout)

    def test_existing_dependabot_preview_fields_control(self):
        expected = parse_dependabot_alerts_summary(MIXED_ALERTS_REPORT)
        out = self._run_ui("control")
        snap = out["controlSnapshot"]
        self.assertEqual(snap["postCount"], 1)
        self.assertFalse(snap["resultHidden"])
        self.assertTrue(snap["errorHidden"])
        self.assertEqual(snap["format"], "dependabot-alerts")
        self.assertEqual(snap["alertCount"], "3")
        self.assertEqual(snap["stateCounts"], "open:2 dismissed:0 fixed:1 auto_dismissed:0")
        self.assertEqual(snap["severityCounts"], "low:1 medium:1 high:1 critical:0")
        self.assertEqual(snap["reportSha256"], expected["report_sha256"])

    def test_dependabot_open_patchable_count_and_rejection_edges(self):
        expected_mixed = parse_dependabot_alerts_summary(MIXED_ALERTS_REPORT)
        expected_zero = parse_dependabot_alerts_summary(ZERO_PATCHABLE_REPORT)

        out = self._run_ui("patch_ready")
        mixed = out["mixedSnapshot"]
        self.assertTrue(mixed["htmlHasOpenPatchableEl"])
        self.assertFalse(mixed["resultHidden"])
        self.assertTrue(mixed["errorHidden"])
        self.assertEqual(mixed["openPatchableCount"], str(expected_mixed["open_alerts_with_available_patched_version"]))
        self.assertEqual(mixed["openPatchableCount"], "1")
        self.assertEqual(mixed["reportSha256"], expected_mixed["report_sha256"])

        for marker in (PKG_MARKER, ADV_MARKER, PATH_MARKER, PATCH_VER_MARKER, FIXED_VER_MARKER):
            self.assertNotIn(marker, mixed["allText"])

        zero = out["zeroSnapshot"]
        self.assertFalse(zero["resultHidden"])
        self.assertTrue(zero["errorHidden"])
        self.assertEqual(zero["openPatchableCount"], str(expected_zero["open_alerts_with_available_patched_version"]))
        self.assertEqual(zero["openPatchableCount"], "0")

        for cleared in (
            out["afterCloseSnapshot"],
            out["afterReopenSnapshot"],
            out["afterMalformedClientInputSnapshot"],
        ):
            self.assertTrue(cleared["resultHidden"])
            self.assertEqual(cleared["openPatchableCount"], "")

        self.assertFalse(out["afterMalformedClientInputSnapshot"]["errorHidden"])
        self.assertEqual(out["afterMalformedClientInputSnapshot"]["errorText"], "Geçersiz JSON.")

        for name, bad in out["invalidResponseSnapshots"].items():
            with self.subTest(invalid_case=name):
                self.assertFalse(bad["errorHidden"])
                self.assertEqual(bad["errorText"], "Geçersiz JSON.")
                self.assertTrue(bad["resultHidden"])
                self.assertEqual(bad["openPatchableCount"], "")


if __name__ == "__main__":
    unittest.main()
