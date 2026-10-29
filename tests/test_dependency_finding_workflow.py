import atexit
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path


_BOOT_DATA_DIR = tempfile.mkdtemp(prefix="sniper_job03_test_")
atexit.register(shutil.rmtree, _BOOT_DATA_DIR, True)
os.environ["SNIPER_DATA_DIR"] = _BOOT_DATA_DIR

_DEFAULT_ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = Path(os.environ.get("SNIPER_APP_ROOT", str(_DEFAULT_ROOT))).resolve()
sys.path.insert(0, str(APP_ROOT))

import server  # noqa: E402
from storage import Store  # noqa: E402


def _run_ui_harness(app_root: Path, base_url: str, dep_data: dict, filter_cfg: dict, inspect_id: str | None = None, update_payload: dict | None = None) -> dict:
    script = r"""
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const appRoot = process.argv[1];
const baseUrl = process.argv[2];
const depData = JSON.parse(process.argv[3]);
const filterCfg = JSON.parse(process.argv[4]);
const inspectId = process.argv[5] || "";
const updatePayload = JSON.parse(process.argv[6]);

const html = fs.readFileSync(path.join(appRoot, "static", "index.html"), "utf8");
const appJs = fs.readFileSync(path.join(appRoot, "static", "app.js"), "utf8");

function makeElement(id = "", tagName = "DIV") {
  const attrs = new Map();
  const classes = new Set(["hidden"]);
  let val = (id.startsWith("dependency-filter-") && id !== "dependency-filter-query") ? "all" : "";
  return {
    id,
    tagName,
    href: "#",
    get value() { return val; },
    set value(v) { val = String(v ?? ""); },
    textContent: "",
    innerHTML: "",
    dataset: {},
    style: {},
    disabled: false,
    checked: false,
    files: [],
    classList: {
      add: (...names) => names.forEach(n => classes.add(n)),
      remove: (...names) => names.forEach(n => classes.delete(n)),
      toggle: (name, force) => {
        if (force === undefined) {
          if (classes.has(name)) { classes.delete(name); return false; }
          classes.add(name); return true;
        }
        if (force) classes.add(name); else classes.delete(name);
        return !!force;
      },
      contains: (name) => classes.has(name),
    },
    setAttribute(name, v) { attrs.set(name, String(v)); },
    getAttribute(name) { return attrs.has(name) ? attrs.get(name) : null; },
    addEventListener() {},
    removeEventListener() {},
    replaceChildren() {},
    appendChild() {},
    append() {},
    remove() {},
    reset() {},
    focus() {},
    setSelectionRange() {},
    scrollIntoView() {},
    closest() { return null; },
    matches() { return false; },
    querySelector() { return makeElement("", "BUTTON"); },
    querySelectorAll() { return []; },
  };
}

const elements = new Map();
function getEl(selector) {
  const id = String(selector).replace(/^#/, "");
  if (!elements.has(id)) elements.set(id, makeElement(id));
  return elements.get(id);
}

const submitListeners = [];
const sandbox = {
  console,
  URL,
  URLSearchParams,
  TextEncoder,
  Intl,
  Date,
  Math,
  Number,
  String,
  Boolean,
  Array,
  Object,
  Set,
  Map,
  RegExp,
  Error,
  JSON,
  encodeURIComponent,
  decodeURIComponent,
  setTimeout: () => 1,
  clearTimeout: () => {},
  setInterval: () => 1,
  clearInterval: () => {},
  location: { hash: "#projects" },
  window: { addEventListener() {} },
  fetch: async (relUrl, options = {}) => {
    if (relUrl.startsWith("/api/dependency-findings/") || relUrl.startsWith("/api/dependency-security")) {
      return fetch(baseUrl + relUrl, options);
    }
    return {
      ok: true,
      status: 200,
      headers: { get: () => "application/json" },
      text: async () => "{}",
      json: async () => ({ targets: [], scans: [], engagements: [], lab_runs: [], project_audits: [], total: 0, categories: [], tools: [] }),
    };
  },
  document: {
    body: { style: {} },
    addEventListener(type, fn) {
      if (type === "submit") submitListeners.push(fn);
    },
    getElementById(id) { return getEl(id); },
    querySelector(sel) { return getEl(sel); },
    querySelectorAll() { return []; },
    createElement(tag) { return makeElement("", tag.toUpperCase()); },
  },
};
sandbox.window = sandbox;
sandbox.addEventListener = () => {};

vm.createContext(sandbox);
const strippedJs = appJs.replace(/\bnavigate\(location\.hash\.slice\(1\) \|\| "dashboard"\);\s*loadAll\(\);/, "");
vm.runInContext(strippedJs, sandbox);

(async () => {
  vm.runInContext(`state.dependencySecurity = ${JSON.stringify(depData)};`, sandbox);
  getEl("dependency-filter-query").value = filterCfg.query || "";
  getEl("dependency-filter-source").value = filterCfg.source || "all";
  getEl("dependency-filter-severity").value = filterCfg.severity || "all";
  getEl("dependency-filter-status").value = filterCfg.status || "all";
  sandbox.renderDependencySecurity();

  if (inspectId && typeof sandbox.openDependencyFindingDetail === "function") {
    sandbox.openDependencyFindingDetail(inspectId);
  }

  if (updatePayload) {
    const fakeForm = makeElement("dependency-finding-detail-form", "FORM");
    fakeForm.dataset.id = inspectId;
    const statusEl = makeElement("", "SELECT");
    statusEl.value = updatePayload.status;
    const notesEl = makeElement("", "TEXTAREA");
    notesEl.value = updatePayload.resolution_notes;
    const btnEl = makeElement("", "BUTTON");
    fakeForm.querySelector = (sel) => {
      if (sel === '[name="status"]') return statusEl;
      if (sel === '[name="resolution_notes"]') return notesEl;
      if (sel === 'button[type="submit"]') return btnEl;
      return null;
    };
    for (const fn of submitListeners) {
      await fn({ target: fakeForm, preventDefault() {} });
    }
  }

  const detailEl = elements.get("dependency-finding-detail") || null;
  const out = {
    htmlHasFilterBar: /id=["']dependency-filter-bar["']/.test(html),
    htmlHasDetailPanel: /id=["']dependency-finding-detail["']/.test(html),
    summaryHtml: getEl("dependency-summary").innerHTML,
    findingsHtml: getEl("dependency-findings").innerHTML,
    filterCountText: getEl("dependency-filter-count").textContent,
    detailHtml: detailEl ? detailEl.innerHTML : null,
  };
  process.stdout.write(JSON.stringify(out));
})();
"""
    proc = subprocess.run(
        [
            "node",
            "-e",
            script,
            str(app_root),
            base_url,
            json.dumps(dep_data),
            json.dumps(filter_cfg),
            inspect_id or "",
            json.dumps(update_payload),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(proc.stdout)


class DependencyFindingWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp.name) / "test.db"
        self.store = Store(self.db_path)
        self.prev_store = server.STORE
        server.STORE = self.store
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.port = self.httpd.server_address[1]
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.server_thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.server_thread.start()

        self.store.import_dependency_findings(
            {
                "project_path": "/tmp/dep-proj",
                "source": "trivy",
                "source_path": "/tmp/dep-proj/trivy.json",
                "source_timestamp": "2026-10-16T10:00:00+00:00",
                "document_hash": "1" * 64,
                "findings": [
                    {
                        "project_path": "/tmp/dep-proj",
                        "source": "trivy",
                        "vulnerability_id": "CVE-2026-1001",
                        "package_name": "urllib3",
                        "installed_version": "1.26.0",
                        "fixed_version": "1.26.19",
                        "severity": "high",
                        "title": "Redirects header leak",
                        "summary": "Authorization header forwarded across cross-host redirect.",
                        "target": "requirements.txt",
                        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-1001", "javascript:alert(1)"],
                    }
                ],
            }
        )
        self.store.import_dependency_findings(
            {
                "project_path": "/tmp/dep-proj",
                "source": "osv",
                "source_path": "/tmp/dep-proj/osv.json",
                "source_timestamp": "2026-10-16T11:00:00+00:00",
                "document_hash": "2" * 64,
                "findings": [
                    {
                        "project_path": "/tmp/dep-proj",
                        "source": "osv",
                        "vulnerability_id": "GHSA-xxxx-yyyy",
                        "package_name": "flask",
                        "installed_version": "2.0.0",
                        "fixed_version": "2.3.3",
                        "severity": "medium",
                        "title": "Session cookie parsing issue",
                        "summary": "Vary header missing on session variation.",
                        "target": "requirements.txt",
                        "references": ["https://osv.dev/vulnerability/GHSA-xxxx-yyyy"],
                    }
                ],
            }
        )

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        server.STORE = self.prev_store
        self.temp.cleanup()

    def test_PassingControl_renders_all_dependency_findings_and_summary(self):
        dep_data = self.store.dependency_security()
        ui = _run_ui_harness(APP_ROOT, self.base_url, dep_data, {})
        self.assertIn("CVE-2026-1001", ui["findingsHtml"])
        self.assertIn("GHSA-xxxx-yyyy", ui["findingsHtml"])
        self.assertIn("ETKİN BULGU", ui["summaryHtml"])

    def test_FilterAndSingleFindingDetailWorkflow_filters_and_updates_resolution_note(self):
        dep_data = self.store.dependency_security()
        trivy_finding = next(f for f in dep_data["findings"] if f["vulnerability_id"] == "CVE-2026-1001")

        ui = _run_ui_harness(
            APP_ROOT,
            self.base_url,
            dep_data,
            {"source": "trivy", "severity": "high", "status": "open", "query": "urllib3"},
            inspect_id=trivy_finding["id"],
            update_payload={"status": "in_progress", "resolution_notes": "1.26.19 yükseltme PR #42 açıldı"},
        )
        self.assertTrue(ui["htmlHasFilterBar"])
        self.assertTrue(ui["htmlHasDetailPanel"])
        # Updating an open-only result to in_progress removes it from that filtered page.
        self.assertNotIn("CVE-2026-1001", ui["findingsHtml"])
        self.assertNotIn("GHSA-xxxx-yyyy", ui["findingsHtml"])
        self.assertEqual(ui["filterCountText"], "0 eşleşme / 2 bulgu")
        self.assertIsNotNone(ui["detailHtml"])
        self.assertIn("Authorization header forwarded across cross-host redirect.", ui["detailHtml"])
        self.assertIn("1.26.19 yükseltme PR #42 açıldı", ui["detailHtml"])
        self.assertIn("Durum ve çözüm notu güncellendi.", ui["detailHtml"])
        self.assertNotIn("javascript:alert(1)", ui["detailHtml"])

        updated = next(f for f in self.store.dependency_security()["findings"] if f["id"] == trivy_finding["id"])
        self.assertEqual(updated["status"], "in_progress")
        self.assertEqual(updated["resolution_notes"], "1.26.19 yükseltme PR #42 açıldı")

    def test_EdgeCase_unmatched_filter_shows_zero_findings(self):
        dep_data = self.store.dependency_security()
        ui = _run_ui_harness(
            APP_ROOT,
            self.base_url,
            dep_data,
            {"source": "osv", "severity": "critical", "status": "resolved", "query": "nonexistent-pkg"},
        )
        self.assertEqual(ui["filterCountText"], "0 / 2 bulgu")
        self.assertEqual(ui["findingsHtml"], "")


if __name__ == "__main__":
    unittest.main()
