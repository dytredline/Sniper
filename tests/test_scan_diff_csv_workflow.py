import csv
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path


import atexit
import shutil

_BOOT_DATA_DIR = tempfile.mkdtemp(prefix="sniper_diff_csv_test_")
atexit.register(shutil.rmtree, _BOOT_DATA_DIR, True)
os.environ["SNIPER_DATA_DIR"] = _BOOT_DATA_DIR

_DEFAULT_ROOT = Path.cwd().resolve() if (Path.cwd() / "storage.py").exists() else Path(__file__).resolve().parents[1]
APP_ROOT = Path(os.environ.get("SNIPER_APP_ROOT", str(_DEFAULT_ROOT))).resolve()
sys.path.insert(0, str(APP_ROOT))

from scanner import normalize_target  # noqa: E402
import server  # noqa: E402
from storage import Store  # noqa: E402


def _run_ui_harness(app_root: Path, payload: dict) -> dict:
    script = r"""
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const appRoot = process.argv[1];
const payload = JSON.parse(process.argv[2]);
const html = fs.readFileSync(path.join(appRoot, "static", "index.html"), "utf8");
const appJs = fs.readFileSync(path.join(appRoot, "static", "app.js"), "utf8");

function makeElement(id = "", tagName = "DIV") {
  const attrs = new Map();
  const classes = new Set(["hidden"]);
  return {
    id,
    tagName,
    href: "#",
    value: "all",
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
    setAttribute(name, val) {
      attrs.set(name, String(val));
      if (name === "href") this.href = String(val);
    },
    getAttribute(name) {
      return attrs.has(name) ? attrs.get(name) : null;
    },
    addEventListener() {},
    removeEventListener() {},
    replaceChildren() {},
    appendChild() {},
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
  if (!elements.has(id)) {
    elements.set(id, makeElement(id));
  }
  return elements.get(id);
}

const diffTabs = ["new", "resolved", "persistent"].map(tab => {
  const el = makeElement(`tab-${tab}`, "BUTTON");
  el.dataset.tab = tab;
  el.classList.remove("hidden");
  if (tab === "new") el.classList.add("active");
  return el;
});

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
  location: { hash: "#dashboard" },
  window: { addEventListener() {} },
  fetch: async (url) => ({
    ok: true,
    status: 200,
    headers: { get: () => "application/json" },
    text: async () => JSON.stringify(payload.trendResponse || {}),
    json: async () => (payload.trendResponse || {}),
  }),
  document: {
    body: { style: {} },
    addEventListener() {},
    getElementById(id) { return getEl(id); },
    querySelector(sel) {
      if (sel === "#scan-diff-modal .diff-tab.active") {
        return diffTabs.find(t => t.classList.contains("active")) || diffTabs[0];
      }
      return getEl(sel);
    },
    querySelectorAll(sel) {
      if (sel === "#scan-diff-modal .diff-tab") return diffTabs;
      return [];
    },
    createElement(tag) { return makeElement("", tag.toUpperCase()); },
  },
};
sandbox.window = sandbox;
sandbox.addEventListener = () => {};

vm.createContext(sandbox);
// Prevent initial loadAll() network call on startup from overwriting state
const strippedJs = appJs.replace(/\bnavigate\(location\.hash\.slice\(1\) \|\| "dashboard"\);\s*loadAll\(\);/, "");
vm.runInContext(strippedJs, sandbox);

sandbox.renderScanDiffResult(payload.diffResult);
const jsonEl = getEl("scan-diff-download");
const htmlEl = getEl("scan-diff-download-html");
const csvEl = elements.get("scan-diff-download-csv") || null;

(async () => {
  await sandbox.openTrend("target-test-1");
  const drawerHtml = getEl("drawer-content").innerHTML;
  const out = {
    htmlHasScanDiffDownloadJson: /id=["']scan-diff-download["']/.test(html),
    htmlHasScanDiffDownloadHtml: /id=["']scan-diff-download-html["']/.test(html),
    htmlHasScanDiffDownloadCsv: /id=["']scan-diff-download-csv["']/.test(html),
    jsonHref: jsonEl.href,
    jsonDownload: jsonEl.getAttribute("download"),
    htmlHref: htmlEl.href,
    htmlDownload: htmlEl.getAttribute("download"),
    csvTouchedByRender: csvEl !== null,
    csvHref: csvEl ? csvEl.href : null,
    csvDownload: csvEl ? csvEl.getAttribute("download") : null,
    drawerHtml,
  };
  process.stdout.write(JSON.stringify(out));
})();
"""
    proc = subprocess.run(
        [os.environ.get("SNIPER_NODE_BINARY") or shutil.which("node") or "/nonexistent-node",
         "-e", script, str(app_root), json.dumps(payload)],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(proc.stdout)


class ScanDiffCsvWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp.name) / "test.db"
        self.store = Store(self.db_path)
        self.prev_store = server.STORE
        self.prev_scan_diff = server.SCAN_DIFF
        server.STORE = self.store
        server.SCAN_DIFF = server.ScanDiff(self.store)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.port = self.httpd.server_address[1]
        self.server_thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.server_thread.start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        server.STORE = self.prev_store
        server.SCAN_DIFF = self.prev_scan_diff
        self.temp.cleanup()

    def _create_completed_scan(self, target_id: str, score: int, grade: str, findings: list[dict], created_at: str) -> dict:
        scan = self.store.create_scan(target_id)
        self.store.mark_scan_running(scan["id"])
        self.store.complete_scan(
            scan["id"],
            {
                "score": score,
                "grade": grade,
                "counts": {"medium": len(findings)},
                "findings": findings,
                "metadata": {},
                "scope": {},
            },
        )
        with self.store._connect() as db:
            db.execute(
                "UPDATE scans SET created_at = ?, finished_at = ? WHERE id = ?",
                (created_at, created_at, scan["id"]),
            )
        return self.store.get_scan(scan["id"])

    def test_PassingControl_baseline_trend_and_existing_json_html_diff_exports(self):
        target = self.store.create_target(normalize_target("https://control-diff.example.com"))
        scan1 = self._create_completed_scan(
            target["id"],
            score=90,
            grade="A",
            findings=[{"id": "f-base", "severity": "low", "title": "Base Finding"}],
            created_at="2026-10-16T10:00:00+00:00",
        )
        scan2 = self._create_completed_scan(
            target["id"],
            score=78,
            grade="C",
            findings=[{"id": "f-new", "severity": "medium", "title": "New Finding"}],
            created_at="2026-10-16T11:00:00+00:00",
        )

        trend = self.store.target_trend(target["id"])
        self.assertEqual(len(trend["points"]), 2)
        first_point, second_point = trend["points"]
        self.assertNotIn("diff_links", first_point)
        self.assertIn("diff_links", second_point)
        base_path = f"/api/scans/diff/{scan1['id']}/{scan2['id']}"
        self.assertEqual(second_point["diff_links"]["previous_scan_id"], scan1["id"])
        self.assertEqual(second_point["diff_links"]["json"], base_path)
        self.assertEqual(second_point["diff_links"]["html"], f"{base_path}/report.html")

        ui = _run_ui_harness(
            APP_ROOT,
            {
                "diffResult": {
                    "summary": {
                        "scan_1_id": scan1["id"],
                        "scan_2_id": scan2["id"],
                        "score_delta": -12,
                        "new_count": 1,
                        "resolved_count": 1,
                        "persistent_count": 0,
                    },
                    "new_findings": [],
                    "resolved_findings": [],
                    "persistent_findings": [],
                },
                "trendResponse": trend,
            },
        )
        self.assertTrue(ui["htmlHasScanDiffDownloadJson"])
        self.assertTrue(ui["htmlHasScanDiffDownloadHtml"])
        self.assertEqual(ui["jsonHref"], f"{base_path}/report.json?download=1")
        self.assertEqual(ui["jsonDownload"], f"sniper-diff-{scan1['id']}-{scan2['id']}.json")
        self.assertEqual(ui["htmlHref"], f"{base_path}/report.html?download=1")
        self.assertEqual(ui["htmlDownload"], f"sniper-diff-{scan1['id']}-{scan2['id']}.html")
        self.assertIn(f'href="{base_path}/report.html"', ui["drawerHtml"])

    def test_TargetTrendAndScanDiffUi_expose_csv_download_and_serve_formula_neutral_csv(self):
        target = self.store.create_target(normalize_target("https://csv-diff.example.com"))
        scan1 = self._create_completed_scan(
            target["id"],
            score=92,
            grade="A",
            findings=[{"id": "f-old", "severity": "low", "title": "Resolved Header Signal"}],
            created_at="2026-10-16T12:00:00+00:00",
        )
        scan2 = self._create_completed_scan(
            target["id"],
            score=75,
            grade="C",
            findings=[{"id": "f-formula", "severity": "high", "title": "=2+2 Formula Signal", "affected_asset": "https://csv-diff.example.com/login"}],
            created_at="2026-10-16T13:00:00+00:00",
        )

        trend = self.store.target_trend(target["id"])
        second_point = trend["points"][1]
        expected_base = f"/api/scans/diff/{scan1['id']}/{scan2['id']}"
        self.assertEqual(
            second_point["diff_links"],
            {
                "previous_scan_id": scan1["id"],
                "json": expected_base,
                "html": f"{expected_base}/report.html",
                "csv": f"{expected_base}/report.csv",
            },
        )

        # Follow the trend CSV link against the HTTP server
        csv_url = f"http://127.0.0.1:{self.port}{second_point['diff_links']['csv']}?download=1"
        with urllib.request.urlopen(csv_url) as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("text/csv", resp.headers.get("Content-Type", ""))
            self.assertIn(
                f'filename="sniper-diff-{scan1["id"]}-{scan2["id"]}.csv"',
                resp.headers.get("Content-Disposition", ""),
            )
            body = resp.read().decode("utf-8")

        self.assertTrue(body.startswith("\ufeff"))
        rows = list(csv.DictReader(io.StringIO(body.lstrip("\ufeff"))))
        self.assertEqual(len(rows), 2)
        new_row = next(r for r in rows if r["change"] == "new")
        self.assertEqual(new_row["title"], "'=2+2 Formula Signal")

        # Verify UI wiring in static/index.html and static/app.js
        ui = _run_ui_harness(
            APP_ROOT,
            {
                "diffResult": {
                    "summary": {
                        "scan_1_id": scan1["id"],
                        "scan_2_id": scan2["id"],
                        "score_delta": -17,
                        "new_count": 1,
                        "resolved_count": 1,
                        "persistent_count": 0,
                    },
                    "new_findings": [],
                    "resolved_findings": [],
                    "persistent_findings": [],
                },
                "trendResponse": trend,
            },
        )
        self.assertTrue(ui["htmlHasScanDiffDownloadCsv"], "static/index.html must include #scan-diff-download-csv")
        self.assertTrue(ui["csvTouchedByRender"], "renderScanDiffResult must wire #scan-diff-download-csv")
        self.assertEqual(ui["csvHref"], f"{expected_base}/report.csv?download=1")
        self.assertEqual(ui["csvDownload"], f"sniper-diff-{scan1['id']}-{scan2['id']}.csv")
        self.assertIn(f'href="{expected_base}/report.csv"', ui["drawerHtml"])
        self.assertIn("trend-diff-csv-link", ui["drawerHtml"])

    def test_EdgeCases_same_timestamp_omits_diff_links_and_special_ids_encode_and_reverse_csv_400(self):
        target = self.store.create_target(normalize_target("https://edge-diff.example.com"))
        same_ts = "2026-10-16T14:00:00+00:00"
        scan1 = self._create_completed_scan(target["id"], 88, "B", [], created_at=same_ts)
        scan2 = self._create_completed_scan(target["id"], 84, "B", [], created_at=same_ts)

        trend = self.store.target_trend(target["id"])
        self.assertEqual(len(trend["points"]), 2)
        self.assertNotIn("diff_links", trend["points"][0])
        self.assertNotIn("diff_links", trend["points"][1])

        # Reverse chronology on report.csv must reject with HTTP 400
        later_scan = self._create_completed_scan(
            target["id"], 80, "B", [], created_at="2026-10-16T15:00:00+00:00"
        )
        reverse_url = f"http://127.0.0.1:{self.port}/api/scans/diff/{later_scan['id']}/{scan1['id']}/report.csv"
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(reverse_url)
        self.assertEqual(ctx.exception.code, 400)
        ctx.exception.close()

        # URL-unsafe characters in scan IDs are encoded in #scan-diff-download-csv.href
        ui = _run_ui_harness(
            APP_ROOT,
            {
                "diffResult": {
                    "summary": {
                        "scan_1_id": "scan/1?a=b",
                        "scan_2_id": "scan#2&c=d",
                        "score_delta": 0,
                        "new_count": 0,
                        "resolved_count": 0,
                        "persistent_count": 0,
                    },
                    "new_findings": [],
                    "resolved_findings": [],
                    "persistent_findings": [],
                },
                "trendResponse": {"target": {"hostname": "edge-diff.example.com"}, "points": []},
            },
        )
        self.assertEqual(
            ui["csvHref"],
            "/api/scans/diff/scan%2F1%3Fa%3Db/scan%232%26c%3Dd/report.csv?download=1",
        )


if __name__ == "__main__":
    unittest.main()
