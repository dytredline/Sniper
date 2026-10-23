import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";

const app = readFileSync(new URL("../static/app.js", import.meta.url), "utf8");

function actualNavigationSource(source) {
  const start = source.indexOf("const NAVIGATION_DESTINATIONS = Object.freeze({");
  const end = source.indexOf("\nasync function loadAll()", start);
  const hashStart = source.indexOf('window.addEventListener("hashchange", () => navigate(location.hash.slice(1)));');
  const hashEnd = source.indexOf("\n", hashStart);
  const startup = 'navigate(location.hash.slice(1) || "dashboard");';
  const startupStart = source.indexOf(startup);
  assert.ok(start >= 0 && end > start, "constant navigation destination resolver must be present");
  assert.ok(hashStart >= 0 && hashEnd > hashStart, "real hashchange handler must be present");
  assert.ok(startupStart >= 0, "real initial hash navigation must be present");
  return `${source.slice(start, end)}\n${source.slice(hashStart, hashEnd)}\n`
    + `function runInitialNavigation() { ${startup} }\n`
    + "({ navigationDestination, navigate, runInitialNavigation });";
}

function node(dataset = {}) {
  const classes = new Set();
  return {
    dataset,
    textContent: "",
    classList: {
      add(name) { classes.add(name); },
      remove(name) { classes.delete(name); },
      toggle(name, force) { if (force) classes.add(name); else classes.delete(name); },
      contains(name) { return classes.has(name); },
    },
  };
}

function harness(initialHash) {
  const origin = "https://sniper.local";
  const location = { origin, hash: initialHash, href: `${origin}/${initialHash}` };
  const historyCalls = [];
  const listeners = new Map();
  const pageLabel = node();
  const sidebar = node();
  const views = ["dashboard", "reports", "targets"].map(view => node({ view }));
  const navItems = ["dashboard", "reports", "targets"].map(nav => node({ nav }));
  const context = vm.createContext({
    location,
    history: {
      replaceState(_state, _title, destination) {
        historyCalls.push(destination);
        const target = new URL(destination, location.href);
        location.href = target.href;
        location.hash = target.hash;
      },
    },
    window: {
      addEventListener(type, callback) { listeners.set(type, callback); },
    },
    $(selector) {
      if (selector === "#page-label") return pageLabel;
      if (selector === ".sidebar") return sidebar;
      throw new Error(`unexpected selector ${selector}`);
    },
    $$(selector) {
      if (selector === "[data-view]") return views;
      if (selector === ".nav-item") return navItems;
      throw new Error(`unexpected selector ${selector}`);
    },
    loadAudit() { throw new Error("invalid hashes must not open audit"); },
  });
  const methods = vm.runInContext(actualNavigationSource(app), context, { filename: "static/app.js/navigation" });
  return {
    ...methods,
    location,
    historyCalls,
    origin,
    pageLabel,
    views,
    fireHashChange() { listeners.get("hashchange")(); },
  };
}

const hostileHashes = [
  "#//evil.test/path",
  "#https://evil.test/path",
  "#javascript:alert(1)",
  "#\\evil.test",
  "#%2f%2fevil.test",
  "#%5cevil.test",
];

test("initial hostile hashes resolve to the constant dashboard fragment without changing origin", () => {
  for (const hash of hostileHashes) {
    const ui = harness(hash);
    ui.runInitialNavigation();
    assert.deepEqual(ui.historyCalls, ["#dashboard"], hash);
    assert.equal(ui.location.hash, "#dashboard", hash);
    assert.equal(new URL(ui.location.href).origin, ui.origin, hash);
  }
});

test("hashchange hostile values resolve to dashboard while a valid view remains functional", () => {
  for (const hash of hostileHashes) {
    const ui = harness("#reports");
    ui.location.hash = hash;
    ui.location.href = `${ui.origin}/${hash}`;
    ui.fireHashChange();
    assert.deepEqual(ui.historyCalls, ["#dashboard"], hash);
    assert.equal(new URL(ui.location.href).origin, ui.origin, hash);
  }

  const valid = harness("#reports");
  valid.runInitialNavigation();
  assert.deepEqual(valid.historyCalls, []);
  assert.equal(valid.navigationDestination("reports").hash, "#reports");
  assert.equal(valid.pageLabel.textContent, "Raporlar");
  assert.equal(valid.views.find(item => item.dataset.view === "reports").classList.contains("active"), true);
});
