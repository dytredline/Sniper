import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";

const app = readFileSync(new URL("../static/app.js", import.meta.url), "utf8");
const html = readFileSync(new URL("../static/index.html", import.meta.url), "utf8");
const advanced = readFileSync(new URL("../static/advanced_tools.js", import.meta.url), "utf8");
const server = readFileSync(new URL("../server.py", import.meta.url), "utf8");

// --- küçük sahte DOM -------------------------------------------------------------------
class El {
  constructor(tag) {
    this.tagName = tag.toUpperCase(); this.children = []; this.dataset = {}; this.listeners = {};
    this._text = ""; this.value = ""; this.checked = false; this.files = []; this.label = "";
    const classes = new Set();
    this.classList = { add: c => classes.add(c), remove: c => classes.delete(c), contains: c => classes.has(c),
      toggle: (c, on) => { const v = on === undefined ? !classes.has(c) : on; v ? classes.add(c) : classes.delete(c); return v; } };
  }
  append(...nodes) { for (const n of nodes) this.children.push(typeof n === "string" ? new Text(n) : n); }
  replaceChildren() { this.children = []; this._text = ""; }
  get childNodes() { return this.children; }
  set textContent(v) { this.children = []; this._text = String(v); }
  get textContent() { return this._text + this.children.map(c => c.textContent).join(""); }
  set innerHTML(v) { this.children = []; this._text = String(v); this.html = String(v); }
  get innerHTML() { return this.html || ""; }
  addEventListener(type, fn) { (this.listeners[type] ||= []).push(fn); }
  *walk() { yield this; for (const c of this.children) if (c instanceof El) yield* c.walk(); }
}
class Text { constructor(t) { this.textContent = t; } }

function makeDom(ids) {
  const nodes = new Map(ids.map(id => [id, new El(id.includes("route") ? "select" : "div")]));
  return {
    nodes,
    readyState: "complete",
    createElement: tag => new El(tag),
    createTextNode: text => new Text(text),
    getElementById: id => nodes.get(id) || null,
    querySelector(selector) {
      const match = selector.match(/data-advanced-field="([^"]+)"/);
      if (!match) return null;
      for (const node of nodes.get("advanced-tool-fields").walk()) if (node.dataset.advancedField === match[1]) return node;
      return null;
    },
    addEventListener() {},
  };
}

async function loadAdvanced(apiImpl) {
  const ids = ["advanced-tool-route", "advanced-tool-form", "advanced-tool-fields", "advanced-tool-error", "advanced-tool-summary",
    "advanced-tool-output", "advanced-tool-submit", "advanced-tool-refresh", "advanced-tool-route-info", "advanced-tool-panel"];
  const document = makeDom(ids);
  const calls = [];
  const api = async (path, options = {}) => { calls.push({ path, options }); return apiImpl ? apiImpl(path, options) : {}; };
  const context = vm.createContext({ document, api, esc: v => String(v), console, Promise, JSON, Object, Array, Number, String, encodeURIComponent });
  context.globalThis = context;
  vm.runInContext(advanced, context);
  await new Promise(resolve => setImmediate(resolve)); // init'in liste yüklemesi bitsin
  return { context, document, calls, tools: context.SniperAdvancedTools };
}

const field = (dom, name) => {
  for (const node of dom.nodes.get("advanced-tool-fields").walk()) if (node.dataset.advancedField === name) return node;
  throw new Error(`alan yok: ${name}`);
};

// --- kart hedefleri ------------------------------------------------------------------------
test("every tool card destination resolves to an existing view, action, panel, flow or form route", async () => {
  const mapSource = app.slice(app.indexOf("const TOOL_CARD_DESTINATIONS"), app.indexOf("});", app.indexOf("const TOOL_CARD_DESTINATIONS")) + 3);
  const map = vm.runInNewContext(`(${mapSource.replace("const TOOL_CARD_DESTINATIONS = ", "").replace(/;$/, "")})`);
  const { tools } = await loadAdvanced();
  const flows = new Set(tools.FLOWS.map(flow => flow.id));
  const formRoutes = new Set([...html.matchAll(/<option value="(\/api\/[^"]+)"/g)].map(m => m[1]));
  const views = ["dashboard", "targets", "projects", "pentest", "tooling", "lab", "reports", "audit"];
  let completedWithoutRoute = 0;
  for (const [route, destination] of Object.entries(map)) {
    if (destination.view) assert.ok(views.includes(destination.view), route);
    if (destination.action) assert.ok(html.includes(`data-action="${destination.action}"`), `${route} → ${destination.action}`);
    if (destination.panel) assert.ok(html.includes(`id="${destination.panel}"`), `${route} → ${destination.panel}`);
    if (destination.flow) assert.ok(flows.has(destination.flow), `${route} → akış ${destination.flow}`);
    if (destination.route) assert.ok(formRoutes.has(destination.route), `${route} → seçenek ${destination.route}`);
    if (destination.panel === "completed-backlog-panel" && !destination.route) completedWithoutRoute += 1;
  }
  assert.equal(completedWithoutRoute, 0, "genel forma rotası seçilmeden giden kart kalmamalı");
  for (const route of ["/api/project-audits", "/api/project-audits/diff", "/api/web-infra/dns-email-audit", "/api/privacy-dataflow/audit", "/api/zero-trust-mesh/audit"]) {
    assert.ok(map[route], `yerleşik araç rotası eşlenmeli: ${route}`);
  }
});

test("every advanced flow route exists in server.py", async () => {
  const { tools } = await loadAdvanced();
  for (const flow of tools.FLOWS) {
    if (flow.route.includes("{")) {
      const tail = flow.route.split("}/").pop().replace("{slug}", "");
      const pieces = tail.split("/").filter(Boolean);
      assert.ok(pieces.every(piece => server.includes(`"${piece}"`)), flow.route);
    } else {
      assert.ok(server.includes(`"${flow.route}"`), flow.route);
    }
  }
  for (const slug of Object.keys(tools.EVIDENCE_SLUGS)) assert.ok(server.includes(`"${slug}"`), slug);
});

test("card with a flow opens the advanced panel flow, card with a form route preselects it", () => {
  const start = app.indexOf("function openToolCardRoute(route) {");
  const end = app.indexOf("\ndocument.addEventListener", start);
  const opened = [];
  const select = { value: "", dispatchEvent() {} };
  const panel = { scrollIntoView() {}, querySelector() { return null; } };
  const ctx = vm.createContext({
    TOOL_CARD_DESTINATIONS: {
      "/a": { panel: "advanced-tool-panel", flow: "k6-loopback" },
      "/b": { panel: "completed-backlog-panel", route: "/api/privacy-dataflow/audit" },
    },
    toolCardProfileAvailable: () => true,
    state: { toolingReadiness: { tools: [{ profiles: [{ route: "/a" }, { route: "/b" }] }] } },
    document: { getElementById: id => (id === "completed-trivy-route" ? select : panel) },
    navigate() {},
  });
  ctx.globalThis = ctx;
  ctx.openAdvancedToolFlow = flow => opened.push(flow);
  vm.runInContext(app.slice(start, end), ctx);
  assert.equal(vm.runInContext('openToolCardRoute("/a")', ctx), true);
  assert.deepEqual(opened, ["k6-loopback"]);
  assert.equal(vm.runInContext('openToolCardRoute("/b")', ctx), true);
  assert.equal(select.value, "/api/privacy-dataflow/audit");
});

// --- yük üretimi -----------------------------------------------------------------------
test("advanced flows build exactly the key sets the server expects", async () => {
  const { tools, document } = await loadAdvanced();
  tools.lists.targets.push({ id: "tgt_1", hostname: "app.local" });
  tools.lists.engagements.push({ id: "eng_1", name: "Denetim", status: "active", authorization_ref: "YETKI-1", special_approvals: { redacted_data_proof: true } });
  tools.lists.audits.push({ id: "prj_1" }, { id: "prj_2" });

  tools.selectFlow("zap-af-preview");
  field(document, "target_id").value = "tgt_1";
  field(document, "engagement_id").value = "eng_1";
  field(document, "mode").value = "PASSIVE_ONLY";
  field(document, "confirm_authorized").checked = true;
  field(document, "confirm_crawl").checked = true;
  let flow = tools.FLOWS.find(f => f.id === "zap-af-preview");
  let req = tools.buildRequest(flow, await tools.readValues(flow));
  assert.deepEqual(Object.keys(JSON.parse(req.options.body)).sort(),
    ["confirm_authorized", "confirm_crawl", "engagement_id", "mode", "selected_path", "target_id"]);
  field(document, "mode").value = "ACTIVE_ROOT";
  assert.throws(() => tools.buildRequest(flow, { mode: "ACTIVE_ROOT", confirm_active: false }), /aktif kurallar onayı/);

  tools.selectFlow("nmap-service-fingerprint");
  field(document, "target_id").value = "tgt_1";
  field(document, "engagement_id").value = "eng_1";
  field(document, "ports").value = "22, 443";
  flow = tools.FLOWS.find(f => f.id === "nmap-service-fingerprint");
  await assert.rejects(tools.readValues(flow), /Onay gerekli/);
  field(document, "confirm_authorized").checked = true;
  field(document, "confirm_service_probes").checked = true;
  req = tools.buildRequest(flow, await tools.readValues(flow));
  assert.deepEqual(JSON.parse(req.options.body), {
    target_id: "tgt_1", engagement_id: "eng_1", ports: [22, 443], confirm_authorized: true, confirm_service_probes: true,
  });
  field(document, "ports").value = "1,2,3,4,5,6,7,8,9";
  await assert.rejects(tools.readValues(flow), /1–8/);

  flow = tools.FLOWS.find(f => f.id === "burp-logger-csv");
  assert.deepEqual(JSON.parse(JSON.stringify(flow.build({ report: "a,b", status_column: "Status", mime_column: "" }))),
    { report: "a,b", columns: { status: "Status", mime: null } });

  flow = tools.FLOWS.find(f => f.id === "trivy-db-freshness");
  assert.deepEqual(JSON.parse(JSON.stringify(tools.buildRequest(flow, {}))), { path: "/api/tool-reports/trivy/db-freshness", options: {} });

  flow = tools.FLOWS.find(f => f.id === "ssllabs-rate-state");
  assert.equal(tools.buildRequest(flow, { hostname: "a b" }).path, "/api/tools/ssllabs/rate-state?hostname=a%20b");

  flow = tools.FLOWS.find(f => f.id === "project-audit-diff");
  assert.throws(() => flow.build({ before_id: "prj_1", after_id: "prj_1" }), /farklı/);
  assert.deepEqual({ ...flow.build({ before_id: "prj_1", after_id: "prj_2" }) }, { before_id: "prj_1", after_id: "prj_2" });
});

test("evidence link coerces report types per slug and encodes the engagement path", async () => {
  const { tools } = await loadAdvanced();
  const flow = tools.FLOWS.find(f => f.id === "tool-evidence");
  const jsonl = flow.build({ slug: "trufflehog-json", control_id: "WSTG-ATHN-01", report: '{"a":1}\n{"b":2}\n', confirm_link: true });
  assert.deepEqual(JSON.parse(JSON.stringify(jsonl.report)), [{ a: 1 }, { b: 2 }]);
  const text = flow.build({ slug: "schemathesis-junit", control_id: "C", report: "<testsuite/>", confirm_link: true });
  assert.equal(text.report, "<testsuite/>");
  assert.throws(() => flow.build({ slug: "sarif", control_id: "C", report: "[1]", confirm_link: true }), /JSON nesnesi/);
  assert.throws(() => flow.build({ slug: "yok", control_id: "C", report: "{}", confirm_link: true }), /Geçersiz rapor türü/);
  const req = tools.buildRequest(flow, { engagement_id: "eng/../x", slug: "sarif", control_id: "C", report: "{}", confirm_link: true });
  assert.equal(req.path, "/api/engagements/eng%2F..%2Fx/tool-evidence/sarif");
  assert.deepEqual(Object.keys(JSON.parse(req.options.body)).sort(), ["confirm_link", "control_id", "report"]);
  assert.throws(() => tools.buildRequest(flow, { engagement_id: "", slug: "sarif" }), /Denetim seçilmedi/);
});

test("engagement selects only offer eligible engagements; proof flows require redacted proof approval", async () => {
  const { tools, document } = await loadAdvanced();
  tools.lists.engagements.push(
    { id: "a", name: "A", status: "active", authorization_ref: "R", special_approvals: { redacted_data_proof: true } },
    { id: "b", name: "B", status: "active", authorization_ref: "R", special_approvals: {} },
    { id: "c", name: "C", status: "paused", authorization_ref: "R", special_approvals: { redacted_data_proof: true } },
  );
  tools.selectFlow("zap-site-active");
  assert.deepEqual([...field(document, "engagement_id").children.map(o => o.value)], ["", "a", "b"]);
  tools.selectFlow("tool-evidence");
  assert.deepEqual([...field(document, "engagement_id").children.map(o => o.value)], ["", "a"]);
});

test("submit renders server data with textContent and shows errors without HTML", async () => {
  const { tools, document, calls } = await loadAdvanced(async () => ({ format: "<img src=x onerror=alert(1)>", total: 2, nested: { a: 1 } }));
  tools.selectFlow("dns-email");
  field(document, "hostname").value = "example.org";
  document.nodes.get("advanced-tool-route").value = "dns-email";
  const data = await tools.submit();
  assert.equal(data.total, 2);
  assert.deepEqual(JSON.parse(calls.at(-1).options.body), { hostname: "example.org" });
  const output = document.nodes.get("advanced-tool-output");
  assert.match(output.textContent, /onerror/);
  assert.equal(output.innerHTML, "");
  assert.equal(document.nodes.get("advanced-tool-summary").innerHTML, "");

  field(document, "hostname").value = "";
  assert.equal(await tools.submit(), null);
  assert.match(document.nodes.get("advanced-tool-error").textContent, /gerekli/);
});

// --- index.html ve yardımcılar ------------------------------------------------------------
test("index.html loads the boundary renderers as a module and the advanced panel script", () => {
  assert.match(html, /<script type="module" src="\/tool_boundary_summaries\.js\?v=\d+"><\/script>/);
  assert.match(html, /<script src="\/advanced_tools\.js\?v=\d+" defer><\/script>/);
  for (const id of ["advanced-tool-panel", "advanced-tool-form", "advanced-tool-route", "advanced-tool-fields", "advanced-tool-output", "taint-engine-status"]) {
    assert.ok(html.includes(`id="${id}"`), id);
  }
});

test("boundary renderers are published under a namespace and do not clobber app.js helpers", async () => {
  const before = globalThis.requestDependencyRemediationPlan;
  await import("../static/tool_boundary_summaries.js");
  assert.equal(globalThis.requestDependencyRemediationPlan, before);
  assert.equal(typeof globalThis.SniperToolBoundary.renderBurpHandoffManifestHtml, "function");
});

test("no static script references an element id missing from index.html", () => {
  const ids = new Set([...html.matchAll(/id="([^"]+)"/g)].map(m => m[1]));
  const dir = new URL("../static/", import.meta.url);
  const sources = readdirSync(dir).filter(name => name.endsWith(".js")).map(name => readFileSync(new URL(name, dir), "utf8"));
  const dynamic = new Set(sources.flatMap(source => [...source.matchAll(/id=["']([A-Za-z0-9_-]+)["']/g)].map(m => m[1])));
  const missing = [];
  for (const source of sources) {
    for (const m of source.matchAll(/getElementById\(\s*["']([A-Za-z0-9_-]+)["']\s*\)/g)) {
      if (!ids.has(m[1]) && !dynamic.has(m[1])) missing.push(m[1]);
    }
  }
  assert.deepEqual(missing, []);
});

test("taint engine status text explains engines and model errors", () => {
  const start = app.indexOf("function taintEngineStatusText(engine) {");
  const end = app.indexOf("\nfunction renderTaintEngineStatus", start);
  const ctx = vm.createContext({});
  vm.runInContext(app.slice(start, end), ctx);
  const text = vm.runInContext(`taintEngineStatusText({ enabled: true, python: "interprocedural_ast", javascript: "token_fallback", models: { python: { errors: [] }, javascript: { errors: ["extra.json: bozuk"] } } })`, ctx);
  assert.match(text, /Python: fonksiyonlar ve dosyalar arası/);
  assert.match(text, /belirteç tabanlı yedek motor/);
  assert.match(text, /javascript: extra\.json: bozuk/);
  assert.match(vm.runInContext(`taintEngineStatusText({ enabled: false })`, ctx), /kapalı/);
  assert.equal(vm.runInContext(`taintEngineStatusText(null)`, ctx), "");
});

test("project audit history offers a comparison button wired to the diff flow", () => {
  assert.match(html, /data-action="open-project-audit-diff"/);
  const start = app.indexOf('const opener = event.target.closest?.(\'[data-action="open-project-audit-diff"]\');');
  assert.ok(start > 0);
  assert.match(app.slice(start, start + 400), /openAdvancedToolFlow\("project-audit-diff"\)/);
});

test("sandbox flows build exact bodies with a single confirmation", async () => {
  const { tools } = await loadAdvanced();
  const body = (id, values) => JSON.parse(tools.buildRequest(tools.FLOWS.find(f => f.id === id), values).options.body);
  assert.deepEqual(body("sandbox-scope", { scope: "critical", enabled: "on", confirm: true }),
    { confirm: true, action: "scope", scope: "critical", enabled: true });
  assert.equal(body("sandbox-scope", { scope: "local", enabled: "off", confirm: true }).enabled, false);
  assert.deepEqual(body("sandbox-target-add", { port: "3000", tools: "both", label: "api", confirm: true }),
    { confirm: true, action: "add-local", port: 3000, tools: ["k6", "schemathesis"], label: "api" });
  assert.throws(() => body("sandbox-target-add", { port: "abc", tools: "both", confirm: true }), /tam sayı/);
  assert.deepEqual(body("sandbox-target-remove", { id: "local:3000", confirm: true }), { confirm: true, action: "remove", id: "local:3000" });
  assert.deepEqual(body("sandbox-verify-start", { host: "ornek.com", port: "443", scheme: "https", tools: "k6", confirm: true }),
    { confirm: true, action: "verify-start", host: "ornek.com", port: 443, scheme: "https", tools: ["k6"] });
  assert.deepEqual(body("sandbox-verify", { id: "a".repeat(32), confirm: true }), { confirm: true, action: "verify", id: "a".repeat(32) });
  assert.deepEqual(body("sandbox-preset-set", { name: "ozel", vus: "7", duration_s: "20", confirm: true }),
    { confirm: true, action: "preset-set", name: "ozel", vus: 7, duration_s: 20 });
  assert.deepEqual(body("k6-sandbox", { target: "http://127.0.0.1:3000", path: "/", method: "GET", preset: "", confirm: true }),
    { confirm: true, target: "http://127.0.0.1:3000", path: "/", method: "GET" });
  assert.equal(body("k6-sandbox", { target: "https://ornek.com:443", path: "/a", method: "HEAD", preset: "yogun", confirm: true }).preset, "yogun");
  const st = body("schemathesis-sandbox", { target: "http://127.0.0.1:3000", schema: { openapi: "3.0.3", paths: {} }, max_examples: "5", max_time_s: "30", confirm: true });
  assert.deepEqual(Object.keys(st).sort(), ["confirm", "max_examples", "max_time_s", "schema", "target"]);
  assert.deepEqual(body("k6-authorized", { target: "https://api.ornek.com:443", path: "/health", method: "GET", preset: "hafif", confirm_authorized: true }),
    { confirm_authorized: true, target: "https://api.ornek.com:443", path: "/health", method: "GET", preset: "hafif" });
  assert.deepEqual(body("schemathesis-authorized", { target: "https://api.ornek.com:443", schema: { openapi: "3.0.3", paths: {} }, max_examples: "5", max_time_s: "30", confirm_authorized: true }),
    { confirm_authorized: true, target: "https://api.ornek.com:443", schema: { openapi: "3.0.3", paths: {} }, max_examples: 5, max_time_s: 30 });
  assert.deepEqual(body("sandbox-target-add", { port: "3000", tools: "all", label: "", confirm: true }).tools, ["k6", "schemathesis", "playwright", "runtime_proof"]);
  assert.deepEqual(body("sandbox-target-tools", { id: "local:3000", tools: "playwright", confirm: true }),
    { confirm: true, action: "set-tools", id: "local:3000", tools: ["playwright"] });
  assert.deepEqual(body("playwright-sandbox", { target: "http://127.0.0.1:3000", paths: ["/", "/giris"], timeout_s: "15",
    reflection_probe: "on", screenshot: "off", ignore_https_errors: "off", confirm: true }),
  { confirm: true, target: "http://127.0.0.1:3000", paths: ["/", "/giris"], timeout_s: 15, reflection_probe: true,
    screenshot: false, ignore_https_errors: false });
  assert.deepEqual(body("playwright-authorized", { target: "https://uygulama.example", paths: ["/", "/giris"],
    timeout_s: "15", reflection_probe: "off", screenshot: "off", ignore_https_errors: "off", confirm_authorized: true }),
  { confirm_authorized: true, target: "https://uygulama.example", paths: ["/", "/giris"], timeout_s: 15,
    reflection_probe: false, screenshot: false, ignore_https_errors: false });
  const authorizedPlaywright = tools.FLOWS.find(f => f.id === "playwright-authorized");
  assert.equal(authorizedPlaywright.fields.filter(f => f.type === "checkbox").length, 1);
  assert.equal(authorizedPlaywright.fields.find(f => f.type === "checkbox").name, "confirm_authorized");
  assert.deepEqual(body("bounded-dast-runtime-proof", { audit_id: "prj_1", finding_index: "0",
    profile_id: "open_redirect", target: "http://127.0.0.1:3000", path: "/redirect", parameter: "", confirm_local: true }),
  { profile_id: "open_redirect", target: "http://127.0.0.1:3000", path: "/redirect", parameter: "next", confirm_local: true });
  assert.deepEqual(body("bounded-dast-runtime-proof", { audit_id: "prj_1", finding_index: "2",
    profile_id: "cors_credentials", target: "http://127.0.0.1:3000", path: "/cors", parameter: "", confirm_local: true }),
  { profile_id: "cors_credentials", target: "http://127.0.0.1:3000", path: "/cors", parameter: "", confirm_local: true });
  assert.deepEqual(body("bounded-dast-runtime-proof", { audit_id: "prj_1", finding_index: "3",
    profile_id: "clickjacking_headers", target: "http://127.0.0.1:3000", path: "/", parameter: "", confirm_local: true }),
  { profile_id: "clickjacking_headers", target: "http://127.0.0.1:3000", path: "/", parameter: "", confirm_local: true });
  assert.deepEqual(body("asan-selftest", { confirm_local: true }), { confirm_local: true });
  assert.deepEqual(body("asan-source-proof", { audit_id: "prj_1", finding_index: "4",
    source_relpath: "src/problem.c", confirm_local: true }),
  { source_relpath: "src/problem.c", confirm_local: true });
  assert.throws(() => body("asan-source-proof", { audit_id: "prj_1", finding_index: "-1",
    source_relpath: "src/problem.c", confirm_local: true }), /negatif olmayan/);
  assert.deepEqual(body("asan-compile-database-proof", { audit_id: "prj_1", finding_index: "4",
    compile_commands_relpath: "build/compile_commands.json", entry_index: "7", confirm_local: true }),
  { compile_commands_relpath: "build/compile_commands.json", entry_index: 7, confirm_local: true });
  assert.throws(() => body("asan-compile-database-proof", { audit_id: "prj_1", finding_index: "4",
    compile_commands_relpath: "compile_commands.json", entry_index: "-1", confirm_local: true }), /negatif olmayan/);
  for (const flow of tools.FLOWS.filter(f => f.group === "Yalıtılmış test")) {
    assert.ok(flow.fields.filter(f => f.type === "checkbox").length <= 1, `${flow.id}: tek onay`);
  }
});
