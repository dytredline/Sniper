// Tehdit modeli paneli ve erişilebilirlik tablosu: güvenilmeyen metinler kaçışlanır, sıralama doğru.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const source = readFileSync(new URL("../static/threat_model.js", import.meta.url), "utf8");

function makeElement(tag = "div") {
  return {
    tagName: tag, id: "", className: "", dataset: {}, innerHTML: "", children: [],
    appendChild(child) { this.children.push(child); return child; },
    insertBefore(child) { this.children.unshift(child); return child; },
    querySelector(sel) {
      if (sel === ".threat-model-panel") return this.children.find(c => c.className === "threat-model-panel") || null;
      return null;
    },
  };
}

function load(fetchImpl) {
  const detail = makeElement("section");
  const context = {
    document: { createElement: makeElement, getElementById: id => (id === "project-audit-detail" ? detail : null) },
    fetch: fetchImpl,
    encodeURIComponent,
  };
  context.globalThis = context;
  vm.runInNewContext(source, context);
  return { context, detail };
}

test("reachability table escapes package names and orders by effective severity", () => {
  const { context } = load(async () => ({}));
  const el = makeElement();
  context.renderReachabilitySummary({
    format: "sniper-vulnerability-reachability-v1",
    symbol_analysis: { verdict_counts: { reachable: 1 }, verdict_labels: { reachable: "Erişilebilir" } },
    items: [
      { package_name: "low-pkg", vulnerability_id: "A", reachability: { verdict: "not_imported", effective_severity: "low", base_severity: "medium", evidence: [] } },
      { package_name: "<img src=x onerror=alert(1)>", vulnerability_id: "B", reachability: { verdict: "reachable", effective_severity: "critical", base_severity: "critical", evidence: [{ file: "a.js", line: 3 }], matched_symbols: ["merge"] } },
    ],
  }, el);
  const html = el.children[0].innerHTML;
  assert.ok(!html.includes("<img"));
  assert.ok(html.includes("&lt;img src=x onerror=alert(1)&gt;"));
  assert.ok(html.indexOf("&lt;img") < html.indexOf("low-pkg"), "kritik ve erişilebilir önce");
  assert.ok(html.includes("medium'dan düşürüldü"));
});

test("threat panel renders model with escaped findings and ignores other formats", async () => {
  const model = {
    route_count: 1, threats: [{ id: "T01", stride: "T", stride_label: "Kurcalama", title: "SQL", status: "finding", status_label: "Bulgu var", finding_refs: [0], finding_count: 1 }],
    routes: [{ method: "GET", path: "/<script>", handler: "h", file: "a.py", line: 2 }], stride_counts: { T: { finding: 1, review: 0 } }, notes: [],
  };
  const { context, detail } = load(async () => ({ ok: true, json: async () => ({ threat_model: model, svg: "<svg></svg>" }) }));
  await context.renderThreatModel({ id: "prj_1", findings: [{ file: "<b>x</b>", line: 1, title: "t" }] });
  const panel = detail.children[0];
  assert.equal(panel.className, "threat-model-panel");
  assert.ok(panel.innerHTML.includes("&lt;b&gt;x&lt;/b&gt;"));
  assert.ok(panel.innerHTML.includes("/&lt;script&gt;"));
  assert.ok(panel.innerHTML.includes("<svg></svg>"));
  const el = makeElement();
  context.renderReachabilitySummary({ format: "other", items: [] }, el);
  assert.equal(el.children.length, 0);
});

test("20. tur: öncelik puanı varsa tablo puana göre sıralanır, katman ve kullanım kaçışlı yazılır", () => {
  const { context } = load(async () => ({}));
  const el = makeElement();
  context.renderReachabilitySummary({
    format: "sniper-vulnerability-reachability-v1",
    symbol_analysis: { verdict_counts: {}, verdict_labels: {} },
    items: [
      { package_name: "low-score", vulnerability_id: "A", priority: { score: 12, tier: "monitor", tier_label: "İzle" },
        usage: { label: "Yalnız geçişli" }, reachability: { verdict: "not_imported", effective_severity: "critical", base_severity: "critical", evidence: [] } },
      { package_name: "top", vulnerability_id: "B", priority: { score: 79, tier: "fix_first", tier_label: "Önce <düzelt>" },
        usage: { label: "<b>Kodda</b>" }, reachability: { verdict: "reachable", effective_severity: "high", base_severity: "high", evidence: [] } },
    ],
  }, el);
  const html = el.children[0].innerHTML;
  assert.ok(html.indexOf(">top<") < html.indexOf(">low-score<"));
  assert.ok(html.includes("prio-chip prio-fix_first"));
  assert.ok(html.includes("Önce &lt;düzelt&gt;"));
  assert.ok(html.includes("&lt;b&gt;Kodda&lt;/b&gt;"));
});
