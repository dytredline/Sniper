import fs from "node:fs";
import vm from "node:vm";
import assert from "node:assert/strict";
import { test } from "node:test";

const sourcePath = process.env.SNIPER_TOOL_EVIDENCE_APP_JS || new URL("../static/app.js", import.meta.url).pathname;
const source = fs.readFileSync(sourcePath, "utf8");
function appFixture() {
  const element = {
    innerHTML: "", value: "", checked: false, dataset: {}, style: {},
    addEventListener() {}, querySelector() { return this; }, querySelectorAll() { return []; },
    classList: { add() {}, remove() {}, toggle() {} },
  };
  const document = {
    addEventListener() {}, querySelector() { return element; }, querySelectorAll() { return []; },
    getElementById() { return element; }, createElement() { return element; },
  };
  const context = {
    document, window: { addEventListener() {} }, location: { hash: "#dashboard" },
    history: { replaceState() {} }, navigator: {},
    fetch: () => new Promise(() => {}), setTimeout() {}, setInterval() {}, clearInterval() {},
  };
  vm.runInNewContext(source + "\nglobalThis.__summary = toolEvidenceSummary; globalThis.__render = renderWorkspaceOverview;", context, { timeout: 2000 });
  return { summary: context.__summary, render: context.__render, element };
}

test("overview keeps Nmap and testssl aggregate counts", () => {
  const { summary } = appFixture();
  assert.equal(summary({ tool_identity: "nmap-xml", host_count: 2, open_port_count: 3 }), "Host: 2 · Açık port: 3");
  assert.equal(summary({ tool_identity: "testssl-flat-json", record_count: 4, severity_counts: { HIGH: 1, CRITICAL: 2 } }), "Kayıt: 4 · HIGH: 1 · CRITICAL: 2");
});

test("overview renders the linked Semgrep aggregate instead of false host and port zeros", () => {
  const { summary, render, element } = appFixture();
  const link = { tool_identity: "semgrep-local", control_id: "CTL-1", report_sha256: "a".repeat(64), result_count: 7, severity_counts: { ERROR: 3, WARNING: 2 } };
  assert.equal(summary(link), "Bulgu: 7 · ERROR: 3 · WARNING: 2");
  render({ categories: [], tests: [], tool_evidence: [link], special_approvals: {}, coverage: { percent: 0, completed: 0, total: 0 }, remediation: {}, latest_scan: null });
  assert.match(element.innerHTML, /semgrep-local · CTL-1/);
  assert.match(element.innerHTML, /Bulgu: 7 · ERROR: 3 · WARNING: 2/);
  assert.doesNotMatch(element.innerHTML, /Host: 0 · Açık port: 0/);
});

test("overview identifies every installed evidence family from its actual aggregate fields", () => {
  const { summary } = appFixture();
  const cases = [
    [{ tool_identity: "trivy-native-json", result_count: 3, finding_counts: { vulnerabilities: 2, misconfigurations: 1 } }, "Sonuç: 3 · Zafiyet: 2 · Yanlış yapılandırma: 1"],
    [{ tool_identity: "gitleaks-native-json", total_findings: 5, rules_triggered: 2, files_affected: 3 }, "Bulgu: 5 · Kural: 2 · Dosya: 3"],
    [{ tool_identity: "nuclei-jsonl", record_count: 8, unique_template_count: 6, severity_counts: { high: 2, critical: 1 } }, "Kayıt: 8 · Şablon: 6 · HIGH: 2 · CRITICAL: 1"],
    [{ tool_identity: "burp-sitemap-xml", item_count: 9 }, "Site haritası kaydı: 9"],
    [{ tool_identity: "zap-traditional-json", site_count: 1, alert_type_count: 4, instance_count: 10 }, "Site: 1 · Uyarı türü: 4 · Örnek: 10"],
  ];
  for (const [link, expected] of cases) assert.equal(summary(link), expected, link.tool_identity);
});

test("unknown evidence identity never invents Nmap counts", () => {
  const { summary } = appFixture();
  assert.equal(summary({ tool_identity: "future-parser", result_count: 12 }), "Toplu kanıt bağlantısı · uzman incelemesi gerekli");
});

test("overview shows npm severity buckets and TruffleHog unverified count", () => {
  const { summary } = appFixture();
  assert.equal(
    summary({ tool_identity: "npm-audit-v2", affected_package_count: 4, package_severity_counts: { info: 0, low: 1, moderate: 1, high: 1, critical: 1 } }),
    "Etkilenen paket: 4 · info: 0 · low: 1 · moderate: 1 · high: 1 · critical: 1",
  );
  assert.equal(
    summary({ tool_identity: "trufflehog-native-json-records", total_findings: 3, verified_findings: 1, unverified_findings: 2, detectors_triggered: 2 }),
    "Bulgu: 3 · Doğrulanmış: 1 · Doğrulanmamış: 2 · Dedektör: 2",
  );
});
