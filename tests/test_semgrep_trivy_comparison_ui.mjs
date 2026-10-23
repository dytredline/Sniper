import fs from 'node:fs';
import vm from 'node:vm';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

const appJsPath = process.argv[2] ?? new URL('../static/app.js', import.meta.url).pathname;
const indexHtmlPath = new URL('../static/index.html', import.meta.url).pathname;

function buildFakeDom() {
  const elements = new Map();
  const documentListeners = new Map();
  const requests = [];
  let customTrivyResponse = null;
  let postResponseHook = null;

  function element(key) {
    if (elements.has(key)) return elements.get(key);
    const classes = new Set();
    const node = {
      id: String(key).replace(/^#/, ''),
      dataset: {},
      style: {},
      value: '',
      files: [],
      innerHTML: '',
      textContent: '',
      disabled: false,
      classList: {
        add: name => classes.add(name),
        remove: name => classes.delete(name),
        contains: name => classes.has(name),
        toggle(name, force) {
          if (force === undefined ? !classes.has(name) : force) classes.add(name);
          else classes.delete(name);
        },
      },
      addEventListener(name, callback) {
        const key = String(name);
        this.handlers ??= new Map();
        const items = this.handlers.get(key) || [];
        items.push(callback);
        this.handlers.set(key, items);
      },
      append() {},
      appendChild() {},
      remove() {},
      focus() {},
      reset() {},
      setSelectionRange() {},
      setAttribute() {},
      removeAttribute() {},
      querySelector: selector => element(selector),
      querySelectorAll: () => [],
      closest(selector) {
        if (selector === '[data-action]') {
          if (this.dataset.action === 'open-ssllabs-preview') return this;
          if (this.dataset.action === 'submit-ssllabs-preview') return this;
          if (this.dataset.action === 'open-semgrep-preview') return this;
          if (this.dataset.action === 'submit-semgrep-preview') return this;
          if (this.dataset.action === 'open-semgrep-trivy-compare') return this;
        }
        if (selector === '[data-close]') {
          if (this.dataset.close === 'ssllabs-preview-modal') return this;
          if (this.dataset.close === 'semgrep-preview-modal') return this;
          if (this.dataset.close === 'semgrep-trivy-compare-modal') return this;
        }
        return null;
      },
    };
    elements.set(key, node);
    return node;
  }

  const document = {
    body: element('body'),
    querySelector: selector => element(selector),
    querySelectorAll: selector => selector === ".modal-backdrop,.drawer-backdrop,.workspace-backdrop" ? [element("#semgrep-trivy-compare-modal")] : [],
    getElementById: id => element('#' + id),
    createElement: tag => element('created:' + tag),
    addEventListener(name, callback) {
      const callbacks = documentListeners.get(name) || [];
      callbacks.push(callback);
      documentListeners.set(name, callbacks);
    },
  };

  const getResponses = {
    '/api/dashboard': {},
    '/api/targets': { targets: [] },
    '/api/scans?limit=200': { scans: [] },
    '/api/engagements': { engagements: [] },
    '/api/lab-runs': { lab_runs: [] },
    '/api/project-audits': { project_audits: [], total: 0 },
    '/api/tooling': { tools: [], categories: [], summary: {}, policy: { native: '', external: '', completion: '' } },
    '/api/dependency-security': {},
  };

  async function fetch(path, options = {}) {
    requests.push({ path, options });
    const isPost = options.method === 'POST';
    if (isPost && postResponseHook) {
      const response = postResponseHook(path, options);
      if (response !== undefined) return response;
    }
    if (isPost && path === '/api/tool-reports/semgrep-native-json/summary') {
      const body = JSON.parse(options.body);
      if (body && typeof body === 'object' && !Array.isArray(body) && body.report && typeof body.report === 'object' && !Array.isArray(body.report)) {
        const report = body.report;
        if (report.results && Array.isArray(report.results) && report.errors && Array.isArray(report.errors) && report.paths && typeof report.paths === 'object' && !Array.isArray(report.paths) && report.paths.scanned && Array.isArray(report.paths.scanned)) {
          const resultCount = report.results.length;
          const allowedSeverities = ['ERROR', 'WARNING', 'EXPERIMENT', 'INVENTORY', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
          const severityCounts = {};
          for (const sev of allowedSeverities) severityCounts[sev] = 0;
          for (const result of report.results) {
            if (result && typeof result === 'object' && !Array.isArray(result) && result.extra && typeof result.extra === 'object' && !Array.isArray(result.extra) && typeof result.extra.severity === 'string') {
              const sev = result.extra.severity;
              if (allowedSeverities.includes(sev)) severityCounts[sev]++;
            }
          }
          const reportSha256 = 'a'.repeat(64);
          return {
            ok: true,
            status: 200,
            json: async () => ({
              format: 'semgrep-native-json',
              result_count: resultCount,
              severity_counts: severityCounts,
              report_sha256: reportSha256,
            }),
          };
        }
      }
      return { ok: true, status: 200, json: async () => ({ format: '', result_count: 0, severity_counts: {}, report_sha256: '' }) };
    }
    if (isPost && path === '/api/tool-reports/trivy-native-json/summary') {
      if (customTrivyResponse) {
        return {
          ok: true,
          status: 200,
          json: async () => customTrivyResponse,
        };
      }
      const body = JSON.parse(options.body);
      if (body && typeof body === 'object' && !Array.isArray(body) && body.report && typeof body.report === 'object' && !Array.isArray(body.report)) {
        const report = body.report;
        const results = report.Results !== undefined ? report.Results : [];
        if (report.SchemaVersion === 2 && Array.isArray(results)) {
          const resultCount = results.length;
          const classCounts = {
            'os-pkgs': 0,
            'lang-pkgs': 0,
            config: 0,
            secret: 0,
            license: 0,
            'license-file': 0,
            crypto: 0,
            custom: 0,
            unknown: 0,
          };
          const vulnCounts = {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            unknown: 0,
          };
          const misconfigSevCounts = {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            unknown: 0,
          };
          const findingCounts = {
            vulnerabilities: 0,
            misconfigurations: 0,
            secrets: 0,
            licenses: 0,
          };
          for (const res of results) {
            if (res && typeof res === 'object' && !Array.isArray(res)) {
              const cls = typeof res.Class === 'string' && res.Class in classCounts ? res.Class : 'unknown';
              classCounts[cls]++;
              if (res.Vulnerabilities && Array.isArray(res.Vulnerabilities)) {
                findingCounts.vulnerabilities += res.Vulnerabilities.length;
                for (const v of res.Vulnerabilities) {
                  if (v && typeof v === 'object' && !Array.isArray(v)) {
                    const sev = typeof v.Severity === 'string' ? v.Severity.toLowerCase() : 'unknown';
                    vulnCounts[sev in vulnCounts ? sev : 'unknown']++;
                  }
                }
              }
              if (res.Misconfigurations && Array.isArray(res.Misconfigurations)) {
                findingCounts.misconfigurations += res.Misconfigurations.length;
                for (const m of res.Misconfigurations) {
                  if (m && typeof m === 'object' && !Array.isArray(m)) {
                    const sev = typeof m.Severity === 'string' ? m.Severity.toLowerCase() : 'unknown';
                    misconfigSevCounts[sev in misconfigSevCounts ? sev : 'unknown']++;
                  }
                }
              }
              if (res.Secrets && Array.isArray(res.Secrets)) {
                findingCounts.secrets += res.Secrets.length;
              }
              if (res.Licenses && Array.isArray(res.Licenses)) {
                findingCounts.licenses += res.Licenses.length;
              }
            }
          }
          const reportSha256 = 'b'.repeat(64);
          return {
            ok: true,
            status: 200,
            json: async () => ({
              format: 'trivy-native-json',
              schema_version: 2,
              result_count: resultCount,
              class_counts: classCounts,
              vuln_counts: vulnCounts,
              misconfig_sev_counts: misconfigSevCounts,
              finding_counts: findingCounts,
              report_sha256: reportSha256,
            }),
          };
        }
      }
      return { ok: true, status: 200, json: async () => ({ format: '', schema_version: 0, result_count: 0, class_counts: {}, vuln_counts: {}, misconfig_sev_counts: {}, finding_counts: {}, report_sha256: '' }) };
    }
    const body = getResponses[path] || {};
    return { ok: true, status: 200, json: async () => body };
  }

  async function dispatchDocument(name, target, extra = {}) {
    const callbacks = documentListeners.get(name) || [];
    const event = { target, currentTarget: target, preventDefault() {}, stopPropagation() {}, ...extra };
    for (const callback of callbacks) await callback(event);
  }

  return {
    document,
    element,
    requests,
    documentListeners,
    fetch,
    dispatchDocument,
    setCustomTrivyResponse(val) { customTrivyResponse = val; },
    setPostResponseHook(hook) { postResponseHook = hook; },
  };
}

function createContext(document, fetch) {
  return vm.createContext({
    document,
    window: { addEventListener() {} },
    location: { hash: '' },
    history: { replaceState() {} },
    fetch,
    TextEncoder,
    URL,
    console,
    setTimeout: () => 0,
    clearTimeout() {},
    setInterval: () => 0,
  });
}

function runApp(document, fetch) {
  const context = createContext(document, fetch);
  const appJs = fs.readFileSync(appJsPath, 'utf8');
  vm.runInContext(appJs, context, { filename: appJsPath });
  return new Promise(resolve => setImmediate(resolve));
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

function trivySummary(resultCount, digestCharacter = 'b') {
  return {
    format: 'trivy-native-json', schema_version: 2, result_count: resultCount,
    class_counts: { 'os-pkgs': 0, 'lang-pkgs': 0, config: resultCount, secret: 0, license: 0, 'license-file': 0, crypto: 0, custom: 0, unknown: 0 },
    vuln_counts: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
    misconfig_sev_counts: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
    finding_counts: { vulnerabilities: 0, misconfigurations: 0, secrets: 0, licenses: 0 },
    report_sha256: digestCharacter.repeat(64),
  };
}

function summaryResponse(summary) {
  return { ok: true, status: 200, json: async () => summary };
}

function trivyReport(resultCount) {
  return JSON.stringify({ SchemaVersion: 2, Results: Array.from({ length: resultCount }, () => ({ Class: 'config' })) });
}

async function waitForPostCount(requests, count) {
  for (let attempt = 0; attempt < 30; attempt++) {
    if (requests.filter(request => request.options.method === 'POST').length >= count) return;
    await new Promise(resolve => setImmediate(resolve));
  }
  assert.fail(`Expected ${count} POST requests`);
}

describe('Semgrep-Trivy comparison UI', () => {
  it('should open modal, submit two valid reports, POST each once, show separate cards including Trivy misconfig severity and SHA-256 digest, and clear on close', async () => {
    const indexHtml = fs.readFileSync(indexHtmlPath, 'utf8');
    assert.strictEqual(indexHtml.includes('id="compare-trivy-misconfig-sev-counts"'), true);
    assert.strictEqual(indexHtml.includes('id="compare-trivy-report-sha256"'), true);

    const { document, element, requests, fetch, dispatchDocument } = buildFakeDom();
    await runApp(document, fetch);

    const openBtn = element('#open-semgrep-trivy-compare');
    openBtn.dataset.action = 'open-semgrep-trivy-compare';
    const modal = element('#semgrep-trivy-compare-modal');
    modal.classList.add('hidden');
    const form = element('#semgrep-trivy-compare-form');
    const semgrepPasteInput = element('#compare-semgrep-paste');
    const trivyPasteInput = element('#compare-trivy-paste');
    const errorEl = element('#semgrep-trivy-compare-error');
    const resultEl = element('#semgrep-trivy-compare-result');
    const semgrepCard = element('#compare-semgrep-card');
    const trivyCard = element('#compare-trivy-card');

    // Open modal
    await dispatchDocument('click', openBtn);
    assert.strictEqual(modal.classList.contains('hidden'), false);

    // Paste valid Semgrep JSON
    const semgrepJson = JSON.stringify({
      results: [
        {
          check_id: 'test-id',
          path: '/path/SYNTHETIC_PRIVATE_MARKER.js',
          start: { line: 1, col: 1 },
          end: { line: 1, col: 10 },
          extra: {
            message: 'SYNTHETIC_PRIVATE_MARKER',
            lines: 'lines',
            fingerprint: 'fingerprint-123',
            severity: 'ERROR',
            metadata: {},
          },
        },
      ],
      errors: [],
      paths: { scanned: ['/path/SYNTHETIC_PRIVATE_MARKER.js'] },
    });
    semgrepPasteInput.value = semgrepJson;

    // Paste valid Trivy JSON with mixed misconfiguration severities (CRITICAL, high, missing -> unknown, unrecognized -> unknown)
    const trivyJson = JSON.stringify({
      SchemaVersion: 2,
      Results: [
        {
          Class: 'config',
          Target: 'SYNTHETIC_PRIVATE_MARKER_TARGET',
          Vulnerabilities: [
            {
              Severity: 'HIGH',
            },
          ],
          Misconfigurations: [
            { Severity: 'CRITICAL', Title: 'SYNTHETIC_PRIVATE_MARKER_MISCONFIG_1' },
            { Severity: 'high', Message: 'SYNTHETIC_PRIVATE_MARKER_MISCONFIG_2' },
            { Title: 'missing_severity_counts_as_unknown' },
            { Severity: 'informational', Title: 'unrecognized_severity_counts_as_unknown' },
          ],
        },
      ],
    });
    trivyPasteInput.value = trivyJson;

    // Submit form
    await dispatchDocument('submit', form);

    // Assert exactly two POSTs to distinct endpoints
    const postRequests = requests.filter(r => r.options.method === 'POST');
    assert.strictEqual(postRequests.length, 2);
    const semgrepPost = postRequests.find(r => r.path === '/api/tool-reports/semgrep-native-json/summary');
    const trivyPost = postRequests.find(r => r.path === '/api/tool-reports/trivy-native-json/summary');
    assert.ok(semgrepPost);
    assert.ok(trivyPost);

    // Assert distinct bodies
    const semgrepBody = JSON.parse(semgrepPost.options.body);
    const trivyBody = JSON.parse(trivyPost.options.body);
    assert.deepStrictEqual(semgrepBody, { report: JSON.parse(semgrepJson) });
    assert.deepStrictEqual(trivyBody, { report: JSON.parse(trivyJson) });

    // Assert visible cards and separate text
    assert.strictEqual(semgrepCard.classList.contains('hidden'), false);
    assert.strictEqual(trivyCard.classList.contains('hidden'), false);
    assert.strictEqual(resultEl.classList.contains('hidden'), false);

    const semgrepFormatEl = element('#compare-semgrep-format');
    const semgrepResultCountEl = element('#compare-semgrep-result-count');
    const semgrepSeverityCountsEl = element('#compare-semgrep-severity-counts');
    const trivyFormatEl = element('#compare-trivy-format');
    const trivyResultCountEl = element('#compare-trivy-result-count');
    const trivyClassCountsEl = element('#compare-trivy-class-counts');
    const trivyVulnCountsEl = element('#compare-trivy-vuln-counts');
    const trivyMisconfigSevCountsEl = element('#compare-trivy-misconfig-sev-counts');
    const trivyFindingCountsEl = element('#compare-trivy-finding-counts');
    const trivyReportSha256El = element('#compare-trivy-report-sha256');

    assert.strictEqual(semgrepFormatEl.textContent, 'semgrep-native-json');
    assert.strictEqual(semgrepResultCountEl.textContent, '1');
    assert.strictEqual(semgrepSeverityCountsEl.textContent, 'ERROR:1 WARNING:0 EXPERIMENT:0 INVENTORY:0 CRITICAL:0 HIGH:0 MEDIUM:0 LOW:0 INFO:0');

    assert.strictEqual(trivyFormatEl.textContent, 'trivy-native-json');
    assert.strictEqual(trivyResultCountEl.textContent, '1');
    assert.strictEqual(trivyClassCountsEl.textContent, 'os-pkgs:0 lang-pkgs:0 config:1 secret:0 license:0 license-file:0 crypto:0 custom:0 unknown:0');
    assert.strictEqual(trivyVulnCountsEl.textContent, 'critical:0 high:1 medium:0 low:0 unknown:0');
    assert.strictEqual(trivyMisconfigSevCountsEl.textContent, 'critical:1 high:1 medium:0 low:0 unknown:2');
    assert.strictEqual(trivyFindingCountsEl.textContent, 'vulnerabilities:1 misconfigurations:4 secrets:0 licenses:0');
    assert.strictEqual(trivyReportSha256El.textContent, 'b'.repeat(64));

    // Assert no private marker in rendered content
    const allText = [
      semgrepFormatEl.textContent,
      semgrepResultCountEl.textContent,
      semgrepSeverityCountsEl.textContent,
      trivyFormatEl.textContent,
      trivyResultCountEl.textContent,
      trivyClassCountsEl.textContent,
      trivyVulnCountsEl.textContent,
      trivyMisconfigSevCountsEl.textContent,
      trivyFindingCountsEl.textContent,
      trivyReportSha256El.textContent,
      resultEl.innerHTML,
      errorEl.textContent,
    ].join(' ');
    assert.strictEqual(allText.includes('SYNTHETIC_PRIVATE_MARKER'), false);

    // Assert inputs cleared
    assert.strictEqual(semgrepPasteInput.value, '');
    assert.strictEqual(trivyPasteInput.value, '');

    // Closing modal clears the added fields
    const closeBtn = element('#semgrep-trivy-compare-modal [data-close="semgrep-trivy-compare-modal"]');
    closeBtn.dataset.close = 'semgrep-trivy-compare-modal';
    await dispatchDocument('click', closeBtn);
    assert.strictEqual(trivyMisconfigSevCountsEl.textContent, '');
    assert.strictEqual(trivyReportSha256El.textContent, '');
    assert.strictEqual(trivyCard.classList.contains('hidden'), true);
    assert.strictEqual(resultEl.classList.contains('hidden'), true);
  });

  it('should reject malformed Trivy comparison response (misconfig_sev_counts sum mismatch or invalid digest) and hide/clear results', async () => {
    const { document, element, fetch, dispatchDocument, setCustomTrivyResponse } = buildFakeDom();
    await runApp(document, fetch);

    const form = element('#semgrep-trivy-compare-form');
    const trivyPasteInput = element('#compare-trivy-paste');
    const errorEl = element('#semgrep-trivy-compare-error');
    const resultEl = element('#semgrep-trivy-compare-result');
    const trivyCard = element('#compare-trivy-card');
    const trivyMisconfigSevCountsEl = element('#compare-trivy-misconfig-sev-counts');
    const trivyReportSha256El = element('#compare-trivy-report-sha256');

    setCustomTrivyResponse({
      format: 'trivy-native-json',
      schema_version: 2,
      result_count: 1,
      class_counts: { 'os-pkgs': 0, 'lang-pkgs': 0, config: 1, secret: 0, license: 0, 'license-file': 0, crypto: 0, custom: 0, unknown: 0 },
      vuln_counts: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
      misconfig_sev_counts: { critical: 1, high: 0, medium: 0, low: 0, unknown: 0 },
      finding_counts: { vulnerabilities: 0, misconfigurations: 2, secrets: 0, licenses: 0 },
      report_sha256: 'b'.repeat(64),
    });

    trivyPasteInput.value = JSON.stringify({ SchemaVersion: 2, Results: [{ Class: 'config' }] });
    await dispatchDocument('submit', form);

    assert.strictEqual(errorEl.textContent, 'Geçersiz JSON.');
    assert.strictEqual(errorEl.classList.contains('hidden'), false);
    assert.strictEqual(resultEl.classList.contains('hidden'), true);
    assert.strictEqual(trivyCard.classList.contains('hidden'), true);
    assert.strictEqual(trivyMisconfigSevCountsEl.textContent, '');
    assert.strictEqual(trivyReportSha256El.textContent, '');
  });

  it('should submit one valid report and one empty, POST only one, show one card, clear inputs', async () => {
    const { document, element, requests, fetch, dispatchDocument } = buildFakeDom();
    await runApp(document, fetch);

    const openBtn = element('#open-semgrep-trivy-compare');
    openBtn.dataset.action = 'open-semgrep-trivy-compare';
    const modal = element('#semgrep-trivy-compare-modal');
    modal.classList.add('hidden');
    const form = element('#semgrep-trivy-compare-form');
    const semgrepPasteInput = element('#compare-semgrep-paste');
    const trivyPasteInput = element('#compare-trivy-paste');
    const resultEl = element('#semgrep-trivy-compare-result');
    const semgrepCard = element('#compare-semgrep-card');
    const trivyCard = element('#compare-trivy-card');

    await dispatchDocument('click', openBtn);
    assert.strictEqual(modal.classList.contains('hidden'), false);

    const semgrepJson = JSON.stringify({
      results: [
        {
          check_id: 'test-id',
          path: '/path/file.js',
          start: { line: 1, col: 1 },
          end: { line: 1, col: 10 },
          extra: {
            message: 'message',
            lines: 'lines',
            fingerprint: 'fingerprint-123',
            severity: 'ERROR',
            metadata: {},
          },
        },
      ],
      errors: [],
      paths: { scanned: ['/path/file.js'] },
    });
    semgrepPasteInput.value = semgrepJson;
    trivyPasteInput.value = '';

    await dispatchDocument('submit', form);

    const postRequests = requests.filter(r => r.options.method === 'POST');
    assert.strictEqual(postRequests.length, 1);
    assert.strictEqual(postRequests[0].path, '/api/tool-reports/semgrep-native-json/summary');

    assert.strictEqual(semgrepCard.classList.contains('hidden'), false);
    assert.strictEqual(trivyCard.classList.contains('hidden'), true);
    assert.strictEqual(resultEl.classList.contains('hidden'), false);

    assert.strictEqual(semgrepPasteInput.value, '');
    assert.strictEqual(trivyPasteInput.value, '');
  });

  it('should submit two empty reports, show generic error, zero POST', async () => {
    const { document, element, requests, fetch, dispatchDocument } = buildFakeDom();
    await runApp(document, fetch);

    const openBtn = element('#open-semgrep-trivy-compare');
    openBtn.dataset.action = 'open-semgrep-trivy-compare';
    const modal = element('#semgrep-trivy-compare-modal');
    modal.classList.add('hidden');
    const form = element('#semgrep-trivy-compare-form');
    const semgrepPasteInput = element('#compare-semgrep-paste');
    const trivyPasteInput = element('#compare-trivy-paste');
    const errorEl = element('#semgrep-trivy-compare-error');
    const resultEl = element('#semgrep-trivy-compare-result');

    await dispatchDocument('click', openBtn);
    assert.strictEqual(modal.classList.contains('hidden'), false);

    semgrepPasteInput.value = '';
    trivyPasteInput.value = '';

    await dispatchDocument('submit', form);

    const postRequests = requests.filter(r => r.options.method === 'POST');
    assert.strictEqual(postRequests.length, 0);
    assert.strictEqual(errorEl.textContent, 'En az bir rapor gerekli.');
    assert.strictEqual(errorEl.classList.contains('hidden'), false);
    assert.strictEqual(resultEl.classList.contains('hidden'), true);
  });

  it('should submit malformed Semgrep JSON, show generic error, zero POST', async () => {
    const { document, element, requests, fetch, dispatchDocument } = buildFakeDom();
    await runApp(document, fetch);

    const openBtn = element('#open-semgrep-trivy-compare');
    openBtn.dataset.action = 'open-semgrep-trivy-compare';
    const modal = element('#semgrep-trivy-compare-modal');
    modal.classList.add('hidden');
    const form = element('#semgrep-trivy-compare-form');
    const semgrepPasteInput = element('#compare-semgrep-paste');
    const trivyPasteInput = element('#compare-trivy-paste');
    const errorEl = element('#semgrep-trivy-compare-error');

    await dispatchDocument('click', openBtn);
    assert.strictEqual(modal.classList.contains('hidden'), false);

    semgrepPasteInput.value = '{ invalid json';
    trivyPasteInput.value = '';

    await dispatchDocument('submit', form);

    const postRequests = requests.filter(r => r.options.method === 'POST');
    assert.strictEqual(postRequests.length, 0);
    assert.strictEqual(errorEl.textContent, 'Geçersiz JSON.');
    assert.strictEqual(errorEl.classList.contains('hidden'), false);
  });

  it('ignores deferred success after close and reopen without new submission', async () => {
    const { document, element, requests, fetch, dispatchDocument, setPostResponseHook } = buildFakeDom();
    await runApp(document, fetch);
    const delayed = deferred();
    setPostResponseHook(path => path === '/api/tool-reports/trivy-native-json/summary' ? delayed.promise : undefined);
    const open = element('#open-semgrep-trivy-compare'); open.dataset.action = 'open-semgrep-trivy-compare';
    const form = element('#semgrep-trivy-compare-form');
    const modal = element('#semgrep-trivy-compare-modal'); modal.classList.add('hidden');
    const result = element('#semgrep-trivy-compare-result');
    const card = element('#compare-trivy-card');
    const count = element('#compare-trivy-result-count');
    const digest = element('#compare-trivy-report-sha256');
    await dispatchDocument('click', open);
    element('#compare-trivy-paste').value = trivyReport(1);
    const pending = dispatchDocument('submit', form);
    await waitForPostCount(requests, 1);
    await dispatchDocument('keydown', modal, { key: 'Escape' });
    assert.strictEqual(modal.classList.contains('hidden'), true);
    await dispatchDocument('click', open);
    assert.strictEqual(modal.classList.contains('hidden'), false);
    delayed.resolve(summaryResponse(trivySummary(1)));
    await pending;
    assert.strictEqual(result.classList.contains('hidden'), true);
    assert.strictEqual(card.classList.contains('hidden'), true);
    assert.strictEqual(count.textContent, '');
    assert.strictEqual(digest.textContent, '');
  });

  it('ignores deferred error after close and reopen', async () => {
    const { document, element, requests, fetch, dispatchDocument, setPostResponseHook } = buildFakeDom();
    await runApp(document, fetch);
    const delayed = deferred();
    setPostResponseHook(path => path === '/api/tool-reports/trivy-native-json/summary' ? delayed.promise : undefined);
    const open = element('#open-semgrep-trivy-compare'); open.dataset.action = 'open-semgrep-trivy-compare';
    const close = element('#compare-close'); close.dataset.close = 'semgrep-trivy-compare-modal';
    const form = element('#semgrep-trivy-compare-form');
    const modal = element('#semgrep-trivy-compare-modal'); modal.classList.add('hidden');
    const error = element('#semgrep-trivy-compare-error');
    await dispatchDocument('click', open);
    element('#compare-trivy-paste').value = trivyReport(1);
    const pending = dispatchDocument('submit', form);
    await waitForPostCount(requests, 1);
    await dispatchDocument('click', close);
    await dispatchDocument('click', open);
    delayed.reject(new Error('synthetic delayed failure'));
    await pending;
    assert.strictEqual(error.classList.contains('hidden'), true);
    assert.strictEqual(error.textContent, '');
  });

  it('keeps newer submit B when deferred submit A succeeds out of order', async () => {
    const { document, element, requests, fetch, dispatchDocument, setPostResponseHook } = buildFakeDom();
    await runApp(document, fetch);
    const delayedA = deferred();
    let postNumber = 0;
    setPostResponseHook(path => {
      if (path !== '/api/tool-reports/trivy-native-json/summary') return undefined;
      postNumber++;
      return postNumber === 1 ? delayedA.promise : summaryResponse(trivySummary(2, 'c'));
    });
    const open = element('#open-semgrep-trivy-compare'); open.dataset.action = 'open-semgrep-trivy-compare';
    const form = element('#semgrep-trivy-compare-form');
    const result = element('#semgrep-trivy-compare-result');
    const count = element('#compare-trivy-result-count');
    const digest = element('#compare-trivy-report-sha256');
    await dispatchDocument('click', open);
    element('#compare-trivy-paste').value = trivyReport(1);
    const pendingA = dispatchDocument('submit', form);
    await waitForPostCount(requests, 1);
    element('#compare-trivy-paste').value = trivyReport(2);
    await dispatchDocument('submit', form);
    assert.strictEqual(result.classList.contains('hidden'), false);
    assert.strictEqual(count.textContent, '2');
    assert.strictEqual(digest.textContent, 'c'.repeat(64));
    delayedA.resolve(summaryResponse(trivySummary(1, 'a')));
    await pendingA;
    assert.strictEqual(result.classList.contains('hidden'), false);
    assert.strictEqual(count.textContent, '2');
    assert.strictEqual(digest.textContent, 'c'.repeat(64));
  });
});
