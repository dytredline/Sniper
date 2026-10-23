import fs from 'node:fs';
import vm from 'node:vm';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

const appJsPath = process.env.SNIPER_UI_APP_JS || new URL('../static/app.js', import.meta.url).pathname;

function buildFakeDom() {
  const elements = new Map();
  const documentListeners = new Map();
  const requests = [];

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
          if (this.dataset.action === 'open-trivy-preview') return this;
          if (this.dataset.action === 'submit-trivy-preview') return this;
        }
        if (selector === '[data-close]') {
          if (this.dataset.close === 'trivy-preview-modal') return this;
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
    querySelectorAll: () => [],
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
    if (isPost && path === '/api/tool-reports/trivy-native-json/summary') {
      const body = JSON.parse(options.body);
      if (body && typeof body === 'object' && !Array.isArray(body) && body.report && typeof body.report === 'object' && !Array.isArray(body.report)) {
        const report = body.report;
        const schemaVersion = report.SchemaVersion;
        const results = report.Results;
        if (schemaVersion === 2 && Array.isArray(results) && results.length <= 500) {
          const classKeys = ['os-pkgs', 'lang-pkgs', 'config', 'secret', 'license', 'license-file', 'crypto', 'custom', 'unknown'];
          const vulnKeys = ['critical', 'high', 'medium', 'low', 'unknown'];
          const findingKeys = ['vulnerabilities', 'misconfigurations', 'secrets', 'licenses'];
          const classCounts = {};
          const vulnCounts = {};
          const findingCounts = {};
          const misconfigSevCounts = {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            unknown: 0,
          };
          for (const k of classKeys) classCounts[k] = 0;
          for (const k of vulnKeys) vulnCounts[k] = 0;
          for (const k of findingKeys) findingCounts[k] = 0;
          let resultCount = 0;
          for (const r of results) {
            if (r && typeof r === 'object' && !Array.isArray(r)) {
              resultCount++;
              const cls = r.Class || 'unknown';
              if (classKeys.includes(cls)) classCounts[cls]++;
              const vulns = Array.isArray(r.Vulnerabilities) ? r.Vulnerabilities : [];
              for (const v of vulns) {
                if (v && typeof v === 'object' && !Array.isArray(v)) {
                  const sev = (v.Severity || 'unknown').toLowerCase();
                  if (vulnKeys.includes(sev)) vulnCounts[sev]++;
                }
              }
              if (r.Misconfigurations && Array.isArray(r.Misconfigurations)) {
                for (const m of r.Misconfigurations) {
                  if (m && typeof m === 'object' && !Array.isArray(m)) {
                    const sev = (m.Severity || 'unknown').toLowerCase();
                    if (sev in misconfigSevCounts) misconfigSevCounts[sev]++;
                  }
                }
                findingCounts.misconfigurations += r.Misconfigurations.length;
              }
              if (r.Secrets && Array.isArray(r.Secrets)) findingCounts.secrets += r.Secrets.length;
              if (r.Licenses && Array.isArray(r.Licenses)) findingCounts.licenses += r.Licenses.length;
              findingCounts.vulnerabilities += vulns.length;
            }
          }
          const reportSha256 = 'a'.repeat(64);
          return {
            ok: true,
            status: 200,
            json: async () => ({
              format: 'trivy-native-json',
              schema_version: 2,
              result_count: resultCount,
              class_counts: classCounts,
              vuln_counts: vulnCounts,
              finding_counts: findingCounts,
              misconfig_sev_counts: misconfigSevCounts,
              report_sha256: reportSha256,
            }),
          };
        }
      }
      return { ok: true, status: 200, json: async () => ({ format: '', schema_version: 0, result_count: 0, class_counts: {}, vuln_counts: {}, finding_counts: {}, misconfig_sev_counts: {}, report_sha256: '' }) };
    }
    const body = getResponses[path] || {};
    return { ok: true, status: 200, json: async () => body };
  }

  async function dispatchDocument(name, target) {
    const callbacks = documentListeners.get(name) || [];
    const event = { target, currentTarget: target, preventDefault() {}, stopPropagation() {} };
    for (const callback of callbacks) await callback(event);
  }

  return { document, element, requests, documentListeners, fetch, dispatchDocument };
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

describe('Trivy preview UI', () => {
  it('should open modal, submit valid Trivy SchemaVersion=2 JSON, render aggregate summary, clear inputs', async () => {
    const { document, element, requests, documentListeners, fetch, dispatchDocument } = buildFakeDom();
    await runApp(document, fetch);

    const openBtn = element('#open-trivy-preview');
    openBtn.dataset.action = 'open-trivy-preview';
    const modal = element('#trivy-preview-modal');
    modal.classList.add('hidden');
    const form = element('#trivy-preview-form');
    const pasteInput = element('#trivy-paste');
    const errorEl = element('#trivy-preview-error');
    const resultEl = element('#trivy-preview-result');
    const formatEl = element('#trivy-format');
    const schemaEl = element('#trivy-schema-version');
    const resultCountEl = element('#trivy-result-count');
    const classCountsEl = element('#trivy-class-counts');
    const vulnCountsEl = element('#trivy-vuln-counts');
    const findingCountsEl = element('#trivy-finding-counts');
    const misconfigSevCountsEl = element('#trivy-misconfig-sev-counts');
    const sha256El = element('#trivy-report-sha256');

    // Open modal
    await dispatchDocument('click', openBtn);
    assert.strictEqual(modal.classList.contains('hidden'), false);

    // Paste valid Trivy JSON with synthetic results including one HIGH misconfig
    const syntheticJson = JSON.stringify({
      SchemaVersion: 2,
      Results: [
        {
          Class: 'config',
          Target: 'synthetic_private_marker',
          Misconfigurations: [
            { Severity: 'HIGH', Title: 'misconfig_marker' },
          ],
        },
      ],
    });
    pasteInput.value = syntheticJson;

    // Submit form
    await dispatchDocument('submit', form);

    // Assert exactly one POST to /api/tool-reports/trivy-native-json/summary
    const postRequests = requests.filter(r => r.path === '/api/tool-reports/trivy-native-json/summary' && r.options.method === 'POST');
    assert.strictEqual(postRequests.length, 1);
    const body = JSON.parse(postRequests[0].options.body);
    assert.deepStrictEqual(body, { report: JSON.parse(syntheticJson) });

    // Assert aggregate fields rendered
    assert.strictEqual(formatEl.textContent, 'trivy-native-json');
    assert.strictEqual(schemaEl.textContent, '2');
    assert.strictEqual(resultCountEl.textContent, '1');
    assert.strictEqual(classCountsEl.textContent, 'os-pkgs:0 lang-pkgs:0 config:1 secret:0 license:0 license-file:0 crypto:0 custom:0 unknown:0');
    assert.strictEqual(vulnCountsEl.textContent, 'critical:0 high:0 medium:0 low:0 unknown:0');
    assert.strictEqual(findingCountsEl.textContent, 'vulnerabilities:0 misconfigurations:1 secrets:0 licenses:0');
    assert.strictEqual(misconfigSevCountsEl.textContent, 'critical:0 high:1 medium:0 low:0 unknown:0');
    assert.strictEqual(sha256El.textContent, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');

    // Assert result visible and error hidden
    assert.strictEqual(resultEl.classList.contains('hidden'), false);
    assert.strictEqual(errorEl.classList.contains('hidden'), true);

    // Assert no marker or raw target/package/secret/path in rendered content
    const formatText = formatEl.textContent;
    const schemaText = schemaEl.textContent;
    const resultCountText = resultCountEl.textContent;
    const classCountsText = classCountsEl.textContent;
    const vulnCountsText = vulnCountsEl.textContent;
    const findingCountsText = findingCountsEl.textContent;
    const misconfigSevCountsText = misconfigSevCountsEl.textContent;
    const sha256Text = sha256El.textContent;
    const resultText = resultEl.innerHTML;
    const errorText = errorEl.textContent;
    const allText = [formatText, schemaText, resultCountText, classCountsText, vulnCountsText, findingCountsText, misconfigSevCountsText, sha256Text, resultText, errorText].join(' ');
    assert.strictEqual(allText.includes('synthetic_private_marker'), false);
    assert.strictEqual(allText.includes('misconfig_marker'), false);
    assert.strictEqual(allText.includes('config'), true);
    assert.strictEqual(allText.includes('trivy-native-json'), true);

    // Assert inputs cleared
    assert.strictEqual(pasteInput.value, '');
  });

  it('should reject malformed JSON with generic error and zero POST', async () => {
    const { document, element, requests, documentListeners, fetch, dispatchDocument } = buildFakeDom();
    await runApp(document, fetch);

    const form = element('#trivy-preview-form');
    const pasteInput = element('#trivy-paste');
    const errorEl = element('#trivy-preview-error');

    pasteInput.value = '{ invalid json';
    await dispatchDocument('submit', form);

    const postRequests = requests.filter(r => r.path === '/api/tool-reports/trivy-native-json/summary' && r.options.method === 'POST');
    assert.strictEqual(postRequests.length, 0);
    assert.strictEqual(errorEl.textContent, 'Geçersiz JSON.');
    assert.strictEqual(errorEl.classList.contains('hidden'), false);
  });

  it('should reject wrong SchemaVersion with generic error and zero POST', async () => {
    const { document, element, requests, documentListeners, fetch, dispatchDocument } = buildFakeDom();
    await runApp(document, fetch);

    const form = element('#trivy-preview-form');
    const pasteInput = element('#trivy-paste');
    const errorEl = element('#trivy-preview-error');

    pasteInput.value = JSON.stringify({ SchemaVersion: 1, Results: [] });
    await dispatchDocument('submit', form);

    const postRequests = requests.filter(r => r.path === '/api/tool-reports/trivy-native-json/summary' && r.options.method === 'POST');
    assert.strictEqual(postRequests.length, 0);
    assert.strictEqual(errorEl.textContent, 'Geçersiz JSON.');
    assert.strictEqual(errorEl.classList.contains('hidden'), false);
  });

  it('should clear inputs on close', async () => {
    const { document, element, requests, documentListeners, fetch, dispatchDocument } = buildFakeDom();
    await runApp(document, fetch);

    const openBtn = element('#open-trivy-preview');
    const closeBtn = element('#trivy-preview-modal [data-close="trivy-preview-modal"]');
    closeBtn.dataset.close = 'trivy-preview-modal';
    const pasteInput = element('#trivy-paste');
    const fileInput = element('#trivy-file');

    await dispatchDocument('click', openBtn);
    pasteInput.value = 'Marker in advisory';
    fileInput.value = 'test.txt';

    await dispatchDocument('click', closeBtn);

    assert.strictEqual(pasteInput.value, '');
    assert.strictEqual(fileInput.value, '');
  });
});
