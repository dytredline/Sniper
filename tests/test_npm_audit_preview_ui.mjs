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
          if (this.dataset.action === 'open-npm-audit-preview') return this;
          if (this.dataset.action === 'submit-npm-audit-preview') return this;
        }
        if (selector === '[data-close]') {
          if (this.dataset.close === 'npm-audit-preview-modal') return this;
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
    if (isPost && path === '/api/tool-reports/npm-audit/summary') {
      const body = JSON.parse(options.body);
      if (body && typeof body === 'object' && body.audit && typeof body.audit === 'object' && !Array.isArray(body.audit)) {
        const audit = body.audit;
        const version = audit.auditReportVersion;
        const vulnerabilities = audit.vulnerabilities;
        if (version === 2 && vulnerabilities && typeof vulnerabilities === 'object' && !Array.isArray(vulnerabilities)) {
          const keys = Object.keys(vulnerabilities);
          const infoCount = keys.filter(k => vulnerabilities[k].severity === 'info').length;
          const lowCount = keys.filter(k => vulnerabilities[k].severity === 'low').length;
          const moderateCount = keys.filter(k => vulnerabilities[k].severity === 'moderate').length;
          const highCount = keys.filter(k => vulnerabilities[k].severity === 'high').length;
          const criticalCount = keys.filter(k => vulnerabilities[k].severity === 'critical').length;
          const affectedPackageCount = keys.length;
          const reportSha256 = 'b'.repeat(64);
          return {
            ok: true,
            status: 200,
            json: async () => ({
              format: 'npm-audit-v2',
              affected_package_count: affectedPackageCount,
              package_severity_counts: {
                info: infoCount,
                low: lowCount,
                moderate: moderateCount,
                high: highCount,
                critical: criticalCount,
              },
              report_sha256: reportSha256,
            }),
          };
        }
      }
      return { ok: true, status: 200, json: async () => ({ format: '', affected_package_count: 0, package_severity_counts: {}, report_sha256: '' }) };
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

describe('NPM audit preview UI', () => {
  it('should open modal, submit valid npm audit v2 JSON, render aggregate summary, clear inputs', async () => {
    const { document, element, requests, documentListeners, fetch, dispatchDocument } = buildFakeDom();
    await runApp(document, fetch);

    const openBtn = element('#open-npm-audit-preview');
    openBtn.dataset.action = 'open-npm-audit-preview';
    const modal = element('#npm-audit-preview-modal');
    modal.classList.add('hidden');
    const form = element('#npm-audit-preview-form');
    const pasteInput = element('#npm-audit-paste');
    const errorEl = element('#npm-audit-preview-error');
    const resultEl = element('#npm-audit-preview-result');
    const formatEl = element('#npm-audit-format');
    const packageCountEl = element('#npm-audit-package-count');
    const severityCountsEl = element('#npm-audit-severity-counts');
    const sha256El = element('#npm-audit-report-sha256');

    // Open modal
    await dispatchDocument('click', openBtn);
    assert.strictEqual(modal.classList.contains('hidden'), false);

    // Paste valid npm audit v2 JSON with synthetic vulnerabilities
    const syntheticJson = JSON.stringify({
      auditReportVersion: 2,
      vulnerabilities: {
        synthetic_private_marker: { severity: 'high', via: ['private_marker'] },
        second: { severity: 'moderate' },
      },
    });
    pasteInput.value = syntheticJson;

    // Submit form
    await dispatchDocument('submit', form);

    // Assert exactly one POST to /api/tool-reports/npm-audit/summary
    const postRequests = requests.filter(r => r.path === '/api/tool-reports/npm-audit/summary' && r.options.method === 'POST');
    assert.strictEqual(postRequests.length, 1);
    const body = JSON.parse(postRequests[0].options.body);
    assert.deepStrictEqual(body, { audit: JSON.parse(syntheticJson) });

    // Assert aggregate fields rendered
    assert.strictEqual(formatEl.textContent, 'npm-audit-v2');
    assert.strictEqual(String(packageCountEl.textContent), '2');
    assert.strictEqual(severityCountsEl.textContent, 'info:0 low:0 moderate:1 high:1 critical:0');
    assert.strictEqual(sha256El.textContent, 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb');

    // Assert result visible and error hidden
    assert.strictEqual(resultEl.classList.contains('hidden'), false);
    assert.strictEqual(errorEl.classList.contains('hidden'), true);

    // Assert no marker or raw advisory/package/path in rendered content
    const formatText = formatEl.textContent;
    const packageCountText = packageCountEl.textContent;
    const severityCountsText = severityCountsEl.textContent;
    const sha256Text = sha256El.textContent;
    const resultText = resultEl.innerHTML;
    const errorText = errorEl.textContent;
    const allText = [formatText, packageCountText, severityCountsText, sha256Text, resultText, errorText].join(' ');
    assert.strictEqual(allText.includes('synthetic_private_marker'), false);
    assert.strictEqual(allText.includes('private_marker'), false);
    assert.strictEqual(allText.includes('second'), false);
    assert.strictEqual(allText.includes('via'), false);
    assert.strictEqual(allText.includes('severity'), false);
    assert.strictEqual(allText.includes('high'), true);
    assert.strictEqual(allText.includes('moderate'), true);
    assert.strictEqual(allText.includes('npm-audit-v2'), true);

    // Assert inputs cleared
    assert.strictEqual(pasteInput.value, '');
  });

  it('should reject malformed JSON with generic error and zero POST', async () => {
    const { document, element, requests, documentListeners, fetch, dispatchDocument } = buildFakeDom();
    await runApp(document, fetch);

    const form = element('#npm-audit-preview-form');
    const pasteInput = element('#npm-audit-paste');
    const errorEl = element('#npm-audit-preview-error');

    pasteInput.value = '{ invalid json';
    await dispatchDocument('submit', form);

    const postRequests = requests.filter(r => r.path === '/api/tool-reports/npm-audit/summary' && r.options.method === 'POST');
    assert.strictEqual(postRequests.length, 0);
    assert.strictEqual(errorEl.textContent, 'Geçersiz JSON.');
    assert.strictEqual(errorEl.classList.contains('hidden'), false);
  });

  it('should reject non-object vulnerabilities with generic error and zero POST', async () => {
    const { document, element, requests, documentListeners, fetch, dispatchDocument } = buildFakeDom();
    await runApp(document, fetch);

    const form = element('#npm-audit-preview-form');
    const pasteInput = element('#npm-audit-paste');
    const errorEl = element('#npm-audit-preview-error');

    pasteInput.value = JSON.stringify({ auditReportVersion: 2, vulnerabilities: [] });
    await dispatchDocument('submit', form);

    const postRequests = requests.filter(r => r.path === '/api/tool-reports/npm-audit/summary' && r.options.method === 'POST');
    assert.strictEqual(postRequests.length, 0);
    assert.strictEqual(errorEl.textContent, 'Geçersiz JSON.');
    assert.strictEqual(errorEl.classList.contains('hidden'), false);
  });

  it('should clear inputs on close', async () => {
    const { document, element, requests, documentListeners, fetch, dispatchDocument } = buildFakeDom();
    await runApp(document, fetch);

    const openBtn = element('#open-npm-audit-preview');
    const closeBtn = element('#npm-audit-preview-modal [data-close="npm-audit-preview-modal"]');
    closeBtn.dataset.close = 'npm-audit-preview-modal';
    const pasteInput = element('#npm-audit-paste');
    const fileInput = element('#npm-audit-file');

    await dispatchDocument('click', openBtn);
    pasteInput.value = 'Marker in advisory';
    fileInput.value = 'test.txt';

    await dispatchDocument('click', closeBtn);

    assert.strictEqual(pasteInput.value, '');
    assert.strictEqual(fileInput.value, '');
  });
});
