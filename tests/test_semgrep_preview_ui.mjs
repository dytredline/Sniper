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
          if (this.dataset.action === 'open-ssllabs-preview') return this;
          if (this.dataset.action === 'submit-ssllabs-preview') return this;
          if (this.dataset.action === 'open-semgrep-preview') return this;
          if (this.dataset.action === 'submit-semgrep-preview') return this;
        }
        if (selector === '[data-close]') {
          if (this.dataset.close === 'ssllabs-preview-modal') return this;
          if (this.dataset.close === 'semgrep-preview-modal') return this;
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
          const sum = allowedSeverities.reduce((acc, k) => acc + severityCounts[k], 0);
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

describe('Semgrep preview UI', () => {
  it('should open modal, submit valid Semgrep JSON, render aggregate summary, clear inputs', async () => {
    const { document, element, requests, documentListeners, fetch, dispatchDocument } = buildFakeDom();
    await runApp(document, fetch);

    const openBtn = element('#open-semgrep-preview');
    openBtn.dataset.action = 'open-semgrep-preview';
    const modal = element('#semgrep-preview-modal');
    modal.classList.add('hidden');
    const form = element('#semgrep-preview-form');
    const pasteInput = element('#semgrep-paste');
    const errorEl = element('#semgrep-preview-error');
    const resultEl = element('#semgrep-preview-result');
    const formatEl = element('#semgrep-format');
    const resultCountEl = element('#semgrep-result-count');
    const severityCountsEl = element('#semgrep-severity-counts');
    const sha256El = element('#semgrep-report-sha256');

    // Open modal
    await dispatchDocument('click', openBtn);
    assert.strictEqual(modal.classList.contains('hidden'), false);

    // Paste valid Semgrep JSON with synthetic report
    const syntheticJson = JSON.stringify({
      results: [
        {
          check_id: 'test-id',
          path: '/path/SYNTHETIC_PRIVATE_MARKER',
          start: { line: 1, col: 1 },
          end: { line: 1, col: 10 },
          extra: {
            message: 'SYNTHETIC_PRIVATE_MARKER message',
            lines: 'SYNTHETIC_PRIVATE_MARKER lines',
            fingerprint: 'fingerprint-123',
            severity: 'ERROR',
            metadata: {},
          },
        },
      ],
      errors: [],
      paths: { scanned: ['/path/file.js'] },
    });
    pasteInput.value = syntheticJson;

    // Submit form
    await dispatchDocument('submit', form);

    // Assert exactly one POST to /api/tool-reports/semgrep-native-json/summary
    const postRequests = requests.filter(r => r.path === '/api/tool-reports/semgrep-native-json/summary' && r.options.method === 'POST');
    assert.strictEqual(postRequests.length, 1);
    const body = JSON.parse(postRequests[0].options.body);
    assert.deepStrictEqual(body, { report: JSON.parse(syntheticJson) });

    // Assert aggregate fields rendered
    assert.strictEqual(formatEl.textContent, 'semgrep-native-json');
    assert.strictEqual(resultCountEl.textContent, '1');
    assert.strictEqual(severityCountsEl.textContent, 'ERROR:1 WARNING:0 EXPERIMENT:0 INVENTORY:0 CRITICAL:0 HIGH:0 MEDIUM:0 LOW:0 INFO:0');
    assert.strictEqual(sha256El.textContent, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');

    // Assert result visible and error hidden
    assert.strictEqual(resultEl.classList.contains('hidden'), false);
    assert.strictEqual(errorEl.classList.contains('hidden'), true);

    // Assert no marker in rendered content
    const formatText = formatEl.textContent;
    const resultCountText = resultCountEl.textContent;
    const severityCountsText = severityCountsEl.textContent;
    const sha256Text = sha256El.textContent;
    const resultText = resultEl.innerHTML;
    const errorText = errorEl.textContent;
    const allText = [formatText, resultCountText, severityCountsText, sha256Text, resultText, errorText].join(' ');
    assert.strictEqual(allText.includes('SYNTHETIC_PRIVATE_MARKER'), false);

    // Assert required format substrings present
    assert.strictEqual(allText.includes('semgrep-native-json'), true);
    assert.strictEqual(allText.includes('ERROR:1'), true);
    assert.strictEqual(allText.includes('WARNING:0'), true);

    // Assert inputs cleared
    assert.strictEqual(pasteInput.value, '');
  });

  it('should reject malformed JSON with generic error and zero POST', async () => {
    const { document, element, requests, documentListeners, fetch, dispatchDocument } = buildFakeDom();
    await runApp(document, fetch);

    const form = element('#semgrep-preview-form');
    const pasteInput = element('#semgrep-paste');
    const errorEl = element('#semgrep-preview-error');

    pasteInput.value = '{ invalid json';
    await dispatchDocument('submit', form);

    const postRequests = requests.filter(r => r.path === '/api/tool-reports/semgrep-native-json/summary' && r.options.method === 'POST');
    assert.strictEqual(postRequests.length, 0);
    assert.strictEqual(errorEl.textContent, 'Geçersiz JSON.');
    assert.strictEqual(errorEl.classList.contains('hidden'), false);
  });

  it('should reject non-array results with generic error and zero POST', async () => {
    const { document, element, requests, documentListeners, fetch, dispatchDocument } = buildFakeDom();
    await runApp(document, fetch);

    const form = element('#semgrep-preview-form');
    const pasteInput = element('#semgrep-paste');
    const errorEl = element('#semgrep-preview-error');

    pasteInput.value = JSON.stringify({ results: 'not-array', errors: [], paths: { scanned: [] } });
    await dispatchDocument('submit', form);

    const postRequests = requests.filter(r => r.path === '/api/tool-reports/semgrep-native-json/summary' && r.options.method === 'POST');
    assert.strictEqual(postRequests.length, 0);
    assert.strictEqual(errorEl.textContent, 'Geçersiz JSON.');
    assert.strictEqual(errorEl.classList.contains('hidden'), false);
  });

  it('should reject missing errors with generic error and zero POST', async () => {
    const { document, element, requests, documentListeners, fetch, dispatchDocument } = buildFakeDom();
    await runApp(document, fetch);

    const form = element('#semgrep-preview-form');
    const pasteInput = element('#semgrep-paste');
    const errorEl = element('#semgrep-preview-error');

    pasteInput.value = JSON.stringify({ results: [], paths: { scanned: [] } });
    await dispatchDocument('submit', form);

    const postRequests = requests.filter(r => r.path === '/api/tool-reports/semgrep-native-json/summary' && r.options.method === 'POST');
    assert.strictEqual(postRequests.length, 0);
    assert.strictEqual(errorEl.textContent, 'Geçersiz JSON.');
    assert.strictEqual(errorEl.classList.contains('hidden'), false);
  });

  it('should reject missing paths with generic error and zero POST', async () => {
    const { document, element, requests, documentListeners, fetch, dispatchDocument } = buildFakeDom();
    await runApp(document, fetch);

    const form = element('#semgrep-preview-form');
    const pasteInput = element('#semgrep-paste');
    const errorEl = element('#semgrep-preview-error');

    pasteInput.value = JSON.stringify({ results: [], errors: [] });
    await dispatchDocument('submit', form);

    const postRequests = requests.filter(r => r.path === '/api/tool-reports/semgrep-native-json/summary' && r.options.method === 'POST');
    assert.strictEqual(postRequests.length, 0);
    assert.strictEqual(errorEl.textContent, 'Geçersiz JSON.');
    assert.strictEqual(errorEl.classList.contains('hidden'), false);
  });

  it('should reject paths.scanned non-array with generic error and zero POST', async () => {
    const { document, element, requests, documentListeners, fetch, dispatchDocument } = buildFakeDom();
    await runApp(document, fetch);

    const form = element('#semgrep-preview-form');
    const pasteInput = element('#semgrep-paste');
    const errorEl = element('#semgrep-preview-error');

    pasteInput.value = JSON.stringify({ results: [], errors: [], paths: { scanned: 'not-array' } });
    await dispatchDocument('submit', form);

    const postRequests = requests.filter(r => r.path === '/api/tool-reports/semgrep-native-json/summary' && r.options.method === 'POST');
    assert.strictEqual(postRequests.length, 0);
    assert.strictEqual(errorEl.textContent, 'Geçersiz JSON.');
    assert.strictEqual(errorEl.classList.contains('hidden'), false);
  });

  it('should reject >500 results with generic error and zero POST', async () => {
    const { document, element, requests, documentListeners, fetch, dispatchDocument } = buildFakeDom();
    await runApp(document, fetch);

    const form = element('#semgrep-preview-form');
    const pasteInput = element('#semgrep-paste');
    const errorEl = element('#semgrep-preview-error');

    const results = [];
    for (let i = 0; i < 501; i++) {
      results.push({
        check_id: 'test-id',
        path: '/path/file.js',
        start: { line: 1, col: 1 },
        end: { line: 1, col: 10 },
        extra: {
          message: 'message',
          lines: 'lines',
          fingerprint: 'fingerprint',
          severity: 'ERROR',
          metadata: {},
        },
      });
    }
    pasteInput.value = JSON.stringify({ results, errors: [], paths: { scanned: ['/path/file.js'] } });
    await dispatchDocument('submit', form);

    const postRequests = requests.filter(r => r.path === '/api/tool-reports/semgrep-native-json/summary' && r.options.method === 'POST');
    assert.strictEqual(postRequests.length, 0);
    assert.strictEqual(errorEl.textContent, 'Geçersiz JSON.');
    assert.strictEqual(errorEl.classList.contains('hidden'), false);
  });

  it('should reject invalid severity in finding with generic error and zero POST', async () => {
    const { document, element, requests, documentListeners, fetch, dispatchDocument } = buildFakeDom();
    await runApp(document, fetch);

    const form = element('#semgrep-preview-form');
    const pasteInput = element('#semgrep-paste');
    const errorEl = element('#semgrep-preview-error');

    pasteInput.value = JSON.stringify({
      results: [
        {
          check_id: 'test-id',
          path: '/path/file.js',
          start: { line: 1, col: 1 },
          end: { line: 1, col: 10 },
          extra: {
            message: 'message',
            lines: 'lines',
            fingerprint: 'fingerprint',
            severity: 'INVALID',
            metadata: {},
          },
        },
      ],
      errors: [],
      paths: { scanned: ['/path/file.js'] },
    });
    await dispatchDocument('submit', form);

    const postRequests = requests.filter(r => r.path === '/api/tool-reports/semgrep-native-json/summary' && r.options.method === 'POST');
    assert.strictEqual(postRequests.length, 0);
    assert.strictEqual(errorEl.textContent, 'Geçersiz JSON.');
    assert.strictEqual(errorEl.classList.contains('hidden'), false);
  });

  it('should clear inputs on close', async () => {
    const { document, element, requests, documentListeners, fetch, dispatchDocument } = buildFakeDom();
    await runApp(document, fetch);

    const openBtn = element('#open-semgrep-preview');
    const closeBtn = element('#semgrep-preview-modal [data-close="semgrep-preview-modal"]');
    closeBtn.dataset.close = 'semgrep-preview-modal';
    const pasteInput = element('#semgrep-paste');
    const fileInput = element('#semgrep-file');

    await dispatchDocument('click', openBtn);
    pasteInput.value = 'Marker in advisory';
    fileInput.value = 'test.txt';

    await dispatchDocument('click', closeBtn);

    assert.strictEqual(pasteInput.value, '');
    assert.strictEqual(fileInput.value, '');
  });
});
