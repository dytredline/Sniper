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
        }
        if (selector === '[data-close]') {
          if (this.dataset.close === 'ssllabs-preview-modal') return this;
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
    if (isPost && path === '/api/tool-reports/ssllabs-host/summary') {
      const body = JSON.parse(options.body);
      if (body && typeof body === 'object' && !Array.isArray(body) && body.report && typeof body.report === 'object' && !Array.isArray(body.report)) {
        const report = body.report;
        if (report.status === 'READY' && Array.isArray(report.endpoints)) {
          const GRADE_ENUM = ['A+', 'A', 'A-', 'B', 'C', 'D', 'E', 'F', 'T', 'M'];
          const grade_counts = {};
          for (const g of GRADE_ENUM) grade_counts[g] = 0;
          for (const ep of report.endpoints) {
            const grade = ep.grade;
            if (grade !== null && grade !== undefined) {
              if (typeof grade === 'string' && GRADE_ENUM.includes(grade)) {
                grade_counts[grade]++;
              }
            }
          }
          const gradeSum = GRADE_ENUM.reduce((acc, k) => acc + grade_counts[k], 0);
          const reportSha256 = 'b'.repeat(64);
          return {
            ok: true,
            status: 200,
            json: async () => ({
              format: 'ssllabs-v4-host',
              assessment_status: report.status,
              endpoint_count: report.endpoints.length,
              grade_counts,
              report_sha256: reportSha256,
            }),
          };
        }
      }
      return { ok: true, status: 200, json: async () => ({ format: '', assessment_status: '', endpoint_count: 0, grade_counts: {}, report_sha256: '' }) };
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

describe('SSL Labs preview UI', () => {
  it('should open modal, submit valid SSL Labs JSON, render aggregate summary, clear inputs', async () => {
    const { document, element, requests, documentListeners, fetch, dispatchDocument } = buildFakeDom();
    await runApp(document, fetch);

    const openBtn = element('#open-ssllabs-preview');
    openBtn.dataset.action = 'open-ssllabs-preview';
    const modal = element('#ssllabs-preview-modal');
    modal.classList.add('hidden');
    const form = element('#ssllabs-preview-form');
    const pasteInput = element('#ssllabs-paste');
    const errorEl = element('#ssllabs-preview-error');
    const resultEl = element('#ssllabs-preview-result');
    const formatEl = element('#ssllabs-format');
    const statusEl = element('#ssllabs-status');
    const endpointCountEl = element('#ssllabs-endpoint-count');
    const gradeCountsEl = element('#ssllabs-grade-counts');
    const sha256El = element('#ssllabs-report-sha256');

    // Open modal
    await dispatchDocument('click', openBtn);
    assert.strictEqual(modal.classList.contains('hidden'), false);

    // Paste valid SSL Labs JSON with synthetic report
    const syntheticJson = JSON.stringify({
      status: 'READY',
      host: 'SYNTHETIC_PRIVATE_MARKER',
      endpoints: [
        { grade: 'A', ipAddress: 'SYNTHETIC_PRIVATE_MARKER' },
        { grade: null, details: { cert: { subject: 'SYNTHETIC_PRIVATE_MARKER' } } }
      ]
    });
    pasteInput.value = syntheticJson;

    // Submit form
    await dispatchDocument('submit', form);

    // Assert exactly one POST to /api/tool-reports/ssllabs-host/summary
    const postRequests = requests.filter(r => r.path === '/api/tool-reports/ssllabs-host/summary' && r.options.method === 'POST');
    assert.strictEqual(postRequests.length, 1);
    const body = JSON.parse(postRequests[0].options.body);
    assert.deepStrictEqual(body, { report: JSON.parse(syntheticJson) });

    // Assert aggregate fields rendered
    assert.strictEqual(formatEl.textContent, 'ssllabs-v4-host');
    assert.strictEqual(statusEl.textContent, 'READY');
    assert.strictEqual(String(endpointCountEl.textContent), '2');
    assert.strictEqual(gradeCountsEl.textContent, 'A+:0 A:1 A-:0 B:0 C:0 D:0 E:0 F:0 T:0 M:0');
    assert.strictEqual(sha256El.textContent, 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb');

    // Assert result visible and error hidden
    assert.strictEqual(resultEl.classList.contains('hidden'), false);
    assert.strictEqual(errorEl.classList.contains('hidden'), true);

    // Assert no marker, host, IP or cert in rendered content
    const formatText = formatEl.textContent;
    const statusText = statusEl.textContent;
    const endpointCountText = endpointCountEl.textContent;
    const gradeCountsText = gradeCountsEl.textContent;
    const sha256Text = sha256El.textContent;
    const resultText = resultEl.innerHTML;
    const errorText = errorEl.textContent;
    const allText = [formatText, statusText, endpointCountText, gradeCountsText, sha256Text, resultText, errorText].join(' ');
    assert.strictEqual(allText.includes('SYNTHETIC_PRIVATE_MARKER'), false);

    assert.strictEqual(allText.includes('ipAddress'), false);
    assert.strictEqual(allText.includes('subject'), false);
    assert.strictEqual(allText.includes('ssllabs-v4-host'), true);
    assert.strictEqual(allText.includes('READY'), true);
    assert.strictEqual(allText.includes('endpoint_count'), false);
    assert.strictEqual(allText.includes('A:1'), true);

    // Assert inputs cleared
    assert.strictEqual(pasteInput.value, '');
  });

  it('should reject malformed JSON with generic error and zero POST', async () => {
    const { document, element, requests, documentListeners, fetch, dispatchDocument } = buildFakeDom();
    await runApp(document, fetch);

    const form = element('#ssllabs-preview-form');
    const pasteInput = element('#ssllabs-paste');
    const errorEl = element('#ssllabs-preview-error');

    pasteInput.value = '{ invalid json';
    await dispatchDocument('submit', form);

    const postRequests = requests.filter(r => r.path === '/api/tool-reports/ssllabs-host/summary' && r.options.method === 'POST');
    assert.strictEqual(postRequests.length, 0);
    assert.strictEqual(errorEl.textContent, 'Geçersiz JSON.');
    assert.strictEqual(errorEl.classList.contains('hidden'), false);
  });

  it('should reject non-array endpoints with generic error and zero POST', async () => {
    const { document, element, requests, documentListeners, fetch, dispatchDocument } = buildFakeDom();
    await runApp(document, fetch);

    const form = element('#ssllabs-preview-form');
    const pasteInput = element('#ssllabs-paste');
    const errorEl = element('#ssllabs-preview-error');

    pasteInput.value = JSON.stringify({ status: 'READY', endpoints: 'not-array' });
    await dispatchDocument('submit', form);

    const postRequests = requests.filter(r => r.path === '/api/tool-reports/ssllabs-host/summary' && r.options.method === 'POST');
    assert.strictEqual(postRequests.length, 0);
    assert.strictEqual(errorEl.textContent, 'Geçersiz JSON.');
    assert.strictEqual(errorEl.classList.contains('hidden'), false);
  });

  it('should reject invalid status with generic error and zero POST', async () => {
    const { document, element, requests, documentListeners, fetch, dispatchDocument } = buildFakeDom();
    await runApp(document, fetch);

    const form = element('#ssllabs-preview-form');
    const pasteInput = element('#ssllabs-paste');
    const errorEl = element('#ssllabs-preview-error');

    pasteInput.value = JSON.stringify({ status: 'INVALID_STATUS', endpoints: [] });
    await dispatchDocument('submit', form);

    const postRequests = requests.filter(r => r.path === '/api/tool-reports/ssllabs-host/summary' && r.options.method === 'POST');
    assert.strictEqual(postRequests.length, 0);
    assert.strictEqual(errorEl.textContent, 'Geçersiz JSON.');
    assert.strictEqual(errorEl.classList.contains('hidden'), false);
  });

  it('should clear inputs on close', async () => {
    const { document, element, requests, documentListeners, fetch, dispatchDocument } = buildFakeDom();
    await runApp(document, fetch);

    const openBtn = element('#open-ssllabs-preview');
    const closeBtn = element('#ssllabs-preview-modal [data-close="ssllabs-preview-modal"]');
    closeBtn.dataset.close = 'ssllabs-preview-modal';
    const pasteInput = element('#ssllabs-paste');
    const fileInput = element('#ssllabs-file');

    await dispatchDocument('click', openBtn);
    pasteInput.value = 'Marker in advisory';
    fileInput.value = 'test.txt';

    await dispatchDocument('click', closeBtn);

    assert.strictEqual(pasteInput.value, '');
    assert.strictEqual(fileInput.value, '');
  });
});
