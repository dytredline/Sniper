import assert from 'node:assert/strict';
import { test } from 'node:test';
import fs from 'node:fs';
import vm from 'node:vm';

const appJsPath = process.env.SNIPER_UI_APP_JS
  ? new URL(process.env.SNIPER_UI_APP_JS, import.meta.url).pathname
  : new URL('../static/app.js', import.meta.url).pathname;

function createFakeDOM(overrides = {}) {
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
        this.handlers ??= new Map();
        const items = this.handlers.get(String(name)) || [];
        items.push(callback);
        this.handlers.set(String(name), items);
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
      matches() { return false; },
      closest(selector) {
        if (selector === '[data-action]') {
          return this.dataset.action !== undefined ? this : null;
        }
        if (selector === '[data-close]') {
          return this.dataset.close !== undefined ? this : null;
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
  Object.assign(getResponses, overrides);

  async function fetch(path, options = {}) {
    requests.push({ path, options });
    const isPost = options.method === 'POST';
    if (isPost && path.endsWith('/tool-evidence/testssl-flat-json')) {
      const body = JSON.parse(options.body);
      const severityCounts = {
        INFO: 0, OK: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0, WARN: 0, DEBUG: 0, FATAL: 0,
      };
      for (const row of body.report) severityCounts[row.severity] += 1;
      return {
        ok: true,
        status: 201,
        json: async () => ({
          id: 'tev-fixture', tool_identity: 'testssl-flat-json',
          record_count: body.report.length, severity_counts: severityCounts,
          report_sha256: 'a'.repeat(64),
        }),
      };
    }
    if (isPost && path === '/api/tool-reports/testssl/summary') {
      const body = JSON.parse(options.body);
      const report = body.report;
      if (!Array.isArray(report)) {
        return {
          ok: false,
          status: 400,
          json: async () => ({ error: 'report anahtarı eksik veya geçersiz.' }),
        };
      }
      if (report.length > 500) {
        return {
          ok: false,
          status: 400,
          json: async () => ({ error: 'Kayıt sayısı çok fazla.' }),
        };
      }
      const validSeverities = ['INFO', 'OK', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'WARN', 'DEBUG', 'FATAL'];
      for (const rec of report) {
        if (typeof rec !== 'object' || rec === null || !('severity' in rec) || typeof rec.severity !== 'string') {
          return {
            ok: false,
            status: 400,
            json: async () => ({ error: 'Geçersiz kayıt yapısı.' }),
          };
        }
        if (!validSeverities.includes(rec.severity)) {
          return {
            ok: false,
            status: 400,
            json: async () => ({ error: 'Geçersiz severity.' }),
          };
        }
      }
      const severityCounts = {
        INFO: 0, OK: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0, WARN: 0, DEBUG: 0, FATAL: 0,
      };
      for (const rec of report) {
        severityCounts[rec.severity] = (severityCounts[rec.severity] || 0) + 1;
      }
      const encoder = new TextEncoder();
      const reportStr = JSON.stringify(report);
      const hash = await crypto.subtle.digest('SHA-256', encoder.encode(reportStr));
      const sha256 = Array.from(new Uint8Array(hash))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
      return {
        ok: true,
        status: 200,
        json: async () => ({
          format: 'testssl-flat-json',
          record_count: report.length,
          severity_counts: severityCounts,
          report_sha256: sha256,
        }),
      };
    }
    const body = getResponses[path] || {};
    return { ok: true, status: 200, json: async () => body };
  }

  const context = vm.createContext({
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
    crypto: { subtle: { digest: async (algorithm, data) => { return new ArrayBuffer(32); } } },
  });

  return { context, document, element, requests, documentListeners };
}

async function dispatchDocument(eventName, target, documentListeners) {
  const callbacks = documentListeners.get(eventName) || [];
  for (const callback of callbacks) {
    const event = {
      target,
      preventDefault() {},
    };
    await callback(event);
  }
}

async function loadApp(overrides = {}) {
  const { context, document, element, requests, documentListeners } = createFakeDOM(overrides);
  const appCode = fs.readFileSync(appJsPath, 'utf8');
  vm.runInContext(appCode, context, { filename: appJsPath });
  await new Promise(resolve => setImmediate(resolve));
  return { document, element, requests, documentListeners };
}

test('testssl-flat-preview-ui: positive flow with valid JSON array (HIGH and INFO)', async () => {
  const { document, element, requests, documentListeners } = await loadApp();

  const openTarget = element('#open-testssl-flat-preview');
  openTarget.dataset.action = 'open-testssl-flat-preview';
  await dispatchDocument('click', openTarget, documentListeners);

  const pasteInput = element('#testssl-paste');
  const form = element('#testssl-preview-form');

  const record1 = JSON.stringify({
    id: 'private-123',
    ip: '192.168.1.1',
    port: '443',
    finding: 'vulnerable',
    severity: 'HIGH',
    name: 'Test HIGH',
  });
  const record2 = JSON.stringify({
    id: 'private-456',
    ip: '10.0.0.1',
    port: '80',
    finding: 'safe',
    severity: 'INFO',
    name: 'Test INFO',
  });
  pasteInput.value = JSON.stringify([JSON.parse(record1), JSON.parse(record2)]);

  await dispatchDocument('submit', form, documentListeners);

  const postRequests = requests.filter(r => r.options?.method === 'POST' && r.path === '/api/tool-reports/testssl/summary');
  assert.strictEqual(postRequests.length, 1, 'Expected exactly one POST to /api/tool-reports/testssl/summary');

  const body = JSON.parse(postRequests[0].options.body);
  assert.deepStrictEqual(body, { report: [JSON.parse(record1), JSON.parse(record2)] }, 'POST body mismatch');

  const recordCountEl = element('#testssl-record-count');
  const severityCountsEl = element('#testssl-severity-counts');
  const sha256El = element('#testssl-report-sha256');

  assert.strictEqual(String(recordCountEl.textContent), '2', 'record_count mismatch');
  assert.ok(severityCountsEl.textContent.includes('HIGH:1'), 'severity_counts HIGH mismatch');
  assert.ok(severityCountsEl.textContent.includes('INFO:1'), 'severity_counts INFO mismatch');
  assert.strictEqual(sha256El.textContent.length, 64, 'report_sha256 length mismatch');

  const resultEl = element('#testssl-preview-result');
  assert.ok(!resultEl.classList.contains('hidden'), 'resultEl should be visible');

  const errorEl = element('#testssl-preview-error');
  assert.ok(errorEl.classList.contains('hidden'), 'errorEl should be hidden');

  const syntheticPrivate = 'private-123';
  assert.ok(!String(document.getElementById('testssl-record-count').textContent).includes(syntheticPrivate), 'synthetic private marker should not be in record count');
  assert.ok(!document.getElementById('testssl-severity-counts').textContent.includes(syntheticPrivate), 'synthetic private marker should not be in severity counts');
  assert.ok(!document.getElementById('testssl-report-sha256').textContent.includes(syntheticPrivate), 'synthetic private marker should not be in report SHA');
});

test('testssl-flat-preview-ui: explicit opt-in links aggregate to a selected control', async () => {
  const { document, element, requests, documentListeners } = await loadApp({
    '/api/engagements': { engagements: [{
      id: 'eng-fixture', name: 'TLS review', status: 'active',
      authorization_ref: 'AUTH-FIXTURE', scope_notes: 'synthetic scope',
      special_approvals: { redacted_data_proof: true },
    }] },
    '/api/engagements/eng-fixture': {
      id: 'eng-fixture', tests: [{ control_id: 'TLS-01', title: 'TLS configuration' }],
    },
  });

  const openTarget = element('#open-testssl-flat-preview');
  openTarget.dataset.action = 'open-testssl-flat-preview';
  await dispatchDocument('click', openTarget, documentListeners);
  const consent = element('#testssl-link-opt-in');
  assert.strictEqual(consent.disabled, false, 'eligible engagement should enable explicit consent');
  consent.checked = true;
  await dispatchDocument('change', consent, documentListeners);
  const engagementSelect = element('#testssl-link-engagement');
  engagementSelect.value = 'eng-fixture';
  await dispatchDocument('change', engagementSelect, documentListeners);
  const controlSelect = element('#testssl-link-control');
  controlSelect.value = 'TLS-01';

  const marker = 'PRIVATE_TESTSSL_UI_MARKER';
  element('#testssl-paste').value = JSON.stringify([{
    id: marker, ip: '198.51.100.9', port: '443', severity: 'HIGH', finding: marker,
  }]);
  await dispatchDocument('submit', element('#testssl-preview-form'), documentListeners);

  const linked = requests.filter(item => item.options?.method === 'POST' && item.path.endsWith('/tool-evidence/testssl-flat-json'));
  assert.strictEqual(linked.length, 1, 'expected one explicit evidence-link request');
  const body = JSON.parse(linked[0].options.body);
  assert.deepStrictEqual(Object.keys(body).sort(), ['confirm_link', 'control_id', 'report']);
  assert.strictEqual(body.confirm_link, true);
  assert.strictEqual(body.control_id, 'TLS-01');
  assert.strictEqual(body.report[0].id, marker);
  assert.strictEqual(requests.filter(item => item.options?.method === 'POST' && item.path === '/api/tool-reports/testssl/summary').length, 0);
  assert.strictEqual(element('#testssl-record-count').textContent, 1);
  assert.ok(element('#testssl-link-result').textContent.includes('TLS-01'));
  assert.ok(!element('#testssl-link-result').textContent.includes(marker));
});

test('testssl-flat-preview-ui: negative flow with malformed JSON', async () => {
  const { document, element, requests, documentListeners } = await loadApp();

  const openTarget = element('#open-testssl-flat-preview');
  openTarget.dataset.action = 'open-testssl-flat-preview';
  await dispatchDocument('click', openTarget, documentListeners);

  const pasteInput = element('#testssl-paste');
  const form = element('#testssl-preview-form');

  pasteInput.value = '{ invalid json';

  await dispatchDocument('submit', form, documentListeners);

  const postRequests = requests.filter(r => r.options?.method === 'POST' && r.path === '/api/tool-reports/testssl/summary');
  assert.strictEqual(postRequests.length, 0, 'Expected zero POSTs for malformed JSON');

  const errorEl = element('#testssl-preview-error');
  assert.ok(!errorEl.classList.contains('hidden'), 'errorEl should be visible');
  assert.ok(errorEl.textContent.length > 0, 'errorEl should have text');

  const resultEl = element('#testssl-preview-result');
  assert.ok(resultEl.classList.contains('hidden'), 'resultEl should be hidden');
});

test('testssl-flat-preview-ui: negative flow with non-array JSON', async () => {
  const { document, element, requests, documentListeners } = await loadApp();

  const openTarget = element('#open-testssl-flat-preview');
  openTarget.dataset.action = 'open-testssl-flat-preview';
  await dispatchDocument('click', openTarget, documentListeners);

  const pasteInput = element('#testssl-paste');
  const form = element('#testssl-preview-form');

  pasteInput.value = JSON.stringify({ report: [] });

  await dispatchDocument('submit', form, documentListeners);

  const postRequests = requests.filter(r => r.options?.method === 'POST' && r.path === '/api/tool-reports/testssl/summary');
  assert.strictEqual(postRequests.length, 0, 'Expected zero POSTs for non-array JSON');

  const errorEl = element('#testssl-preview-error');
  assert.ok(!errorEl.classList.contains('hidden'), 'errorEl should be visible');

  const resultEl = element('#testssl-preview-result');
  assert.ok(resultEl.classList.contains('hidden'), 'resultEl should be hidden');
});

test('testssl-flat-preview-ui: close modal clears inputs and results', async () => {
  const { document, element, requests, documentListeners } = await loadApp();

  const openTarget = element('#open-testssl-flat-preview');
  openTarget.dataset.action = 'open-testssl-flat-preview';
  await dispatchDocument('click', openTarget, documentListeners);

  const pasteInput = element('#testssl-paste');
  pasteInput.value = 'test';

  const closeTarget = element('#testssl-preview-modal');
  closeTarget.dataset.close = 'testssl-preview-modal';
  await dispatchDocument('click', closeTarget, documentListeners);

  assert.strictEqual(pasteInput.value, '', 'pasteInput should be cleared');

  const resultEl = element('#testssl-preview-result');
  assert.ok(resultEl.classList.contains('hidden'), 'resultEl should be hidden after close');
});
