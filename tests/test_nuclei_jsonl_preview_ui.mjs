import assert from 'node:assert/strict';
import { test } from 'node:test';
import fs from 'node:fs';
import vm from 'node:vm';

const appJsPath = process.env.SNIPER_UI_APP_JS
  ? new URL(process.env.SNIPER_UI_APP_JS, import.meta.url).pathname
  : new URL('../static/app.js', import.meta.url).pathname;

function createFakeDOM() {
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

  async function fetch(path, options = {}) {
    requests.push({ path, options });
    const isPost = options.method === 'POST';
    if (isPost && path === '/api/tool-reports/nuclei-jsonl/summary') {
      return {
        ok: true,
        status: 200,
        json: async () => ({
          format: 'nuclei-jsonl',
          record_count: 2,
          unique_template_count: 2,
          severity_counts: { info: 0, low: 0, medium: 1, high: 1, critical: 0, unknown: 0 },
          report_sha256: "a".repeat(64),
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

async function loadApp() {
  const { context, document, element, requests, documentListeners } = createFakeDOM();
  const appCode = fs.readFileSync(appJsPath, 'utf8');
  vm.runInContext(appCode, context, { filename: appJsPath });
  await new Promise(resolve => setImmediate(resolve));
  return { document, element, requests, documentListeners };
}

test('nuclei-jsonl-preview-ui: positive flow with valid JSONL', async () => {
  const { document, element, requests, documentListeners } = await loadApp();

  const openTarget = element('#open-nuclei-jsonl-preview');
  openTarget.dataset.action = 'open-nuclei-jsonl-preview';
  await dispatchDocument('click', openTarget, documentListeners);

  const pasteInput = element('#nuclei-jsonl-paste');
  const form = element('#nuclei-jsonl-preview-form');

  const record1 = JSON.stringify({
    'template-id': 'test-template-1',
    type: 'http',
    info: { severity: 'high', name: 'Test 1' },
  });
  const record2 = JSON.stringify({
    'template-id': 'test-template-2',
    type: 'dns',
    info: { severity: 'medium', name: 'Test 2' },
  });
  pasteInput.value = [record1, record2].join('\n');

  await dispatchDocument('submit', form, documentListeners);

  const postRequests = requests.filter(r => r.options?.method === 'POST' && r.path === '/api/tool-reports/nuclei-jsonl/summary');
  assert.strictEqual(postRequests.length, 1, 'Expected exactly one POST to /api/tool-reports/nuclei-jsonl/summary');

  const body = JSON.parse(postRequests[0].options.body);
  assert.deepStrictEqual(body, { report: [JSON.parse(record1), JSON.parse(record2)] }, 'POST body mismatch');

  const recordCountEl = element('#nuclei-jsonl-record-count');
  const uniqueTemplateCountEl = element('#nuclei-jsonl-unique-template-count');
  const reportSha256El = element('#nuclei-jsonl-report-sha256');

  assert.strictEqual(String(recordCountEl.textContent), '2', 'record_count mismatch');
  assert.strictEqual(String(uniqueTemplateCountEl.textContent), '2', 'unique_template_count mismatch');
  assert.strictEqual(reportSha256El.textContent, 'a'.repeat(64), 'report_sha256 mismatch');

  const resultEl = element('#nuclei-jsonl-preview-result');
  assert.ok(!resultEl.classList.contains('hidden'), 'resultEl should be visible');
});

test('nuclei-jsonl-preview-ui: negative flow with uppercase severity', async () => {
  const { document, element, requests, documentListeners } = await loadApp();

  const openTarget = element('#open-nuclei-jsonl-preview');
  openTarget.dataset.action = 'open-nuclei-jsonl-preview';
  await dispatchDocument('click', openTarget, documentListeners);

  const pasteInput = element('#nuclei-jsonl-paste');
  const form = element('#nuclei-jsonl-preview-form');

  const record = JSON.stringify({
    'template-id': 'test-template',
    type: 'http',
    info: { severity: 'INFO', name: 'Test' },
  });
  pasteInput.value = record;

  await dispatchDocument('submit', form, documentListeners);

  const postRequests = requests.filter(r => r.options?.method === 'POST' && r.path === '/api/tool-reports/nuclei-jsonl/summary');
  assert.strictEqual(postRequests.length, 0, 'Expected zero POSTs for invalid severity');

  const errorEl = element('#nuclei-jsonl-preview-error');
  assert.ok(!errorEl.classList.contains('hidden'), 'errorEl should be visible');
  assert.ok(errorEl.textContent.length > 0, 'errorEl should have text');

  const resultEl = element('#nuclei-jsonl-preview-result');
  assert.ok(resultEl.classList.contains('hidden'), 'resultEl should be hidden');
});

test('nuclei-jsonl-preview-ui: close modal clears inputs and results', async () => {
  const { document, element, requests, documentListeners } = await loadApp();

  const openTarget = element('#open-nuclei-jsonl-preview');
  openTarget.dataset.action = 'open-nuclei-jsonl-preview';
  await dispatchDocument('click', openTarget, documentListeners);

  const pasteInput = element('#nuclei-jsonl-paste');
  pasteInput.value = 'test';

  const closeTarget = element('#nuclei-jsonl-preview-modal');
  closeTarget.dataset.close = 'nuclei-jsonl-preview-modal';
  await dispatchDocument('click', closeTarget, documentListeners);

  assert.strictEqual(pasteInput.value, '', 'pasteInput should be cleared');
});

test('nuclei-jsonl-preview-ui: close/reopen and newer submit invalidate stale async summary responses', async () => {
  const { context, element, requests, documentListeners } = createFakeDOM();
  const pending = [];
  context.fetch = async (path, options = {}) => {
    requests.push({ path, options });
    if (options.method === 'POST' && path === '/api/tool-reports/nuclei-jsonl/summary') {
      return new Promise(resolve => {
        pending.push(resolve);
      });
    }
    return { ok: true, status: 200, json: async () => ({}) };
  };
  vm.runInContext(fs.readFileSync(appJsPath, 'utf8'), context, { filename: appJsPath });
  await new Promise(resolve => setImmediate(resolve));

  const validLineA = JSON.stringify({
    'template-id': 'http-missing-security-headers',
    type: 'http',
    info: { name: 'Missing Headers', severity: 'high' }
  });
  const validLineB = JSON.stringify({
    'template-id': 'tls-version',
    type: 'ssl',
    info: { name: 'TLS Version', severity: 'low' }
  });

  const openAction = element('#open-nuclei-jsonl-preview');
  openAction.dataset.action = 'open-nuclei-jsonl-preview';
  await dispatchDocument('click', openAction, documentListeners);

  element('#nuclei-jsonl-paste').value = validLineA;
  const firstRun = dispatchDocument('submit', element('#nuclei-jsonl-preview-form'), documentListeners);
  await new Promise(resolve => setImmediate(resolve));
  assert.strictEqual(pending.length, 1);

  const closeTarget = element('#nuclei-jsonl-preview-modal');
  closeTarget.dataset.close = 'nuclei-jsonl-preview-modal';
  await dispatchDocument('click', closeTarget, documentListeners);
  assert.strictEqual(element('#nuclei-jsonl-preview-modal').classList.contains('hidden'), true);

  pending[0]({
    ok: true,
    status: 200,
    json: async () => ({
      format: 'nuclei-jsonl',
      record_count: 1,
      unique_template_count: 1,
      severity_counts: { info: 0, low: 0, medium: 0, high: 1, critical: 0, unknown: 0 },
      report_sha256: 'a'.repeat(64)
    })
  });
  await firstRun;

  await dispatchDocument('click', openAction, documentListeners);
  assert.strictEqual(element('#nuclei-jsonl-preview-result').classList.contains('hidden'), true);
  assert.strictEqual(element('#nuclei-jsonl-report-sha256').textContent, '');

  // Race: submit A, then submit B; resolve B first, then resolve A
  element('#nuclei-jsonl-paste').value = validLineA;
  const raceA = dispatchDocument('submit', element('#nuclei-jsonl-preview-form'), documentListeners);
  await new Promise(resolve => setImmediate(resolve));
  element('#nuclei-jsonl-paste').value = validLineB;
  const raceB = dispatchDocument('submit', element('#nuclei-jsonl-preview-form'), documentListeners);
  await new Promise(resolve => setImmediate(resolve));
  assert.strictEqual(pending.length, 3);

  pending[2]({
    ok: true,
    status: 200,
    json: async () => ({
      format: 'nuclei-jsonl',
      record_count: 1,
      unique_template_count: 1,
      severity_counts: { info: 0, low: 1, medium: 0, high: 0, critical: 0, unknown: 0 },
      report_sha256: 'b'.repeat(64)
    })
  });
  await raceB;
  assert.strictEqual(element('#nuclei-jsonl-report-sha256').textContent, 'b'.repeat(64));

  pending[1]({
    ok: true,
    status: 200,
    json: async () => ({
      format: 'nuclei-jsonl',
      record_count: 1,
      unique_template_count: 1,
      severity_counts: { info: 0, low: 0, medium: 0, high: 1, critical: 0, unknown: 0 },
      report_sha256: 'a'.repeat(64)
    })
  });
  await raceA;
  assert.strictEqual(element('#nuclei-jsonl-report-sha256').textContent, 'b'.repeat(64));
});
