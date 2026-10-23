import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

// External test harness: execute the real Sniper browser script with a small fake DOM.
async function loadSniperApp(appJsPath, reportResponse = null) {
  const elements = new Map();
  const documentListeners = new Map();
  const requests = [];
  function element(key) {
    if (elements.has(key)) return elements.get(key);
    const classes = new Set();
    const node = {
      id: String(key).replace(/^#/, ''), dataset: {}, style: {}, value: '', files: [],
      innerHTML: '', textContent: '', disabled: false,
      classList: {
        add: name => classes.add(name), remove: name => classes.delete(name),
        contains: name => classes.has(name), toggle(name, force) {
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
      append() {}, appendChild() {}, remove() {}, focus() {}, reset() {},
      setSelectionRange() {}, setAttribute() {}, removeAttribute() {},
      querySelector: selector => element(selector), querySelectorAll: () => [],
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
    '/api/dashboard': {}, '/api/targets': {targets: []},
    '/api/scans?limit=200': {scans: []}, '/api/engagements': {engagements: []},
    '/api/lab-runs': {lab_runs: []}, '/api/project-audits': {project_audits: [], total: 0},
    '/api/tooling': {tools: [], categories: [], summary: {}, policy: {native: '', external: '', completion: ''}},
    '/api/dependency-security': {},
  };
  async function fetch(path, options = {}) {
    requests.push({path, options});
    const isPost = options.method === 'POST';
    const body = isPost ? (reportResponse || {format: 'sarif', run_count: 1, result_count: 1,
      tools: [{name: 'Semgrep', result_count: 1, levels: {error: 1, warning: 0, note: 0, none: 0}}],
      report_sha256: 'a'.repeat(64)}) : (getResponses[path] || {});
    return {ok: true, status: 200, json: async () => body};
  }
  const context = vm.createContext({
    document, window: {addEventListener() {}}, location: {hash: ''},
    history: {replaceState() {}}, fetch, TextEncoder, URL, console,
    setTimeout: () => 0, clearTimeout() {}, setInterval: () => 0,
  });
  vm.runInContext(fs.readFileSync(appJsPath, 'utf8'), context, {filename: appJsPath});
  await new Promise(resolve => setImmediate(resolve));
  async function dispatchDocument(name, target) {
    const callbacks = documentListeners.get(name) || [];
    const event = {target, currentTarget: target, preventDefault() {}, stopPropagation() {}};
    for (const callback of callbacks) await callback(event);
  }
  return {context, document, element, requests, dispatchDocument, documentListeners};
}

// Helper to create a valid SARIF 2.1.0 Semgrep report
function makeValidSarif() {
  return {
    "$schema": "https://schemastore.azure.com/schemas/json/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Semgrep",
            version: "1.0.0",
            rules: []
          }
        },
        results: [
          {
            ruleId: "test-rule",
            level: "error",
            message: { text: "Test finding" },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: "test.js" },
                  region: { startLine: 1, startColumn: 1 }
                }
              }
            ]
          }
        ]
      }
    ]
  };
}

// Helper to create oversized input (>64KB)
function makeOversizedInput() {
  const bigString = 'x'.repeat(65537);
  return JSON.stringify({ sarif: bigString });
}

// Helper to clear modal state
describe('SARIF Browser Preview UI', () => {
  const appJsPath = process.env.SNIPER_UI_APP_JS || 'static/app.js';

  it('renders valid SARIF and shows allowlisted summary', async () => {
    const validSarif = makeValidSarif();
    const app = await loadSniperApp(appJsPath, {
      format: 'sarif',
      run_count: 1,
      result_count: 1,
      tools: [{
        name: 'Semgrep',
        result_count: 1,
        levels: { error: 1, warning: 0, note: 0, none: 0 }
      }],
      report_sha256: 'a'.repeat(64)
    });

    const pasteInput = app.document.getElementById('sarif-paste');
    const errorEl = app.document.getElementById('sarif-preview-error');
    const resultEl = app.document.getElementById('sarif-preview-result');

    // Set valid SARIF
    pasteInput.value = JSON.stringify(validSarif);

    // Dispatch submit event
    await app.dispatchDocument('submit', app.document.getElementById('sarif-preview-form'));

    // Check no extra POSTs beyond expected one
    const postRequests = app.requests.filter(r => r.options.method === 'POST');
    assert.strictEqual(postRequests.length, 1, 'Expected exactly one POST request');
    assert.strictEqual(postRequests[0].path, '/api/tool-reports/sarif/summary');

    // Check rendered summary
    assert.strictEqual(String(app.document.getElementById('sarif-run-count').textContent), '1');
    assert.strictEqual(String(app.document.getElementById('sarif-result-count').textContent), '1');
    assert.strictEqual(app.document.getElementById('sarif-tool-names').textContent, 'Semgrep');
assert.strictEqual(app.document.getElementById('sarif-levels').textContent, 'error: 1, warning: 0, note: 0, none: 0');
    assert.strictEqual(app.document.getElementById('sarif-report-sha256').textContent, 'a'.repeat(64));

    // Check result panel is visible
    assert.ok(!resultEl.classList.contains('hidden'), 'Result panel should be visible');
    assert.ok(errorEl.classList.contains('hidden'), 'Error should be hidden');

    // Check inputs cleared
    assert.strictEqual(pasteInput.value, '');
  });

  it('rejects invalid JSON with fixed error and no POST', async () => {
    const app = await loadSniperApp(appJsPath);

    const pasteInput = app.document.getElementById('sarif-paste');
    const errorEl = app.document.getElementById('sarif-preview-error');

    // Set invalid JSON
    pasteInput.value = '{invalid json';

    // Dispatch submit event
    await app.dispatchDocument('submit', app.document.getElementById('sarif-preview-form'));

    // Check no POST requests
    const postRequests = app.requests.filter(r => r.options.method === 'POST');
    assert.strictEqual(postRequests.length, 0, 'Expected zero POST requests for invalid JSON');

    // Check fixed error message
    assert.ok(!errorEl.classList.contains('hidden'), 'Error should be visible');
    assert.strictEqual(errorEl.textContent, 'Geçersiz JSON.');
  });

  it('rejects oversized input (>64KB) with fixed error and no POST', async () => {
    const app = await loadSniperApp(appJsPath);

    const pasteInput = app.document.getElementById('sarif-paste');
    const errorEl = app.document.getElementById('sarif-preview-error');

    // Set oversized input
    pasteInput.value = makeOversizedInput();

    // Dispatch submit event
    await app.dispatchDocument('submit', app.document.getElementById('sarif-preview-form'));

    // Check no POST requests
    const postRequests = app.requests.filter(r => r.options.method === 'POST');
    assert.strictEqual(postRequests.length, 0, 'Expected zero POST requests for oversized input');

    // Check fixed error message
    assert.ok(!errorEl.classList.contains('hidden'), 'Error should be visible');
    assert.strictEqual(errorEl.textContent, 'Girdi çok büyük (maksimum 64 KB).');
  });

  it('rejects non-object SARIF (e.g., array) with fixed error and no POST', async () => {
    const app = await loadSniperApp(appJsPath);

    const pasteInput = app.document.getElementById('sarif-paste');
    const errorEl = app.document.getElementById('sarif-preview-error');

    // Set array instead of object
    pasteInput.value = '[1,2,3]';

    // Dispatch submit event
    await app.dispatchDocument('submit', app.document.getElementById('sarif-preview-form'));

    // Check no POST requests
    const postRequests = app.requests.filter(r => r.options.method === 'POST');
    assert.strictEqual(postRequests.length, 0, 'Expected zero POST requests for array input');

    // Check fixed error message
    assert.ok(!errorEl.classList.contains('hidden'), 'Error should be visible');
    assert.strictEqual(errorEl.textContent, 'Geçersiz SARIF yapısı.');
  });

  it('clears inputs and result when modal is closed', async () => {
    const validSarif = makeValidSarif();
    const app = await loadSniperApp(appJsPath, {
      format: 'sarif',
      run_count: 1,
      result_count: 1,
      tools: [{
        name: 'Semgrep',
        result_count: 1,
        levels: { error: 1, warning: 0, note: 0, none: 0 }
      }],
      report_sha256: 'a'.repeat(64)
    });

    const pasteInput = app.document.getElementById('sarif-paste');
    const fileInput = app.document.getElementById('sarif-file');
    const errorEl = app.document.getElementById('sarif-preview-error');
    const resultEl = app.document.getElementById('sarif-preview-result');

    // First: trigger valid submission to show summary
    pasteInput.value = JSON.stringify(validSarif);
    await app.dispatchDocument('submit', app.document.getElementById('sarif-preview-form'));
    assert.ok(!resultEl.classList.contains('hidden'), 'Result panel should be visible after valid submit');

    // Then: simulate invalid JSON submission to create visible error
    pasteInput.value = 'invalid json';
    await app.dispatchDocument('submit', app.document.getElementById('sarif-preview-form'));
    assert.ok(!errorEl.classList.contains('hidden'), 'Error should be visible after invalid submit');
    assert.ok(errorEl.textContent.length > 0, 'Error should contain text after invalid submit');

    // Finally: construct a self-consistent fake close target matching real product behavior
    const fakeCloseTarget = app.document.createElement('div');
    fakeCloseTarget.dataset.close = 'sarif-preview-modal';
    fakeCloseTarget.classList.add('some-class');
    fakeCloseTarget.closest = function(selector) {
      if (selector === '[data-close]') return this;
      return null;
    };

    // Dispatch delegated click on document (product uses document-level delegation)
    await app.dispatchDocument('click', fakeCloseTarget);

    // Verify inputs, result, and error are cleared
    assert.strictEqual(pasteInput.value, '', 'Paste input should be cleared after close');
    assert.strictEqual(fileInput.value, '', 'File input should be cleared after close');
    assert.strictEqual(errorEl.textContent, '', 'Error text should be cleared after close');
    assert.ok(errorEl.classList.contains('hidden'), 'Error should be hidden after close');
    assert.ok(resultEl.classList.contains('hidden'), 'Result panel should be hidden after close');
  });

  it('handles empty paste and file input with fixed error', async () => {
    const app = await loadSniperApp(appJsPath);

    const pasteInput = app.document.getElementById('sarif-paste');
    const fileInput = app.document.getElementById('sarif-file');
    const errorEl = app.document.getElementById('sarif-preview-error');

    // Clear inputs
    pasteInput.value = '';
    fileInput.value = '';

    // Dispatch submit event
    await app.dispatchDocument('submit', app.document.getElementById('sarif-preview-form'));

    // Check no POST requests
    const postRequests = app.requests.filter(r => r.options.method === 'POST');
    assert.strictEqual(postRequests.length, 0, 'Expected zero POST requests for empty input');

    // Check fixed error message
    assert.ok(!errorEl.classList.contains('hidden'), 'Error should be visible');
    assert.strictEqual(errorEl.textContent, 'Boş içerik gönderilemez.');
  });
});
