import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const appJsPath = process.env.SNIPER_UI_APP_JS || new URL('../static/app.js', import.meta.url).pathname;

export async function loadSniperApp(reportResponse = null) {
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
        if (this.id === 'trufflehog-preview-modal' && selector === '[data-action]') return null;
        if (this.id === 'trufflehog-preview-modal' && selector === '[data-close]') return null;
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
    '/api/targets': {targets: []},
    '/api/scans?limit=200': {scans: []},
    '/api/engagements': {engagements: []},
    '/api/lab-runs': {lab_runs: []},
    '/api/project-audits': {project_audits: [], total: 0},
    '/api/tooling': {tools: [], categories: [], summary: {}, policy: {native: '', external: '', completion: ''}},
    '/api/dependency-security': {},
  };

  async function fetch(path, options = {}) {
    requests.push({path, options});
    const isPost = options.method === 'POST';
    const body = isPost ? (reportResponse || {
      format: 'trufflehog-native-json-records',
      total_findings: 2,
      verified_findings: 1,
      unverified_findings: 1,
      detectors_triggered: 2
    }) : (getResponses[path] || {});
    return {ok: true, status: 200, json: async () => body};
  }

  const context = vm.createContext({
    document,
    window: {addEventListener() {}},
    location: {hash: ''},
    history: {replaceState() {}},
    fetch,
    TextEncoder,
    URL,
    console,
    setTimeout: () => 0,
    clearTimeout() {},
    setInterval: () => 0,
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

async function runTest() {
  const app = await loadSniperApp();
  const {document, dispatchDocument, requests} = app;

  // Create DOM elements
  const modal = document.getElementById('trufflehog-preview-modal');
  const form = document.getElementById('trufflehog-preview-form');
  const pasteInput = document.getElementById('trufflehog-paste');
  const fileInput = document.getElementById('trufflehog-file');
  const errorEl = document.getElementById('trufflehog-preview-error');
  const resultEl = document.getElementById('trufflehog-preview-result');
  const openBtn = {
    dataset: { action: 'open-trufflehog-preview' },
    classList: { contains: () => false },
    closest: (selector) => selector === '[data-action]' ? openBtn : null
  };
  const closeBtn = {
    dataset: { close: 'trufflehog-preview-modal' },
    classList: { contains: () => false },
    closest: (selector) => selector === '[data-close]' ? closeBtn : null
  };

  // Initial state checks
  assert.ok(modal);
  assert.ok(form);
  assert.ok(pasteInput);
  assert.ok(fileInput);
  assert.ok(errorEl);
  assert.ok(resultEl);
  assert.ok(openBtn);
  assert.ok(closeBtn);

  // Open modal
  await dispatchDocument('click', openBtn);
  assert.ok(!modal.classList.contains('hidden'), 'Modal should be visible after open click');
  assert.equal(String(document.body.style.overflow), 'hidden', 'Body overflow should be hidden');

  // Submit with valid JSONL
  const validJsonl = JSON.stringify({DetectorName: 'AWS', Verified: true}) + '\n' +
                     JSON.stringify({DetectorName: 'GitHub Token', Verified: false});
  pasteInput.value = validJsonl;
  await dispatchDocument('submit', form);

  // Filter POST requests
  const postRequests = () => requests.filter(r => r.options.method === 'POST');
  assert.equal(postRequests().length, 1, 'Should have exactly one POST request');
  const req = postRequests()[0];
  assert.equal(req.path, '/api/tool-reports/trufflehog/summary');
  assert.equal(req.options.method, 'POST');
  const body = JSON.parse(req.options.body);
  assert.deepEqual(body, {report: [
    {DetectorName: 'AWS', Verified: true},
    {DetectorName: 'GitHub Token', Verified: false}
  ]});

  // Verify result display
  assert.equal(String(document.getElementById('trufflehog-format').textContent), 'trufflehog-native-json-records');
  assert.equal(String(document.getElementById('trufflehog-total').textContent), '2');
  assert.equal(String(document.getElementById('trufflehog-verified').textContent), '1');
  assert.equal(String(document.getElementById('trufflehog-unverified').textContent), '1');
  assert.equal(String(document.getElementById('trufflehog-detectors').textContent), '2');
  assert.ok(!resultEl.classList.contains('hidden'), 'Result should be visible');

  // Submit with malformed JSON
  pasteInput.value = 'not json';
  await dispatchDocument('submit', form);
  assert.equal(postRequests().length, 1, 'Should not add more POSTs on malformed JSON');
  assert.ok(!errorEl.classList.contains('hidden'), 'Error should be shown');

  // Submit with Verified non-boolean
  pasteInput.value = JSON.stringify({DetectorName: 'Test', Verified: 'true'});
  await dispatchDocument('submit', form);
  assert.equal(postRequests().length, 1, 'Should not add more POSTs on invalid Verified');

  // Submit with >500 records
  const manyRecords = Array.from({length: 501}, (_, i) => JSON.stringify({DetectorName: 'Test' + i, Verified: true})).join('\n');
  pasteInput.value = manyRecords;
  await dispatchDocument('submit', form);
  assert.equal(postRequests().length, 1, 'Should not add more POSTs on >500 records');

  // Close modal
  await dispatchDocument('click', closeBtn);
  assert.ok(modal.classList.contains('hidden'), 'Modal should be hidden after close');
  assert.equal(String(document.body.style.overflow), '', 'Body overflow should be reset');

  // Verify clear
  assert.equal(pasteInput.value, '', 'Paste input should be cleared');
  assert.equal(fileInput.value, '', 'File input should be cleared');
  assert.ok(errorEl.classList.contains('hidden'), 'Error should be hidden');
  assert.ok(resultEl.classList.contains('hidden'), 'Result should be hidden');

  // Clear modal again to test clearTrufflehogModal
  await dispatchDocument('click', modal);
  assert.ok(modal.classList.contains('hidden'), 'Modal should be hidden after click on backdrop');

  // Final assertions
  assert.equal(postRequests().length, 1, 'Total POST requests should be exactly 1');
}

await runTest();
process.exit(0);
