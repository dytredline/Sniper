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
      dispatchEvent(event) {
        const handlers = this.handlers?.get(String(event.type));
        if (!handlers) return false;
        for (const handler of handlers) handler(event);
        return true;
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

    if (isPost && /^\/api\/engagements\/[^/]+\/tool-evidence\/nuclei-jsonl$/.test(path)) {
      return {
        ok: true,
        status: 201,
        json: async () => ({
          tool_identity: 'nuclei-jsonl',
          record_count: 2,
          unique_template_count: 2,
          severity_counts: { info: 0, low: 0, medium: 1, high: 1, critical: 0, unknown: 0 },
          report_sha256: "a".repeat(64),
        }),
      };
    }

    if (path === '/api/engagements') {
      return {
        ok: true,
        status: 200,
        json: async () => ({
          engagements: [
            {
              id: 'eng-1',
              name: 'Test Engagement',
              status: 'active',
              authorization_ref: 'AUTH-123',
              special_approvals: { redacted_data_proof: true },
              tests: [
                { control_id: 'ctrl-1', title: 'Test Control' },
              ],
            },
          ],
        }),
      };
    }

    if (/^\/api\/engagements\/eng-1$/.test(path)) {
      return {
        ok: true,
        status: 200,
        json: async () => ({
          id: 'eng-1',
          name: 'Test Engagement',
          status: 'active',
          authorization_ref: 'AUTH-123',
          special_approvals: { redacted_data_proof: true },
          tests: [
            { control_id: 'ctrl-1', title: 'Test Control' },
          ],
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

// Positive: opt-in link flow with valid engagement/control selection
// Candidate app.js must POST to /api/engagements/{id}/tool-evidence/nuclei-jsonl with confirm_link:true
// and render link-success UI and aggregate counts.
test('nuclei-jsonl-link-ui: opt-in link flow with valid engagement/control', async () => {
  const { document, element, requests, documentListeners } = await loadApp();

  const openTarget = element('#open-nuclei-jsonl-preview');
  openTarget.dataset.action = 'open-nuclei-jsonl-preview';
  await dispatchDocument('click', openTarget, documentListeners);

  const linkOptIn = element('#nuclei-jsonl-link-opt-in');
  linkOptIn.checked = true;
  linkOptIn.dispatchEvent(new Event('change', { bubbles: true }));
  await new Promise(resolve => setImmediate(resolve));

  const linkEngagement = element('#nuclei-jsonl-link-engagement');
  linkEngagement.value = 'eng-1';
  linkEngagement.dispatchEvent(new Event('change', { bubbles: true }));
  await new Promise(resolve => setImmediate(resolve));

  const linkControl = element('#nuclei-jsonl-link-control');
  linkControl.value = 'ctrl-1';

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

  const linkPostRequests = requests.filter(r =>
    r.options?.method === 'POST' &&
    /^\/api\/engagements\/eng-1\/tool-evidence\/nuclei-jsonl$/.test(r.path)
  );
  assert.strictEqual(linkPostRequests.length, 1, 'Expected exactly one POST to engagement link endpoint');

  const linkBody = JSON.parse(linkPostRequests[0].options.body);
  assert.strictEqual(linkBody.confirm_link, true, 'confirm_link must be true');
  assert.strictEqual(linkBody.control_id, 'ctrl-1', 'control_id mismatch');
  assert.deepStrictEqual(linkBody.report, [JSON.parse(record1), JSON.parse(record2)], 'report mismatch');

  const linkResult = element('#nuclei-jsonl-link-result');
  assert.ok(!linkResult.classList.contains('hidden'), 'linkResult should be visible');
  assert.ok(linkResult.textContent.includes('Bağlantı'), 'linkResult should contain link success text');

  const recordCountEl = element('#nuclei-jsonl-record-count');
  const reportSha256El = element('#nuclei-jsonl-report-sha256');
  assert.strictEqual(String(recordCountEl.textContent), '2', 'record_count mismatch');
  assert.strictEqual(reportSha256El.textContent, 'a'.repeat(64), 'report_sha256 mismatch');
});

// Negative: opt-in checked but missing engagement or control selection must fail before POST
test('nuclei-jsonl-link-ui: opt-in without engagement/control selection blocks POST', async () => {
  const { document, element, requests, documentListeners } = await loadApp();

  const openTarget = element('#open-nuclei-jsonl-preview');
  openTarget.dataset.action = 'open-nuclei-jsonl-preview';
  await dispatchDocument('click', openTarget, documentListeners);

  const linkOptIn = element('#nuclei-jsonl-link-opt-in');
  linkOptIn.checked = true;
  linkOptIn.dispatchEvent(new Event('change', { bubbles: true }));
  await new Promise(resolve => setImmediate(resolve));

  const pasteInput = element('#nuclei-jsonl-paste');
  const form = element('#nuclei-jsonl-preview-form');

  const record = JSON.stringify({
    'template-id': 'test-template',
    type: 'http',
    info: { severity: 'high', name: 'Test' },
  });
  pasteInput.value = record;

  await dispatchDocument('submit', form, documentListeners);

  const linkPostRequests = requests.filter(r =>
    r.options?.method === 'POST' &&
    /^\/api\/engagements\/[^/]+\/tool-evidence\/nuclei-jsonl$/.test(r.path)
  );
  assert.strictEqual(linkPostRequests.length, 0, 'Expected zero link POSTs when engagement/control missing');

  const errorEl = element('#nuclei-jsonl-preview-error');
  assert.ok(!errorEl.classList.contains('hidden'), 'errorEl should be visible');
  assert.ok(errorEl.textContent.includes('denetimi'), 'errorEl should mention engagement/control');
});

// Negative: unchecked opt-in must POST only to summary endpoint, not link endpoint
test('nuclei-jsonl-link-ui: unchecked opt-in performs only passive summary POST', async () => {
  const { document, element, requests, documentListeners } = await loadApp();

  const openTarget = element('#open-nuclei-jsonl-preview');
  openTarget.dataset.action = 'open-nuclei-jsonl-preview';
  await dispatchDocument('click', openTarget, documentListeners);

  const linkOptIn = element('#nuclei-jsonl-link-opt-in');
  linkOptIn.checked = false;

  const pasteInput = element('#nuclei-jsonl-paste');
  const form = element('#nuclei-jsonl-preview-form');

  const record = JSON.stringify({
    'template-id': 'test-template',
    type: 'http',
    info: { severity: 'high', name: 'Test' },
  });
  pasteInput.value = record;

  await dispatchDocument('submit', form, documentListeners);

  const summaryPostRequests = requests.filter(r =>
    r.options?.method === 'POST' &&
    r.path === '/api/tool-reports/nuclei-jsonl/summary'
  );
  assert.strictEqual(summaryPostRequests.length, 1, 'Expected exactly one summary POST');

  const linkPostRequests = requests.filter(r =>
    r.options?.method === 'POST' &&
    /^\/api\/engagements\/[^/]+\/tool-evidence\/nuclei-jsonl$/.test(r.path)
  );
  assert.strictEqual(linkPostRequests.length, 0, 'Expected zero link POSTs when opt-in unchecked');
});

// Negative: missing engagement ID in opt-in mode must not leak any external identifiers
test('nuclei-jsonl-link-ui: opt-in with empty engagement ID blocks and does not leak', async () => {
  const { document, element, requests, documentListeners } = await loadApp();

  const openTarget = element('#open-nuclei-jsonl-preview');
  openTarget.dataset.action = 'open-nuclei-jsonl-preview';
  await dispatchDocument('click', openTarget, documentListeners);

  const linkOptIn = element('#nuclei-jsonl-link-opt-in');
  linkOptIn.checked = true;
  linkOptIn.dispatchEvent(new Event('change', { bubbles: true }));
  await new Promise(resolve => setImmediate(resolve));

  const linkEngagement = element('#nuclei-jsonl-link-engagement');
  linkEngagement.value = '';

  const pasteInput = element('#nuclei-jsonl-paste');
  const form = element('#nuclei-jsonl-preview-form');

  const record = JSON.stringify({
    'template-id': 'test-template',
    type: 'http',
    info: { severity: 'high', name: 'Test' },
  });
  pasteInput.value = record;

  await dispatchDocument('submit', form, documentListeners);

  const linkPostRequests = requests.filter(r =>
    r.options?.method === 'POST' &&
    /^\/api\/engagements\/[^/]+\/tool-evidence\/nuclei-jsonl$/.test(r.path)
  );
  assert.strictEqual(linkPostRequests.length, 0, 'Expected zero link POSTs when engagement ID empty');

  const errorEl = element('#nuclei-jsonl-preview-error');
  assert.ok(!errorEl.classList.contains('hidden'), 'errorEl should be visible');
  assert.ok(errorEl.textContent.includes('denetimi'), 'errorEl should mention engagement/control');
});
