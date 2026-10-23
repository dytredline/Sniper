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
      checked: false,
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
      matches(selector) {
        if (selector === '[data-dependency-status]') return this.dataset.dependencyStatus !== undefined;
        return false;
      },
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
    '/api/engagements': { engagements: overrides.engagements || [] },
    '/api/lab-runs': { lab_runs: [] },
    '/api/project-audits': { project_audits: [], total: 0 },
    '/api/tooling': { tools: [], categories: [], summary: {}, policy: { native: '', external: '', completion: '' } },
    '/api/dependency-security': {},
  };

  async function fetch(path, options = {}) {
    requests.push({ path, options });
    const isPost = options.method === 'POST';
    if (!isPost && path.startsWith('/api/engagements/')) {
      return {
        ok: true,
        status: 200,
        json: async () => overrides.engagementDetail || {},
      };
    }
    if (isPost && path.endsWith('/tool-evidence/burp-sitemap-xml')) {
      const body = JSON.parse(options.body);
      if (!overrides.acceptEvidenceLink || body.confirm_link !== true || !body.control_id || typeof body.report !== 'string') {
        return { ok: false, status: 400, json: async () => ({ error: 'invalid evidence request' }) };
      }
      return {
        ok: true,
        status: 201,
        json: async () => ({
          id: 'tev-1',
          engagement_id: 'eng-1',
          control_id: body.control_id,
          tool_identity: 'burp-sitemap-xml',
          report_sha256: 'b'.repeat(64),
          item_count: 2,
          status_counts: { '200': 1, '301': 1 },
          mimetype_counts: { HTML: 1, JSON: 0, XML: 1, OTHER: 0, UNKNOWN: 0 },
          created_at: '2026-10-12T16:00:00Z',
        }),
      };
    }
    if (isPost && path === '/api/tool-reports/burp-sitemap/summary') {
      const body = JSON.parse(options.body);
      const xml = body.report;
      if (typeof xml !== 'string') {
        return {
          ok: true,
          status: 400,
          json: async () => ({ error: 'report bir metin olmalı' }),
        };
      }
      const encoder = new TextEncoder();
      if (encoder.encode(xml).length > 60000) {
        return {
          ok: true,
          status: 400,
          json: async () => ({ error: 'Girdi çok büyük (maksimum 60 KB).' }),
        };
      }
      if (xml.includes('<!ENTITY') || xml.includes('<!DOCTYPE') || xml.includes('SYSTEM')) {
        return {
          ok: true,
          status: 400,
          json: async () => ({ error: 'Geçersiz istek.' }),
        };
      }
      if (!xml.trim().startsWith('<items')) {
        return {
          ok: true,
          status: 400,
          json: async () => ({ error: 'Geçersiz istek.' }),
        };
      }
      const itemCount = 2;
      return {
        ok: true,
        status: 200,
        json: async () => ({
          format: 'burp-sitemap-xml',
          item_count: itemCount,
          status_counts: { '200': 1, '301': 1 },
          mimetype_counts: { HTML: 1, JSON: 0, XML: 1, OTHER: 0, UNKNOWN: 0 },
          report_sha256: 'a'.repeat(64),
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

async function showModal(id, show) {
  const el = document.getElementById(id);
  if (el) {
    if (show) el.classList.remove('hidden');
    else el.classList.add('hidden');
  }
}

async function loadApp(overrides = {}) {
  const { context, document, element, requests, documentListeners } = createFakeDOM(overrides);
  const appCode = fs.readFileSync(appJsPath, 'utf8');
  vm.runInContext(appCode, context, { filename: appJsPath });
  await new Promise(resolve => setImmediate(resolve));
  return { document, element, requests, documentListeners };
}

test('burp-xml-preview-ui: positive flow with valid XML', async () => {
  const { document, element, requests, documentListeners } = await loadApp();

  const openTarget = element('#open-burp-xml-preview');
  openTarget.dataset.action = 'open-burp-xml-preview';
  await dispatchDocument('click', openTarget, documentListeners);

  const pasteInput = element('#burp-xml-paste');
  const form = element('#burp-xml-preview-form');

  const xml = '<items><item><status>200</status><mimetype>text/html</mimetype></item><item><status>301</status><mimetype>text/xml</mimetype></item></items>';
  pasteInput.value = xml;

  await dispatchDocument('submit', form, documentListeners);

  const postRequests = requests.filter(r => r.options?.method === 'POST' && r.path === '/api/tool-reports/burp-sitemap/summary');
  assert.strictEqual(postRequests.length, 1, 'Expected exactly one POST to /api/tool-reports/burp-sitemap/summary');

  const body = JSON.parse(postRequests[0].options.body);
  assert.deepStrictEqual(body, { report: xml }, 'POST body mismatch');

  const formatEl = element('#burp-xml-format');
  const itemCountEl = element('#burp-xml-item-count');
  const statusCountsEl = element('#burp-xml-status-counts');
  const mimetypeCountsEl = element('#burp-xml-mimetype-counts');
  const reportSha256El = element('#burp-xml-report-sha256');

  assert.strictEqual(String(formatEl.textContent), 'burp-sitemap-xml', 'format mismatch');
  assert.strictEqual(String(itemCountEl.textContent), '2', 'item_count mismatch');
  assert.strictEqual(String(statusCountsEl.textContent), '200:1 301:1', 'status_counts mismatch');
  assert.strictEqual(String(mimetypeCountsEl.textContent), 'HTML:1 JSON:0 XML:1 OTHER:0 UNKNOWN:0', 'mimetype_counts mismatch');
  assert.strictEqual(String(reportSha256El.textContent), 'a'.repeat(64), 'report_sha256 mismatch');

  const resultEl = element('#burp-xml-preview-result');
  assert.ok(!resultEl.classList.contains('hidden'), 'resultEl should be visible');

  assert.strictEqual(pasteInput.value, '', 'pasteInput should be cleared after success');
});

test('burp-xml-preview-ui: empty paste with no file selection blocks POST and shows generic error', async () => {
  const { document, element, requests, documentListeners } = await loadApp();

  const openTarget = element('#open-burp-xml-preview');
  openTarget.dataset.action = 'open-burp-xml-preview';
  await dispatchDocument('click', openTarget, documentListeners);

  const pasteInput = element('#burp-xml-paste');
  pasteInput.value = '';

  const fileInput = element('#burp-xml-file');
  // Fake DOM initializes fileInput.files to [] (empty FileList); do not set to null
  // to avoid breaking product code that accesses fileInput.files[0]

  const form = element('#burp-xml-preview-form');
  await dispatchDocument('submit', form, documentListeners);

  const postRequests = requests.filter(r => r.options?.method === 'POST' && r.path === '/api/tool-reports/burp-sitemap/summary');
  assert.strictEqual(postRequests.length, 0, 'Expected zero POSTs for empty paste with no file');

  const errorEl = element('#burp-xml-preview-error');
  assert.ok(!errorEl.classList.contains('hidden'), 'errorEl should be visible');
  assert.ok(errorEl.textContent.length > 0, 'errorEl should have text');

  const resultEl = element('#burp-xml-preview-result');
  assert.ok(resultEl.classList.contains('hidden'), 'resultEl should be hidden');
});

test('burp-xml-preview-ui: oversize XML blocks POST and does not clear input', async () => {
  const { document, element, requests, documentListeners } = await loadApp();

  const openTarget = element('#open-burp-xml-preview');
  openTarget.dataset.action = 'open-burp-xml-preview';
  await dispatchDocument('click', openTarget, documentListeners);

  const pasteInput = element('#burp-xml-paste');
  const form = element('#burp-xml-preview-form');

  const largeXml = '<items>' + '<item><status>200</status><mimetype>text/html</mimetype></item>'.repeat(10000) + '</items>';
  pasteInput.value = largeXml;

  await dispatchDocument('submit', form, documentListeners);

  const postRequests = requests.filter(r => r.options?.method === 'POST' && r.path === '/api/tool-reports/burp-sitemap/summary');
  assert.strictEqual(postRequests.length, 0, 'Expected zero POSTs for oversize XML');

  const errorEl = element('#burp-xml-preview-error');
  assert.ok(!errorEl.classList.contains('hidden'), 'errorEl should be visible');
  assert.ok(errorEl.textContent.length > 0, 'errorEl should have text');

  const resultEl = element('#burp-xml-preview-result');
  assert.ok(resultEl.classList.contains('hidden'), 'resultEl should be hidden');

  assert.strictEqual(pasteInput.value, largeXml, 'pasteInput should NOT be cleared on size rejection');
});

test('burp-xml-preview-ui: close modal clears inputs and results', async () => {
  const { document, element, requests, documentListeners } = await loadApp();

  const openTarget = element('#open-burp-xml-preview');
  openTarget.dataset.action = 'open-burp-xml-preview';
  await dispatchDocument('click', openTarget, documentListeners);

  const pasteInput = element('#burp-xml-paste');
  const fileInput = element('#burp-xml-file');
  pasteInput.value = 'test';
  fileInput.value = 'file.xml';

  const closeTarget = element('#burp-xml-preview-modal');
  closeTarget.dataset.close = 'burp-xml-preview-modal';
  await dispatchDocument('click', closeTarget, documentListeners);

  assert.strictEqual(pasteInput.value, '', 'pasteInput should be cleared');
  assert.strictEqual(fileInput.value, '', 'fileInput should be cleared');

  const errorEl = element('#burp-xml-preview-error');
  const resultEl = element('#burp-xml-preview-result');
  assert.ok(errorEl.classList.contains('hidden'), 'errorEl should be hidden');
  assert.ok(resultEl.classList.contains('hidden'), 'resultEl should be hidden');

  assert.strictEqual(element('#burp-xml-format').textContent, '', 'format should be cleared');
  assert.strictEqual(element('#burp-xml-item-count').textContent, '', 'item_count should be cleared');
  assert.strictEqual(element('#burp-xml-status-counts').textContent, '', 'status_counts should be cleared');
  assert.strictEqual(element('#burp-xml-mimetype-counts').textContent, '', 'mimetype_counts should be cleared');
  assert.strictEqual(element('#burp-xml-report-sha256').textContent, '', 'report_sha256 should be cleared');
});

test('burp-xml-preview-ui: explicit opt-in links only aggregate evidence to an eligible manual test', async () => {
  const eligible = {
    id: 'eng-1',
    name: 'Authorized assessment',
    authorization_ref: 'AUTH-2026-01',
    scope_notes: 'Approved staging scope',
    status: 'active',
    special_approvals: { redacted_data_proof: true },
  };
  const ineligible = {
    id: 'eng-2',
    name: 'No redacted evidence approval',
    authorization_ref: 'AUTH-2026-02',
    scope_notes: 'Approved scope',
    status: 'active',
    special_approvals: { redacted_data_proof: false },
  };
  const { element, requests, documentListeners } = await loadApp({
    engagements: [eligible, ineligible],
    engagementDetail: {
      id: 'eng-1',
      tests: [{ control_id: 'WEB-001', title: 'Security headers', status: 'not_tested' }],
    },
    acceptEvidenceLink: true,
  });

  const openTarget = element('#open-burp-xml-preview');
  openTarget.dataset.action = 'open-burp-xml-preview';
  await dispatchDocument('click', openTarget, documentListeners);

  const engagementSelect = element('#burp-xml-link-engagement');
  assert.match(engagementSelect.innerHTML, /eng-1/);
  assert.doesNotMatch(engagementSelect.innerHTML, /eng-2/);

  const optIn = element('#burp-xml-link-opt-in');
  optIn.checked = true;
  await dispatchDocument('change', optIn, documentListeners);
  assert.ok(!element('#burp-xml-link-fields').classList.contains('hidden'));

  engagementSelect.value = 'eng-1';
  await dispatchDocument('change', engagementSelect, documentListeners);
  assert.ok(requests.some(r => r.path === '/api/engagements/eng-1' && !r.options?.method));
  const controlSelect = element('#burp-xml-link-control');
  assert.match(controlSelect.innerHTML, /WEB-001/);
  controlSelect.value = 'WEB-001';

  const xml = '<items><item><status>200</status><mimetype>text/html</mimetype></item><item><status>301</status><mimetype>text/xml</mimetype></item></items>';
  element('#burp-xml-paste').value = xml;
  await dispatchDocument('submit', element('#burp-xml-preview-form'), documentListeners);

  const linkRequest = requests.find(r => r.options?.method === 'POST' && r.path === '/api/engagements/eng-1/tool-evidence/burp-sitemap-xml');
  assert.ok(linkRequest, 'Expected the explicit evidence-link route');
  assert.deepStrictEqual(JSON.parse(linkRequest.options.body), {
    control_id: 'WEB-001',
    report: xml,
    confirm_link: true,
  });
  assert.equal(requests.filter(r => r.options?.method === 'POST' && r.path === '/api/tool-reports/burp-sitemap/summary').length, 0);
  assert.equal(element('#burp-xml-report-sha256').textContent, 'b'.repeat(64));
  assert.match(element('#burp-xml-link-result').textContent, /WEB-001/);
  assert.match(element('#burp-xml-link-result').textContent, /kaynak XML saklanmaz/);
  assert.equal(element('#burp-xml-paste').value, '');
});

test('burp-xml-preview-ui: checked evidence linking without selected engagement and test blocks submission', async () => {
  const eligible = {
    id: 'eng-1',
    name: 'Authorized assessment',
    authorization_ref: 'AUTH-2026-01',
    scope_notes: 'Approved staging scope',
    status: 'active',
    special_approvals: { redacted_data_proof: true },
  };
  const { element, requests, documentListeners } = await loadApp({
    engagements: [eligible],
    engagementDetail: {
      id: 'eng-1',
      tests: [{ control_id: 'WEB-001', title: 'Security headers', status: 'not_tested' }],
    },
  });
  const openTarget = element('#open-burp-xml-preview');
  openTarget.dataset.action = 'open-burp-xml-preview';
  await dispatchDocument('click', openTarget, documentListeners);

  const optIn = element('#burp-xml-link-opt-in');
  optIn.checked = true;
  await dispatchDocument('change', optIn, documentListeners);
  element('#burp-xml-paste').value = '<items><item><status>200</status><mimetype>text/html</mimetype></item></items>';
  await dispatchDocument('submit', element('#burp-xml-preview-form'), documentListeners);

  assert.equal(requests.filter(r => r.options?.method === 'POST').length, 0);
  assert.match(element('#burp-xml-preview-error').textContent, /denetimi ve test adımını seçin/);
});

