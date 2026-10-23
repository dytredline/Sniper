import assert from 'node:assert/strict';
import { test } from 'node:test';
import fs from 'node:fs';
import vm from 'node:vm';

const appJs = new URL('../static/app.js', import.meta.url).pathname;
const indexHtml = new URL('../static/index.html', import.meta.url).pathname;

test('Nuclei HTTP UI exposes every control used by the runtime flow', () => {
  const html = fs.readFileSync(indexHtml, 'utf8');
  for (const id of [
    'nuclei-http-scan-modal', 'nuclei-http-scan-form', 'nuclei-http-target',
    'nuclei-http-engagement', 'nuclei-http-template-ids',
    'nuclei-http-include-excluded', 'nuclei-http-confirm-authorized',
    'nuclei-http-start', 'nuclei-http-cancel', 'nuclei-http-status',
    'nuclei-http-result', 'nuclei-http-record-count',
    'nuclei-http-unique-template-count', 'nuclei-http-severity-counts',
    'nuclei-http-report-sha256',
  ]) assert.match(html, new RegExp(`id=["']${id}["']`));
  assert.match(html, /data-action=["']open-nuclei-http-scan["']/);
});

function setup() {
  const elements = new Map();
  const listeners = new Map();
  const requests = [];
  const classes = () => {
    const values = new Set(['hidden']);
    return {
      add: key => values.add(key), remove: key => values.delete(key),
      contains: key => values.has(key),
      toggle(key, force) { if (force ?? !values.has(key)) values.add(key); else values.delete(key); },
    };
  };
  const element = key => {
    if (elements.has(key)) return elements.get(key);
    const node = {
      id: key.replace(/^#/, ''), dataset: {}, style: {}, value: '', files: [],
      innerHTML: '', textContent: '', disabled: false, checked: false,
      classList: classes(), handlers: new Map(),
      addEventListener(type, callback) {
        const callbacks = this.handlers.get(type) || [];
        callbacks.push(callback);
        this.handlers.set(type, callbacks);
      },
      append() {}, appendChild() {}, replaceChildren() {}, remove() {}, focus() {}, reset() {},
      setAttribute() {}, removeAttribute() {}, setSelectionRange() {},
      querySelector: selector => element(selector), querySelectorAll: () => [],
      closest: () => null,
    };
    elements.set(key, node);
    return node;
  };
  const document = {
    body: element('body'), querySelector: element, querySelectorAll: () => [],
    getElementById: id => element('#' + id), createElement: tag => element('created:' + tag),
    addEventListener(type, callback) {
      const callbacks = listeners.get(type) || [];
      callbacks.push(callback);
      listeners.set(type, callbacks);
    },
  };
  async function fetch(path, options = {}) {
    requests.push({ path, options });
    const responses = {
      '/api/dashboard': {},
      '/api/targets': { targets: [{ id: 'target-1', hostname: 'example.org', status: 'ready' }] },
      '/api/scans?limit=200': { scans: [] },
      '/api/engagements': { engagements: [{ id: 'eng-1', target_id: 'target-1', status: 'active', authorization_ref: 'approved', scope_notes: 'example.org' }] },
      '/api/lab-runs': { lab_runs: [] },
      '/api/project-audits': { project_audits: [], total: 0 },
      '/api/tooling': { tools: [], categories: [], summary: {}, policy: {} },
      '/api/dependency-security': {},
      '/api/nuclei/http-scans': { job_id: '0123456789abcdef', state: 'starting' },
      '/api/nuclei/http-scans/0123456789abcdef': {
        job_id: '0123456789abcdef', state: 'completed', record_count: 1,
        unique_template_count: 1, severity_counts: { high: 1 }, report_sha256: 'a'.repeat(64),
      },
    };
    return { ok: true, status: path === '/api/nuclei/http-scans' ? 202 : 200, json: async () => responses[path] || {} };
  }
  const context = vm.createContext({
    document, window: { addEventListener() {} }, location: { hash: '' },
    history: { replaceState() {} }, fetch, TextEncoder, URL, console,
    setTimeout: () => 0, clearTimeout() {}, setInterval: () => 0,
  });
  vm.runInContext(fs.readFileSync(appJs, 'utf8'), context, { filename: appJs });
  return { context, element, requests };
}

async function submit(form) {
  for (const handler of form.handlers.get('submit') || []) {
    await handler({ preventDefault() {}, target: form });
  }
  await new Promise(resolve => setImmediate(resolve));
}

test('authorized broad Nuclei UI submits no profile or template selector and renders aggregate', async () => {
  const { context, element, requests } = setup();
  await new Promise(resolve => setImmediate(resolve));
  vm.runInContext("openNucleiHttpScan('target-1')", context);
  element('#nuclei-http-target').value = 'target-1';
  element('#nuclei-http-engagement').value = 'eng-1';
  element('#nuclei-http-confirm-authorized').checked = true;
  await submit(element('#nuclei-http-scan-form'));
  const posts = requests.filter(item => item.path === '/api/nuclei/http-scans' && item.options.method === 'POST');
  assert.equal(posts.length, 1);
  assert.deepEqual(JSON.parse(posts[0].options.body), {
    target_id: 'target-1', engagement_id: 'eng-1', confirm_authorized: true, include_excluded: false,
  });
  // Simulate running status via correct single-object call
  vm.runInContext("nucleiHttpRenderStatus({ job_id: '0123456789abcdef', state: 'running', elapsed_seconds: 42.7 })", context);
  assert.equal(element('#nuclei-http-status').textContent, 'Nuclei taraması çalışıyor…');
  assert.equal(element('#nuclei-http-cancel').disabled, false);
  // Required elapsed assertions
  assert.equal(element('#nuclei-http-elapsed').textContent, 'Geçen süre: 42s');
  assert.equal(element('#nuclei-http-elapsed').classList.contains('hidden'), false);
  // Simulate completed status via correct single-object call
  vm.runInContext("nucleiHttpRenderStatus({ job_id: '0123456789abcdef', state: 'completed', record_count: 1, unique_template_count: 1, severity_counts: { high: 1 }, report_sha256: 'a'.repeat(64) })", context);
  assert.equal(element('#nuclei-http-record-count').textContent, '1');
  assert.equal(element('#nuclei-http-report-sha256').textContent, 'a'.repeat(64));
  assert.equal(element('#nuclei-http-result').classList.contains('hidden'), false);
  assert.equal(element('#nuclei-http-cancel').disabled, true);
  // Required elapsed-hidden assertion after completion
  assert.equal(element('#nuclei-http-elapsed').classList.contains('hidden'), true);
});

test('Nuclei UI requires explicit consent and passes only exact requested IDs', async () => {
  const { context, element, requests } = setup();
  await new Promise(resolve => setImmediate(resolve));
  vm.runInContext("openNucleiHttpScan('target-1')", context);
  element('#nuclei-http-target').value = 'target-1';
  element('#nuclei-http-engagement').value = 'eng-1';
  await submit(element('#nuclei-http-scan-form'));
  assert.equal(requests.filter(item => item.path === '/api/nuclei/http-scans' && item.options.method === 'POST').length, 0);
  element('#nuclei-http-confirm-authorized').checked = true;
  element('#nuclei-http-template-ids').value = '1001mem, test-id';
  element('#nuclei-http-include-excluded').checked = true;
  await submit(element('#nuclei-http-scan-form'));
  const posts = requests.filter(item => item.path === '/api/nuclei/http-scans' && item.options.method === 'POST');
  assert.equal(posts.length, 1);
  assert.deepEqual(JSON.parse(posts[0].options.body).template_ids, ['1001mem', 'test-id']);
  assert.equal(JSON.parse(posts[0].options.body).include_excluded, true);
});
