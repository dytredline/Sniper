import {describe, it} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

function harness(response) {
  const nodes = new Map();
  const listeners = new Map();
  const requests = [];
  function node(id) {
    if (nodes.has(id)) return nodes.get(id);
    const classes = new Set();
    const value = {
      id, dataset: {}, style: {}, value: '', files: [], textContent: '', innerHTML: '', disabled: false,
      classList: {
        add: name => classes.add(name), remove: name => classes.delete(name),
        contains: name => classes.has(name), toggle(name, force) {
          if (force === undefined ? !classes.has(name) : force) classes.add(name);
          else classes.delete(name);
        },
      },
      addEventListener() {}, append() {}, appendChild() {}, remove() {}, focus() {}, reset() {},
      setAttribute() {}, removeAttribute() {}, querySelector: key => node(key), querySelectorAll: () => [],
      closest() { return null; },
    };
    nodes.set(id, value);
    return value;
  }
  const document = {
    body: node('body'), getElementById: id => node(id),
    querySelector: key => node(key), querySelectorAll: () => [],
    createElement: key => node('created:' + key),
    addEventListener(name, callback) {
      const callbacks = listeners.get(name) || [];
      callbacks.push(callback);
      listeners.set(name, callbacks);
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
    return {ok: true, status: 200, json: async () => options.method === 'POST' ? response : (getResponses[path] || {})};
  }
  const context = vm.createContext({
    document, window: {addEventListener() {}}, location: {hash: ''},
    history: {replaceState() {}}, fetch, TextEncoder, URL, console,
    setTimeout: () => 0, clearTimeout() {}, setInterval: () => 0,
  });
  vm.runInContext(fs.readFileSync(process.env.SNIPER_UI_APP_JS || 'static/app.js', 'utf8'), context);
  async function dispatch(type, target) {
    for (const callback of listeners.get(type) || []) {
      await callback({target, preventDefault() {}, stopPropagation() {}});
    }
  }
  return {document, node, requests, dispatch, context};
}

function validReport() {
  return {
    root_group: {name: 'private check'}, state: {testRunDurationMs: 1000},
    metrics: {http_reqs: {type: 'counter', values: {count: 3}},
      http_req_duration: {type: 'trend', contains: 'time', values: {'p(95)': 22}}},
  };
}

describe('k6 saved classic summary preview', () => {
  it('posts one local report and renders numeric aggregates only', async () => {
    const h = harness({format: 'k6-handle-summary-json', http_requests: 3, duration_p95_ms: 22,
      threshold_counts: {passed: 2, failed: 1}, report_sha256: 'a'.repeat(64)});
    h.document.getElementById('k6-summary-paste').value = JSON.stringify(validReport());
    await h.dispatch('submit', h.document.getElementById('k6-summary-preview-form'));
    const posts = h.requests.filter(r => r.options.method === 'POST');
    assert.equal(posts.length, 1);
    assert.equal(posts[0].path, '/api/tool-reports/k6-summary-json/summary');
    assert.deepEqual(Object.keys(JSON.parse(posts[0].options.body)), ['report']);
    assert.equal(h.document.getElementById('k6-summary-http-requests').textContent, '3');
    assert.equal(h.document.getElementById('k6-summary-p95').textContent, '22');
    assert.equal(h.document.getElementById('k6-summary-threshold-passed').textContent, '2');
    assert.equal(h.document.getElementById('k6-summary-threshold-failed').textContent, '1');
    assert.equal(h.document.getElementById('k6-summary-report-sha256').textContent, 'a'.repeat(64));
    assert.equal(h.document.getElementById('k6-summary-paste').value, '');
  });

  it('rejects machine-readable schema before POST', async () => {
    const h = harness(null);
    h.document.getElementById('k6-summary-paste').value = JSON.stringify({
      ...validReport(), $schema: 'https://schemas.k6.io/summary/1.0.0/schema.json',
    });
    await h.dispatch('submit', h.document.getElementById('k6-summary-preview-form'));
    assert.equal(h.requests.filter(r => r.options.method === 'POST').length, 0);
    assert.equal(h.document.getElementById('k6-summary-preview-error').textContent,
      'Geçersiz veya desteklenmeyen klasik k6 JSON raporu.');
  });

  it('rejects untrusted response values without rendering them', async () => {
    const h = harness({format: 'k6-handle-summary-json', http_requests: 'private URL', duration_p95_ms: 22,
      threshold_counts: {passed: 2, failed: 1}, report_sha256: 'a'.repeat(64)});
    h.document.getElementById('k6-summary-paste').value = JSON.stringify(validReport());
    await h.dispatch('submit', h.document.getElementById('k6-summary-preview-form'));
    assert.equal(h.document.getElementById('k6-summary-preview-result').classList.contains('hidden'), true);
    assert.equal(h.document.getElementById('k6-summary-http-requests').textContent, '');
  });

  it('declares a card action for the report route', () => {
    const h = harness(null);
    const route = vm.runInContext('TOOL_CARD_DESTINATIONS["/api/tool-reports/k6-summary-json/summary"]', h.context);
    assert.equal(route.action, 'open-k6-summary-preview');
    assert.match(fs.readFileSync('static/index.html', 'utf8'), /id="k6-summary-preview-modal"/);
  });

  it('opens the preview modal from the tool card without submitting a report', async () => {
    const h = harness(null);
    const modal = h.document.getElementById('k6-summary-preview-modal');
    modal.classList.add('hidden');
    const button = h.node('k6-card-button');
    button.dataset.action = 'open-k6-summary-preview';
    button.closest = selector => selector === '[data-action]' ? button : null;
    await h.dispatch('click', button);
    assert.equal(modal.classList.contains('hidden'), false);
    assert.equal(h.requests.filter(r => r.options.method === 'POST').length, 0);
  });
});
