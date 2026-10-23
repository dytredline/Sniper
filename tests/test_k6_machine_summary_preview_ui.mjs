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
    version: '1.0.0',
    metadata: {generatedAt: '2025-01-15T10:30:45Z', k6Version: '1.5.0'},
    config: {execution: 'local', duration: 1, script: 'private-script.js'},
    results: {metrics: [
      {name: 'http_reqs', type: 'counter', contains: 'default', values: {count: 3}},
      {name: 'http_req_duration', type: 'trend', contains: 'time', values: {'p(95)': 22}},
    ]},
  };
}

describe('k6 saved machine-readable v1 summary preview', () => {
  it('posts only after submit and renders numeric aggregates, never private fields', async () => {
    const h = harness({format: 'k6-machine-summary-v1', http_requests: 3, duration_p95_ms: 22,
      threshold_counts: {passed: 0, failed: 0}, report_sha256: 'a'.repeat(64)});
    h.document.getElementById('k6-machine-summary-paste').value = JSON.stringify(validReport());
    await h.dispatch('submit', h.document.getElementById('k6-machine-summary-preview-form'));
    const posts = h.requests.filter(r => r.options.method === 'POST');
    assert.equal(posts.length, 1);
    assert.equal(posts[0].path, '/api/tool-reports/k6-machine-summary-v1/summary');
    assert.deepEqual(Object.keys(JSON.parse(posts[0].options.body)), ['report']);
    assert.equal(h.document.getElementById('k6-machine-summary-http-requests').textContent, '3');
    assert.equal(h.document.getElementById('k6-machine-summary-p95').textContent, '22');
    assert.equal(h.document.getElementById('k6-machine-summary-threshold-passed').textContent, '0 (veri yok)');
    assert.equal(h.document.getElementById('k6-machine-summary-threshold-failed').textContent, '0 (veri yok)');
    assert.equal(h.document.getElementById('k6-machine-summary-report-sha256').textContent, 'a'.repeat(64));
    assert.equal(h.document.getElementById('k6-machine-summary-paste').value, '');
  });

  it('rejects classic shape before POST', async () => {
    const h = harness(null);
    h.document.getElementById('k6-machine-summary-paste').value = JSON.stringify({
      root_group: {}, state: {}, metrics: {http_reqs: {type: 'counter', values: {count: 3}}},
    });
    await h.dispatch('submit', h.document.getElementById('k6-machine-summary-preview-form'));
    assert.equal(h.requests.filter(r => r.options.method === 'POST').length, 0);
    assert.equal(h.document.getElementById('k6-machine-summary-preview-error').classList.contains('hidden'), false);
  });

  it('rejects untrusted response without rendering it', async () => {
    const h = harness({format: 'k6-machine-summary-v1', http_requests: 'private URL', duration_p95_ms: 22,
      threshold_counts: {passed: 0, failed: 0}, report_sha256: 'a'.repeat(64)});
    h.document.getElementById('k6-machine-summary-paste').value = JSON.stringify(validReport());
    await h.dispatch('submit', h.document.getElementById('k6-machine-summary-preview-form'));
    assert.equal(h.document.getElementById('k6-machine-summary-preview-result').classList.contains('hidden'), true);
    assert.equal(h.document.getElementById('k6-machine-summary-http-requests').textContent, '');
  });

  it('exposes a separate card action and modal without starting a scan', async () => {
    const h = harness(null);
    const route = vm.runInContext('TOOL_CARD_DESTINATIONS["/api/tool-reports/k6-machine-summary-v1/summary"]', h.context);
    assert.equal(route.action, 'open-k6-machine-summary-preview');
    const modal = h.document.getElementById('k6-machine-summary-preview-modal');
    modal.classList.add('hidden');
    const button = h.node('k6-machine-card-button');
    button.dataset.action = 'open-k6-machine-summary-preview';
    button.closest = selector => selector === '[data-action]' ? button : null;
    await h.dispatch('click', button);
    assert.equal(modal.classList.contains('hidden'), false);
    assert.equal(h.requests.filter(r => r.options.method === 'POST').length, 0);
    const html = fs.readFileSync('static/index.html', 'utf8');
    assert.match(html, /id="k6-machine-summary-preview-modal"/);
    assert.match(html, /v1 şemasında eşik sonuçları yoktur/);
  });
});
