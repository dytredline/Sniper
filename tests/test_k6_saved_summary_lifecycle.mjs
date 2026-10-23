import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { test } from 'node:test';

const APP = process.env.SNIPER_APP_JS || process.env.SNIPER_UI_APP_JS || new URL('../static/app.js', import.meta.url).pathname;

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function tick() {
  return new Promise(resolve => setImmediate(resolve));
}

function harness() {
  const nodes = new Map();
  const listeners = new Map();
  const posts = [];
  const pending = [];

  function node(key) {
    if (nodes.has(key)) return nodes.get(key);
    const classes = new Set();
    const n = {
      id: String(key).replace(/^#/, ''),
      dataset: {},
      style: {},
      value: '',
      files: [],
      textContent: '',
      innerHTML: '',
      checked: false,
      disabled: false,
      classList: {
        add: x => classes.add(x),
        remove: x => classes.delete(x),
        contains: x => classes.has(x),
        toggle(x, yes) {
          if (yes === undefined ? !classes.has(x) : yes) classes.add(x);
          else classes.delete(x);
        },
      },
      addEventListener() {},
      append() {},
      appendChild() {},
      remove() {},
      focus() {},
      reset() {},
      setAttribute() {},
      removeAttribute() {},
      hasAttribute() { return false; },
      getClientRects() { return [1]; },
      querySelector: selector => node(selector),
      querySelectorAll: () => [],
      matches() { return false; },
      closest(selector) {
        if (selector === '[data-action]' && this.dataset.action) return this;
        if (selector === '[data-close]' && this.dataset.close) return this;
        return null;
      },
    };
    nodes.set(key, n);
    return n;
  }

  const document = {
    body: node('body'),
    activeElement: node('body'),
    getElementById: id => node('#' + id),
    querySelector: s => node(s),
    querySelectorAll: () => [],
    createElement: t => node('created:' + t),
    addEventListener(type, cb) {
      const arr = listeners.get(type) || [];
      arr.push(cb);
      listeners.set(type, arr);
    },
  };

  const defaults = {
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
    if (options.method === 'POST') {
      posts.push({ path, body: JSON.parse(options.body) });
      const d = deferred();
      pending.push(d);
      return d.promise.then(
        body => ({ ok: true, status: 200, json: async () => body }),
        err => ({ ok: false, status: err?.status || 500, json: async () => ({ error: err?.message || 'Sunucu hatası.' }) })
      );
    }
    return { ok: true, status: 200, json: async () => defaults[path] || {} };
  }

  const ctx = vm.createContext({
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

  vm.runInContext(fs.readFileSync(APP, 'utf8'), ctx, { filename: APP });

  async function dispatch(type, target, wait = true, extra = {}) {
    let defaultPrevented = false;
    const event = {
      target,
      currentTarget: target,
      ...extra,
      get defaultPrevented() { return defaultPrevented; },
      preventDefault() { defaultPrevented = true; },
      stopPropagation() {},
      stopImmediatePropagation() {},
    };
    const calls = (listeners.get(type) || []).map(cb => cb(event));
    if (wait) await Promise.all(calls);
    return Promise.all(calls);
  }

  function action(value) {
    const n = node('action:' + value);
    n.dataset.action = value;
    return n;
  }

  function close(value) {
    const n = node('close:' + value);
    n.dataset.close = value;
    return n;
  }

  return { node, posts, pending, dispatch, action, close, ready: tick };
}

const cases = [
  {
    name: 'classic',
    prefix: 'k6-summary',
    modal: 'k6-summary-preview-modal',
    openAction: 'open-k6-summary-preview',
    endpoint: '/api/tool-reports/k6-summary-json/summary',
    report: n => ({
      root_group: { name: 'private' },
      state: { testRunDurationMs: 1000 },
      metrics: { http_reqs: { type: 'counter', values: { count: n } } },
    }),
    summary: (n, ch) => ({
      format: 'k6-handle-summary-json',
      http_requests: n,
      duration_p95_ms: null,
      threshold_counts: { passed: 0, failed: 0 },
      report_sha256: ch.repeat(64),
    }),
  },
  {
    name: 'machine-v1',
    prefix: 'k6-machine-summary',
    modal: 'k6-machine-summary-preview-modal',
    openAction: 'open-k6-machine-summary-preview',
    endpoint: '/api/tool-reports/k6-machine-summary-v1/summary',
    report: n => ({
      version: '1.0.0',
      metadata: { generatedAt: '2025-01-15T10:30:45Z', k6Version: '1.5.0' },
      config: { execution: 'local', duration: 1 },
      results: { metrics: [{ name: 'http_reqs', type: 'counter', contains: 'default', values: { count: n } }] },
    }),
    summary: (n, ch) => ({
      format: 'k6-machine-summary-v1',
      http_requests: n,
      duration_p95_ms: null,
      threshold_counts: { passed: 0, failed: 0 },
      report_sha256: ch.repeat(64),
    }),
  },
];

for (const c of cases) {
  test(c.name + ' normal saved preview control posts once and renders aggregate', async () => {
    const h = harness();
    await h.ready();
    const modal = h.node('#' + c.modal);
    const result = h.node('#' + c.prefix + '-preview-result');
    modal.classList.remove('hidden');
    result.classList.add('hidden');
    h.node('#' + c.prefix + '-paste').value = JSON.stringify(c.report(3));
    const request = h.dispatch('submit', h.node('#' + c.prefix + '-preview-form'), false);
    await tick();
    assert.equal(h.posts.length, 1);
    assert.equal(h.posts[0].path, c.endpoint);
    h.pending.shift().resolve(c.summary(3, 'a'));
    await request;
    assert.equal(result.classList.contains('hidden'), false);
    assert.equal(h.node('#' + c.prefix + '-http-requests').textContent, '3');
    assert.equal(h.node('#' + c.prefix + '-report-sha256').textContent, 'a'.repeat(64));
  });

  test(c.name + ' closed modal (backdrop, close button, Escape, reopen) rejects late aggregate/error and keeps cleared DOM', async () => {
    const h = harness();
    await h.ready();
    const modal = h.node('#' + c.modal);
    const result = h.node('#' + c.prefix + '-preview-result');
    const error = h.node('#' + c.prefix + '-preview-error');

    // 1. Backdrop click while summary POST is in flight
    await h.dispatch('click', h.action(c.openAction));
    h.node('#' + c.prefix + '-paste').value = JSON.stringify(c.report(4));
    const req1 = h.dispatch('submit', h.node('#' + c.prefix + '-preview-form'), false);
    await tick();
    assert.equal(h.posts.length, 1);
    await h.dispatch('click', modal);
    assert.equal(modal.classList.contains('hidden'), true);
    h.pending.shift().resolve(c.summary(4, 'b'));
    await req1;
    assert.equal(result.classList.contains('hidden'), true);
    assert.equal(h.node('#' + c.prefix + '-http-requests').textContent, '');
    assert.equal(h.node('#' + c.prefix + '-paste').value, '');

    // 2. Escape key while error response is in flight, followed by reopen
    await h.dispatch('click', h.action(c.openAction));
    h.node('#' + c.prefix + '-paste').value = JSON.stringify(c.report(6));
    const req2 = h.dispatch('submit', h.node('#' + c.prefix + '-preview-form'), false);
    await tick();
    assert.equal(h.posts.length, 2);
    await h.dispatch('keydown', h.node('body'), true, { key: 'Escape' });
    assert.equal(modal.classList.contains('hidden'), true);
    assert.equal(h.node('#' + c.prefix + '-paste').value, '');
    await h.dispatch('click', h.action(c.openAction));
    h.pending.shift().reject(new Error('network failure'));
    await req2;
    assert.equal(error.classList.contains('hidden'), true);
    assert.equal(error.textContent, '');
    assert.equal(result.classList.contains('hidden'), true);
  });

  test(c.name + ' older A may not overwrite newer B or no-event input edit or slow file.text()', async () => {
    const h = harness();
    await h.ready();
    const modal = h.node('#' + c.modal);
    const result = h.node('#' + c.prefix + '-preview-result');
    const error = h.node('#' + c.prefix + '-preview-error');
    modal.classList.remove('hidden');
    result.classList.add('hidden');

    // 1. A then B race (both success and error)
    h.node('#' + c.prefix + '-paste').value = JSON.stringify(c.report(4));
    const requestA = h.dispatch('submit', h.node('#' + c.prefix + '-preview-form'), false);
    await tick();
    h.node('#' + c.prefix + '-paste').value = JSON.stringify(c.report(5));
    const requestB = h.dispatch('submit', h.node('#' + c.prefix + '-preview-form'), false);
    await tick();
    assert.equal(h.posts.length, 2);
    const [pendingA, pendingB] = h.pending.splice(0, 2);
    pendingB.resolve(c.summary(5, 'c'));
    await requestB;
    pendingA.resolve(c.summary(4, 'b'));
    await requestA;
    assert.equal(result.classList.contains('hidden'), false);
    assert.equal(h.node('#' + c.prefix + '-http-requests').textContent, '5');
    assert.equal(h.node('#' + c.prefix + '-report-sha256').textContent, 'c'.repeat(64));

    // 2. No-event input value edit while request is in flight
    h.node('#' + c.prefix + '-paste').value = JSON.stringify(c.report(7));
    const requestC = h.dispatch('submit', h.node('#' + c.prefix + '-preview-form'), false);
    await tick();
    assert.equal(h.posts.length, 3);
    h.node('#' + c.prefix + '-paste').value = JSON.stringify(c.report(8));
    h.pending.shift().resolve(c.summary(7, 'd'));
    await requestC;
    assert.equal(result.classList.contains('hidden'), true);
    assert.equal(h.node('#' + c.prefix + '-http-requests').textContent, '');
    assert.equal(h.node('#' + c.prefix + '-paste').value, JSON.stringify(c.report(8)));

    // 3. Slow file.text() aborted by modal close does not POST or render error
    h.node('#' + c.prefix + '-paste').value = '';
    const slowFile = deferred();
    h.node('#' + c.prefix + '-file').value = 'slow.json';
    h.node('#' + c.prefix + '-file').files = [{ size: 120, text: () => slowFile.promise }];
    const fileReq = h.dispatch('submit', h.node('#' + c.prefix + '-preview-form'), false);
    await tick();
    await h.dispatch('click', h.close(c.modal));
    slowFile.resolve(JSON.stringify(c.report(9)));
    await fileReq;
    assert.equal(h.posts.length, 3);
    assert.equal(result.classList.contains('hidden'), true);
    assert.equal(error.classList.contains('hidden'), true);
  });
}
