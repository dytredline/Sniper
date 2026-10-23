import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const appPath = process.env.SNIPER_TASK74_APP_JS || fileURLToPath(new URL('../static/app.js', import.meta.url));

function harness() {
  const nodes = new Map();
  const listeners = new Map();
  const pending = { gitleaks: [], sarif: [] };
  const posts = [];
  function node(key) {
    if (nodes.has(key)) return nodes.get(key);
    const classes = new Set();
    const n = {
      id: String(key).replace(/^#/, ''), dataset: {}, style: {},
      value: '', files: [], checked: false, disabled: false,
      innerHTML: '', textContent: '',
      classList: {
        add: name => classes.add(name),
        remove: name => classes.delete(name),
        contains: name => classes.has(name),
        toggle(name, force) {
          if (force === undefined ? !classes.has(name) : force) classes.add(name);
          else classes.delete(name);
        },
      },
      addEventListener() {}, append() {}, appendChild() {}, remove() {},
      focus() {}, reset() {}, setSelectionRange() {}, setAttribute() {}, removeAttribute() {},
      querySelector: selector => node(selector), querySelectorAll: () => [],
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
    querySelector: selector => node(selector), querySelectorAll: () => [],
    getElementById: id => node('#' + id),
    createElement: tag => node('created:' + tag),
    addEventListener(name, callback) {
      const list = listeners.get(name) || [];
      list.push(callback);
      listeners.set(name, list);
    },
  };
  const responses = {
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
      if (path === '/api/tool-reports/gitleaks/summary') {
        return new Promise(resolve => pending.gitleaks.push(body => resolve({ ok: true, status: 200, json: async () => body })));
      }
      if (path === '/api/tool-reports/sarif/summary') {
        return new Promise(resolve => pending.sarif.push(body => resolve({ ok: true, status: 200, json: async () => body })));
      }
      throw new Error('Unexpected synthetic POST: ' + path);
    }
    return { ok: true, status: 200, json: async () => responses[path] || {} };
  }
  const context = vm.createContext({
    document, window: { addEventListener() {} }, location: { hash: '' },
    history: { replaceState() {} }, fetch, TextEncoder, URL, console,
    setTimeout: () => 0, clearTimeout() {}, setInterval: () => 0,
  });
  vm.runInContext(fs.readFileSync(appPath, 'utf8'), context, { filename: appPath });
  async function dispatch(name, target, wait = true) {
    const event = {
      target, currentTarget: target,
      preventDefault() {}, stopPropagation() {}, stopImmediatePropagation() {},
    };
    const results = (listeners.get(name) || []).map(callback => callback(event));
    if (wait) await Promise.all(results);
    return Promise.all(results);
  }
  function action(name) {
    const target = node('action:' + name);
    target.dataset.action = name;
    return target;
  }
  function close(name) {
    const target = node('close:' + name);
    target.dataset.close = name;
    return target;
  }
  return { node, pending, posts, dispatch, action, close, ready: () => new Promise(resolve => setImmediate(resolve)) };
}

test('Gitleaks late summary cannot repopulate a closed modal while a SARIF preview stays current', async () => {
  const h = harness();
  await h.ready();
  const gitleaksModal = h.node('#gitleaks-preview-modal');
  const gitleaksResult = h.node('#gitleaks-preview-result');
  const gitleaksPaste = h.node('#gitleaks-paste');
  const sarifResult = h.node('#sarif-preview-result');
  gitleaksModal.classList.add('hidden');
  gitleaksResult.classList.add('hidden');
  sarifResult.classList.add('hidden');

  await h.dispatch('click', h.action('open-gitleaks-json-preview'));
  gitleaksPaste.value = JSON.stringify([{ RuleID: 'synthetic-rule', File: 'fixture', Secret: 'synthetic-secret' }]);
  const oldRequest = h.dispatch('submit', h.node('#gitleaks-preview-form'), false);
  assert.equal(h.pending.gitleaks.length, 1);
  assert.equal(h.posts.filter(item => item.path === '/api/tool-reports/gitleaks/summary').length, 1);

  await h.dispatch('click', h.close('gitleaks-preview-modal'));
  assert.equal(gitleaksModal.classList.contains('hidden'), true);
  assert.equal(gitleaksPaste.value, '');
  assert.equal(gitleaksResult.classList.contains('hidden'), true);

  await h.dispatch('click', h.action('open-sarif-preview'));
  h.node('#sarif-paste').value = JSON.stringify({ version: '2.1.0', runs: [{ tool: { driver: { name: 'synthetic-tool' } }, results: [{}] }] });
  const currentRequest = h.dispatch('submit', h.node('#sarif-preview-form'), false);
  assert.equal(h.pending.sarif.length, 1);
  h.pending.sarif.shift()({
    format: 'sarif', run_count: 1, result_count: 1,
    tools: [{ name: 'synthetic-tool', levels: { error: 1 } }],
    report_sha256: 'a'.repeat(64),
  });
  await currentRequest;
  assert.equal(h.node('#sarif-result-count').textContent, 1);
  assert.equal(sarifResult.classList.contains('hidden'), false);

  h.pending.gitleaks.shift()({
    format: 'gitleaks-native-json', total_findings: 1,
    rules_triggered: 1, files_affected: 1,
  });
  await oldRequest;
  assert.equal(gitleaksResult.classList.contains('hidden'), true);
  assert.equal(h.node('#gitleaks-total-findings').textContent, '');
  assert.equal(h.node('#sarif-result-count').textContent, 1);
  assert.equal(h.posts.length, 2);
});
