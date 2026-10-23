import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { test } from 'node:test';

const APP = process.env.SNIPER_APP_JS || new URL('../static/app.js', import.meta.url).pathname;
function deferred() {
  let resolve;
  const promise = new Promise(r => { resolve = r; });
  return { promise, resolve };
}
function harness() {
  const nodes = new Map(), listeners = new Map(), pending = [], posts = [];
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
    body: node('body'), querySelector: selector => node(selector), querySelectorAll: () => [],
    getElementById: id => node('#' + id), createElement: tag => node('created:' + tag),
    addEventListener(name, cb) {
      const list = listeners.get(name) || []; list.push(cb); listeners.set(name, list);
    },
  };
  const getResponses = {
    '/api/dashboard': {}, '/api/targets': { targets: [] }, '/api/scans?limit=200': { scans: [] },
    '/api/engagements': { engagements: [] }, '/api/lab-runs': { lab_runs: [] },
    '/api/project-audits': { project_audits: [], total: 0 },
    '/api/tooling': { tools: [], categories: [], summary: {}, policy: { native: '', external: '', completion: '' } },
    '/api/dependency-security': {},
  };
  async function fetch(path, options = {}) {
    if (options.method === 'POST') {
      posts.push({ path, body: JSON.parse(options.body) });
      assert.equal(path, '/api/tool-reports/npm-audit/summary');
      const d = deferred(); pending.push(d);
      return d.promise.then(body => ({ ok: true, status: 200, json: async () => body }));
    }
    return { ok: true, status: 200, json: async () => getResponses[path] || {} };
  }
  const context = vm.createContext({
    document, window: { addEventListener() {} }, location: { hash: '' }, history: { replaceState() {} },
    fetch, TextEncoder, URL, console, setTimeout: () => 0, clearTimeout() {}, setInterval: () => 0,
  });
  vm.runInContext(fs.readFileSync(APP, 'utf8'), context, { filename: APP });
  async function dispatch(name, target, wait = true, extra = {}) {
    const event = { target, currentTarget: target, preventDefault() {}, stopPropagation() {}, stopImmediatePropagation() {}, ...extra };
    const results = (listeners.get(name) || []).map(cb => cb(event));
    if (wait) await Promise.all(results);
    return Promise.all(results);
  }
  function action(value) { const n = node('action:' + value); n.dataset.action = value; return n; }
  function close(value) { const n = node('close:' + value); n.dataset.close = value; return n; }
  function input(count) {
    const vulnerabilities = {};
    for (let i=0;i<count;i++) vulnerabilities['synthetic-package-' + i] = { severity: 'high', via: [] };
    return JSON.stringify({ auditReportVersion: 2, vulnerabilities });
  }
  function summary(count) {
    return {
      format: 'npm-audit-v2', affected_package_count: count,
      package_severity_counts: { info: 0, low: 0, moderate: 0, high: count, critical: 0 },
      report_sha256: 'b'.repeat(64),
    };
  }
  return { node, pending, posts, dispatch, action, close, input, summary, ready: () => new Promise(r => setImmediate(r)) };
}

test('normal saved npm audit preview control renders one aggregate and clears pasted input', async () => {
  const h=harness(); await h.ready();
  const modal=h.node('#npm-audit-preview-modal'), result=h.node('#npm-audit-preview-result');
  modal.classList.add('hidden'); result.classList.add('hidden');
  await h.dispatch('click',h.action('open-npm-audit-preview'));
  h.node('#npm-audit-paste').value=h.input(1);
  const p=h.dispatch('submit',h.node('#npm-audit-preview-form'),false);
  assert.equal(h.pending.length,1); assert.equal(h.posts.length,1);
  h.pending.shift().resolve(h.summary(1)); await p;
  assert.equal(modal.classList.contains('hidden'),false);
  assert.equal(result.classList.contains('hidden'),false);
  assert.equal(h.node('#npm-audit-package-count').textContent,'1');
  assert.equal(h.node('#npm-audit-paste').value,'');
});

test('late npm audit summary must not repopulate preview after close', async () => {
  const h=harness(); await h.ready();
  const modal=h.node('#npm-audit-preview-modal'), result=h.node('#npm-audit-preview-result');
  modal.classList.add('hidden'); result.classList.add('hidden');
  await h.dispatch('click',h.action('open-npm-audit-preview'));
  h.node('#npm-audit-paste').value=h.input(1);
  const p=h.dispatch('submit',h.node('#npm-audit-preview-form'),false);
  assert.equal(h.pending.length,1);
  await h.dispatch('click',h.close('npm-audit-preview-modal'));
  assert.equal(modal.classList.contains('hidden'),true);
  assert.equal(result.classList.contains('hidden'),true);
  h.pending.shift().resolve(h.summary(1)); await p;
  assert.equal(result.classList.contains('hidden'),true);
  assert.equal(h.node('#npm-audit-package-count').textContent,'');
});

test('older npm audit summary must not overwrite a newer reopened preview', async () => {
  const h=harness(); await h.ready();
  const modal=h.node('#npm-audit-preview-modal'), result=h.node('#npm-audit-preview-result');
  modal.classList.add('hidden'); result.classList.add('hidden');
  await h.dispatch('click',h.action('open-npm-audit-preview'));
  h.node('#npm-audit-paste').value=h.input(1);
  const old=h.dispatch('submit',h.node('#npm-audit-preview-form'),false);
  await h.dispatch('click',h.close('npm-audit-preview-modal'));
  await h.dispatch('click',h.action('open-npm-audit-preview'));
  h.node('#npm-audit-paste').value=h.input(2);
  const current=h.dispatch('submit',h.node('#npm-audit-preview-form'),false);
  assert.equal(h.pending.length,2); assert.equal(h.posts.length,2);
  h.pending[1].resolve(h.summary(2)); await current;
  assert.equal(result.classList.contains('hidden'),false);
  assert.equal(h.node('#npm-audit-package-count').textContent,'2');
  h.pending[0].resolve(h.summary(1)); await old;
  assert.equal(h.node('#npm-audit-package-count').textContent,'2');
});

test('closing during npm audit file.text must not start summary POST', async () => {
  const h=harness(); await h.ready();
  const modal=h.node('#npm-audit-preview-modal');
  modal.classList.add('hidden'); h.node('#npm-audit-preview-result').classList.add('hidden');
  await h.dispatch('click',h.action('open-npm-audit-preview'));
  const fileRead=deferred();
  h.node('#npm-audit-file').files=[{ size: 70, text: () => fileRead.promise }];
  const p=h.dispatch('submit',h.node('#npm-audit-preview-form'),false);
  assert.equal(h.posts.length,0);
  await h.dispatch('click',h.close('npm-audit-preview-modal'));
  fileRead.resolve(h.input(1));
  await Promise.resolve(); await Promise.resolve();
  if (h.pending.length) h.pending.shift().resolve(h.summary(1));
  await p;
  assert.equal(h.posts.length,0);
});

test("Escape close invalidates pending npm audit response and clears private input", async () => {
  const h=harness(); await h.ready();
  const modal=h.node("#npm-audit-preview-modal"), result=h.node("#npm-audit-preview-result");
  modal.classList.add("hidden"); result.classList.add("hidden");
  await h.dispatch("click", h.action("open-npm-audit-preview"));
  h.node("#npm-audit-paste").value=h.input(1);
  const p=h.dispatch("submit", h.node("#npm-audit-preview-form"), false);
  assert.equal(h.pending.length,1);
  await h.dispatch("keydown", modal, true, { key: "Escape" });
  assert.equal(modal.classList.contains("hidden"),true);
  assert.equal(h.node("#npm-audit-paste").value,"");
  h.pending.shift().resolve(h.summary(1)); await p;
  assert.equal(result.classList.contains("hidden"),true);
  assert.equal(h.node("#npm-audit-package-count").textContent,"");
});
