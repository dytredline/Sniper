import assert from 'node:assert/strict';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { test } from 'node:test';

const APP = process.env.SNIPER_UI_APP_JS || fileURLToPath(new URL('../static/app.js', import.meta.url));
const REPORT = ['notBefore=Jan  1 00:00:00 2025 GMT', 'notAfter=Jan  1 00:00:00 2027 GMT', 'sha256 Fingerprint=' + Array(32).fill('AA').join(':')].join('\n');
const REPORT2 = REPORT.replace('Jan  1 00:00:00 2027 GMT', 'Oct 27 00:00:00 2026 GMT').replace('AA:AA', 'BB:AA');
function deferred() {
  let resolve;
  const promise = new Promise(r => { resolve = r; });
  return { promise, resolve };
}
function harness() {
  const nodes = new Map(), listeners = new Map(), pending = [], posts = [], controlPending = new Map();
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
      hasAttribute() { return false; },
      querySelector: selector => node(selector), querySelectorAll: () => [],
      matches() { return false; },
      closest(selector) {
        if (selector === '[data-action]' && this.dataset.action) return this;
        if (selector === '[data-close]' && this.dataset.close) return this;
        if (selector.startsWith('[data-action=') && selector.includes(this.dataset.action)) return this;
        if (selector.startsWith('[data-close=') && selector.includes(this.dataset.close)) return this;
        return null;
      },
    };
    nodes.set(key, n);
    return n;
  }
  const document = {
    body: node('body'), activeElement: node('body'),
    querySelector: selector => node(selector), querySelectorAll: () => [],
    getElementById: id => node('#' + id), createElement: tag => node('created:' + tag),
    addEventListener(name, cb) {
      const list = listeners.get(name) || []; list.push(cb); listeners.set(name, list);
    },
  };
  const getResponses = {
    '/api/dashboard': {}, '/api/targets': { targets: [] }, '/api/scans?limit=200': { scans: [] },
    '/api/engagements': { engagements: [
      {id:'A',name:'A',status:'active',authorization_ref:'AUTH-A',scope_notes:'scope A',special_approvals:{redacted_data_proof:true}},
      {id:'B',name:'B',status:'active',authorization_ref:'AUTH-B',scope_notes:'scope B',special_approvals:{redacted_data_proof:true}}
    ] }, '/api/lab-runs': { lab_runs: [] },
    '/api/project-audits': { project_audits: [], total: 0 },
    '/api/tooling': { tools: [], categories: [], summary: {}, policy: { native: '', external: '', completion: '' } },
    '/api/dependency-security': {},
  };
  async function fetch(path, options = {}) {
    if (path === '/api/engagements/A' || path === '/api/engagements/B') {
      const deferredGet = deferred();
      controlPending.set(path.at(-1), deferredGet);
      return deferredGet.promise.then(body => ({ ok: true, status: 200, json: async () => body }));
    }
    if (options.method === 'POST') {
      posts.push({ path, body: JSON.parse(options.body) });
      assert.equal(path, '/api/tool-reports/openssl-x509/summary');
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
  async function dispatch(name, target, wait = true) {
    const event = { target, currentTarget: target, preventDefault() {}, stopPropagation() {}, stopImmediatePropagation() {} };
    const results = (listeners.get(name) || []).map(cb => cb(event));
    if (wait) await Promise.all(results);
    return Promise.all(results);
  }
  function action(value) { const n = node('action:' + value); n.dataset.action = value; return n; }
  function close(value) { const n = node('close:' + value); n.dataset.close = value; return n; }
  function summary(validity, shaChar) {
    return {
      format: 'openssl-x509-dates-fingerprint-v1', validity,
      not_before_utc: '2025-01-01T00:00:00Z',
      not_after_utc: validity === 'expiring_soon' ? '2026-10-27T00:00:00Z' : '2027-01-01T00:00:00Z',
      days_until_expiry: validity === 'expiring_soon' ? 10 : 76,
      report_sha256: shaChar.repeat(64),
    };
  }
  return { node, pending, posts, controlPending, dispatch, action, close, summary, ready: () => new Promise(r => setImmediate(r)) };
}


test('TestSSL in-order engagement controls remain aligned (passing control)', async () => {
  const h = harness(); await h.ready();
  const modal = h.node('#testssl-preview-modal');
  modal.classList.add('hidden');
  await h.dispatch('click', h.action('open-testssl-flat-preview'));
  const choice = h.node('#testssl-link-engagement');
  const control = h.node('#testssl-link-control');
  choice.value = 'A';
  const first = h.dispatch('change', choice, false);
  assert.equal(h.controlPending.has('A'), true);
  h.controlPending.get('A').resolve({id:'A', tests:[{control_id:'A-1', title:'A test'}]});
  await first;
  choice.value = 'B';
  const second = h.dispatch('change', choice, false);
  assert.equal(h.controlPending.has('B'), true);
  h.controlPending.get('B').resolve({id:'B', tests:[{control_id:'B-1', title:'B test'}]});
  await second;
  assert.match(control.innerHTML, /B-1/);
  assert.doesNotMatch(control.innerHTML, /A-1/);
  assert.equal(control.disabled, false);
  assert.equal(h.posts.length, 0);
});

test('TestSSL old A controls must not replace selected B after out-of-order GET', async () => {
  const h = harness(); await h.ready();
  const modal = h.node('#testssl-preview-modal');
  modal.classList.add('hidden');
  await h.dispatch('click', h.action('open-testssl-flat-preview'));
  const choice = h.node('#testssl-link-engagement');
  const control = h.node('#testssl-link-control');
  choice.value = 'A';
  const first = h.dispatch('change', choice, false);
  choice.value = 'B';
  const second = h.dispatch('change', choice, false);
  assert.equal(h.controlPending.size, 2);
  h.controlPending.get('B').resolve({id:'B', tests:[{control_id:'B-1', title:'B test'}]});
  await second;
  assert.match(control.innerHTML, /B-1/);
  h.controlPending.get('A').resolve({id:'A', tests:[{control_id:'A-1', title:'A test'}]});
  await first;
  assert.equal(choice.value, 'B');
  assert.doesNotMatch(control.innerHTML, /A-1/);
  assert.match(control.innerHTML, /B-1/);
  assert.equal(h.posts.length, 0);
});

test('TestSSL stale A validation error cannot clear newer B controls', async () => {
  const h = harness(); await h.ready();
  h.node('#testssl-preview-modal').classList.add('hidden');
  await h.dispatch('click', h.action('open-testssl-flat-preview'));
  const choice = h.node('#testssl-link-engagement');
  const control = h.node('#testssl-link-control');
  choice.value = 'A';
  const first = h.dispatch('change', choice, false);
  choice.value = 'B';
  const second = h.dispatch('change', choice, false);
  h.controlPending.get('B').resolve({id:'B', tests:[{control_id:'B-1', title:'B test'}]});
  await second;
  h.controlPending.get('A').resolve({id:'WRONG', tests:[]});
  await first;
  assert.match(control.innerHTML, /B-1/);
  assert.doesNotMatch(control.innerHTML, /yüklenemedi/i);
  assert.equal(control.disabled, false);
  assert.equal(h.posts.length, 0);
});

test('TestSSL close invalidates pending controls GET before modal reopen', async () => {
  const h = harness(); await h.ready();
  h.node('#testssl-preview-modal').classList.add('hidden');
  await h.dispatch('click', h.action('open-testssl-flat-preview'));
  const choice = h.node('#testssl-link-engagement');
  const control = h.node('#testssl-link-control');
  choice.value = 'A';
  const first = h.dispatch('change', choice, false);
  await h.dispatch('click', h.close('testssl-preview-modal'));
  h.controlPending.get('A').resolve({id:'A', tests:[{control_id:'A-1', title:'A test'}]});
  await first;
  assert.doesNotMatch(control.innerHTML, /A-1/);
  assert.equal(control.disabled, true);
  assert.equal(h.posts.length, 0);
});

test('TestSSL opt-out invalidates pending control load', async () => {
  const h = harness(); await h.ready();
  h.node('#testssl-preview-modal').classList.add('hidden');
  await h.dispatch('click', h.action('open-testssl-flat-preview'));
  const choice = h.node('#testssl-link-engagement');
  const control = h.node('#testssl-link-control');
  choice.value = 'A';
  const first = h.dispatch('change', choice, false);
  const optIn = h.node('#testssl-link-opt-in');
  optIn.checked = false;
  await h.dispatch('change', optIn);
  h.controlPending.get('A').resolve({id:'A', tests:[{control_id:'A-1', title:'A test'}]});
  await first;
  assert.doesNotMatch(control.innerHTML, /A-1/);
  assert.equal(control.disabled, true);
  assert.equal(h.posts.length, 0);
});
