import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { test } from 'node:test';

const APP = process.env.SNIPER_UI_APP_JS || new URL('../static/app.js', import.meta.url).pathname;
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
      assert.ok(path === '/api/tool-reports/testssl/summary' || path === '/api/engagements/A/tool-evidence/testssl-flat-json');
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


const serverSummary = {
  format: 'testssl-flat-json',
  record_count: 0,
  severity_counts: Object.fromEntries(['INFO','OK','LOW','MEDIUM','HIGH','CRITICAL','WARN','DEBUG','FATAL'].map(k => [k, 0])),
  report_sha256: 'a'.repeat(64),
};
function prepare(h) {
  h.node('#testssl-preview-modal').classList.add('hidden');
  h.node('#testssl-preview-result').classList.add('hidden');
  h.node('#testssl-preview-error').classList.add('hidden');
  h.node('#testssl-paste').value = '[]';
}
test('control: in-order TestSSL summary POST renders aggregate without linking', async () => {
  const h=harness(); await h.ready(); prepare(h);
  await h.dispatch('click', h.action('open-testssl-flat-preview'));
  h.node('#testssl-paste').value = '[]';
  const inFlight=h.dispatch('submit', h.node('#testssl-preview-form'), false);
  assert.equal(h.posts.length, 1);
  assert.equal(h.posts[0].path, '/api/tool-reports/testssl/summary');
  assert.deepEqual(h.posts[0].body, {report: []});
  h.pending[0].resolve(serverSummary);
  await inFlight;
  assert.equal(h.node('#testssl-preview-result').classList.contains('hidden'), false);
  assert.equal(h.node('#testssl-record-count').textContent, 0);
  assert.equal(h.posts.length, 1);
});
test('feature: closed TestSSL modal must not resurrect late summary after reopen', async () => {
  const h=harness(); await h.ready(); prepare(h);
  await h.dispatch('click', h.action('open-testssl-flat-preview'));
  h.node('#testssl-paste').value = '[]';
  const inFlight=h.dispatch('submit', h.node('#testssl-preview-form'), false);
  assert.equal(h.posts.length, 1);
  await h.dispatch('click', h.close('testssl-preview-modal'));
  assert.equal(h.node('#testssl-preview-result').classList.contains('hidden'), true);
  h.pending[0].resolve(serverSummary);
  await inFlight;
  await h.dispatch('click', h.action('open-testssl-flat-preview'));
  assert.equal(h.node('#testssl-preview-result').classList.contains('hidden'), true);
  assert.equal(h.node('#testssl-record-count').textContent, '');
  assert.equal(h.posts.length, 1);
});

test('feature: old summary must not put an error over a newer confirmed evidence link', async () => {
  const h=harness(); await h.ready(); prepare(h);
  await h.dispatch('click', h.action('open-testssl-flat-preview'));
  h.node('#testssl-paste').value = '[]';
  const oldInFlight=h.dispatch('submit', h.node('#testssl-preview-form'), false);
  assert.equal(h.posts[0].path, '/api/tool-reports/testssl/summary');
  await h.dispatch('click', h.close('testssl-preview-modal'));
  await h.dispatch('click', h.action('open-testssl-flat-preview'));
  h.node('#testssl-paste').value = '[]';
  const optIn=h.node('#testssl-link-opt-in'); optIn.checked=true;
  await h.dispatch('change', optIn);
  const engagement=h.node('#testssl-link-engagement'); engagement.value='A';
  const controlLoad=h.dispatch('change', engagement, false);
  h.controlPending.get('A').resolve({id:'A',tests:[{control_id:'A-1',title:'A test'}]});
  await controlLoad;
  const control=h.node('#testssl-link-control'); control.value='A-1';
  const newInFlight=h.dispatch('submit', h.node('#testssl-preview-form'), false);
  assert.equal(h.posts[1].path, '/api/engagements/A/tool-evidence/testssl-flat-json');
  assert.equal(h.posts[1].body.confirm_link,true);
  assert.equal(h.posts[1].body.control_id,'A-1');
  h.pending[1].resolve({...serverSummary,tool_identity:'testssl-flat-json',report_sha256:'b'.repeat(64)});
  await newInFlight;
  assert.equal(h.node('#testssl-link-result').classList.contains('hidden'),false);
  assert.equal(h.node('#testssl-preview-error').classList.contains('hidden'),true);
  h.pending[0].resolve(serverSummary);
  await oldInFlight;
  assert.equal(h.node('#testssl-preview-error').classList.contains('hidden'),true);
  assert.equal(h.node('#testssl-report-sha256').textContent,'b'.repeat(64));
  assert.equal(h.posts.length,2);
});
