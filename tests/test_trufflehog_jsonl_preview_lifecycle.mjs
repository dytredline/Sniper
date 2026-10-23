import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { test } from 'node:test';

const APP =
  process.env.SNIPER_APP_JS ||
  process.env.SNIPER_UI_APP_JS ||
  new URL('../static/app.js', import.meta.url).pathname;

const REPORT_A = [
  JSON.stringify({ DetectorName: 'AWS', Verified: true }),
  JSON.stringify({ DetectorName: 'GitHub', Verified: false }),
].join('\n');

const REPORT_B = JSON.stringify({ DetectorName: 'SlackWebhook', Verified: true });

function deferred() {
  let resolve, reject;
  const promise = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

function tick() {
  return new Promise(resolve => setImmediate(resolve));
}

function summaryA() {
  return {
    format: 'trufflehog-native-json-records',
    total_findings: 2,
    verified_findings: 1,
    unverified_findings: 1,
    detectors_triggered: 2,
  };
}

function summaryB() {
  return {
    format: 'trufflehog-native-json-records',
    total_findings: 1,
    verified_findings: 1,
    unverified_findings: 0,
    detectors_triggered: 1,
  };
}

function harness() {
  const nodes = new Map();
  const listeners = new Map();
  const pending = [];
  const posts = [];

  function node(key) {
    if (nodes.has(key)) return nodes.get(key);
    const classes = new Set();
    const n = {
      id: String(key).replace(/^#/, ''),
      dataset: {},
      style: {},
      value: '',
      files: [],
      checked: false,
      disabled: false,
      innerHTML: '',
      textContent: '',
      classList: {
        add: name => classes.add(name),
        remove: name => classes.delete(name),
        contains: name => classes.has(name),
        toggle(name, force) {
          if (force === undefined ? !classes.has(name) : force) classes.add(name);
          else classes.delete(name);
        },
      },
      addEventListener(name, cb) {
        this.handlers ??= new Map();
        const list = this.handlers.get(String(name)) || [];
        list.push(cb);
        this.handlers.set(String(name), list);
      },
      append() {},
      appendChild() {},
      remove() {},
      focus() {},
      reset() {},
      setSelectionRange() {},
      setAttribute() {},
      removeAttribute() {},
      hasAttribute() {
        return false;
      },
      getClientRects() {
        return [1];
      },
      matches() {
        return false;
      },
      querySelector: selector => node(selector),
      querySelectorAll: () => [],
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
    body: node('body'),
    activeElement: node('body'),
    querySelector: selector => node(selector),
    querySelectorAll: () => [],
    getElementById: id => node('#' + id),
    createElement: tag => node('created:' + tag),
    addEventListener(name, cb) {
      const list = listeners.get(name) || [];
      list.push(cb);
      listeners.set(name, list);
    },
  };

  const getResponses = {
    '/api/dashboard': {},
    '/api/targets': { targets: [] },
    '/api/scans?limit=200': { scans: [] },
    '/api/engagements': { engagements: [] },
    '/api/lab-runs': { lab_runs: [] },
    '/api/project-audits': { project_audits: [], total: 0 },
    '/api/tooling': {
      tools: [],
      categories: [],
      summary: {},
      policy: { native: '', external: '', completion: '' },
    },
    '/api/dependency-security': {},
  };

  async function fetch(path, options = {}) {
    if (options.method === 'POST') {
      posts.push({ path, body: JSON.parse(options.body) });
      assert.equal(path, '/api/tool-reports/trufflehog/summary');
      const d = deferred();
      pending.push(d);
      return d.promise.then(
        body => ({ ok: true, status: 200, json: async () => body }),
        err => ({
          ok: false,
          status: err?.status || 500,
          json: async () => ({ error: err?.message || 'Sunucu hatası.' }),
        })
      );
    }
    return { ok: true, status: 200, json: async () => getResponses[path] || {} };
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

  vm.runInContext(fs.readFileSync(APP, 'utf8'), context, { filename: APP });

  node('#trufflehog-preview-modal').classList.add('hidden');
  node('#trufflehog-preview-result').classList.add('hidden');
  node('#trufflehog-preview-error').classList.add('hidden');

  async function dispatch(name, target, wait = true, extra = {}) {
    let defaultPrevented = false;
    const event = {
      target,
      currentTarget: target,
      ...extra,
      get defaultPrevented() {
        return defaultPrevented;
      },
      preventDefault() {
        defaultPrevented = true;
      },
      stopPropagation() {},
      stopImmediatePropagation() {},
    };
    const elementHandlers = target?.handlers?.get(name) || [];
    const docHandlers = listeners.get(name) || [];
    const run = Promise.all([...elementHandlers, ...docHandlers].map(cb => cb(event)));
    if (wait) await run;
    return run;
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

  return { node, pending, posts, dispatch, action, close, context, ready: tick };
}

test('control: valid saved TruffleHog JSONL preview posts once, renders aggregate counts, and clears inputs on completion and close', async () => {
  const h = harness();
  await h.ready();
  const modal = h.node('#trufflehog-preview-modal');
  const form = h.node('#trufflehog-preview-form');
  const paste = h.node('#trufflehog-paste');
  const fileInput = h.node('#trufflehog-file');
  const result = h.node('#trufflehog-preview-result');
  const error = h.node('#trufflehog-preview-error');

  await h.dispatch('click', h.action('open-trufflehog-preview'));
  assert.equal(modal.classList.contains('hidden'), false);
  assert.equal(h.posts.length, 0);

  paste.value = REPORT_A;
  const req1 = h.dispatch('submit', form, false);
  await tick();
  assert.equal(h.posts.length, 1);
  assert.equal(h.posts[0].path, '/api/tool-reports/trufflehog/summary');
  assert.deepEqual(h.posts[0].body, {
    report: [
      { DetectorName: 'AWS', Verified: true },
      { DetectorName: 'GitHub', Verified: false },
    ],
  });

  h.pending.shift().resolve(summaryA());
  await req1;

  assert.equal(result.classList.contains('hidden'), false);
  assert.equal(error.classList.contains('hidden'), true);
  assert.equal(String(h.node('#trufflehog-format').textContent), 'trufflehog-native-json-records');
  assert.equal(String(h.node('#trufflehog-total').textContent), '2');
  assert.equal(String(h.node('#trufflehog-verified').textContent), '1');
  assert.equal(String(h.node('#trufflehog-unverified').textContent), '1');
  assert.equal(String(h.node('#trufflehog-detectors').textContent), '2');
  assert.equal(paste.value, '');

  // File input control
  fileInput.value = 'report-b.jsonl';
  fileInput.files = [{ name: 'report-b.jsonl', size: REPORT_B.length, text: async () => REPORT_B }];
  const req2 = h.dispatch('submit', form, false);
  await tick();
  assert.equal(h.posts.length, 2);
  h.pending.shift().resolve(summaryB());
  await req2;

  assert.equal(result.classList.contains('hidden'), false);
  assert.equal(String(h.node('#trufflehog-total').textContent), '1');
  assert.equal(String(h.node('#trufflehog-verified').textContent), '1');
  assert.equal(String(h.node('#trufflehog-unverified').textContent), '0');
  assert.equal(String(h.node('#trufflehog-detectors').textContent), '1');
  assert.equal(fileInput.value, '');

  await h.dispatch('click', h.close('trufflehog-preview-modal'));
  assert.equal(modal.classList.contains('hidden'), true);
  assert.equal(result.classList.contains('hidden'), true);
  assert.equal(error.classList.contains('hidden'), true);
});

test('close_before_response: closing modal via Kapat, backdrop, or Escape invalidates pending response/error and slow file.text()', async () => {
  const h = harness();
  await h.ready();
  const modal = h.node('#trufflehog-preview-modal');
  const form = h.node('#trufflehog-preview-form');
  const paste = h.node('#trufflehog-paste');
  const fileInput = h.node('#trufflehog-file');
  const result = h.node('#trufflehog-preview-result');
  const error = h.node('#trufflehog-preview-error');

  // 1. Close button before response settles
  await h.dispatch('click', h.action('open-trufflehog-preview'));
  paste.value = REPORT_A;
  const req1 = h.dispatch('submit', form, false);
  await tick();
  assert.equal(h.posts.length, 1);

  await h.dispatch('click', h.close('trufflehog-preview-modal'));
  assert.equal(modal.classList.contains('hidden'), true);
  assert.equal(paste.value, '');
  assert.equal(result.classList.contains('hidden'), true);

  h.pending.shift().resolve(summaryA());
  await req1;

  assert.equal(result.classList.contains('hidden'), true);
  assert.equal(error.classList.contains('hidden'), true);
  assert.equal(String(h.node('#trufflehog-format').textContent), '');
  assert.equal(String(h.node('#trufflehog-total').textContent), '');
  assert.equal(String(h.node('#trufflehog-verified').textContent), '');
  assert.equal(String(h.node('#trufflehog-unverified').textContent), '');
  assert.equal(String(h.node('#trufflehog-detectors').textContent), '');

  // 2. Backdrop close + reopen before response settles
  await h.dispatch('click', h.action('open-trufflehog-preview'));
  paste.value = REPORT_A;
  const req2 = h.dispatch('submit', form, false);
  await tick();
  assert.equal(h.posts.length, 2);

  await h.dispatch('click', modal);
  assert.equal(modal.classList.contains('hidden'), true);
  await h.dispatch('click', h.action('open-trufflehog-preview'));
  assert.equal(modal.classList.contains('hidden'), false);
  paste.value = REPORT_B;

  h.pending.shift().resolve(summaryA());
  await req2;

  assert.equal(result.classList.contains('hidden'), true);
  assert.equal(String(h.node('#trufflehog-total').textContent), '');
  assert.equal(paste.value, REPORT_B);

  // 3. Escape key close before error response settles
  const req3 = h.dispatch('submit', form, false);
  await tick();
  assert.equal(h.posts.length, 3);

  await h.dispatch('keydown', modal, true, { key: 'Escape' });
  assert.equal(modal.classList.contains('hidden'), true);
  assert.equal(paste.value, '');

  h.pending.shift().reject(new Error('late network error'));
  await req3;

  assert.equal(result.classList.contains('hidden'), true);
  assert.equal(error.classList.contains('hidden'), true);
  assert.equal(error.textContent, '');

  // 4. Close during slow file.text() must not send POST
  await h.dispatch('click', h.action('open-trufflehog-preview'));
  const slowFile = deferred();
  fileInput.value = 'slow.jsonl';
  fileInput.files = [{ name: 'slow.jsonl', size: 120, text: () => slowFile.promise }];
  const req4 = h.dispatch('submit', form, false);
  await tick();
  assert.equal(h.posts.length, 3);

  await h.dispatch('click', h.close('trufflehog-preview-modal'));
  slowFile.resolve(REPORT_A);
  await req4;

  assert.equal(h.posts.length, 3);
  assert.equal(result.classList.contains('hidden'), true);
  assert.equal(error.classList.contains('hidden'), true);
});

test('edit_before_response: editing paste or file input while response is pending preserves new input and ignores stale response or error', async () => {
  const h = harness();
  await h.ready();
  const modal = h.node('#trufflehog-preview-modal');
  const form = h.node('#trufflehog-preview-form');
  const paste = h.node('#trufflehog-paste');
  const fileInput = h.node('#trufflehog-file');
  const result = h.node('#trufflehog-preview-result');
  const error = h.node('#trufflehog-preview-error');

  await h.dispatch('click', h.action('open-trufflehog-preview'));

  // 1. User edits pasted text (with input event) while POST A is pending
  paste.value = REPORT_A;
  const req1 = h.dispatch('submit', form, false);
  await tick();
  assert.equal(h.posts.length, 1);

  paste.value = REPORT_B;
  await h.dispatch('input', paste);

  h.pending.shift().resolve(summaryA());
  await req1;

  assert.equal(result.classList.contains('hidden'), true);
  assert.equal(error.classList.contains('hidden'), true);
  assert.equal(String(h.node('#trufflehog-total').textContent), '');
  assert.equal(paste.value, REPORT_B);

  // 2. User edits pasted text silently (without input event) while POST A is pending
  paste.value = REPORT_A;
  const req2 = h.dispatch('submit', form, false);
  await tick();
  assert.equal(h.posts.length, 2);

  paste.value = REPORT_B;
  h.pending.shift().resolve(summaryA());
  await req2;

  assert.equal(result.classList.contains('hidden'), true);
  assert.equal(error.classList.contains('hidden'), true);
  assert.equal(String(h.node('#trufflehog-total').textContent), '');
  assert.equal(paste.value, REPORT_B);

  // 3. User changes file selection while POST is pending; stale error must not show or clear new file
  paste.value = '';
  const fileA = { name: 'a.jsonl', size: REPORT_A.length, text: async () => REPORT_A };
  const fileB = { name: 'b.jsonl', size: REPORT_B.length, text: async () => REPORT_B };
  fileInput.value = 'a.jsonl';
  fileInput.files = [fileA];
  const req3 = h.dispatch('submit', form, false);
  await tick();
  assert.equal(h.posts.length, 3);

  fileInput.value = 'b.jsonl';
  fileInput.files = [fileB];
  await h.dispatch('change', fileInput);

  h.pending.shift().reject(new Error('stale file A error'));
  await req3;

  assert.equal(result.classList.contains('hidden'), true);
  assert.equal(error.classList.contains('hidden'), true);
  assert.equal(error.textContent, '');
  assert.equal(fileInput.value, 'b.jsonl');
  assert.equal(fileInput.files[0], fileB);

  // 4. Submitting B then having older A resolve after B must keep B's summary
  const reqA = h.dispatch('submit', form, false);
  await tick();
  assert.equal(h.posts.length, 4);

  fileInput.value = '';
  fileInput.files = [];
  paste.value = REPORT_A;
  const reqB = h.dispatch('submit', form, false);
  await tick();
  assert.equal(h.posts.length, 5);

  const [pendingA, pendingB] = h.pending.splice(0, 2);
  pendingB.resolve(summaryA());
  await reqB;
  assert.equal(result.classList.contains('hidden'), false);
  assert.equal(String(h.node('#trufflehog-total').textContent), '2');

  pendingA.resolve(summaryB());
  await reqA;
  assert.equal(result.classList.contains('hidden'), false);
  assert.equal(String(h.node('#trufflehog-total').textContent), '2');
});
