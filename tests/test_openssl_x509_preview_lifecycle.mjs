import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { test } from 'node:test';

const APP =
  process.env.SNIPER_APP_JS ||
  process.env.SNIPER_UI_APP_JS ||
  new URL('../static/app.js', import.meta.url).pathname;

const REPORT_C = [
  'notBefore=Jan  1 00:00:00 2025 GMT',
  'notAfter=Jan  1 00:00:00 2027 GMT',
  'sha256 Fingerprint=' + Array(32).fill('AA').join(':'),
].join('\n');

const REPORT_D = REPORT_C
  .replace('Jan  1 00:00:00 2027 GMT', 'Oct 27 00:00:00 2026 GMT')
  .replace('AA:AA', 'BB:AA');

function deferred() {
  let resolve, reject;
  const promise = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
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
      addEventListener() {},
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
      assert.equal(path, '/api/tool-reports/openssl-x509/summary');
      const d = deferred();
      pending.push(d);
      return d.promise.then(response => {
        if (response && response.__httpStatus && response.__httpStatus !== 200) {
          return {
            ok: false,
            status: response.__httpStatus,
            json: async () => ({ error: response.error || 'Geçersiz OpenSSL x509 raporu.' }),
          };
        }
        return { ok: true, status: 200, json: async () => response };
      });
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

  async function dispatch(name, target, wait = true, extra = {}) {
    const event = {
      target,
      currentTarget: target,
      defaultPrevented: false,
      preventDefault() {
        this.defaultPrevented = true;
      },
      stopPropagation() {},
      stopImmediatePropagation() {},
      ...extra,
    };
    const results = (listeners.get(name) || []).map(cb => cb(event));
    if (wait) await Promise.all(results);
    return Promise.all(results);
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

  function summary(validity, shaChar) {
    return {
      format: 'openssl-x509-dates-fingerprint-v1',
      validity,
      not_before_utc: '2025-01-01T00:00:00Z',
      not_after_utc: validity === 'expiring_soon' ? '2026-10-27T00:00:00Z' : '2027-01-01T00:00:00Z',
      days_until_expiry: validity === 'expiring_soon' ? 10 : 76,
      report_sha256: shaChar.repeat(64),
    };
  }

  return {
    node,
    pending,
    posts,
    dispatch,
    action,
    close,
    summary,
    context,
    ready: () => new Promise(r => setImmediate(r)),
  };
}

test('normal saved OpenSSL x509 preview control posts once and renders aggregate', async () => {
  const h = harness();
  await h.ready();
  const modal = h.node('#openssl-x509-preview-modal');
  const result = h.node('#openssl-x509-preview-result');
  const error = h.node('#openssl-x509-preview-error');
  modal.classList.add('hidden');
  result.classList.add('hidden');
  error.classList.add('hidden');

  await h.dispatch('click', h.action('open-openssl-x509-preview'));
  assert.equal(modal.classList.contains('hidden'), false);
  assert.equal(h.posts.length, 0);

  h.node('#openssl-x509-paste').value = REPORT_C;
  const p = h.dispatch('submit', h.node('#openssl-x509-preview-form'), false);
  assert.equal(h.posts.length, 1);
  assert.equal(h.posts[0].path, '/api/tool-reports/openssl-x509/summary');
  assert.deepEqual(h.posts[0].body, { report: REPORT_C });

  h.pending.shift().resolve(h.summary('valid', 'a'));
  await p;

  assert.equal(result.classList.contains('hidden'), false);
  assert.equal(error.classList.contains('hidden'), true);
  assert.equal(h.node('#openssl-x509-validity').textContent, 'Geçerli');
  assert.equal(h.node('#openssl-x509-before').textContent, '2025-01-01T00:00:00Z');
  assert.equal(h.node('#openssl-x509-after').textContent, '2027-01-01T00:00:00Z');
  assert.equal(h.node('#openssl-x509-days').textContent, '76');
  assert.equal(h.node('#openssl-x509-sha').textContent, 'a'.repeat(64));
  assert.equal(h.node('#openssl-x509-paste').value, '');
});

test('late OpenSSL x509 summary or error must not repopulate preview after Kapat, backdrop, or Escape close', async () => {
  const h = harness();
  await h.ready();
  const modal = h.node('#openssl-x509-preview-modal');
  const result = h.node('#openssl-x509-preview-result');
  const error = h.node('#openssl-x509-preview-error');
  const paste = h.node('#openssl-x509-paste');
  modal.classList.add('hidden');
  result.classList.add('hidden');
  error.classList.add('hidden');

  // 1. Close via Kapat button while summary POST is pending
  await h.dispatch('click', h.action('open-openssl-x509-preview'));
  paste.value = REPORT_C;
  const p1 = h.dispatch('submit', h.node('#openssl-x509-preview-form'), false);
  assert.equal(h.pending.length, 1);

  await h.dispatch('click', h.close('openssl-x509-preview-modal'));
  assert.equal(modal.classList.contains('hidden'), true);
  assert.equal(paste.value, '');
  assert.equal(result.classList.contains('hidden'), true);
  assert.equal(error.classList.contains('hidden'), true);

  h.pending.shift().resolve(h.summary('valid', 'a'));
  await p1;
  assert.equal(result.classList.contains('hidden'), true);
  assert.equal(error.classList.contains('hidden'), true);
  assert.equal(h.node('#openssl-x509-validity').textContent, '');
  assert.equal(h.node('#openssl-x509-sha').textContent, '');

  // 2. Close via Escape key while summary POST is pending (and rejects late)
  await h.dispatch('click', h.action('open-openssl-x509-preview'));
  assert.equal(modal.classList.contains('hidden'), false);
  paste.value = REPORT_C;
  const p2 = h.dispatch('submit', h.node('#openssl-x509-preview-form'), false);
  assert.equal(h.pending.length, 1);

  await h.dispatch('keydown', modal, true, { key: 'Escape' });
  assert.equal(modal.classList.contains('hidden'), true);
  assert.equal(paste.value, '');
  assert.equal(result.classList.contains('hidden'), true);
  assert.equal(error.classList.contains('hidden'), true);

  h.pending.shift().reject(new Error('late error after Escape'));
  await p2;
  assert.equal(result.classList.contains('hidden'), true);
  assert.equal(error.classList.contains('hidden'), true);
  assert.equal(error.textContent, '');

  // 3. Close via backdrop click while summary POST is pending, then reopen before it settles
  await h.dispatch('click', h.action('open-openssl-x509-preview'));
  paste.value = REPORT_C;
  const p3 = h.dispatch('submit', h.node('#openssl-x509-preview-form'), false);
  assert.equal(h.pending.length, 1);

  await h.dispatch('click', modal);
  assert.equal(modal.classList.contains('hidden'), true);
  assert.equal(paste.value, '');

  await h.dispatch('click', h.action('open-openssl-x509-preview'));
  assert.equal(modal.classList.contains('hidden'), false);
  h.pending.shift().resolve(h.summary('valid', 'c'));
  await p3;
  assert.equal(result.classList.contains('hidden'), true);
  assert.equal(h.node('#openssl-x509-validity').textContent, '');
  assert.equal(h.posts.length, 3);
});

test('older OpenSSL x509 response C must not overwrite newly reopened or resubmitted preview D', async () => {
  const h = harness();
  await h.ready();
  const modal = h.node('#openssl-x509-preview-modal');
  const result = h.node('#openssl-x509-preview-result');
  const error = h.node('#openssl-x509-preview-error');
  modal.classList.add('hidden');
  result.classList.add('hidden');
  error.classList.add('hidden');

  // 1. Close after C, reopen and submit D; D resolves first, then older C resolves
  await h.dispatch('click', h.action('open-openssl-x509-preview'));
  h.node('#openssl-x509-paste').value = REPORT_C;
  const oldReq = h.dispatch('submit', h.node('#openssl-x509-preview-form'), false);
  await h.dispatch('click', h.close('openssl-x509-preview-modal'));

  await h.dispatch('click', h.action('open-openssl-x509-preview'));
  h.node('#openssl-x509-paste').value = REPORT_D;
  const currentReq = h.dispatch('submit', h.node('#openssl-x509-preview-form'), false);
  assert.equal(h.pending.length, 2);

  h.pending[1].resolve(h.summary('expiring_soon', 'b'));
  await currentReq;
  assert.equal(result.classList.contains('hidden'), false);
  assert.equal(h.node('#openssl-x509-validity').textContent, 'Yakında sona erecek');
  assert.equal(h.node('#openssl-x509-sha').textContent, 'b'.repeat(64));

  h.pending[0].resolve(h.summary('valid', 'a'));
  await oldReq;
  assert.equal(result.classList.contains('hidden'), false);
  assert.equal(h.node('#openssl-x509-validity').textContent, 'Yakında sona erecek');
  assert.equal(h.node('#openssl-x509-sha').textContent, 'b'.repeat(64));
  assert.equal(error.classList.contains('hidden'), true);
  h.pending.length = 0;

  // 2. Same open modal: submit C (rejects late) then D (resolves first)
  h.node('#openssl-x509-paste').value = REPORT_C;
  const sameModalOld = h.dispatch('submit', h.node('#openssl-x509-preview-form'), false);
  h.node('#openssl-x509-paste').value = REPORT_D;
  const sameModalNew = h.dispatch('submit', h.node('#openssl-x509-preview-form'), false);
  assert.equal(h.pending.length, 2);

  h.pending[1].resolve(h.summary('expiring_soon', 'd'));
  await sameModalNew;
  assert.equal(result.classList.contains('hidden'), false);
  assert.equal(h.node('#openssl-x509-validity').textContent, 'Yakında sona erecek');
  assert.equal(h.node('#openssl-x509-sha').textContent, 'd'.repeat(64));

  h.pending[0].reject(new Error('stale C failure'));
  await sameModalOld;
  assert.equal(result.classList.contains('hidden'), false);
  assert.equal(error.classList.contains('hidden'), true);
  assert.equal(h.node('#openssl-x509-validity').textContent, 'Yakında sona erecek');
  assert.equal(h.node('#openssl-x509-sha').textContent, 'd'.repeat(64));
});

test('preserves empty, 4096-byte size, and response-shape validations without leaking certificate/subject/key/fingerprint secrets', async () => {
  const h = harness();
  await h.ready();
  const modal = h.node('#openssl-x509-preview-modal');
  const result = h.node('#openssl-x509-preview-result');
  const error = h.node('#openssl-x509-preview-error');
  const paste = h.node('#openssl-x509-paste');
  modal.classList.add('hidden');
  result.classList.add('hidden');
  error.classList.add('hidden');

  await h.dispatch('click', h.action('open-openssl-x509-preview'));

  // Empty input -> 0 POSTs, generic error
  paste.value = '';
  await h.dispatch('submit', h.node('#openssl-x509-preview-form'));
  assert.equal(h.posts.length, 0);
  assert.equal(error.classList.contains('hidden'), false);
  assert.equal(error.textContent, 'Geçersiz OpenSSL x509 raporu.');
  assert.equal(result.classList.contains('hidden'), true);

  // Oversize input (>4096 bytes) with synthetic PEM/subject/key -> 0 POSTs, no secret echoed
  const secretMarker = 'CN=secret.internal.example/PRIVATE_KEY_MARKER_78/AA:BB:CC:DD';
  paste.value = secretMarker + '\n' + 'X'.repeat(4100);
  await h.dispatch('submit', h.node('#openssl-x509-preview-form'));
  assert.equal(h.posts.length, 0);
  assert.equal(error.classList.contains('hidden'), false);
  assert.equal(error.textContent, 'Geçersiz OpenSSL x509 raporu.');
  assert.equal(error.textContent.includes('secret.internal'), false);
  assert.equal(error.textContent.includes('PRIVATE_KEY_MARKER_78'), false);
  assert.equal(error.textContent.includes('AA:BB'), false);

  // Malformed summary response shape -> generic error, result remains hidden
  paste.value = REPORT_C;
  const badShapeReq = h.dispatch('submit', h.node('#openssl-x509-preview-form'), false);
  assert.equal(h.posts.length, 1);
  h.pending.shift().resolve({
    format: 'openssl-x509-dates-fingerprint-v1',
    validity: 'valid',
    not_before_utc: '2025-01-01T00:00:00Z',
    not_after_utc: '2027-01-01T00:00:00Z',
    days_until_expiry: 76,
    report_sha256: 'not-a-valid-sha256-' + secretMarker,
  });
  await badShapeReq;
  assert.equal(result.classList.contains('hidden'), true);
  assert.equal(error.classList.contains('hidden'), false);
  assert.equal(error.textContent, 'Geçersiz OpenSSL x509 raporu.');
  assert.equal(error.textContent.includes('secret.internal'), false);
  assert.equal(h.node('#openssl-x509-sha').textContent, '');
});

test('input edit while old summary pending must not display old report or error as current and must preserve edited textarea B', async () => {
  const h = harness();
  await h.ready();
  const modal = h.node('#openssl-x509-preview-modal');
  const result = h.node('#openssl-x509-preview-result');
  const error = h.node('#openssl-x509-preview-error');
  const input = h.node('#openssl-x509-paste');
  modal.classList.add('hidden');
  result.classList.add('hidden');
  error.classList.add('hidden');

  await h.dispatch('click', h.action('open-openssl-x509-preview'));
  input.value = REPORT_C;
  const pendingSuccess = h.dispatch('submit', h.node('#openssl-x509-preview-form'), false);
  assert.equal(h.posts.length, 1);
  assert.equal(h.pending.length, 1);

  // User edits textarea to REPORT_D in the same open modal without resubmitting
  input.value = REPORT_D;
  await h.dispatch('input', input);
  assert.equal(h.posts.length, 1);

  h.pending.shift().resolve(h.summary('valid', 'a'));
  await pendingSuccess;

  assert.equal(h.posts.length, 1);
  assert.equal(result.classList.contains('hidden'), true);
  assert.equal(error.classList.contains('hidden'), true);
  assert.equal(h.node('#openssl-x509-validity').textContent, '');
  assert.equal(h.node('#openssl-x509-sha').textContent, '');
  assert.equal(input.value, REPORT_D);

  // Same-open-modal input edit while old request rejects late: error must stay hidden and B preserved
  input.value = REPORT_C;
  const pendingFailure = h.dispatch('submit', h.node('#openssl-x509-preview-form'), false);
  assert.equal(h.posts.length, 2);
  assert.equal(h.pending.length, 1);

  input.value = REPORT_D;
  await h.dispatch('input', input);
  assert.equal(h.posts.length, 2);

  h.pending.shift().reject(new Error('late A failure after input edit'));
  await pendingFailure;

  assert.equal(h.posts.length, 2);
  assert.equal(result.classList.contains('hidden'), true);
  assert.equal(error.classList.contains('hidden'), true);
  assert.equal(error.textContent, '');
  assert.equal(input.value, REPORT_D);
});

test('pre-response value comparison guards edited textarea B even without DOM input event, and later explicit submit of B renders only B', async () => {
  const h = harness();
  await h.ready();
  const modal = h.node('#openssl-x509-preview-modal');
  const result = h.node('#openssl-x509-preview-result');
  const error = h.node('#openssl-x509-preview-error');
  const input = h.node('#openssl-x509-paste');
  modal.classList.add('hidden');
  result.classList.add('hidden');
  error.classList.add('hidden');

  await h.dispatch('click', h.action('open-openssl-x509-preview'));

  // 1. Value changes to REPORT_D without dispatching DOM 'input' event (success path)
  input.value = REPORT_C;
  const silentEditSuccess = h.dispatch('submit', h.node('#openssl-x509-preview-form'), false);
  assert.equal(h.posts.length, 1);
  input.value = REPORT_D;
  h.pending.shift().resolve(h.summary('valid', 'a'));
  await silentEditSuccess;

  assert.equal(h.posts.length, 1);
  assert.equal(result.classList.contains('hidden'), true);
  assert.equal(error.classList.contains('hidden'), true);
  assert.equal(h.node('#openssl-x509-validity').textContent, '');
  assert.equal(input.value, REPORT_D);

  // 2. Value changes to REPORT_D without dispatching DOM 'input' event (error path)
  input.value = REPORT_C;
  const silentEditError = h.dispatch('submit', h.node('#openssl-x509-preview-form'), false);
  assert.equal(h.posts.length, 2);
  input.value = REPORT_D;
  h.pending.shift().reject(new Error('silent edit stale error'));
  await silentEditError;

  assert.equal(h.posts.length, 2);
  assert.equal(result.classList.contains('hidden'), true);
  assert.equal(error.classList.contains('hidden'), true);
  assert.equal(error.textContent, '');
  assert.equal(input.value, REPORT_D);

  // 3. Explicit submit of edited REPORT_D posts once for D and renders D aggregate summary
  const submitB = h.dispatch('submit', h.node('#openssl-x509-preview-form'), false);
  assert.equal(h.posts.length, 3);
  assert.deepEqual(h.posts[2].body, { report: REPORT_D });
  h.pending.shift().resolve(h.summary('expiring_soon', 'b'));
  await submitB;

  assert.equal(result.classList.contains('hidden'), false);
  assert.equal(error.classList.contains('hidden'), true);
  assert.equal(h.node('#openssl-x509-validity').textContent, 'Yakında sona erecek');
  assert.equal(h.node('#openssl-x509-sha').textContent, 'b'.repeat(64));
  assert.equal(input.value, '');
});
